//sdn:deterministic

package core

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
	"sdn.sh/internal/regproto"
)

// activeRelay returns the relay a network's peers send through: the first of
// its set this agent's probes find up, or the first of the set when none is.
// Each side chooses for itself; roaming reconciles the two, since a packet
// arriving through another relay moves the receiver's endpoint there.
// Every change to desired state reselects, so the relay it keeps is one the
// set names.
func (c *Core) activeRelay(n *api.NetworkState) model.RelayID {
	if len(n.Relays) == 0 {
		return ""
	}
	if id, ok := c.active[n.Network]; ok {
		return id
	}
	id := c.chooseRelay(n)
	c.active[n.Network] = id
	return id
}

func inSet(n *api.NetworkState, id model.RelayID) bool {
	return slices.ContainsFunc(n.Relays, func(r api.RelayRef) bool { return r.Relay == id })
}

func (c *Core) chooseRelay(n *api.NetworkState) model.RelayID {
	for _, r := range n.Relays {
		if h, ok := c.relays[r.Relay]; !ok || h.up {
			return r.Relay
		}
	}
	return n.Relays[0].Relay
}

// ProbeReply takes a relay's answer to a probe.
func (c *Core) ProbeReply(now time.Time, relay model.RelayID, nonce uint64) {
	h, ok := c.relays[relay]
	if !ok {
		return
	}
	if _, ok := h.outstanding[nonce]; !ok {
		return
	}
	delete(h.outstanding, nonce)
	h.lastReply = now
	if !h.up {
		h.up = true
		c.reselect()
	}
}

// probe sends every relay of every held network a probe, and marks down a
// relay that has answered none for ProbeMisses periods.
func (c *Core) probe(now time.Time) {
	seen := map[model.RelayID]bool{}
	for _, nid := range c.desired.NetworkIDs() {
		for _, r := range c.desired.Networks[nid].Relays {
			if seen[r.Relay] {
				continue
			}
			seen[r.Relay] = true
			h, ok := c.relays[r.Relay]
			if !ok {
				h = &relayHealth{up: true, lastReply: now, outstanding: map[uint64]time.Time{}}
				c.relays[r.Relay] = h
			}
			for _, nonce := range slices.Sorted(maps.Keys(h.outstanding)) {
				if now.Sub(h.outstanding[nonce]) > time.Duration(c.cfg.ProbeMisses)*c.cfg.ProbeEvery {
					delete(h.outstanding, nonce)
				}
			}
			c.nonce++
			h.outstanding[c.nonce] = now
			c.emit(SendProbe{Relay: r.Relay, To: r.Probe, Nonce: c.nonce})
		}
	}
	changed := false
	for _, id := range slices.Sorted(maps.Keys(c.relays)) {
		h := c.relays[id]
		if !seen[id] {
			delete(c.relays, id)
			continue
		}
		if h.up && now.Sub(h.lastReply) > time.Duration(c.cfg.ProbeMisses)*c.cfg.ProbeEvery {
			h.up = false
			changed = true
		}
	}
	if changed {
		c.reselect()
	}
}

// reselect recomputes each network's active relay, and marks for
// reconciliation every namespace whose relay changed, which rewrites its
// relay peers' endpoints. Leaving a relay that left the set is no failover.
func (c *Core) reselect() {
	for _, nid := range c.desired.NetworkIDs() {
		n := c.desired.Networks[nid]
		if len(n.Relays) == 0 {
			continue
		}
		id := c.chooseRelay(n)
		prev, ok := c.active[nid]
		if ok && prev == id {
			continue
		}
		if ok && inSet(n, prev) {
			c.Stats.Failovers++
		}
		c.active[nid] = id
		for _, name := range slices.Sorted(maps.Keys(c.ns)) {
			st := c.ns[name]
			if i, ok := c.ifaces[st.iface]; ok && i.network == nid {
				st.dirty = true
			}
		}
	}
}

// Active returns each network's active relay, for metrics and tests.
func (c *Core) Active() map[model.NetworkID]model.RelayID { return maps.Clone(c.active) }

// registerFresh registers every relay peer a batch just installed or moved.
func (c *Core) registerFresh(now time.Time, st *nsState) {
	if len(st.fresh) == 0 {
		return
	}
	keys := slices.SortedFunc(maps.Keys(st.fresh), compareKey)
	st.fresh = map[model.Key]bool{}
	c.register(now, st, keys)
	if c.cfg.RegisterRetries <= 0 {
		return
	}
	r, ok := c.resends[st.name]
	if !ok {
		r = &resend{}
		c.resends[st.name] = r
	}
	r.keys = slices.Compact(slices.SortedFunc(slices.Values(append(r.keys, keys...)), compareKey))
	r.left, r.gap = c.cfg.RegisterRetries, c.cfg.RegisterRetry
	r.at = now.Add(r.gap)
}

// resend is a namespace's fresh directions awaiting another registration.
type resend struct {
	keys []model.Key
	at   time.Time
	gap  time.Duration
	left int
}

// resendDue sends the registrations whose retry is due.
func (c *Core) resendDue(now time.Time) {
	for _, name := range slices.Sorted(maps.Keys(c.resends)) {
		r := c.resends[name]
		if now.Before(r.at) {
			continue
		}
		st, ok := c.ns[name]
		if !ok {
			delete(c.resends, name)
			continue
		}
		c.register(now, st, r.keys)
		r.left--
		r.gap *= 3
		r.at = now.Add(r.gap)
		if r.left <= 0 {
			delete(c.resends, name)
		}
	}
}

// register sends a registration for each relay peer named, to every relay of
// its set, or for every relay peer when keys is nil.
func (c *Core) register(now time.Time, st *nsState, keys []model.Key) {
	i, ok := c.ifaces[st.iface]
	if !ok || i.phase != ready && i.phase != configuring {
		return
	}
	n, ok := c.desired.Networks[i.network]
	if !ok {
		return
	}
	x, ok := n.Interface(i.id)
	if !ok || x.State != api.Live {
		return
	}
	for _, p := range x.Peers {
		if len(p.Relays) == 0 {
			continue
		}
		if _, installed := st.peers[p.PublicKey]; !installed {
			continue
		}
		if keys != nil && !slices.Contains(keys, p.PublicKey) {
			continue
		}
		counter := c.nextCounter(now)
		for _, rp := range p.Relays {
			key := regproto.RelayKey(p.Registration, rp.Relay)
			c.emit(SendRegistration{From: i.port, To: rp.Send, Payload: regproto.Encode(key, rp.Send, counter)})
			c.Stats.Registrations++
		}
	}
}

// nextCounter derives a registration counter from the clock, so it survives
// an agent restart, and keeps it rising within a run.
func (c *Core) nextCounter(now time.Time) uint64 {
	v := uint64(now.UnixMilli())
	if v <= c.counter {
		v = c.counter + 1
	}
	c.counter = v
	return v
}

// UnderlayChanged re-registers every direction at once, as after the host's
// address changes or it resumes, rather than waiting out the period.
func (c *Core) UnderlayChanged(now time.Time) {
	c.lastRegister = now
	for _, name := range slices.Sorted(maps.Keys(c.ns)) {
		c.register(now, c.ns[name], nil)
	}
}

// Tick runs the core's timers: attach deadlines, drain grace periods,
// registration and probe periods, and resyncs.
func (c *Core) Tick(now time.Time) {
	for _, id := range slices.Sorted(maps.Keys(c.ifaces)) {
		i := c.ifaces[id]
		switch {
		case (i.phase == creating || i.phase == registering) && !now.Before(i.deadline):
			c.abort(i, errAttachTimeout)
		case i.phase == configuring && c.handoverWaits(i) && !now.Before(i.handoverBy):
			c.ns[i.ns].dirty = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.ns)) {
		st := c.ns[name]
		if !st.nextDrain.IsZero() && !now.Before(st.nextDrain) {
			st.dirty = true
		}
		if !st.ackBy.IsZero() && !now.Before(st.ackBy) {
			st.dirty = true
		}
	}
	c.retryReleases(now)
	if c.cfg.ProbeEvery > 0 && !now.Before(c.lastProbe.Add(c.cfg.ProbeEvery)) {
		c.lastProbe = now
		c.probe(now)
	}
	if c.cfg.RegisterEvery > 0 && !now.Before(c.lastRegister.Add(c.cfg.RegisterEvery)) {
		c.UnderlayChanged(now)
	}
	c.resendDue(now)
	if c.cfg.ResyncEvery > 0 && !now.Before(c.lastResync.Add(c.cfg.ResyncEvery)) {
		c.lastResync = now
		c.scan()
		for _, name := range slices.Sorted(maps.Keys(c.ns)) {
			st := c.ns[name]
			if i, ok := c.ifaces[st.iface]; ok && i.phase == ready && !st.busy && !st.observe {
				st.observe = true
				c.emit(Observe{Namespace: name})
			}
		}
	}
}

// NextWake is the earliest time Tick has work.
func (c *Core) NextWake(now time.Time) time.Time {
	next := c.lastProbe.Add(c.cfg.ProbeEvery)
	soonest := func(t time.Time) {
		if !t.IsZero() && t.Before(next) {
			next = t
		}
	}
	if c.cfg.ProbeEvery == 0 {
		next = c.lastRegister.Add(c.cfg.RegisterEvery)
	}
	soonest(c.lastRegister.Add(c.cfg.RegisterEvery))
	soonest(c.lastResync.Add(c.cfg.ResyncEvery))
	soonest(c.nextRelease)
	for _, name := range slices.Sorted(maps.Keys(c.resends)) {
		soonest(c.resends[name].at)
	}
	for _, id := range slices.Sorted(maps.Keys(c.ifaces)) {
		i := c.ifaces[id]
		switch {
		case i.phase == creating || i.phase == registering:
			soonest(i.deadline)
		case i.phase == configuring && c.handoverWaits(i) && !c.ns[i.ns].dirty:
			soonest(i.handoverBy)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.ns)) {
		st := c.ns[name]
		// A dirty namespace replans as soon as it can, and Actions plans
		// every one it can at once, so only a retry still ahead of now is a
		// reason to wake; a drain or an acknowledgment's deadline matters
		// until a plan has seen it pass.
		if !st.dirty {
			soonest(st.nextDrain)
			soonest(st.ackBy)
		}
		if st.dirty && !st.busy && !st.observe && st.retryAt.After(now) {
			soonest(st.retryAt)
		}
	}
	if next.Before(now) {
		return now
	}
	return next
}

var errAttachTimeout = errors.New("the control plane did not answer in time")

// RegistrationAcked takes a relay's acknowledgment, from the relay port
// from, of a registration sent from a device's listen port. Only a
// direction a new peer waits on has any effect.
func (c *Core) RegistrationAcked(now time.Time, port uint16, from netip.AddrPort) {
	key := ackKey{port, from}
	name, ok := c.awaitingAck[key]
	if c.Debug != nil {
		c.Debug(fmt.Sprintf("ack from %v for port %d awaited by %q", from, port, name))
	}
	if !ok {
		return
	}
	delete(c.awaitingAck, key)
	st, ok := c.ns[name]
	if !ok {
		return
	}
	for _, k := range slices.SortedFunc(maps.Keys(st.acks), compareKey) {
		if w := st.acks[k]; w.path == from && !w.acked {
			w.acked = true
			st.dirty = true
			c.Stats.Acked++
		}
	}
}

// handoverWaits reports whether a configuring interface's namespace holds
// a slot back, which delays its handover until handoverBy.
func (c *Core) handoverWaits(i *iface) bool {
	st, ok := c.ns[i.ns]
	return ok && len(st.awaiting) > 0
}
