//wirenet:deterministic

package core

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/regproto"
)

// edgeRelay chooses the relay path a peer's traffic takes: of the peer's
// paths, the one through the relay of highest weight for the edge
// (model.RelayWeight) among those this agent's probes find up, or of them
// all when none is. Both ends weigh the same, so they choose the same relay
// while their probes agree, and roaming reconciles them when they differ,
// since a packet arriving through another relay moves the receiver's
// endpoint there. A relay's loss moves only the edges it carried, each to
// its own next relay, so a network's traffic spreads over every relay in
// its set and a dead relay's over the survivors.
func (c *Core) edgeRelay(self model.InterfaceID, p api.Peer) (api.RelayPath, bool) {
	var best api.RelayPath
	var bestW uint64
	bestUp, found := false, false
	for _, rp := range p.Relays {
		h, probed := c.relays[rp.Relay]
		up := !probed || h.up
		w := model.RelayWeight(self, p.Interface, rp.Relay)
		if !found || up && !bestUp || up == bestUp && (w > bestW || w == bestW && rp.Relay < best.Relay) {
			best, bestW, bestUp, found = rp, w, up, true
		}
	}
	return best, found
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
		c.relaysChanged(map[model.RelayID]bool{relay: true})
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
	down := map[model.RelayID]bool{}
	for _, id := range slices.Sorted(maps.Keys(c.relays)) {
		h := c.relays[id]
		if !seen[id] {
			delete(c.relays, id)
			continue
		}
		if h.up && now.Sub(h.lastReply) > time.Duration(c.cfg.ProbeMisses)*c.cfg.ProbeEvery {
			h.up = false
			down[id] = true
			c.Stats.Failovers++
		}
	}
	if len(down) > 0 {
		c.relaysChanged(down)
	}
}

// relaysChanged marks for reconciliation every namespace whose network names
// a relay that went down or came back, which moves the endpoints of the
// edges that relay's health decides.
func (c *Core) relaysChanged(ids map[model.RelayID]bool) {
	for _, name := range slices.Sorted(maps.Keys(c.ns)) {
		st := c.ns[name]
		i, ok := c.ifaces[st.iface]
		if !ok {
			continue
		}
		n, ok := c.desired.Networks[i.network]
		if ok && slices.ContainsFunc(n.Relays, func(r api.RelayRef) bool { return ids[r.Relay] }) {
			st.dirty = true
		}
	}
}

// RelaysUp reports which relays of the held networks this agent's probes
// find up, for status and metrics.
func (c *Core) RelaysUp() map[model.RelayID]bool {
	out := map[model.RelayID]bool{}
	for _, id := range slices.Sorted(maps.Keys(c.relays)) {
		out[id] = c.relays[id].up
	}
	return out
}

// registerFresh registers every relay peer a batch just installed or moved,
// and schedules each direction's registration again at every relay that has
// yet to acknowledge it, the first after RegisterRetry and each gap three
// times the last. Each direction keeps its own schedule, so a namespace
// gaining peers resends only the new ones.
func (c *Core) registerFresh(now time.Time, st *nsState) {
	if len(st.fresh) == 0 {
		return
	}
	fresh := st.fresh
	st.fresh = map[model.Key]bool{}
	sent := c.register(now, st, func(key model.Key, _ netip.AddrPort) bool { return fresh[key] })
	if c.cfg.RegisterRetries <= 0 || len(sent) == 0 {
		return
	}
	port := c.ifaces[st.iface].port
	sched := c.resends[st.name]
	if sched == nil {
		sched = map[model.Key]*resend{}
		c.resends[st.name] = sched
	}
	for _, d := range sent {
		r := sched[d.key]
		if r == nil {
			r = &resend{paths: map[netip.AddrPort]uint16{}}
			sched[d.key] = r
		}
		r.left, r.gap = c.cfg.RegisterRetries, c.cfg.RegisterRetry
		r.at = now.Add(r.gap)
		r.paths[d.path] = port
		c.resendAck[ackKey{port, d.path}] = resendRef{st.name, d.key}
	}
}

// resend is one direction's schedule of further registrations, to the
// relay ports that have yet to acknowledge it, each with the listen port it
// was sent from.
type resend struct {
	at    time.Time
	gap   time.Duration
	left  int
	paths map[netip.AddrPort]uint16
}

// resendRef names the direction an acknowledgment ends a schedule for.
type resendRef struct {
	ns  string
	key model.Key
}

// resendDue sends the registrations whose retry is due.
func (c *Core) resendDue(now time.Time) {
	for _, name := range slices.Sorted(maps.Keys(c.resends)) {
		sched := c.resends[name]
		st, ok := c.ns[name]
		if !ok {
			c.endResends(name, nil)
			continue
		}
		due := map[model.Key]bool{}
		for _, key := range slices.SortedFunc(maps.Keys(sched), compareKey) {
			if !now.Before(sched[key].at) {
				due[key] = true
			}
		}
		if len(due) == 0 {
			continue
		}
		c.register(now, st, func(key model.Key, path netip.AddrPort) bool {
			if !due[key] {
				return false
			}
			_, waiting := sched[key].paths[path]
			return waiting
		})
		for _, key := range slices.SortedFunc(maps.Keys(due), compareKey) {
			r := sched[key]
			r.left--
			r.gap *= 3
			r.at = now.Add(r.gap)
			if r.left <= 0 {
				c.endResends(name, []model.Key{key})
			}
		}
	}
}

// endResends drops a namespace's schedules for keys, or every schedule it
// has when keys is nil.
func (c *Core) endResends(name string, keys []model.Key) {
	sched := c.resends[name]
	if keys == nil {
		keys = slices.SortedFunc(maps.Keys(sched), compareKey)
	}
	for _, key := range keys {
		if r, ok := sched[key]; ok {
			for _, path := range slices.SortedFunc(maps.Keys(r.paths), netip.AddrPort.Compare) {
				delete(c.resendAck, ackKey{r.paths[path], path})
			}
			delete(sched, key)
		}
	}
	if len(sched) == 0 {
		delete(c.resends, name)
	}
}

// sentTo is one registration register sent: a direction, by its peer's key,
// and the relay port it went to.
type sentTo struct {
	key  model.Key
	path netip.AddrPort
}

// register sends a registration for each relay peer and relay port want
// accepts, or for every one when want is nil, and returns what it sent.
func (c *Core) register(now time.Time, st *nsState, want func(model.Key, netip.AddrPort) bool) []sentTo {
	i, ok := c.ifaces[st.iface]
	if !ok || i.phase != ready && i.phase != configuring {
		return nil
	}
	n, ok := c.desired.Networks[i.network]
	if !ok {
		return nil
	}
	x, ok := n.Interface(i.id)
	if !ok || x.State != api.Live {
		return nil
	}
	var sent []sentTo
	for _, p := range x.Peers {
		if len(p.Relays) == 0 {
			continue
		}
		if _, installed := st.peers[p.PublicKey]; !installed {
			continue
		}
		var counter uint64
		for _, rp := range p.Relays {
			if want != nil && !want(p.PublicKey, rp.Send) {
				continue
			}
			if counter == 0 {
				counter = c.nextCounter(now)
			}
			key := regproto.RelayKey(p.Registration, rp.Relay)
			c.emit(SendRegistration{From: i.port, To: rp.Send, Payload: regproto.Encode(key, rp.Send, counter)})
			c.Stats.Registrations++
			sent = append(sent, sentTo{p.PublicKey, rp.Send})
		}
	}
	return sent
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
		sched := c.resends[name]
		for _, key := range slices.SortedFunc(maps.Keys(sched), compareKey) {
			soonest(sched[key].at)
		}
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
// from, of a registration sent from a device's listen port. It ends that
// direction's resends to the relay, and releases a new peer waiting on it.
// It reports whether the acknowledgment changed anything; the relay
// acknowledges every registration, periodic ones included, and most change
// nothing.
func (c *Core) RegistrationAcked(now time.Time, port uint16, from netip.AddrPort) bool {
	key := ackKey{port, from}
	changed := false
	if ref, ok := c.resendAck[key]; ok {
		changed = true
		delete(c.resendAck, key)
		if r, ok := c.resends[ref.ns][ref.key]; ok {
			delete(r.paths, from)
			if len(r.paths) == 0 {
				c.endResends(ref.ns, []model.Key{ref.key})
			}
		}
	}
	name, ok := c.awaitingAck[key]
	if !ok {
		return changed
	}
	if c.Debug != nil {
		c.Debug(fmt.Sprintf("ack from %v for port %d awaited by %q", from, port, name))
	}
	delete(c.awaitingAck, key)
	st, ok := c.ns[name]
	if !ok {
		return changed
	}
	for _, k := range slices.SortedFunc(maps.Keys(st.acks), compareKey) {
		if w := st.acks[k]; w.path == from && !w.acked {
			w.acked = true
			st.dirty = true
			c.Stats.Acked++
		}
	}
	return true
}

// handoverWaits reports whether a configuring interface's namespace holds
// a slot back, which delays its handover until handoverBy.
func (c *Core) handoverWaits(i *iface) bool {
	st, ok := c.ns[i.ns]
	return ok && len(st.awaiting) > 0
}
