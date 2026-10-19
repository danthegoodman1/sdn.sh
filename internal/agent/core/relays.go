//wirenet:deterministic

package core

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/kernel"
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
	floor := c.counter
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
		r.left, r.gap, r.after = c.cfg.RegisterRetries, c.cfg.RegisterRetry, floor
		r.at = now.Add(r.gap)
		r.paths[d.path] = port
		c.resendAck[ackKey{port, d.path}] = resendRef{st.name, d.key}
	}
}

// relayed is what withdrawing a relay peer's direction takes: its secret
// and the relay ports it registers at.
type relayed struct {
	secret model.Secret
	relays []api.RelayPath
}

// track records what withdrawing each relay peer's direction takes, for as
// long as the namespace's desired state names the peer or its device holds
// it.
func (c *Core) track(st *nsState, x *api.Interface) {
	seen := map[model.Key]bool{}
	for _, p := range x.Peers {
		if len(p.Relays) > 0 {
			seen[p.PublicKey] = true
			st.relayed[p.PublicKey] = relayed{p.Registration, slices.Clone(p.Relays)}
		}
	}
	maps.DeleteFunc(st.relayed, func(key model.Key, _ relayed) bool {
		_, installed := st.peers[key]
		return !seen[key] && !installed
	})
}

// withdraw tells each relay of every relay peer a batch removed that the
// namespace's direction toward it has no endpoint. A periodic claim sent
// just before the agent learned the peer was going can reach a relay after
// the removal; the withdrawal's higher counter outranks it, whichever
// arrives first, so the relay holds the peer's next initiation until this
// namespace claims again rather than deliver it to a device without the
// peer's key, which costs WireGuard's 5-second retry. Each withdrawal is
// resent unchanged until acknowledged, the first after RegisterRetry and
// each gap three times the last; at its own counter it never outranks a
// claim sent after it.
func (c *Core) withdraw(now time.Time, st *nsState, ops []kernel.Op) {
	i, ok := c.ifaces[st.iface]
	if !ok {
		return
	}
	var counter uint64
	for _, op := range ops {
		if op.Kind != kernel.SetPeers {
			continue
		}
		for _, u := range op.Peers {
			r, ok := st.relayed[u.PublicKey]
			if !u.Remove || !ok {
				continue
			}
			delete(st.relayed, u.PublicKey)
			if counter == 0 {
				counter = c.nextCounter(now)
			}
			for _, rp := range r.relays {
				key := ackKey{i.port, rp.Send}
				w := &withdrawal{
					payload: regproto.EncodeWithdrawal(regproto.RelayKey(r.secret, rp.Relay), rp.Send, counter),
					counter: counter, left: c.cfg.RegisterRetries, gap: c.cfg.RegisterRetry,
				}
				w.at = now.Add(w.gap)
				c.emit(SendRegistration{From: key.port, To: key.path, Payload: w.payload})
				c.Stats.Withdrawals++
				delete(c.withdrawals, key)
				if w.left > 0 {
					c.withdrawals[key] = w
				}
			}
		}
	}
}

// withdrawal is one direction's withdrawal awaiting its relay's
// acknowledgment, and when it goes again.
type withdrawal struct {
	payload [regproto.Size]byte
	counter uint64
	at      time.Time
	gap     time.Duration
	left    int
}

// resendWithdrawals sends again each withdrawal whose retry is due.
func (c *Core) resendWithdrawals(now time.Time) {
	for _, key := range slices.SortedFunc(maps.Keys(c.withdrawals), compareAckKey) {
		w := c.withdrawals[key]
		if now.Before(w.at) {
			continue
		}
		c.emit(SendRegistration{From: key.port, To: key.path, Payload: w.payload})
		c.Stats.Withdrawals++
		w.left--
		w.gap *= 3
		w.at = now.Add(w.gap)
		if w.left <= 0 {
			delete(c.withdrawals, key)
		}
	}
}

func compareAckKey(a, b ackKey) int {
	return cmp.Or(cmp.Compare(a.port, b.port), a.path.Compare(b.path))
}

// resend is one direction's schedule of further registrations, to the
// relay ports that have yet to acknowledge it, each with the listen port it
// was sent from. Only an acknowledgment of a counter above after ends it.
type resend struct {
	at    time.Time
	gap   time.Duration
	left  int
	after uint64
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
			// The claim outranks any withdrawal still being resent.
			delete(c.withdrawals, ackKey{i.port, rp.Send})
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
	c.resendWithdrawals(now)
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
	for _, key := range slices.SortedFunc(maps.Keys(c.withdrawals), compareAckKey) {
		soonest(c.withdrawals[key].at)
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
// from, of the registration at counter sent from a device's listen port.
// A withdrawal's acknowledgment ends its resends. A claim's ends that
// direction's resends to the relay and releases a new peer waiting on it,
// once its counter passes the one the schedule or wait began after: the
// agent's counters rise, so one at or below answers something sent
// earlier, such as the withdrawal of the peer's previous install, and the
// relay may hold no claim at all. It reports whether the acknowledgment
// changed anything; the relay acknowledges every registration, periodic
// ones included, and most change nothing.
func (c *Core) RegistrationAcked(now time.Time, port uint16, from netip.AddrPort, counter uint64) bool {
	key := ackKey{port, from}
	changed := false
	if w, ok := c.withdrawals[key]; ok && w.counter == counter {
		changed = true
		delete(c.withdrawals, key)
	}
	if ref, ok := c.resendAck[key]; ok {
		r, scheduled := c.resends[ref.ns][ref.key]
		if !scheduled || counter > r.after {
			changed = true
			delete(c.resendAck, key)
		}
		if scheduled && counter > r.after {
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
	st, ok := c.ns[name]
	if !ok {
		delete(c.awaitingAck, key)
		return changed
	}
	acked := false
	for _, k := range slices.SortedFunc(maps.Keys(st.acks), compareKey) {
		if w := st.acks[k]; w.path == from && !w.acked && counter > w.after {
			w.acked = true
			st.dirty = true
			c.Stats.Acked++
			acked = true
		}
	}
	if !acked {
		return changed
	}
	if c.Debug != nil {
		c.Debug(fmt.Sprintf("ack %d from %v for port %d awaited by %q", counter, from, port, name))
	}
	delete(c.awaitingAck, key)
	return true
}

// handoverWaits reports whether a configuring interface's namespace holds
// a slot back, which delays its handover until handoverBy.
func (c *Core) handoverWaits(i *iface) bool {
	st, ok := c.ns[i.ns]
	return ok && len(st.awaiting) > 0
}
