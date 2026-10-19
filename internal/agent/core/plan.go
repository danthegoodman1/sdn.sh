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
	"github.com/danthegoodman1/wirenet/internal/kernel"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/nft"
)

// Actions plans a batch for every namespace that needs one and returns
// everything the driver should do, in order.
func (c *Core) Actions(now time.Time) []Action {
	for _, name := range slices.Sorted(maps.Keys(c.ns)) {
		st := c.ns[name]
		if st.busy || !st.dirty || st.observe || now.Before(st.retryAt) {
			continue
		}
		st.dirty = false
		i := c.ifaces[st.iface]
		ops := c.plan(now, st, i)
		if len(ops) == 0 {
			c.Stats.Idle++
			c.settled(now, st, i)
			continue
		}
		c.batches++
		c.Stats.Batches++
		b := RunBatch{ID: c.batches, Namespace: name, Ops: ops}
		st.busy, st.batch = true, &b
		c.emit(b)
	}
	out := c.actions
	c.actions = nil
	return out
}

// plan returns the operations that move a namespace toward its target.
func (c *Core) plan(now time.Time, st *nsState, i *iface) []kernel.Op {
	// Only reconciliation tracks drains and acknowledgments; any other
	// phase owes them nothing.
	st.nextDrain = time.Time{}
	if i == nil || i.phase != configuring && i.phase != ready {
		c.dropWaits(st)
	}
	if st.ref != "" {
		if st.reaped {
			return nil
		}
		return []kernel.Op{{Kind: kernel.Reap, Ref: st.ref, AliasPrefix: c.cfg.AliasPrefix()}}
	}
	if i == nil {
		return nil
	}
	switch i.phase {
	case creating:
		var ops []kernel.Op
		if !st.exists {
			ops = append(ops, kernel.Op{Kind: kernel.CreateNamespace, Namespace: st.name})
		}
		if !st.device {
			ops = append(ops, kernel.Op{
				Kind: kernel.CreateDevice, Namespace: st.name, Device: c.cfg.Device,
				Create: &kernel.DeviceConfig{PrivateKey: i.priv, ListenPort: i.port, Alias: kernel.Alias(c.cfg.AliasPrefix(), i.id)},
			})
		}
		return ops
	case registering:
		return nil
	case configuring, ready:
		return c.planReconcile(now, st, i)
	}
	// Remove the egress link first: its host filter outlives the
	// namespace otherwise. Then the device before the namespace: a process
	// holding the namespace would keep the device, and its host-side
	// socket, alive.
	var ops []kernel.Op
	if !st.egressClear {
		ops = append(ops, kernel.Op{Kind: kernel.SetEgress, Namespace: st.name, EgressIndex: egressIndex(st, i)})
	}
	if st.device {
		ops = append(ops, kernel.Op{Kind: kernel.DeleteDevice, Namespace: st.name, Device: c.cfg.Device})
	}
	if st.exists {
		ops = append(ops, kernel.Op{Kind: kernel.DeleteNamespace, Namespace: st.name})
	}
	return ops
}

// dropWaits forgets everything a namespace's slots wait on.
func (c *Core) dropWaits(st *nsState) {
	st.awaiting = nil
	c.setReverse(st, nil)
	c.dropAcks(st)
}

// setReverse records the co-located interfaces a namespace waits on, so a
// batch done on one replans only the namespaces waiting for it.
func (c *Core) setReverse(st *nsState, ids []model.InterfaceID) {
	for _, id := range st.reverse {
		if w := c.reverseWait[id]; w != nil {
			delete(w, st.name)
			if len(w) == 0 {
				delete(c.reverseWait, id)
			}
		}
	}
	st.reverse = ids
	for _, id := range ids {
		if c.reverseWait[id] == nil {
			c.reverseWait[id] = map[string]bool{}
		}
		c.reverseWait[id][st.name] = true
	}
}

// dropAcks forgets every acknowledgment a namespace's peers wait on.
func (c *Core) dropAcks(st *nsState) {
	port := uint16(0)
	if i, ok := c.ifaces[st.iface]; ok {
		port = i.port
	}
	for _, key := range slices.SortedFunc(maps.Keys(st.acks), compareKey) {
		delete(c.awaitingAck, ackKey{port, st.acks[key].path})
		delete(st.acks, key)
	}
	st.ackBy = time.Time{}
}

// planReconcile orders the operations that bring a built namespace to its
// target.
func (c *Core) planReconcile(now time.Time, st *nsState, i *iface) []kernel.Op {
	n, ok := c.desired.Networks[i.network]
	if !ok && !c.synced {
		// Adopted at start, before the first poll: hold what is installed.
		return nil
	}
	x := &api.Interface{ID: i.id, State: api.Revoked}
	if ok {
		if found, has := n.Interface(i.id); has {
			x = found
		}
		st.revision = n.Revision
	}
	var tgt target
	if ok {
		c.track(st, x)
		tgt = c.target(now, st, n, x)
		if c.Debug != nil {
			var ids []string
			for _, p := range x.Peers {
				ids = append(ids, fmt.Sprintf("%s/d=%v", p.Interface, p.Draining))
			}
			c.Debug(fmt.Sprintf("plan %s rev %d state %s desired %v target %d installed %d", st.name, n.Revision, x.State, ids, len(tgt.peers), len(st.peers)))
		}
	} else {
		c.dropWaits(st)
		tgt = target{rules: &nft.Ruleset{}}
	}
	st.nextDrain = tgt.nextDrain
	var ops []kernel.Op
	if len(st.unflushed) > 0 {
		ops = append(ops, kernel.Op{Kind: kernel.Flush, Namespace: st.name, Addrs: slices.Clone(st.unflushed)})
	}
	if ok && x.Addr6.IsValid() && (st.link == nil || !st.link.Equal(&tgt.link)) {
		l := tgt.link
		ops = append(ops, kernel.Op{Kind: kernel.ConfigureLink, Namespace: st.name, Device: c.cfg.Device, Link: &l})
	}
	if want := egressFor(x, i.port); !want.Equal(st.egress) || want == nil && !st.egressClear {
		op := kernel.Op{Kind: kernel.SetEgress, Namespace: st.name, Egress: want}
		if want == nil {
			op.EgressIndex = egressIndex(st, i)
		}
		ops = append(ops, op)
	}
	// A peer that keeps some addresses and gains others takes them all
	// before the rules change and drops the old ones after, with the
	// removed peers, so no slot or source set ever names an address no
	// peer holds. What a peer drops is flushed like a removed peer's.
	var adds, removes []kernel.PeerUpdate
	var flush []netip.Addr
	want := map[model.Key]bool{}
	for _, tp := range tgt.peers {
		key := tp.peer.PublicKey
		want[key] = true
		inst, installed := st.peers[key]
		allowed := tp.peer.Allowed
		if installed {
			allowed = slices.Compact(kernel.SortPrefixes(slices.Concat(inst.Allowed, tp.peer.Allowed)))
			if dropped := without(inst.Allowed, tp.peer.Allowed); len(dropped) > 0 {
				removes = append(removes, kernel.PeerUpdate{PublicKey: key, Allowed: tp.peer.Allowed, Keepalive: tp.keepalive})
				for _, a := range dropped {
					flush = append(flush, a.Addr())
				}
			}
		}
		u := kernel.PeerUpdate{PublicKey: key, Allowed: allowed, Keepalive: tp.keepalive}
		need := !installed || !slices.Equal(inst.Allowed, allowed) || inst.Keepalive != tp.keepalive
		chosen, hasChosen := st.chosen[key]
		switch {
		case !tp.endpoint.IsValid():
			// A development machine dials in: roaming alone sets its
			// endpoint.
		case !installed:
			u.Endpoint = tp.endpoint
		case !hasChosen:
			// Adopted: an endpoint a roam left on a path the peer may use
			// stays, since roaming owns it.
			if slices.Contains(tp.accept, inst.Endpoint) {
				st.chosen[key] = tp.endpoint
			} else {
				u.Endpoint, need = tp.endpoint, true
			}
		case chosen != tp.endpoint:
			// The desired path moved, as on failover.
			u.Endpoint, need = tp.endpoint, true
		case inst.Endpoint.IsValid() && !slices.Contains(tp.accept, inst.Endpoint):
			// A roam to an endpoint no current path names, such as a port
			// an edge gave up, strands the peer; a roam between the
			// network's relays stays.
			u.Endpoint, need = tp.endpoint, true
		}
		if need {
			adds = append(adds, u)
		}
	}
	if len(adds) > 0 {
		ops = append(ops, kernel.Op{Kind: kernel.SetPeers, Namespace: st.name, Device: c.cfg.Device, Peers: adds})
	}
	if tx := nft.Diff(st.rules, tgt.rules); !tx.Empty() {
		ops = append(ops, kernel.Op{Kind: kernel.ApplyRules, Namespace: st.name, Rules: &tx})
	}
	for _, key := range slices.SortedFunc(maps.Keys(st.peers), compareKey) {
		if want[key] {
			continue
		}
		removes = append(removes, kernel.PeerUpdate{PublicKey: key, Remove: true})
		for _, a := range st.peers[key].Allowed {
			flush = append(flush, a.Addr())
		}
	}
	flush = slices.DeleteFunc(flush, func(a netip.Addr) bool { return slices.Contains(st.unflushed, a) })
	if len(removes) > 0 {
		ops = append(ops,
			kernel.Op{Kind: kernel.SetPeers, Namespace: st.name, Device: c.cfg.Device, Peers: removes},
			kernel.Op{Kind: kernel.Flush, Namespace: st.name, Addrs: flush})
	}
	if st.sweep {
		ops = append(ops, sweep(st.name, n, x, tgt, ok))
	}
	return ops
}

// sweep removes, after a restart lost track of what earlier batches
// removed, every flow that no peer the batch leaves installed accounts for.
// It runs last, so those peers are the target's. With no state for the
// network, the interface was revoked and forgotten and keeps no flow at
// all.
func sweep(name string, n *api.NetworkState, x *api.Interface, tgt target, ok bool) kernel.Op {
	if !ok {
		all := []netip.Prefix{netip.MustParsePrefix("::/0"), netip.MustParsePrefix("0.0.0.0/0")}
		return kernel.Op{Kind: kernel.Sweep, Namespace: name, Prefixes: all}
	}
	keep := slices.Clone(x.Addrs())
	for _, tp := range tgt.peers {
		for _, a := range tp.peer.Allowed {
			keep = append(keep, a.Addr())
		}
	}
	prefixes := []netip.Prefix{n.Prefix6}
	if n.Prefix4.IsValid() {
		prefixes = append(prefixes, n.Prefix4)
	}
	return kernel.Op{Kind: kernel.Sweep, Namespace: name, Addrs: keep, Prefixes: prefixes}
}

// without lists the prefixes of a that b lacks.
func without(a, b []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range a {
		if !slices.Contains(b, p) {
			out = append(out, p)
		}
	}
	return out
}

// egressIndex is the index of the host filter a namespace's egress may
// have left: the installed link's, or else the interface's listen port,
// which every grant uses.
func egressIndex(st *nsState, i *iface) uint16 {
	if st.egress != nil {
		return st.egress.Index
	}
	return i.port
}

// egressFor is a live interface's egress grant, or nil.
func egressFor(x *api.Interface, port uint16) *kernel.EgressConfig {
	if x.State != api.Live || len(x.Egress) == 0 {
		return nil
	}
	e := &kernel.EgressConfig{Index: port}
	for _, r := range x.Egress {
		e.Rules = append(e.Rules, kernel.EgressRule{Proto: r.Proto, Ports: r.Ports})
	}
	return e
}

// settled runs when a namespace needs no operations: whatever phase was
// waiting on it moves on.
func (c *Core) settled(now time.Time, st *nsState, i *iface) {
	if st.ref != "" {
		delete(c.ns, "ref:"+st.ref)
		return
	}
	if i == nil {
		return
	}
	switch i.phase {
	case creating:
		i.priv = model.Key{}
		i.phase, i.attachSent = registering, true
		c.emit(CallAttach{Request: c.attachRequest(i)})
	case configuring:
		// A workload sends as soon as it holds its namespace, so the
		// namespace waits, a bounded time, for the slots it holds back.
		if len(st.awaiting) > 0 && now.Before(i.handoverBy) {
			return
		}
		i.phase = ready
		c.emit(WriteJournal{Entry: c.entry(i)})
		for _, req := range i.waiting {
			c.emit(Reply{Request: req, Interface: c.describe(i)})
		}
		i.waiting = nil
	case detaching, aborting, orphan:
		if i.tornDown {
			return
		}
		i.tornDown = true
		for _, req := range i.waiting {
			c.emit(Reply{Request: req, Err: errors.Join(ErrAttachFailed, i.err)})
		}
		for _, req := range i.detachers {
			c.emit(Reply{Request: req, Interface: c.describe(i)})
		}
		i.waiting, i.detachers = nil, nil
		c.release(i)
		c.finish(i)
	}
}

// BatchDone takes a batch's outcome: done operations completed, and err is
// the next one's failure, if any.
func (c *Core) BatchDone(now time.Time, namespace string, id uint64, done int, err error) {
	st, ok := c.ns[namespace]
	if !ok || st.batch == nil || st.batch.ID != id {
		return
	}
	b := st.batch
	st.busy, st.batch = false, nil
	for _, op := range b.Ops[:done] {
		c.believe(st, op)
	}
	c.withdraw(now, st, b.Ops[:done])
	st.dirty = true
	c.rearm(st)
	if err == nil {
		st.failures = 0
		c.registerFresh(now, st)
		return
	}
	c.Stats.Failures++
	st.failures++
	st.retryAt = now.Add(c.backoff(st.failures))
	failed := b.Ops[done]
	if errors.Is(err, kernel.ErrNoNamespace) {
		// The namespace went behind the agent's back; looking tears the
		// interface down.
		st.observe = true
		c.emit(Observe{Namespace: st.name})
		return
	}
	switch failed.Kind {
	case kernel.CreateDevice:
		if errors.Is(err, kernel.ErrPortInUse) {
			if i, ok := c.ifaces[st.iface]; ok {
				c.badPort[i.port] = true
				if port, ok := c.freePort(); ok {
					i.port = port
					st.retryAt = now
				} else {
					c.abort(i, err)
				}
			}
		}
	case kernel.SetPeers, kernel.ConfigureLink, kernel.DeleteDevice, kernel.SetEgress:
		// A partial failure leaves the device in an unknown state; look
		// before planning again.
		st.observe = true
		st.link = nil
		c.emit(Observe{Namespace: st.name})
	case kernel.ApplyRules:
		// A transaction applies whole or not at all, so the table is as it
		// was; a failure that repeats replaces it.
		if st.failures > 1 {
			st.rules = nil
		}
	}
}

// rearm replans the namespaces waiting for a co-located device to hold
// their reverse peers, once its namespace's peers may have changed.
func (c *Core) rearm(changed *nsState) {
	for _, name := range slices.Sorted(maps.Keys(c.reverseWait[changed.iface])) {
		if st, ok := c.ns[name]; ok && st != changed {
			st.dirty = true
		}
	}
}

func (c *Core) backoff(failures int) time.Duration {
	d := c.cfg.RetryMin
	for range failures - 1 {
		d *= 2
		if d >= c.cfg.RetryMax {
			return c.cfg.RetryMax
		}
	}
	return d
}

// believe records what a completed operation did.
func (c *Core) believe(st *nsState, op kernel.Op) {
	switch op.Kind {
	case kernel.CreateNamespace:
		st.exists = true
	case kernel.CreateDevice:
		st.device = true
	case kernel.DeleteDevice:
		st.device = false
		st.peers = map[model.Key]kernel.Peer{}
	case kernel.DeleteNamespace:
		st.exists, st.device, st.egress = false, false, nil
	case kernel.SetEgress:
		st.egress = op.Egress.Clone()
		st.egressClear = op.Egress == nil
	case kernel.ConfigureLink:
		l := *op.Link
		st.link = &l
	case kernel.ApplyRules:
		if rs, err := nft.Apply(st.rules, *op.Rules); err == nil {
			st.rules = rs
		} else {
			st.rules = nil
		}
	case kernel.Reap:
		st.reaped = true
	case kernel.Sweep:
		st.sweep = false
	case kernel.Flush:
		st.unflushed = slices.DeleteFunc(st.unflushed, func(a netip.Addr) bool { return slices.Contains(op.Addrs, a) })
	case kernel.SetPeers:
		for _, u := range op.Peers {
			if u.Remove {
				for _, a := range st.peers[u.PublicKey].Allowed {
					if !slices.Contains(st.unflushed, a.Addr()) {
						st.unflushed = append(st.unflushed, a.Addr())
					}
				}
				delete(st.peers, u.PublicKey)
				delete(st.chosen, u.PublicKey)
				delete(st.fresh, u.PublicKey)
				continue
			}
			p, existed := st.peers[u.PublicKey]
			for _, a := range without(p.Allowed, u.Allowed) {
				if !slices.Contains(st.unflushed, a.Addr()) {
					st.unflushed = append(st.unflushed, a.Addr())
				}
			}
			p.PublicKey, p.Allowed, p.Keepalive = u.PublicKey, u.Allowed, u.Keepalive
			if u.Endpoint.IsValid() {
				p.Endpoint = u.Endpoint
				st.chosen[u.PublicKey] = u.Endpoint
			}
			st.peers[u.PublicKey] = p
			if !existed || u.Endpoint.IsValid() {
				st.fresh[u.PublicKey] = true
			}
		}
	}
}

// Observed takes a namespace's kernel state, as an Observe asked for.
func (c *Core) Observed(now time.Time, ns kernel.Namespace, err error) {
	st, ok := c.ns[ns.Name]
	if !ok {
		return
	}
	st.observe = false
	st.dirty = true
	if errors.Is(err, kernel.ErrNoNamespace) {
		st.exists = false
		if c.lost(st) {
			c.scan()
		}
		return
	}
	if err != nil {
		st.observe = true
		st.retryAt = now.Add(c.backoff(st.failures + 1))
		return
	}
	st.exists = true
	st.egress = ns.Egress.Clone()
	if st.egress != nil {
		st.egressClear = false
	}
	dev, hasDev := findDevice(ns, c.cfg.Device)
	st.device = hasDev
	before := st.peers
	st.peers = map[model.Key]kernel.Peer{}
	for _, p := range dev.Peers {
		st.peers[p.PublicKey] = p
		if _, known := before[p.PublicKey]; !known {
			// Installed by an operation that failed partway: it registers
			// as any new peer does.
			st.fresh[p.PublicKey] = true
		}
	}
	defer c.registerFresh(now, st)
	c.rearm(st)
	for _, key := range slices.SortedFunc(maps.Keys(st.chosen), compareKey) {
		if _, ok := st.peers[key]; !ok {
			delete(st.chosen, key)
		}
	}
	if i, ok := c.ifaces[st.iface]; ok && i.phase == ready && (!hasDev || !dev.HasKey || dev.PublicKey != i.pub) {
		// The device vanished or changed behind the agent's back: its key
		// is gone, and so is the interface.
		i.phase = detaching
		c.emit(WriteJournal{Entry: c.entry(i)})
	}
}

// SettledNamespace is a namespace with nothing pending, and the network
// revision its kernel state reflects: zero once the host holds no state for
// the network, as after the interface was revoked and forgotten.
type SettledNamespace struct {
	Interface model.InterfaceID
	Network   model.NetworkID
	Revision  uint64
}

// Settled lists the ready namespaces with nothing in flight or pending and
// reconciled against the network revision held.
func (c *Core) Settled() map[string]SettledNamespace {
	out := map[string]SettledNamespace{}
	for _, name := range slices.Sorted(maps.Keys(c.ns)) {
		st := c.ns[name]
		i, ok := c.ifaces[st.iface]
		if !ok || i.phase != ready || st.busy || st.dirty || st.observe || st.sweep || len(st.awaiting) > 0 || len(st.unflushed) > 0 {
			continue
		}
		n, ok := c.desired.Networks[i.network]
		switch {
		case !ok && c.synced:
			out[name] = SettledNamespace{Interface: i.id, Network: i.network}
		case ok && n.Revision == st.revision:
			out[name] = SettledNamespace{Interface: i.id, Network: i.network, Revision: st.revision}
		}
	}
	return out
}

// Pending describes what keeps the core busy, for diagnostics.
func (c *Core) Pending() []string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(c.ns)) {
		st := c.ns[name]
		if st.busy || st.dirty || st.observe || len(st.awaiting) > 0 {
			out = append(out, fmt.Sprintf("namespace %s: busy=%v dirty=%v observe=%v awaiting=%v failures=%d retry=%v", name, st.busy, st.dirty, st.observe, st.awaiting, st.failures, st.retryAt))
		}
	}
	for _, id := range slices.Sorted(maps.Keys(c.ifaces)) {
		if i := c.ifaces[id]; i.phase != ready {
			out = append(out, fmt.Sprintf("interface %s: %s torn=%v released=%v releasing=%v sent=%v", id, i.phase, i.tornDown, i.released, i.releasing, i.attachSent))
		}
	}
	return out
}

// Busy reports whether any namespace has work in flight or pending.
func (c *Core) Busy() bool {
	for _, name := range slices.Sorted(maps.Keys(c.ns)) {
		st := c.ns[name]
		if st.busy || st.dirty || st.observe {
			return true
		}
	}
	for _, id := range slices.Sorted(maps.Keys(c.ifaces)) {
		if p := c.ifaces[id].phase; p != ready {
			return true
		}
	}
	return false
}
