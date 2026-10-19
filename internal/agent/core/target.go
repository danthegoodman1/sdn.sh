//wirenet:deterministic

package core

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/kernel"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/nft"
	"github.com/danthegoodman1/wirenet/internal/slots"
)

// target is what one namespace should hold now.
type target struct {
	link  kernel.LinkConfig
	peers []tpeer
	rules *nft.Ruleset
	// nextDrain is when the earliest draining peer's grace ends.
	nextDrain time.Time
}

// tpeer is one peer the namespace should hold.
type tpeer struct {
	peer      api.Peer
	endpoint  netip.AddrPort
	accept    []netip.AddrPort
	keepalive time.Duration
	// awaiting marks a peer no slot names yet: a co-located one whose
	// device has yet to hold the reverse peer, or a relay peer new to the
	// namespace whose relay has yet to acknowledge it.
	awaiting bool
}

// loopback is the address co-located devices reach each other at. Both
// sockets live in the host namespace, so the packet never leaves it.
func loopback(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)
}

// linkConfig is a device's addresses, routes and MTU. A gateway's
// namespace forwards for its development machines.
func linkConfig(n *api.NetworkState, x *api.Interface) kernel.LinkConfig {
	l := kernel.LinkConfig{
		Addrs:   []netip.Prefix{netip.PrefixFrom(x.Addr6, 128)},
		Routes:  []netip.Prefix{n.Prefix6},
		MTU:     n.MTU,
		Forward: x.Kind == api.Gateway,
	}
	if x.Addr4.IsValid() && n.Prefix4.IsValid() {
		l.Addrs = append(l.Addrs, netip.PrefixFrom(x.Addr4, 32))
		l.Routes = append(l.Routes, n.Prefix4)
	}
	return l
}

// target computes what a namespace should hold. A draining peer stays until
// its grace period ends, counted from when this agent first saw it drain; a
// peer claiming an address an installed peer holds waits for the holder to
// leave.
func (c *Core) target(now time.Time, st *nsState, n *api.NetworkState, x *api.Interface) target {
	t := target{link: linkConfig(n, x)}
	owner := map[netip.Prefix]model.Key{}
	for _, key := range slices.SortedFunc(maps.Keys(st.peers), compareKey) {
		for _, a := range st.peers[key].Allowed {
			owner[a] = key
		}
	}
	draining := map[model.Key]bool{}
	acking := map[model.Key]bool{}
	sessioning, checkable := map[model.Key]bool{}, map[model.Key]bool{}
	var port uint16
	if i, ok := c.ifaces[st.iface]; ok {
		port = i.port
	}
	st.awaiting = nil
	var reverse []model.InterfaceID
	if x.State == api.Live {
		for _, p := range x.Peers {
			if p.Draining {
				draining[p.PublicKey] = true
				seen, ok := st.drain[p.PublicKey]
				if !ok {
					seen = now
					st.drain[p.PublicKey] = now
				}
				grace := c.cfg.DrainGrace
				if svc, ok := n.Service(p.Service); ok && svc.Mode == api.Cutover {
					grace = 0
				}
				end := seen.Add(grace)
				if !now.Before(end) {
					continue
				}
				if t.nextDrain.IsZero() || end.Before(t.nextDrain) {
					t.nextDrain = end
				}
			}
			if conflicted(owner, p) {
				c.Stats.Conflicts++
				continue
			}
			tp := c.tpeer(x.ID, p)
			switch {
			case p.Draining:
			case p.Loopback != 0:
				// Both waits start while the peer is new; a session can
				// form only once the other device holds this one.
				held := c.holdsReverse(st, p)
				sessioning[p.PublicKey] = c.awaitsSession(now, st, x, p, held)
				checkable[p.PublicKey] = held
				tp.awaiting = !held || sessioning[p.PublicKey]
				if !held {
					reverse = append(reverse, p.Interface)
				}
			default:
				// A peer no slot names holds nothing back, but its wait
				// still delays the handover: a backend's attach answers
				// once the relay holds its edges' ports, so an
				// orchestrator that removes the old backend then strands
				// no client.
				tp.awaiting = c.awaitsAck(now, st, port, p, tp)
				acking[p.PublicKey] = tp.awaiting
			}
			if tp.awaiting {
				st.awaiting = append(st.awaiting, p.Interface)
			}
			// A draining peer carries nothing new, so it is never armed.
			if tp.keepalive > 0 && st.peers[p.PublicKey].Keepalive == 0 && (tp.awaiting || p.Draining) {
				tp.keepalive = 0
			}
			t.peers = append(t.peers, tp)
		}
	}
	for _, key := range slices.SortedFunc(maps.Keys(st.drain), compareKey) {
		if !draining[key] {
			delete(st.drain, key)
		}
	}
	c.setReverse(st, reverse)
	st.ackBy = time.Time{}
	for _, key := range slices.SortedFunc(maps.Keys(st.acks), compareKey) {
		w := st.acks[key]
		if acking[key] {
			if st.ackBy.IsZero() || w.until.Before(st.ackBy) {
				st.ackBy = w.until
			}
			continue
		}
		if !w.acked && !now.Before(w.until) {
			c.Stats.AckTimeouts++
			if c.Debug != nil {
				c.Debug(fmt.Sprintf("%s: no ack from %v for port %d by %v", st.name, w.path, port, w.until))
			}
		}
		delete(c.awaitingAck, ackKey{port, w.path})
		delete(st.acks, key)
	}
	var check []model.Key
	var checkBy time.Time
	for _, key := range slices.SortedFunc(maps.Keys(st.sessions), compareKey) {
		w := st.sessions[key]
		if !sessioning[key] {
			if !w.up && !w.until.IsZero() && !now.Before(w.until) {
				c.Stats.SessionTimeouts++
			}
			delete(st.sessions, key)
			continue
		}
		if w.until.IsZero() {
			continue
		}
		if st.ackBy.IsZero() || w.until.Before(st.ackBy) {
			st.ackBy = w.until
		}
		if _, installed := st.peers[key]; installed && checkable[key] {
			check = append(check, key)
			if checkBy.IsZero() || w.until.After(checkBy) {
				checkBy = w.until
			}
		}
	}
	if len(check) > 0 && !st.checking {
		st.checking = true
		c.emit(CheckSessions{Namespace: st.name, Device: c.cfg.Device, Keys: check, Until: checkBy})
	}
	slices.SortFunc(t.peers, func(a, b tpeer) int { return compareKey(a.peer.PublicKey, b.peer.PublicKey) })
	t.rules = c.rules(n, x, t.peers)
	return t
}

// holdsReverse reports whether the co-located device a peer names holds
// this namespace's interface as a peer, as far as the agent knows: the
// other namespace's peers, less what a batch running there removes.
// Anything sent to a device without the reverse peer is dropped, and
// WireGuard waits five seconds before trying again, so keepalive, which
// sends at once when armed, and slots, which send a workload's traffic,
// wait for it.
func (c *Core) holdsReverse(st *nsState, p api.Peer) bool {
	self, ok := c.ifaces[st.iface]
	if !ok {
		return false
	}
	other, ok := c.ifaces[p.Interface]
	if !ok || other.phase.tearingDown() {
		return false
	}
	ost, ok := c.ns[other.ns]
	if !ok {
		return false
	}
	if _, ok := ost.peers[self.pub]; !ok {
		return false
	}
	if ost.batch == nil {
		return true
	}
	for _, op := range ost.batch.Ops {
		switch op.Kind {
		case kernel.DeleteDevice, kernel.DeleteNamespace:
			return false
		case kernel.SetPeers:
			for _, u := range op.Peers {
				if u.Remove && u.PublicKey == self.pub {
					return false
				}
			}
		}
	}
	return true
}

// awaitsAck reports whether a relay peer new to the namespace still waits
// for the relay its edge sends through to acknowledge the namespace's
// registration toward it. A relay binds a new edge's port only once it loads the table naming
// it, which can trail the agent installing the peer, and a handshake
// initiation sent to a port no socket holds is dropped; WireGuard then
// waits five seconds before trying again. A peer installed before, such
// as one adopted at start or one whose path moves on failover, never
// waits, and none waits past AckWait.
func (c *Core) awaitsAck(now time.Time, st *nsState, port uint16, p api.Peer, tp tpeer) bool {
	if len(p.Relays) == 0 || !tp.endpoint.IsValid() {
		return false
	}
	w, ok := st.acks[p.PublicKey]
	if !ok {
		if _, installed := st.peers[p.PublicKey]; installed {
			return false
		}
		w = &ackWait{until: now.Add(c.cfg.AckWait), after: c.counter}
		st.acks[p.PublicKey] = w
	}
	if w.path != tp.endpoint {
		delete(c.awaitingAck, ackKey{port, w.path})
		w.path = tp.endpoint
	}
	if w.acked || !now.Before(w.until) {
		return false
	}
	c.awaitingAck[ackKey{port, w.path}] = st.name
	return true
}

// awaitsSession reports whether a co-located peer new to the namespace,
// which keeps the pair alive from its side and which this interface
// reaches too, still waits for this namespace's device to hold a session
// with it. Arming keepalive sends an initiation, and so would this side's
// first connection: two initiations that cross each discard the other's
// pending handshake and cost both sides 5 seconds (noise.c, send.c). Once
// a session holds, the connection uses it and initiates nothing. A peer
// installed before never waits, and none waits past AckWait from when the
// other device holds the reverse peer.
func (c *Core) awaitsSession(now time.Time, st *nsState, x *api.Interface, p api.Peer, held bool) bool {
	if p.Keepalive || !slices.ContainsFunc(x.Reach, func(r api.Reach) bool { return r.Service == p.Service }) {
		return false
	}
	w, ok := st.sessions[p.PublicKey]
	if !ok {
		if _, installed := st.peers[p.PublicKey]; installed {
			return false
		}
		w = &sessionWait{}
		st.sessions[p.PublicKey] = w
	}
	if held && w.until.IsZero() {
		w.until = now.Add(c.cfg.AckWait)
	}
	return !w.up && (w.until.IsZero() || now.Before(w.until))
}

// SessionsSeen takes a session check's answer: the peers the namespace's
// device holds a session with. A check that failed ends every wait, so the
// slots go in as they would without one.
func (c *Core) SessionsSeen(now time.Time, namespace string, up []model.Key, err error) {
	st, ok := c.ns[namespace]
	if !ok {
		return
	}
	st.checking = false
	st.dirty = true
	if err != nil {
		if c.Debug != nil {
			c.Debug(fmt.Sprintf("%s: session check: %v", namespace, err))
		}
		for _, key := range slices.SortedFunc(maps.Keys(st.sessions), compareKey) {
			st.sessions[key].up = true
		}
		return
	}
	for _, key := range up {
		if w, ok := st.sessions[key]; ok {
			w.up = true
		}
	}
}

func conflicted(owner map[netip.Prefix]model.Key, p api.Peer) bool {
	for _, a := range allowedOf(p) {
		if o, ok := owner[a]; ok && o != p.PublicKey {
			return true
		}
	}
	return false
}

// allowedOf is a peer's allowed IPs: its own addresses, and those of the
// development machines it fronts.
func allowedOf(p api.Peer) []netip.Prefix {
	out := slices.Clone(p.Allowed)
	for _, f := range p.Fronts {
		out = append(out, f.Allowed...)
	}
	return out
}

func (c *Core) tpeer(self model.InterfaceID, p api.Peer) tpeer {
	p.Allowed = kernel.SortPrefixes(allowedOf(p))
	tp := tpeer{peer: p}
	if p.Keepalive {
		tp.keepalive = c.cfg.Keepalive
	}
	if p.Loopback != 0 {
		tp.endpoint = loopback(p.Loopback)
		tp.accept = []netip.AddrPort{tp.endpoint}
		return tp
	}
	for _, rp := range p.Relays {
		tp.accept = append(tp.accept, rp.Send)
	}
	if rp, ok := c.edgeRelay(self, p); ok {
		tp.endpoint = rp.Send
	}
	return tp
}

// rules builds the namespace's nftables table from the peers it holds, so a
// slot never names an address without a peer and a source set never names
// an address with none, and rejects every service address of the network
// it does not translate.
func (c *Core) rules(n *api.NetworkState, x *api.Interface, peers []tpeer) *nft.Ruleset {
	rs := &nft.Ruleset{Forward: x.Kind == api.Gateway}
	live := map[model.InterfaceID]bool{x.ID: true}
	for _, p := range peers {
		if !p.peer.Draining && !p.awaiting {
			live[p.peer.Interface] = true
		}
	}
	families := []nft.Family{nft.IPv6}
	if x.Addr4.IsValid() {
		families = append(families, nft.IPv4)
	}
	madeMap := map[string]bool{}
	for _, r := range x.Reach {
		svc, ok := n.Service(r.Service)
		if !ok {
			continue
		}
		var backends []api.Backend
		for _, b := range svc.Backends {
			if live[b.Interface] {
				backends = append(backends, b)
			}
		}
		for _, f := range families {
			addr := svc.Addr6
			if f == nft.IPv4 {
				addr = svc.Addr4
			}
			if !addr.IsValid() {
				continue
			}
			rs.Rules.Reject = append(rs.Rules.Reject, addr)
			if len(backends) == 0 {
				continue
			}
			name := nft.MapName(svc.ID, f)
			if !madeMap[name] {
				madeMap[name] = true
				rs.Maps = append(rs.Maps, nft.Map{Name: name, Family: f, Slots: slotMap(backends, f)})
			}
			rs.Rules.Translate = append(rs.Rules.Translate, nft.Translate{Addr: addr, Proto: r.Proto, Ports: r.Ports, Map: name})
		}
	}
	// So is every other service of the network, whether another interface
	// here reaches it or none does. A connection to one fails at once and
	// leaves conntrack nothing. Sent untranslated, it would keep an entry
	// for 120 seconds, and NAT runs once per entry, so a later connection
	// landing on its tuple would miss the service's translation once policy
	// restored it, and be refused.
	others := slices.Clone(n.Unreached)
	for _, svc := range n.Services {
		others = append(others, svc.Addr6, svc.Addr4)
	}
	for _, a := range others {
		if a.IsValid() && (a.Is6() || x.Addr4.IsValid()) {
			rs.Rules.Reject = append(rs.Rules.Reject, a)
		}
	}
	madeSet := map[string]bool{}
	for _, in := range x.Inbound {
		for _, f := range families {
			name := nft.SetName(in.From, f)
			if !madeSet[name] {
				madeSet[name] = true
				set := nft.Set{Name: name, Family: f}
				for _, p := range peers {
					if p.peer.Draining {
						continue
					}
					if p.peer.Service == in.From {
						set.Addrs = append(set.Addrs, inFamily(own(p.peer), f)...)
					}
					for _, fr := range p.peer.Fronts {
						if fr.Service == in.From {
							set.Addrs = append(set.Addrs, inFamily(fr.Allowed, f)...)
						}
					}
				}
				rs.Sets = append(rs.Sets, set)
			}
			rs.Rules.Accept = append(rs.Rules.Accept, nft.Accept{Set: name, Family: f, Proto: in.Proto, Ports: in.Ports})
		}
	}
	// A gateway's development machines take replies alone: no new flow is
	// forwarded to one, from a backend or from another machine.
	if x.Kind == api.Gateway {
		for _, f := range []nft.Family{nft.IPv6, nft.IPv4} {
			set := nft.Set{Name: nft.DeviceSetName(f), Family: f}
			for _, p := range peers {
				if p.peer.DialsIn {
					set.Addrs = append(set.Addrs, inFamily(p.peer.Allowed, f)...)
				}
			}
			rs.Sets = append(rs.Sets, set)
			rs.Rules.Shield = append(rs.Rules.Shield, set.Name)
		}
	}
	rs.Normalize()
	return rs
}

// own is a peer's own addresses, without those of machines it fronts.
func own(p api.Peer) []netip.Prefix {
	out := slices.Clone(p.Allowed)
	for _, f := range p.Fronts {
		out = slices.DeleteFunc(out, func(a netip.Prefix) bool { return slices.Contains(f.Allowed, a) })
	}
	return out
}

func inFamily(prefixes []netip.Prefix, f nft.Family) []netip.Addr {
	var out []netip.Addr
	for _, a := range prefixes {
		if nft.FamilyOf(a.Addr()) == f {
			out = append(out, a.Addr())
		}
	}
	return out
}

// slotMap fills every slot with its backend's address in one family. Every
// backend of an IPv4-capable service has an IPv4 address, and both families
// assign each slot to the same backend.
func slotMap(backends []api.Backend, f nft.Family) []netip.Addr {
	ids := make([]model.InterfaceID, len(backends))
	for i, b := range backends {
		ids[i] = b.Interface
	}
	table := slots.Assign(ids)
	out := make([]netip.Addr, len(table))
	for slot, i := range table {
		if f == nft.IPv4 {
			out[slot] = backends[i].Addr4
		} else {
			out[slot] = backends[i].Addr6
		}
	}
	return out
}

func compareKey(a, b model.Key) int { return strings.Compare(string(a[:]), string(b[:])) }
