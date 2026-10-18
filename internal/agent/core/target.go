//sdn:deterministic

package core

import (
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/kernel"
	"sdn.sh/internal/model"
	"sdn.sh/internal/nft"
	"sdn.sh/internal/slots"
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
}

// loopback is the address co-located devices reach each other at. Both
// sockets live in the host namespace, so the packet never leaves it.
func loopback(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)
}

// linkConfig is a device's addresses, routes and MTU.
func linkConfig(n *api.NetworkState, x *api.Interface) kernel.LinkConfig {
	l := kernel.LinkConfig{
		Addrs:  []netip.Prefix{netip.PrefixFrom(x.Addr6, 128)},
		Routes: []netip.Prefix{n.Prefix6},
		MTU:    n.MTU,
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
			t.peers = append(t.peers, c.tpeer(n, p))
		}
	}
	for _, key := range slices.SortedFunc(maps.Keys(st.drain), compareKey) {
		if !draining[key] {
			delete(st.drain, key)
		}
	}
	slices.SortFunc(t.peers, func(a, b tpeer) int { return compareKey(a.peer.PublicKey, b.peer.PublicKey) })
	t.rules = c.rules(n, x, t.peers)
	return t
}

func conflicted(owner map[netip.Prefix]model.Key, p api.Peer) bool {
	for _, a := range p.Allowed {
		if o, ok := owner[a]; ok && o != p.PublicKey {
			return true
		}
	}
	return false
}

func (c *Core) tpeer(n *api.NetworkState, p api.Peer) tpeer {
	p.Allowed = kernel.SortPrefixes(p.Allowed)
	tp := tpeer{peer: p}
	if p.Keepalive {
		tp.keepalive = c.cfg.Keepalive
	}
	if p.Loopback != 0 {
		tp.endpoint = loopback(p.Loopback)
		tp.accept = []netip.AddrPort{tp.endpoint}
		return tp
	}
	active := c.activeRelay(n)
	for _, rp := range p.Relays {
		tp.accept = append(tp.accept, rp.Send)
		if rp.Relay == active {
			tp.endpoint = rp.Send
		}
	}
	if !tp.endpoint.IsValid() && len(p.Relays) > 0 {
		tp.endpoint = p.Relays[0].Send
	}
	return tp
}

// rules builds the namespace's nftables table from the peers it holds, so a
// slot never names an address without a peer and a source set never names
// an address with none.
func (c *Core) rules(n *api.NetworkState, x *api.Interface, peers []tpeer) *nft.Ruleset {
	rs := &nft.Ruleset{Forward: x.Kind == api.Gateway}
	live := map[model.InterfaceID]bool{x.ID: true}
	for _, p := range peers {
		if !p.peer.Draining {
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
	madeSet := map[string]bool{}
	for _, in := range x.Inbound {
		for _, f := range families {
			name := nft.SetName(in.From, f)
			if !madeSet[name] {
				madeSet[name] = true
				set := nft.Set{Name: name, Family: f}
				for _, p := range peers {
					if p.peer.Service != in.From || p.peer.Draining {
						continue
					}
					for _, a := range p.peer.Allowed {
						if nft.FamilyOf(a.Addr()) == f {
							set.Addrs = append(set.Addrs, a.Addr())
						}
					}
				}
				rs.Sets = append(rs.Sets, set)
			}
			rs.Rules.Accept = append(rs.Rules.Accept, nft.Accept{Set: name, Family: f, Proto: in.Proto, Ports: in.Ports})
		}
	}
	rs.Normalize()
	return rs
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
