//sdn:deterministic

// Package compile turns a network's records into each host's desired state,
// and a relay's edges into its port table. Both are pure functions of the
// records, so a compiled network can be cached by its revision.
package compile

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
	"sdn.sh/internal/regproto"
	"sdn.sh/internal/store"
)

// Snapshot is everything about one network that its hosts' state depends
// on.
type Snapshot struct {
	Network    store.Network
	Services   []store.Service
	Interfaces []store.Interface
	Rules      []store.Rule
	Edges      []store.Edge
	// Relays holds the network's relay set, in any order.
	Relays []store.Relay
}

// Connected reports whether an interface still takes part in its network:
// live, or released and draining.
func Connected(i store.Interface) bool {
	return i.State == api.Live || i.State == api.Released && !i.Drained
}

// Built reports whether an agent builds the interface on its host. A
// development machine's record names its gateway's host, where the
// gateway's peer table carries it, so that host builds nothing for it.
func Built(i store.Interface) bool { return i.Kind != api.Device }

// Adjacency says which pairs of services policy connects, in either
// direction, since a WireGuard session needs a peer at both ends.
type Adjacency map[[2]model.ServiceID]bool

// NewAdjacency builds the adjacency of rules.
func NewAdjacency(rules []store.Rule) Adjacency {
	adj := Adjacency{}
	for _, r := range rules {
		if r.To == "" {
			continue
		}
		adj[[2]model.ServiceID{r.From, r.To}] = true
		adj[[2]model.ServiceID{r.To, r.From}] = true
	}
	return adj
}

// Connects reports whether policy connects interfaces of a and b.
func (a Adjacency) Connects(x, y model.ServiceID) bool { return a[[2]model.ServiceID{x, y}] }

// Links decides which interfaces peer: those whose services policy
// connects, and a gateway with every interface one of its live development
// machines may reach or be reached by.
type Links struct {
	adj Adjacency
	// devices holds each gateway's live development machines, by
	// identifier.
	devices map[model.InterfaceID][]store.Interface
}

// NewLinks builds the links among a network's interfaces. A development
// machine counts only behind the live gateway it names on its own host, so
// an interface that takes over the identifier on another host fronts
// nothing.
func NewLinks(adj Adjacency, ifaces []store.Interface) Links {
	gateways := map[model.InterfaceID]model.HostID{}
	for _, i := range ifaces {
		if i.Kind == api.Gateway && i.State == api.Live {
			gateways[i.ID] = i.Host
		}
	}
	l := Links{adj: adj, devices: map[model.InterfaceID][]store.Interface{}}
	for _, i := range ifaces {
		if host, ok := gateways[i.Gateway]; ok && i.Kind == api.Device && i.State == api.Live && host == i.Host {
			l.devices[i.Gateway] = append(l.devices[i.Gateway], i)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(l.devices)) {
		slices.SortFunc(l.devices[id], func(a, b store.Interface) int { return strings.Compare(string(a.ID), string(b.ID)) })
	}
	return l
}

// Connects reports whether two interfaces, neither a development machine,
// need each other as peers.
func (l Links) Connects(x, y store.Interface) bool {
	if l.adj.Connects(x.Service, y.Service) {
		return true
	}
	for _, d := range l.devices[x.ID] {
		if l.adj.Connects(d.Service, y.Service) {
			return true
		}
	}
	for _, d := range l.devices[y.ID] {
		if l.adj.Connects(x.Service, d.Service) {
			return true
		}
	}
	return false
}

// HasDevices reports whether any gateway fronts a live development machine.
func (l Links) HasDevices() bool { return len(l.devices) > 0 }

// Devices lists a gateway's live development machines.
func (l Links) Devices(gateway model.InterfaceID) []store.Interface { return l.devices[gateway] }

// fronts lists the development machines behind gateway y that policy
// connects with x, with their addresses in the families x has.
func (l Links) fronts(x, y store.Interface) []api.Fronted {
	var out []api.Fronted
	for _, d := range l.devices[y.ID] {
		if !l.adj.Connects(x.Service, d.Service) {
			continue
		}
		f := api.Fronted{Interface: d.ID, Service: d.Service, Allowed: []netip.Prefix{netip.PrefixFrom(d.Addr6, 128)}}
		if x.Addr4.IsValid() && d.Addr4.IsValid() {
			f.Allowed = append(f.Allowed, netip.PrefixFrom(d.Addr4, 32))
		}
		out = append(out, f)
	}
	return out
}

// Pair orders two interface identifiers as an edge stores them.
func Pair(x, y model.InterfaceID) (model.InterfaceID, model.InterfaceID) {
	if x < y {
		return x, y
	}
	return y, x
}

// Network compiles each host's state for the snapshot's network.
func Network(s Snapshot) map[model.HostID]api.NetworkState {
	services := map[model.ServiceID]store.Service{}
	for _, svc := range s.Services {
		services[svc.ID] = svc
	}
	adj := NewAdjacency(s.Rules)
	links := NewLinks(adj, s.Interfaces)
	edges := map[[2]model.InterfaceID]store.Edge{}
	for _, e := range s.Edges {
		edges[[2]model.InterfaceID{e.A, e.B}] = e
	}
	relays := map[model.RelayID]store.Relay{}
	for _, r := range s.Relays {
		relays[r.ID] = r
	}
	var refs []api.RelayRef
	for _, id := range s.Network.Relays {
		r, ok := relays[id]
		if !ok || len(r.Addresses) == 0 {
			continue
		}
		refs = append(refs, api.RelayRef{Relay: id, Probe: netip.AddrPortFrom(r.Addresses[0].Advertised, r.ProbePort)})
	}
	connected := slices.DeleteFunc(slices.Clone(s.Interfaces), func(i store.Interface) bool { return !Connected(i) })
	backends := map[model.ServiceID][]api.Backend{}
	for _, i := range connected {
		if i.State == api.Live && i.Kind != api.Device {
			backends[i.Service] = append(backends[i.Service], api.Backend{Interface: i.ID, Addr6: i.Addr6, Addr4: i.Addr4})
		}
	}

	out := map[model.HostID]api.NetworkState{}
	reached := map[model.HostID]map[model.ServiceID]bool{}
	for _, x := range s.Interfaces {
		if !Built(x) {
			continue
		}
		ns, ok := out[x.Host]
		if !ok {
			ns = api.NetworkState{
				Network:  s.Network.ID,
				Name:     s.Network.Name,
				Revision: s.Network.Revision,
				Changed:  s.Network.Changed,
				Prefix6:  s.Network.Prefix6,
				Prefix4:  s.Network.Prefix4,
				MTU:      s.Network.MTU,
				Relays:   refs,
			}
			reached[x.Host] = map[model.ServiceID]bool{}
		}
		iface := api.Interface{
			ID:         x.ID,
			Service:    x.Service,
			Kind:       x.Kind,
			PublicKey:  x.PublicKey,
			Addr6:      x.Addr6,
			Addr4:      x.Addr4,
			ListenPort: x.ListenPort,
			State:      x.State,
		}
		if x.State == api.Live {
			for _, y := range connected {
				if y.ID == x.ID || y.Kind == api.Device || !links.Connects(x, y) {
					continue
				}
				if p, ok := peer(x, y, edges, relays, s.Network.Relays); ok {
					p.Fronts = links.fronts(x, y)
					iface.Peers = append(iface.Peers, p)
				}
			}
			// A gateway peers with its development machines, reaches what
			// they may reach, and answers their names.
			fronted := map[model.ServiceID]bool{}
			for _, d := range links.Devices(x.ID) {
				p := api.Peer{Interface: d.ID, Service: d.Service, PublicKey: d.PublicKey, DialsIn: true,
					Allowed: []netip.Prefix{netip.PrefixFrom(d.Addr6, 128)}}
				if d.Addr4.IsValid() {
					p.Allowed = append(p.Allowed, netip.PrefixFrom(d.Addr4, 32))
				}
				iface.Peers = append(iface.Peers, p)
				fronted[d.Service] = true
			}
			slices.SortFunc(iface.Peers, func(a, b api.Peer) int { return strings.Compare(string(a.Interface), string(b.Interface)) })
			for _, svc := range slices.Sorted(maps.Keys(fronted)) {
				iface.Inbound = append(iface.Inbound,
					api.Inbound{From: svc, Proto: model.UDP, Ports: model.PortRange{Lo: 53, Hi: 53}},
					api.Inbound{From: svc, Proto: model.TCP, Ports: model.PortRange{Lo: 53, Hi: 53}})
			}
			for _, r := range s.Rules {
				switch {
				case r.From == x.Service && r.To == "":
					iface.Egress = append(iface.Egress, api.Egress{Proto: r.Proto, Ports: r.Ports})
				case r.From == x.Service || fronted[r.From]:
					if _, ok := services[r.To]; ok {
						iface.Reach = append(iface.Reach, api.Reach{Service: r.To, Proto: r.Proto, Ports: r.Ports})
						reached[x.Host][r.To] = true
					}
				}
				if r.To == x.Service {
					iface.Inbound = append(iface.Inbound, api.Inbound{From: r.From, Proto: r.Proto, Ports: r.Ports})
				}
			}
			slices.SortFunc(iface.Reach, compareReach)
			iface.Reach = slices.Compact(iface.Reach)
			slices.SortFunc(iface.Inbound, compareInbound)
			iface.Inbound = slices.Compact(iface.Inbound)
			slices.SortFunc(iface.Egress, compareEgress)
			iface.Egress = slices.Compact(iface.Egress)
		}
		ns.Interfaces = append(ns.Interfaces, iface)
		out[x.Host] = ns
	}
	for _, host := range slices.Sorted(maps.Keys(out)) {
		ns := out[host]
		for _, id := range slices.Sorted(maps.Keys(reached[host])) {
			svc := services[id]
			ns.Services = append(ns.Services, api.Service{
				ID:       svc.ID,
				Name:     svc.Name,
				Addr6:    svc.Addr6,
				Addr4:    svc.Addr4,
				Mode:     svc.Mode,
				Backends: backends[id],
			})
		}
		out[host] = ns
	}
	return out
}

// peer builds x's peer entry for y, or reports false when the edge a relay
// path needs has yet to exist.
func peer(x, y store.Interface, edges map[[2]model.InterfaceID]store.Edge, relays map[model.RelayID]store.Relay, order []model.RelayID) (api.Peer, bool) {
	p := api.Peer{
		Interface: y.ID,
		Service:   y.Service,
		PublicKey: y.PublicKey,
		Allowed:   []netip.Prefix{netip.PrefixFrom(y.Addr6, 128)},
		Draining:  y.State == api.Released,
	}
	if x.Addr4.IsValid() && y.Addr4.IsValid() {
		p.Allowed = append(p.Allowed, netip.PrefixFrom(y.Addr4, 32))
	}
	if x.Host == y.Host {
		p.Loopback = y.ListenPort
		// Exactly one side of a co-located pair keeps a session up, so the
		// two never initiate at the same instant.
		p.Keepalive = x.ID < y.ID
		return p, true
	}
	a, b := Pair(x.ID, y.ID)
	e, ok := edges[[2]model.InterfaceID{a, b}]
	if !ok || !e.Dormant.IsZero() {
		return api.Peer{}, false
	}
	p.Registration = e.SecretAB
	if x.ID == e.B {
		p.Registration = e.SecretBA
	}
	for _, id := range order {
		for _, ports := range e.Ports {
			if ports.Relay != id {
				continue
			}
			port := ports.AB
			if x.ID == e.B {
				port = ports.BA
			}
			adv, ok := advertised(relays[id], ports.Addr)
			if !ok {
				continue
			}
			p.Relays = append(p.Relays, api.RelayPath{Relay: id, Send: netip.AddrPortFrom(adv, port)})
		}
	}
	return p, true
}

func advertised(r store.Relay, local netip.Addr) (netip.Addr, bool) {
	for _, a := range r.Addresses {
		if a.Local == local {
			return a.Advertised, true
		}
	}
	return netip.Addr{}, false
}

func compareReach(a, b api.Reach) int {
	return cmp.Or(cmp.Compare(a.Service, b.Service), cmp.Compare(a.Proto, b.Proto),
		cmp.Compare(a.Ports.Lo, b.Ports.Lo), cmp.Compare(a.Ports.Hi, b.Ports.Hi))
}

func compareInbound(a, b api.Inbound) int {
	return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.Proto, b.Proto),
		cmp.Compare(a.Ports.Lo, b.Ports.Lo), cmp.Compare(a.Ports.Hi, b.Ports.Hi))
}

// Relay compiles a relay's port table from the edges holding ports on it.
func Relay(r store.Relay, edges []store.Edge, generation uint64) api.RelayState {
	st := api.RelayState{Relay: r.ID, Generation: generation}
	for _, e := range edges {
		for _, ports := range e.Ports {
			if ports.Relay != r.ID {
				continue
			}
			adv, ok := advertised(r, ports.Addr)
			if !ok {
				continue
			}
			st.Ports = append(st.Ports,
				api.RelayPort{
					Local:      netip.AddrPortFrom(ports.Addr, ports.AB),
					Peer:       ports.BA,
					Advertised: netip.AddrPortFrom(adv, ports.AB),
					Key:        regproto.RelayKey(e.SecretAB, r.ID),
				},
				api.RelayPort{
					Local:      netip.AddrPortFrom(ports.Addr, ports.BA),
					Peer:       ports.AB,
					Advertised: netip.AddrPortFrom(adv, ports.BA),
					Key:        regproto.RelayKey(e.SecretBA, r.ID),
				})
		}
	}
	slices.SortFunc(st.Ports, func(a, b api.RelayPort) int { return a.Local.Compare(b.Local) })
	return st
}

func compareEgress(a, b api.Egress) int {
	if c := strings.Compare(string(a.Proto), string(b.Proto)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Ports.Lo, b.Ports.Lo); c != 0 {
		return c
	}
	return cmp.Compare(a.Ports.Hi, b.Ports.Hi)
}
