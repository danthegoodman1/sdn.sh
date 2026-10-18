//sdn:deterministic

package sim

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/cp"
	"sdn.sh/internal/kernel/kmodel"
	"sdn.sh/internal/model"
	"sdn.sh/internal/nft"
	"sdn.sh/internal/slots"
	"sdn.sh/internal/store"
)

// checkMoves fails the run if any allowed IP moved between two peers: the
// agent must remove an address's holder before another peer claims it.
func (w *World) checkMoves(h *hostNode) {
	if len(h.kernel.Moves) > 0 {
		m := h.kernel.Moves[0]
		w.fail("%s: allowed IP %v moved from %s to %s in %s", h.name, m.Prefix, w.byKey[m.From], w.byKey[m.To], m.Namespace)
	}
}

// expected is what a namespace must hold at a revision, by the oracle: the
// orchestrator's rules applied to the interfaces the control plane held.
type expected struct {
	live     bool
	peers    map[model.Key]expPeer
	draining map[model.Key][]netip.Prefix
	maps     map[string][]netip.Addr
	sets     map[string][]netip.Addr
}

type expPeer struct {
	allowed   []netip.Prefix
	keepalive bool
}

// expect computes, independently of the compiler and the agent, what one
// interface's namespace holds at a network revision.
func (w *World) expect(net model.NetworkID, rev uint64, id model.InterfaceID) (expected, bool) {
	if rev == 0 {
		// The host holds nothing for the network: the interface must hold
		// nothing either.
		return expected{peers: map[model.Key]expPeer{}, maps: map[string][]netip.Addr{}, sets: map[string][]netip.Addr{}}, true
	}
	snap, ok := w.cp.snaps[net][rev]
	n := w.orch.network(net)
	if !ok || n == nil {
		return expected{}, false
	}
	rules := n.rulesAt(rev)
	e := expected{peers: map[model.Key]expPeer{}, draining: map[model.Key][]netip.Prefix{}, maps: map[string][]netip.Addr{}, sets: map[string][]netip.Addr{}}
	var x *store.Interface
	for i := range snap {
		if snap[i].ID == id {
			x = &snap[i]
		}
	}
	if x == nil || x.State != api.Live {
		return e, true
	}
	e.live = true
	adjacent := func(a, b model.ServiceID) bool {
		for _, r := range rules {
			if r.To != "" && (r.From == a && r.To == b || r.From == b && r.To == a) {
				return true
			}
		}
		return false
	}
	for _, y := range snap {
		connected := y.State == api.Live || y.State == api.Released && !y.Drained
		if y.ID == x.ID || y.Kind == api.Device || !connected || !adjacent(x.Service, y.Service) {
			continue
		}
		allowed := []netip.Prefix{netip.PrefixFrom(y.Addr6, 128)}
		if x.Addr4.IsValid() && y.Addr4.IsValid() {
			allowed = append(allowed, netip.PrefixFrom(y.Addr4, 32))
		}
		if y.State == api.Released {
			e.draining[y.PublicKey] = allowed
			continue
		}
		e.peers[y.PublicKey] = expPeer{allowed: allowed, keepalive: y.Host == x.Host && x.ID < y.ID}
	}
	families := []nft.Family{nft.IPv6}
	if x.Addr4.IsValid() {
		families = append(families, nft.IPv4)
	}
	svc := map[model.ServiceID]*svcIntent{}
	for _, s := range n.services {
		svc[s.id] = s
	}
	for _, r := range rules {
		if r.From != x.Service || r.To == "" {
			continue
		}
		var backends []store.Interface
		for _, y := range snap {
			if y.Service != r.To || y.State != api.Live || y.Kind == api.Device {
				continue
			}
			if _, peer := e.peers[y.PublicKey]; peer || y.ID == x.ID {
				backends = append(backends, y)
			}
		}
		if len(backends) == 0 {
			continue
		}
		ids := make([]model.InterfaceID, len(backends))
		for i, b := range backends {
			ids[i] = b.ID
		}
		table := slots.Assign(ids)
		for _, f := range families {
			if f == nft.IPv4 && !svc[r.To].addr4.IsValid() {
				continue
			}
			addrs := make([]netip.Addr, len(table))
			for slot, i := range table {
				addrs[slot] = backends[i].Addr6
				if f == nft.IPv4 {
					addrs[slot] = backends[i].Addr4
				}
			}
			e.maps[nft.MapName(r.To, f)] = addrs
		}
	}
	for _, r := range rules {
		if r.To != x.Service {
			continue
		}
		for _, f := range families {
			name := nft.SetName(r.From, f)
			var addrs []netip.Addr
			for _, y := range snap {
				if _, peer := e.peers[y.PublicKey]; !peer || y.Service != r.From {
					continue
				}
				if f == nft.IPv6 {
					addrs = append(addrs, y.Addr6)
				} else if y.Addr4.IsValid() {
					addrs = append(addrs, y.Addr4)
				}
			}
			slices.SortFunc(addrs, netip.Addr.Compare)
			e.sets[name] = addrs
		}
	}
	return e, true
}

// compare checks a namespace's kernel state against what the oracle
// expects. strict also forbids draining peers.
func (w *World) compare(ns *kmodel.Netns, dev *kmodel.Device, e expected, strict bool) error {
	for _, p := range dev.PeerList() {
		if want, ok := e.peers[p.PublicKey]; ok {
			if !slices.Equal(p.Allowed, sortPrefixes(want.allowed)) {
				return fmt.Errorf("peer %s allows %v, want %v", w.byKey[p.PublicKey], p.Allowed, want.allowed)
			}
			if (p.Keepalive > 0) != want.keepalive {
				return fmt.Errorf("peer %s keepalive %v, want armed=%v", w.byKey[p.PublicKey], p.Keepalive, want.keepalive)
			}
			continue
		}
		if allowed, ok := e.draining[p.PublicKey]; ok && !strict {
			if !slices.Equal(p.Allowed, sortPrefixes(allowed)) {
				return fmt.Errorf("draining peer %s allows %v, want %v", w.byKey[p.PublicKey], p.Allowed, allowed)
			}
			continue
		}
		return fmt.Errorf("holds peer %s, which policy does not connect", w.byKey[p.PublicKey])
	}
	for _, key := range slices.SortedFunc(maps.Keys(e.peers), compareKeys) {
		if _, ok := dev.Peers[key]; !ok {
			return fmt.Errorf("lacks peer %s", w.byKey[key])
		}
	}
	var rs nft.Ruleset
	if ns.Rules != nil {
		rs = *ns.Rules
	} else if e.live {
		return fmt.Errorf("has no nftables table")
	}
	var names []string
	for _, m := range rs.Maps {
		names = append(names, m.Name)
		want, ok := e.maps[m.Name]
		if !ok {
			return fmt.Errorf("holds slot map %s, which nothing reaches", m.Name)
		}
		if !slices.Equal(m.Slots, want) {
			return fmt.Errorf("slot map %s differs from its backends", m.Name)
		}
	}
	if !slices.Equal(names, slices.Sorted(maps.Keys(e.maps))) {
		return fmt.Errorf("slot maps %v, want %v", names, slices.Sorted(maps.Keys(e.maps)))
	}
	names = nil
	for _, s := range rs.Sets {
		names = append(names, s.Name)
		if want := e.sets[s.Name]; !slices.Equal(s.Addrs, want) {
			return fmt.Errorf("source set %s holds %v, want %v", s.Name, s.Addrs, want)
		}
	}
	if !slices.Equal(names, slices.Sorted(maps.Keys(e.sets))) {
		return fmt.Errorf("source sets %v, want %v", names, slices.Sorted(maps.Keys(e.sets)))
	}
	return nil
}

func sortPrefixes(p []netip.Prefix) []netip.Prefix {
	out := slices.Clone(p)
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	return out
}

func compareKeys(a, b model.Key) int { return cmp.Compare(string(a[:]), string(b[:])) }

// checkSafety runs the properties that hold at every instant: every settled
// namespace holds exactly what the oracle expects at its revision, and no
// flow outlives the peer it went through.
func (w *World) checkSafety() {
	for _, h := range w.hosts {
		w.checkMoves(h)
		if !h.up || w.failure != nil {
			continue
		}
		settled := h.core.Settled()
		for _, name := range sortedKeys(settled) {
			s := settled[name]
			ns, ok := h.kernel.Named(name)
			if !ok {
				w.fail("%s: settled namespace %s is gone", h.name, name)
				return
			}
			dev, ok := ns.Devices[h.cfg.Device]
			if !ok {
				w.fail("%s: settled namespace %s has no device", h.name, name)
				return
			}
			e, ok := w.expect(s.Network, s.Revision, s.Interface)
			if !ok {
				w.fail("%s: no record of %s at revision %d", h.name, s.Network, s.Revision)
				return
			}
			if err := w.compare(ns, dev, e, false); err != nil {
				w.fail("%s: %s (%s) at revision %d: %v; the control plane compiled %s", h.name, s.Interface, name, s.Revision, err, w.compiledPeers(h, s.Network, s.Interface))
				return
			}
			for _, id := range slices.Sorted(maps.Keys(ns.Flows)) {
				f := ns.Flows[id]
				p, ok := dev.Peers[f.Peer]
				if !ok || !holds(p.Allowed, f.Remote) {
					w.fail("%s: %s keeps a flow to %v after its peer %s left", h.name, s.Interface, f.Remote, w.byKey[f.Peer])
					return
				}
			}
		}
	}
}

// probe is a connection the liveness check opens and what it must do.
type probe struct {
	f     *flow
	allow bool
	what  string
}

// checkLiveness runs once faults have stopped and the system has had time to
// converge: every agent is idle on the latest state, every namespace matches
// the oracle exactly, nothing is orphaned, and permitted flows connect while
// forbidden ones do not.
func (w *World) checkLiveness() {
	o := w.orch
	// A timer may fire as the quiet phase ends; give agents a moment to
	// finish what it started.
	for range 50 {
		idle := true
		for _, h := range w.hosts {
			if h.up && h.core.Busy() {
				idle = false
			}
		}
		if idle {
			break
		}
		w.runUntil(w.now().Add(100 * time.Millisecond))
	}
	if len(o.attaching) > 0 {
		w.fail("%d attaches never answered", len(o.attaching))
		return
	}
	for _, x := range sortedKeys(o.ifaces) {
		if o.ifaces[x].state == detachingState {
			w.fail("detach of %s never answered", x)
			return
		}
	}
	for _, h := range w.hosts {
		if !h.up {
			w.fail("%s's agent is down", h.name)
			return
		}
		if h.core.Busy() {
			w.fail("%s's agent is still busy: %v", h.name, h.core.Pending())
			return
		}
		var gen uint64
		w.cp.view(func(tx store.ReadTx) error {
			gen, _, _ = cp.HostGeneration(tx, h.id)
			return nil
		})
		if h.core.Generation() != gen {
			w.fail("%s holds generation %d of %d", h.name, h.core.Generation(), gen)
			return
		}
		snap, _ := h.kernel.Snapshot(h.cfg.Prefix, h.cfg.AliasPrefix())
		var named []string
		for _, ns := range snap.Namespaces {
			if ns.Name == "" {
				w.fail("%s: a namespace only a process holds still has device %s", h.name, ns.Devices[0].Alias)
				return
			}
			named = append(named, ns.Name)
		}
		var journaled, attached []string
		for _, id := range sortedKeys(h.journal) {
			journaled = append(journaled, h.journal[id].Namespace)
		}
		for _, id := range sortedKeys(o.ifaces) {
			if x := o.ifaces[id]; x.host == h {
				attached = append(attached, x.ns)
			}
		}
		slices.Sort(journaled)
		slices.Sort(attached)
		if !slices.Equal(named, journaled) || !slices.Equal(journaled, attached) {
			w.fail("%s: namespaces %v, journal %v, orchestrator %v", h.name, named, journaled, attached)
			return
		}
		settled := h.core.Settled()
		for _, name := range named {
			s, ok := settled[name]
			if !ok {
				w.fail("%s: %s never settled", h.name, name)
				return
			}
			ns, _ := h.kernel.Named(name)
			e, _ := w.expect(s.Network, s.Revision, s.Interface)
			if err := w.compare(ns, ns.Devices[h.cfg.Device], e, true); err != nil {
				w.fail("%s: %s at the latest revision %d: %v", h.name, s.Interface, s.Revision, err)
				return
			}
		}
	}
	w.probeAll()
}

// probeAll opens a connection for every permitted service flow and for a
// sample of forbidden ones, then checks the outcomes.
func (w *World) probeAll() {
	o := w.orch
	var probes []probe
	for _, x := range o.live() {
		n := o.network(x.network)
		var rev uint64
		w.cp.view(func(tx store.ReadTx) error {
			rec, err := tx.Network(x.network)
			rev = rec.Revision
			return err
		})
		e, ok := w.expect(x.network, rev, x.id)
		if !ok || !e.live {
			continue
		}
		rules := n.rulesAt(rev)
		for _, r := range rules {
			if r.From != x.service || r.To == "" {
				continue
			}
			var s *svcIntent
			for _, c := range n.services {
				if c.id == r.To {
					s = c
				}
			}
			proto, port := r.Proto, r.Ports.Lo
			if proto == model.AnyProto {
				proto, port = model.TCP, 80
			}
			if _, ok := e.maps[nft.MapName(r.To, nft.IPv6)]; ok {
				probes = append(probes, probe{w.open(x, s.addr6, proto, port), true, fmt.Sprintf("%s to %s over IPv6 %s/%d", x.id, s.name, proto, port)})
			}
			if _, ok := e.maps[nft.MapName(r.To, nft.IPv4)]; ok {
				probes = append(probes, probe{w.open(x, s.addr4, proto, port), true, fmt.Sprintf("%s to %s over IPv4 %s/%d", x.id, s.name, proto, port)})
			}
		}
		for _, y := range o.live() {
			if y.network != x.network || y.id == x.id {
				continue
			}
			if _, peer := e.peers[y.key]; !peer {
				probes = append(probes, probe{w.open(x, y.addr6, model.TCP, 80), false, fmt.Sprintf("%s to unconnected %s", x.id, y.id)})
				if x.addr4.IsValid() && y.addr4.IsValid() {
					probes = append(probes, probe{w.open(x, y.addr4, model.TCP, 80), false, fmt.Sprintf("%s to unconnected %s over IPv4", x.id, y.id)})
				}
				continue
			}
			if !permitsPort(rules, x.service, y.service, 9) {
				probes = append(probes, probe{w.open(x, y.addr6, model.TCP, 9), false, fmt.Sprintf("%s to %s on a port policy does not name", x.id, y.id)})
			}
		}
	}
	w.runUntil(w.now().Add(3 * time.Second))
	for _, p := range probes {
		ok := p.f.state == established
		if ok != p.allow {
			w.fail("%s: established=%v", p.what, ok)
			return
		}
		if ok {
			w.summary.FlowsOK++
		} else {
			w.summary.FlowsDenied++
		}
	}
}

// permitsPort reports whether a rule lets a reach b on a TCP port.
func permitsPort(rules []store.Rule, a, b model.ServiceID, port uint16) bool {
	for _, r := range rules {
		if r.From == a && r.To == b && (r.Proto == model.AnyProto || r.Proto == model.TCP && r.Ports.Contains(port)) {
			return true
		}
	}
	return false
}

// compiledPeers describes what the agent's desired state lists for an
// interface, for a failure report.
func (w *World) compiledPeers(h *hostNode, net model.NetworkID, id model.InterfaceID) string {
	n, ok := h.core.Desired().Networks[net]
	if !ok {
		return "nothing for the network"
	}
	x, ok := n.Interface(id)
	if !ok {
		return fmt.Sprintf("no entry at revision %d", n.Revision)
	}
	var b []string
	for _, p := range x.Peers {
		b = append(b, fmt.Sprintf("%s(draining=%v relays=%d allowed=%v)", p.Interface, p.Draining, len(p.Relays), p.Allowed))
	}
	return fmt.Sprintf("at revision %d, state %s, peers %v", n.Revision, x.State, b)
}
