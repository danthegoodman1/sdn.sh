//wirenet:deterministic

package sim

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	agentcore "github.com/danthegoodman1/wirenet/internal/agent/core"
	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/compile"
	"github.com/danthegoodman1/wirenet/internal/cp"
	"github.com/danthegoodman1/wirenet/internal/dns"
	"github.com/danthegoodman1/wirenet/internal/kernel"
	"github.com/danthegoodman1/wirenet/internal/kernel/kmodel"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/nft"
	"github.com/danthegoodman1/wirenet/internal/slots"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// checkMoves fails the run if any allowed IP moved between two peers: the
// agent must remove an address's holder before another peer claims it.
func (w *World) checkMoves(h *hostNode) {
	if len(h.kernel.Moves) > 0 {
		m := h.kernel.Moves[0]
		w.fail("%s: allowed IP %v moved from %s to %s in %s", h.name, m.Prefix, w.byKey[m.From], w.byKey[m.To], m.Namespace)
	}
}

// checkColocated fails the run if a batch arms keepalive on a co-located
// peer, or points a slot at one, before that peer's device holds the
// reverse peer, judged when the agent plans the batch. Anything sent to a
// device without the reverse peer is dropped, and WireGuard waits five
// seconds before trying again.
func (w *World) checkColocated(h *hostNode, b agentcore.RunBatch) {
	ns, ok := h.kernel.Named(b.Namespace)
	if !ok {
		return
	}
	dev, ok := ns.Devices[h.cfg.Device]
	if !ok {
		return
	}
	// The endpoint each allowed address routes to, once the batch's peers
	// are in.
	route := map[netip.Addr]netip.AddrPort{}
	for _, p := range dev.PeerList() {
		for _, a := range p.Allowed {
			route[a.Addr()] = p.Endpoint
		}
	}
	for _, op := range b.Ops {
		switch op.Kind {
		case kernel.SetPeers:
			for _, u := range op.Peers {
				if u.Remove {
					continue
				}
				ep := u.Endpoint
				if p, ok := dev.Peers[u.PublicKey]; ok && !ep.IsValid() {
					ep = p.Endpoint
				}
				for _, a := range u.Allowed {
					route[a.Addr()] = ep
				}
				if u.Keepalive == 0 || !ep.Addr().IsLoopback() {
					continue
				}
				if p, ok := dev.Peers[u.PublicKey]; ok && p.Keepalive > 0 {
					continue
				}
				if !holdsReverse(h, dev, ep) {
					w.fail("%s: %s arms keepalive toward %s before that device holds the reverse peer", h.name, b.Namespace, w.byKey[u.PublicKey])
					return
				}
			}
		case kernel.ApplyRules:
			for _, a := range slotAddrs(op.Rules) {
				if ep, ok := route[a]; ok && ep.Addr().IsLoopback() && !holdsReverse(h, dev, ep) {
					w.fail("%s: %s points a slot at %v before that device holds the reverse peer", h.name, b.Namespace, a)
					return
				}
			}
		}
	}
}

// slotAddrs lists every address a transaction writes into a slot.
func slotAddrs(tx *nft.Transaction) []netip.Addr {
	if tx == nil {
		return nil
	}
	written := slices.Clone(tx.AddMaps)
	if tx.Replace != nil {
		written = append(written, tx.Replace.Maps...)
	}
	var out []netip.Addr
	for _, m := range written {
		out = append(out, m.Slots...)
	}
	for _, u := range tx.Slots {
		out = append(out, u.Addr)
	}
	return out
}

// holdsReverse reports whether the device listening on a loopback endpoint
// holds dev's key as a peer.
func holdsReverse(h *hostNode, dev *kmodel.Device, endpoint netip.AddrPort) bool {
	other, ok := h.kernel.PortOwner(endpoint.Port())
	return ok && other.Peers[dev.Private.Public()] != nil
}

// checkFlushed fails the run if a Flush or Sweep removed a flow whose
// translated address a peer of the device still allows: the connection had
// somewhere to go.
func (w *World) checkFlushed(h *hostNode) {
	for _, f := range h.kernel.Flushed {
		ns, ok := h.kernel.Named(f.Namespace)
		if !ok {
			continue
		}
		dev, ok := ns.Devices[h.cfg.Device]
		if !ok {
			continue
		}
		if p, ok := dev.Route(f.Flow.Remote); ok {
			w.fail("%s: %s flushed a flow to %v, dialed as %v, which peer %s still allows", h.name, f.Namespace, f.Flow.Remote, f.Flow.Dialed, w.byKey[p.PublicKey])
			break
		}
	}
	h.kernel.Flushed = nil
}

// checkTables fails the run if a namespace's table names an address its
// device cannot route: a slot whose backend has no peer, or a source address
// no peer holds. It runs after every kernel operation, since a batch must
// leave every state between its operations safe.
func (w *World) checkTables(h *hostNode, name string) {
	ns, ok := h.kernel.Named(name)
	if !ok || ns.Rules == nil {
		return
	}
	dev, ok := ns.Devices[h.cfg.Device]
	if !ok {
		return
	}
	var own []netip.Prefix
	if dev.Link != nil {
		own = dev.Link.Addrs
	}
	routed := func(a netip.Addr) bool {
		if _, ok := dev.Route(a); ok {
			return true
		}
		return holds(own, a)
	}
	for _, m := range ns.Rules.Maps {
		for slot, a := range m.Slots {
			if !routed(a) {
				w.fail("%s: slot %d of %s in %s names %v, which no peer holds", h.name, slot, m.Name, name, a)
				return
			}
		}
	}
	for _, s := range ns.Rules.Sets {
		for _, a := range s.Addrs {
			if _, ok := dev.Route(a); !ok {
				w.fail("%s: source set %s in %s names %v, which no peer holds", h.name, s.Name, name, a)
				return
			}
		}
	}
}

// checkJournal fails the run if a journal entry carries the private key of
// any device on the host: keys live in the kernel alone.
func (w *World) checkJournal(h *hostNode, e agentcore.JournalEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		w.fail("%s: journal entry for %s does not encode: %v", h.name, e.Interface, err)
		return
	}
	for _, ns := range h.kernel.All() {
		for _, d := range ns.DeviceList() {
			if bytes.Contains(b, []byte(d.Private.String())) {
				w.fail("%s: the journal entry for %s holds the private key of %s's device", h.name, e.Interface, ns.Name)
				return
			}
		}
	}
}

// expected is what a namespace must hold at a revision, by the oracle: the
// orchestrator's rules applied to the interfaces the control plane held.
type expected struct {
	live     bool
	egress   *kernel.EgressConfig
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
	pts := points(rules)
	// reach holds, for each service, whether x's service reaches it and
	// whether it reaches x's.
	reach := map[model.ServiceID][2]bool{}
	between := func(s model.ServiceID) (to, from bool) {
		v, ok := reach[s]
		if !ok {
			v = [2]bool{reaches(rules, pts, x.Service, s), reaches(rules, pts, s, x.Service)}
			reach[s] = v
		}
		return v[0], v[1]
	}
	for _, y := range snap {
		connected := y.State == api.Live || y.State == api.Released && !y.Drained
		xy, yx := between(y.Service)
		if y.ID == x.ID || y.Kind == api.Device || !connected || !xy && !yx {
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
		// The side that reaches the other keeps alive, or the lower ID
		// when each reaches the other.
		keeps := x.ID < y.ID
		if xy != yx {
			keeps = xy
		}
		e.peers[y.PublicKey] = expPeer{allowed: allowed, keepalive: y.Host == x.Host && keeps}
	}
	if rs := egressRules(rules, x.Service); len(rs) > 0 {
		e.egress = &kernel.EgressConfig{Index: x.ListenPort, Rules: rs}
	}
	families := []nft.Family{nft.IPv6}
	if x.Addr4.IsValid() {
		families = append(families, nft.IPv4)
	}
	for _, to := range n.services {
		if xto, _ := between(to.id); !xto {
			continue
		}
		var backends []store.Interface
		for _, y := range snap {
			if y.Service != to.id || y.State != api.Live || y.Kind == api.Device {
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
			if f == nft.IPv4 && !to.addr4.IsValid() {
				continue
			}
			addrs := make([]netip.Addr, len(table))
			for slot, i := range table {
				addrs[slot] = backends[i].Addr6
				if f == nft.IPv4 {
					addrs[slot] = backends[i].Addr4
				}
			}
			e.maps[nft.MapName(to.id, f)] = addrs
		}
	}
	for _, from := range n.services {
		if _, fromx := between(from.id); !fromx {
			continue
		}
		for _, f := range families {
			name := nft.SetName(from.id, f)
			var addrs []netip.Addr
			for _, y := range snap {
				if _, peer := e.peers[y.PublicKey]; !peer || y.Service != from.id {
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
	if !ns.Egress.Equal(e.egress) {
		return fmt.Errorf("egress %+v, want %+v", ns.Egress, e.egress)
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
// namespace holds exactly what the oracle expects at its revision, every
// ready interface's resolver answers what the oracle expects at the
// revision its agent holds, and no flow outlives the peer it went through.
func (w *World) checkSafety() {
	for _, h := range w.hosts {
		w.checkMoves(h)
		if !h.up || w.failure != nil {
			continue
		}
		w.checkZones(h)
		settled := h.core.Settled()
		for _, name := range sortedKeys(settled) {
			s := settled[name]
			ns, ok := h.kernel.Named(name)
			if !ok {
				if h.unnamed[name] {
					// An operator deleted its name; the agent learns at its
					// next look.
					continue
				}
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

// zoneAt is one interface's zone at a network revision. A zone depends on
// nothing else, so each is checked once.
type zoneAt struct {
	net model.NetworkID
	rev uint64
	id  model.InterfaceID
}

// checkZones compares what each ready interface's resolver would answer,
// from its agent's desired state, with what the oracle expects at that
// revision.
func (w *World) checkZones(h *hostNode) {
	desired := h.core.Desired()
	for _, li := range h.core.Interfaces() {
		if !li.Ready {
			continue
		}
		n, x, ok := desired.Interface(li.Interface)
		if !ok {
			continue
		}
		at := zoneAt{n.Network, n.Revision, x.ID}
		if w.zoned[at] {
			continue
		}
		want, ok := w.expectNames(at)
		if !ok {
			continue
		}
		w.zoned[at] = true
		got := map[string]dns.Name{}
		for _, name := range dns.ZoneFor(n, x).Names {
			got[name.FQDN] = name
		}
		for _, fqdn := range slices.Sorted(maps.Keys(want)) {
			if got[fqdn] != want[fqdn] {
				w.fail("%s: %s at revision %d answers %s with %+v, want %+v", h.name, x.ID, n.Revision, fqdn, got[fqdn], want[fqdn])
				return
			}
		}
		for _, fqdn := range slices.Sorted(maps.Keys(got)) {
			if _, ok := want[fqdn]; !ok {
				w.fail("%s: %s at revision %d answers %s with %+v, which it should not know", h.name, x.ID, n.Revision, fqdn, got[fqdn])
				return
			}
		}
	}
}

// expectNames computes, independently of the compiler and the resolver, the
// names one interface's resolver answers at a network revision: each service
// its own may reach, and each live member of one, and its own member name.
func (w *World) expectNames(at zoneAt) (map[string]dns.Name, bool) {
	snap, ok := w.cp.snaps[at.net][at.rev]
	n := w.orch.network(at.net)
	if !ok || n == nil {
		return nil, false
	}
	var x *store.Interface
	for i := range snap {
		if snap[i].ID == at.id {
			x = &snap[i]
		}
	}
	names := map[string]dns.Name{}
	if x == nil || x.State != api.Live {
		return names, true
	}
	domain := strings.ToLower(n.name) + ".internal."
	add := func(rel string, addr6, addr4 netip.Addr) {
		name := dns.Name{FQDN: rel + "." + domain, AAAA: addr6}
		if x.Addr4.IsValid() && addr4.IsValid() {
			name.A = addr4
		}
		names[name.FQDN] = name
	}
	rules := n.rulesAt(at.rev)
	pts := points(rules)
	for _, s := range n.services {
		if s.id == x.Service && x.Member != "" {
			add(x.Member+"."+s.name, x.Addr6, x.Addr4)
		}
		if !reaches(rules, pts, x.Service, s.id) {
			continue
		}
		add(s.name, s.addr6, s.addr4)
		for _, y := range snap {
			if y.Service == s.id && y.Member != "" && y.State == api.Live && y.Kind != api.Device {
				add(y.Member+"."+s.name, y.Addr6, y.Addr4)
			}
		}
	}
	return names, true
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
		for _, idx := range slices.Sorted(maps.Keys(h.kernel.EgressChains)) {
			if !h.kernel.EgressLinked(idx) {
				w.fail("%s: the egress filter for link %d outlives the link", h.name, idx)
				return
			}
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
				w.fail("%s: %s never settled; pending %v", h.name, name, h.core.Pending())
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
	w.countRelayEdges()
}

// countRelayEdges counts, once the system has converged and carried the
// liveness probes, the relay edges whose ends send through different
// relays, and those whose ends agree on a relay other than the heaviest
// both agents find up. Roaming owns the endpoint, so an edge whose ends'
// probes once disagreed can stay where the last packet left it.
func (w *World) countRelayEdges() {
	relayAt := map[netip.Addr]model.RelayID{}
	for _, r := range w.relays {
		relayAt[r.advertised] = r.id
	}
	type end struct {
		relay model.RelayID
		set   []model.RelayID
		up    map[model.RelayID]bool
	}
	sends := map[[2]model.InterfaceID]end{}
	for _, h := range w.hosts {
		if !h.up || h.core == nil {
			continue
		}
		up := h.core.RelaysUp()
		settled := h.core.Settled()
		for _, name := range sortedKeys(settled) {
			s := settled[name]
			n, ok := h.core.Desired().Networks[s.Network]
			ns, named := h.kernel.Named(name)
			if !ok || !named {
				continue
			}
			dev, ok := ns.Devices[h.cfg.Device]
			if !ok {
				continue
			}
			var set []model.RelayID
			for _, r := range n.Relays {
				set = append(set, r.Relay)
			}
			for _, p := range dev.PeerList() {
				if r, ok := relayAt[p.Endpoint.Addr()]; ok {
					sends[[2]model.InterfaceID{s.Interface, w.byKey[p.PublicKey]}] = end{r, set, up}
				}
			}
		}
	}
	keys := slices.SortedFunc(maps.Keys(sends), func(a, b [2]model.InterfaceID) int {
		return cmp.Or(strings.Compare(string(a[0]), string(b[0])), strings.Compare(string(a[1]), string(b[1])))
	})
	for _, k := range keys {
		a := sends[k]
		b, ok := sends[[2]model.InterfaceID{k[1], k[0]}]
		if !ok || k[1] < k[0] {
			continue
		}
		w.summary.RelayEdges++
		if a.relay != b.relay {
			w.summary.RelaySplit++
			continue
		}
		var best model.RelayID
		var weight uint64
		for _, r := range a.set {
			if !a.up[r] || !b.up[r] {
				continue
			}
			if x := model.RelayWeight(k[0], k[1], r); best == "" || x > weight {
				best, weight = r, x
			}
		}
		if best != "" && a.relay != best {
			w.summary.RelayDrift++
		}
	}
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
		pts := points(rules)
		// To each service x reaches: a flow in each protocol the rules
		// open toward it, and one flow they close.
		for _, s := range n.services {
			var open, shut []point
			seen := map[model.Proto]bool{}
			for _, p := range pts {
				switch {
				case permits(rules, x.service, s.id, p.proto, p.port):
					if !seen[p.proto] {
						seen[p.proto] = true
						open = append(open, p)
					}
				case len(shut) == 0:
					shut = append(shut, p)
				}
			}
			if len(open) == 0 {
				continue
			}
			for _, f := range []nft.Family{nft.IPv6, nft.IPv4} {
				if _, ok := e.maps[nft.MapName(s.id, f)]; !ok {
					continue
				}
				addr := s.addr6
				if f == nft.IPv4 {
					addr = s.addr4
				}
				for _, p := range open {
					probes = append(probes, probe{w.open(x, addr, p.proto, p.port), true, fmt.Sprintf("%s to %s over %v %s/%d", x.id, s.name, f, p.proto, p.port)})
				}
				for _, p := range shut {
					probes = append(probes, probe{w.open(x, addr, p.proto, p.port), false, fmt.Sprintf("%s to %s over %v %s/%d, which policy closes", x.id, s.name, f, p.proto, p.port)})
				}
			}
		}
		for _, y := range o.live() {
			if y.network != x.network || y.id == x.id {
				continue
			}
			if _, peer := e.peers[y.key]; !peer {
				probes = append(probes, probe{w.open(x, y.addr6, model.TCP, 80), false, fmt.Sprintf("%s to unconnected %s", x.id, y.id)})
				if x.addr4.IsValid() && y.addr4.IsValid() && !w.heldByAnother(x.network, rev, y.id, y.addr4) {
					probes = append(probes, probe{w.open(x, y.addr4, model.TCP, 80), false, fmt.Sprintf("%s to unconnected %s over IPv4", x.id, y.id)})
				}
				continue
			}
			if !permits(rules, x.service, y.service, model.TCP, 9) {
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

// heldByAnother reports whether a connected interface other than id holds
// addr at a revision. A revoked interface's workload keeps running, and once
// the quarantine ends its IPv4 address may belong to another interface, which
// a probe to the address would reach.
func (w *World) heldByAnother(net model.NetworkID, rev uint64, id model.InterfaceID, addr netip.Addr) bool {
	for _, i := range w.cp.snaps[net][rev] {
		if i.ID != id && i.Addr4 == addr && compile.Connected(i) {
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
