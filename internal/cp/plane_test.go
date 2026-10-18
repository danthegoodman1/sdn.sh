package cp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
	"sdn.sh/internal/prng"
	"sdn.sh/internal/store"
	"sdn.sh/internal/store/mem"
	"sdn.sh/internal/store/pgstore/pgtest"
)

var t0 = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

type fixture struct {
	t      *testing.T
	s      store.Store
	p      *Plane
	now    time.Time
	rng    *prng.Rand
	hosts  map[string]model.HostID
	relays []string
}

func newFixture(t *testing.T, s store.Store) *fixture {
	cfg := DefaultConfig()
	return &fixture{
		t: t, s: s, now: t0, rng: prng.New(1),
		p:     &Plane{Config: cfg, Rand: prng.New(2)},
		hosts: map[string]model.HostID{},
	}
}

// eachStore runs fn over the memory store, and again over Postgres when
// SDN_TEST_POSTGRES names a database.
func eachStore(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Run("mem", func(t *testing.T) { fn(t, newFixture(t, mem.New())) })
	t.Run("postgres", func(t *testing.T) { fn(t, newFixture(t, pgtest.Open(t))) })
}

func (f *fixture) update(fn func(store.Tx) error) store.Change {
	f.t.Helper()
	ch, err := f.s.Update(context.Background(), fn)
	if err != nil {
		f.t.Fatal(err)
	}
	return ch
}

func (f *fixture) tryUpdate(fn func(store.Tx) error) error {
	_, err := f.s.Update(context.Background(), fn)
	return err
}

func (f *fixture) relay(name string) model.RelayID {
	var id model.RelayID
	octet := byte(1 + len(f.relays))
	f.relays = append(f.relays, name)
	f.update(func(tx store.Tx) error {
		r, _, err := f.p.CreateRelay(tx, f.now, api.CreateRelay{
			Name: name,
			Addresses: []api.RelayAddress{{
				Local:      netip.AddrFrom4([4]byte{10, 0, 0, octet}),
				Advertised: netip.AddrFrom4([4]byte{198, 51, 100, octet}),
			}},
			PortLo: 20000, PortHi: 20099, ProbePort: 19999,
		})
		id = r.ID
		return err
	})
	return id
}

func (f *fixture) network(req api.CreateNetwork) store.Network {
	var n store.Network
	f.update(func(tx store.Tx) error {
		var err error
		n, err = f.p.CreateNetwork(tx, f.now, req)
		return err
	})
	return n
}

func (f *fixture) service(net, name string, ipv4 bool) store.Service {
	var s store.Service
	f.update(func(tx store.Tx) error {
		var err error
		s, err = f.p.CreateService(tx, f.now, net, api.CreateService{Name: name, IPv4: ipv4})
		return err
	})
	return s
}

func (f *fixture) rule(net, from, to string, proto model.Proto, port uint16) store.Rule {
	var r store.Rule
	f.update(func(tx store.Tx) error {
		var err error
		r, err = f.p.CreateRule(tx, f.now, net, api.CreateRule{From: from, To: to, Proto: proto, Ports: model.PortRange{Lo: port, Hi: port}})
		return err
	})
	return r
}

func (f *fixture) host(name string) model.HostID {
	if id, ok := f.hosts[name]; ok {
		return id
	}
	f.update(func(tx store.Tx) error {
		h, _, err := f.p.CreateHost(tx, f.now, api.CreateHost{Name: name})
		f.hosts[name] = h.ID
		return err
	})
	return f.hosts[name]
}

// attach issues an interface and returns it with the private key the agent
// would keep.
func (f *fixture) attach(host, net, svc string) (store.Interface, model.Key) {
	f.t.Helper()
	priv, _ := model.NewPrivateKey(f.rng)
	id, _ := model.NewID(model.InterfacePrefix, f.rng)
	var i store.Interface
	h := f.host(host)
	f.update(func(tx store.Tx) error {
		var err error
		i, err = f.p.Attach(tx, f.now, h, api.AttachRequest{
			Interface: model.InterfaceID(id), Network: net, Service: svc,
			PublicKey: priv.Public(), ListenPort: uint16(40000 + f.rng.Below(1000)),
		})
		return err
	})
	return i, priv
}

func (f *fixture) state(host string) api.StateUpdate {
	f.t.Helper()
	var u api.StateUpdate
	if err := f.s.View(context.Background(), func(tx store.ReadTx) error {
		var err error
		u, err = HostState(tx, NoCache{}, f.host(host), 0)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return u
}

func peerIDs(u api.StateUpdate, iface model.InterfaceID) []model.InterfaceID {
	for _, n := range u.Networks {
		if i, ok := n.Interface(iface); ok {
			var out []model.InterfaceID
			for _, p := range i.Peers {
				out = append(out, p.Interface)
			}
			return out
		}
	}
	return nil
}

func sortedIDs(ids ...model.InterfaceID) []model.InterfaceID {
	slices.Sort(ids)
	return ids
}

// TestOverlappingNetworksCompileToExactlyThePermittedPeers is Phase 2's
// gate: two networks on identical prefixes, four interfaces across two
// hosts, and each host's state names exactly the peers policy permits.
func TestOverlappingNetworksCompileToExactlyThePermittedPeers(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r1")
		p6 := netip.MustParsePrefix("fd00:42::/64")
		p4 := netip.MustParsePrefix("10.42.0.0/16")
		f.network(api.CreateNetwork{Name: "shop", Prefix6: p6, Prefix4: p4, Relays: []model.RelayID{relay}})
		f.network(api.CreateNetwork{Name: "bank", Prefix6: p6, Prefix4: p4, Relays: []model.RelayID{relay}})
		for _, net := range []string{"shop", "bank"} {
			f.service(net, "web", true)
			f.service(net, "db", true)
			f.service(net, "batch", true)
		}
		f.rule("shop", "web", "db", model.TCP, 5432)
		f.rule("bank", "batch", "db", model.TCP, 5432)

		shopWeb, _ := f.attach("h1", "shop", "web")
		shopDB, _ := f.attach("h2", "shop", "db")
		bankBatch, _ := f.attach("h1", "bank", "batch")
		bankDB, _ := f.attach("h2", "bank", "db")
		// A shop batch job policy names nowhere: it peers with nothing.
		shopBatch, _ := f.attach("h2", "shop", "batch")

		if shopWeb.Addr6 != bankBatch.Addr6 || shopWeb.Addr4 != bankBatch.Addr4 {
			t.Fatalf("identical prefixes allocated differently: %v %v vs %v %v", shopWeb.Addr6, shopWeb.Addr4, bankBatch.Addr6, bankBatch.Addr4)
		}
		h1, h2 := f.state("h1"), f.state("h2")
		cases := []struct {
			u     api.StateUpdate
			iface store.Interface
			want  []model.InterfaceID
		}{
			{h1, shopWeb, []model.InterfaceID{shopDB.ID}},
			{h1, bankBatch, []model.InterfaceID{bankDB.ID}},
			{h2, shopDB, []model.InterfaceID{shopWeb.ID}},
			{h2, bankDB, []model.InterfaceID{bankBatch.ID}},
			{h2, shopBatch, nil},
		}
		for _, c := range cases {
			if got := peerIDs(c.u, c.iface.ID); !slices.Equal(got, c.want) {
				t.Errorf("%s peers %v, want %v", c.iface.ID, got, c.want)
			}
		}
		// Each peer carries exactly the peer's own address per family, and a
		// relay path with this direction's port.
		for _, n := range h1.Networks {
			for _, i := range n.Interfaces {
				for _, p := range i.Peers {
					if len(p.Allowed) != 2 || p.Allowed[0].Bits() != 128 || p.Allowed[1].Bits() != 32 {
						t.Errorf("%s peer %s allowed %v", i.ID, p.Interface, p.Allowed)
					}
					if len(p.Relays) != 1 || p.Loopback != 0 || p.Keepalive {
						t.Errorf("%s peer %s path %+v", i.ID, p.Interface, p)
					}
				}
			}
		}
	})
}

func TestEdgesCarryOnePortPerDirectionPerRelay(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		r1, r2 := f.relay("r1"), f.relay("r2")
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{r1, r2}})
		f.service("n", "a", false)
		f.rule("n", "a", "a", model.TCP, 80)
		x, _ := f.attach("h1", "n", "a")
		y, _ := f.attach("h2", "n", "a")
		z, _ := f.attach("h2", "n", "a")
		h1 := f.state("h1")
		xi, _ := h1.Networks[0].Interface(x.ID)
		if len(xi.Peers) != 2 {
			t.Fatalf("x peers %d", len(xi.Peers))
		}
		seen := map[netip.AddrPort]bool{}
		for _, p := range xi.Peers {
			if len(p.Relays) != 2 || p.Relays[0].Relay != r1 || p.Relays[1].Relay != r2 {
				t.Fatalf("relay paths %+v", p.Relays)
			}
			for _, rp := range p.Relays {
				if seen[rp.Send] {
					t.Fatalf("port %v used twice", rp.Send)
				}
				seen[rp.Send] = true
			}
		}
		// y and z share a host, so they peer over loopback with keepalive on
		// exactly one side.
		h2 := f.state("h2")
		yi, _ := h2.Networks[0].Interface(y.ID)
		zi, _ := h2.Networks[0].Interface(z.ID)
		var yz, zy api.Peer
		for _, p := range yi.Peers {
			if p.Interface == z.ID {
				yz = p
			}
		}
		for _, p := range zi.Peers {
			if p.Interface == y.ID {
				zy = p
			}
		}
		if yz.Loopback != z.ListenPort || zy.Loopback != y.ListenPort || len(yz.Relays) != 0 {
			t.Fatalf("loopback paths %+v %+v", yz, zy)
		}
		if yz.Keepalive == zy.Keepalive {
			t.Fatalf("keepalive on both or neither side: %v %v", yz.Keepalive, zy.Keepalive)
		}
		// The relay sees both directions of the x–y edge, each forwarding to
		// the other's port.
		var rs api.RelayState
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			var err error
			rs, err = RelayState(tx, r1)
			return err
		})
		if len(rs.Ports) != 4 {
			t.Fatalf("relay ports %d, want 2 edges × 2 directions", len(rs.Ports))
		}
		for _, p := range rs.Ports {
			var back *api.RelayPort
			for j := range rs.Ports {
				if rs.Ports[j].Local.Port() == p.Peer {
					back = &rs.Ports[j]
				}
			}
			if back == nil || back.Peer != p.Local.Port() {
				t.Fatalf("port %v's peer %d does not point back", p.Local, p.Peer)
			}
		}
	})
}

func TestAnIPv6OnlyServiceDrawsNothingFromTheIPv4Pool(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		n := f.network(api.CreateNetwork{Name: "n", Prefix4: netip.MustParsePrefix("10.9.0.0/30")})
		f.service("n", "six", false)
		for range 5 {
			i, _ := f.attach("h", "n", "six")
			if i.Addr4.IsValid() {
				t.Fatalf("IPv6-only interface got %v", i.Addr4)
			}
		}
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			got, _ := tx.Network(n.ID)
			if got.Next4 != first4 {
				t.Errorf("IPv4 cursor moved to %d", got.Next4)
			}
			return nil
		})
		// A /30 has two usable addresses: the service takes one and one
		// interface the other.
		f.service("n", "four", true)
		f.attach("h", "n", "four")
		err := f.tryUpdate(func(tx store.Tx) error {
			_, err := f.p.Attach(tx, f.now, f.host("h"), api.AttachRequest{
				Interface: "if-extra", Network: "n", Service: "four", PublicKey: model.Key{1}, ListenPort: 1,
			})
			return err
		})
		var ae *api.Error
		if !errors.As(err, &ae) || ae.Code != api.CodeExhausted {
			t.Fatalf("attach into a full pool: %v", err)
		}
	})
}

func TestIPv6AddressesAreNeverReused(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "a", false)
		seen := map[netip.Addr]bool{}
		for range 50 {
			i, _ := f.attach("h", "n", "a")
			if seen[i.Addr6] {
				t.Fatalf("%v reused", i.Addr6)
			}
			seen[i.Addr6] = true
			f.update(func(tx store.Tx) error { return f.p.Revoke(tx, f.now, i.ID) })
		}
	})
}

// TestAReleasedIPv4AddressWaitsOutItsQuarantine is Phase 2's quarantine
// gate.
func TestAReleasedIPv4AddressWaitsOutItsQuarantine(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n", Prefix4: netip.MustParsePrefix("10.9.0.0/29")})
		f.service("n", "a", true)
		// A /29 holds six usable addresses: one for the service, five for
		// interfaces.
		var held []store.Interface
		for range 5 {
			i, _ := f.attach("h", "n", "a")
			held = append(held, i)
		}
		gone := held[2]
		f.update(func(tx store.Tx) error { return f.p.Release(tx, f.now, f.host("h"), []model.InterfaceID{gone.ID}) })
		attachAt := func(at time.Time) (store.Interface, error) {
			var i store.Interface
			err := f.tryUpdate(func(tx store.Tx) error {
				var err error
				i, err = f.p.Attach(tx, at, f.host("h"), api.AttachRequest{
					Interface: model.InterfaceID(fmt.Sprintf("if-at%d", at.Unix())), Network: "n", Service: "a",
					PublicKey: model.Key{9}, ListenPort: 9,
				})
				return err
			})
			return i, err
		}
		if _, err := attachAt(f.now.Add(f.p.Config.Quarantine4 - time.Second)); err == nil {
			t.Fatal("reallocated an address inside its quarantine")
		}
		i, err := attachAt(f.now.Add(f.p.Config.Quarantine4 + time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if i.Addr4 != gone.Addr4 {
			t.Fatalf("got %v, want the quarantined %v", i.Addr4, gone.Addr4)
		}
	})
}

// TestRevocationRemovesTheKeyEverywhereWithNoGrace checks that a revoked
// interface leaves every other host's state at once, while a released one
// stays as a draining peer.
func TestRevocationRemovesTheKeyEverywhereWithNoGrace(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{relay}})
		f.service("n", "web", false)
		f.service("n", "db", false)
		f.rule("n", "web", "db", model.TCP, 5432)
		db1, _ := f.attach("h1", "n", "db")
		db2, _ := f.attach("h1", "n", "db")
		var webs []store.Interface
		for _, h := range []string{"h2", "h3"} {
			w, _ := f.attach(h, "n", "web")
			webs = append(webs, w)
		}
		f.update(func(tx store.Tx) error { return f.p.Release(tx, f.now, f.host("h1"), []model.InterfaceID{db1.ID}) })
		f.update(func(tx store.Tx) error { return f.p.Revoke(tx, f.now, db2.ID) })
		for i, h := range []string{"h2", "h3"} {
			u := f.state(h)
			wi, _ := u.Networks[0].Interface(webs[i].ID)
			if len(wi.Peers) != 1 || wi.Peers[0].Interface != db1.ID || !wi.Peers[0].Draining {
				t.Fatalf("%s peers %+v; want only the draining db1", h, wi.Peers)
			}
			svc := u.Networks[0].Services[0]
			if len(svc.Backends) != 0 {
				t.Fatalf("%s: service still lists backends %+v", h, svc.Backends)
			}
		}
		// db2's own host learns it was revoked.
		own, _ := f.state("h1").Networks[0].Interface(db2.ID)
		if own.State != api.Revoked || len(own.Peers) != 0 {
			t.Fatalf("revoked interface's own state %+v", own)
		}
		// Once the grace period passes, the released one leaves too.
		f.now = f.now.Add(f.p.Config.DrainGrace + time.Second)
		f.update(func(tx store.Tx) error { _, err := f.p.Sweep(tx, f.now); return err })
		for i, h := range []string{"h2", "h3"} {
			wi, _ := f.state(h).Networks[0].Interface(webs[i].ID)
			if len(wi.Peers) != 0 {
				t.Fatalf("%s still peers with %+v after the grace period", h, wi.Peers)
			}
		}
	})
}

func TestARuleNamingAnEmptyServiceCompilesToNoPeers(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "web", false)
		f.service("n", "db", false)
		f.rule("n", "web", "db", model.TCP, 5432)
		w, _ := f.attach("h", "n", "web")
		n := f.state("h").Networks[0]
		wi, _ := n.Interface(w.ID)
		if len(wi.Peers) != 0 || len(wi.Reach) != 1 {
			t.Fatalf("peers %+v reach %+v", wi.Peers, wi.Reach)
		}
		if len(n.Services) != 1 || len(n.Services[0].Backends) != 0 {
			t.Fatalf("services %+v; want db with no backends", n.Services)
		}
	})
}

func TestMixedFamiliesCompileToIPv6Alone(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n", Prefix4: netip.MustParsePrefix("10.1.0.0/16")})
		f.service("n", "four", true)
		f.service("n", "six", false)
		f.rule("n", "four", "six", model.TCP, 80)
		a, _ := f.attach("h1", "n", "four")
		b, _ := f.attach("h1", "n", "six")
		n := f.state("h1").Networks[0]
		ai, _ := n.Interface(a.ID)
		bi, _ := n.Interface(b.ID)
		if len(ai.Peers[0].Allowed) != 1 || !ai.Peers[0].Allowed[0].Addr().Is6() {
			t.Fatalf("four's peer allowed %v", ai.Peers[0].Allowed)
		}
		if len(bi.Peers[0].Allowed) != 1 || !bi.Peers[0].Allowed[0].Addr().Is6() {
			t.Fatalf("six's peer allowed %v", bi.Peers[0].Allowed)
		}
		if !a.Addr4.IsValid() || b.Addr4.IsValid() {
			t.Fatalf("addresses %v %v", a.Addr4, b.Addr4)
		}
	})
}

func TestFullyConnectedPolicyPeersEveryPair(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{relay}})
		f.service("n", "mesh", false)
		f.rule("n", "mesh", "mesh", model.AnyProto, 0)
		var all []model.InterfaceID
		for i := range 6 {
			x, _ := f.attach(fmt.Sprintf("h%d", i%3), "n", "mesh")
			all = append(all, x.ID)
		}
		slices.Sort(all)
		for h := range 3 {
			for _, n := range f.state(fmt.Sprintf("h%d", h)).Networks {
				for _, i := range n.Interfaces {
					want := slices.DeleteFunc(slices.Clone(all), func(id model.InterfaceID) bool { return id == i.ID })
					if got := peerIDs(api.StateUpdate{Networks: []api.NetworkState{n}}, i.ID); !slices.Equal(got, want) {
						t.Fatalf("%s peers %v, want %v", i.ID, got, want)
					}
				}
			}
		}
		// Six interfaces on three hosts, two per host: 15 pairs, 3 co-located.
		var edges []store.Edge
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			n, _ := tx.NetworkByName("n")
			edges, _ = tx.Edges(n.ID)
			return nil
		})
		if len(edges) != 12 {
			t.Fatalf("%d edges, want 12", len(edges))
		}
	})
}

// TestADisconnectedPairKeepsItsEdgeForTheQuarantine covers a rule that goes
// away and comes back: the pair gets its edge back with the same ports, so
// endpoints peers roamed to stay valid, and only once the quarantine passes
// does the edge go and its ports free up.
func TestADisconnectedPairKeepsItsEdgeForTheQuarantine(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.p.Config.LeaseTTL = time.Hour
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{relay}})
		f.service("n", "a", false)
		f.service("n", "b", false)
		r := f.rule("n", "a", "b", model.TCP, 1)
		f.attach("h1", "n", "a")
		f.attach("h2", "n", "b")
		edges := func() []store.Edge {
			var out []store.Edge
			f.s.View(context.Background(), func(tx store.ReadTx) error {
				n, _ := tx.NetworkByName("n")
				out, _ = tx.Edges(n.ID)
				return nil
			})
			return out
		}
		before := edges()
		f.update(func(tx store.Tx) error { return f.p.DeleteRule(tx, f.now, "n", r.ID) })
		if e := edges(); len(e) != 1 || e[0].Dormant.IsZero() {
			t.Fatalf("edges after the rule went: %+v", e)
		}
		if peers := peerIDs(f.state("h1"), before[0].A); len(peers) != 0 {
			peers = peerIDs(f.state("h1"), before[0].B)
			if len(peers) != 0 {
				t.Fatalf("a dormant edge still peers %v", peers)
			}
		}
		f.rule("n", "a", "b", model.TCP, 1)
		after := edges()
		if len(after) != 1 || !after[0].Dormant.IsZero() || after[0].Ports[0] != before[0].Ports[0] || after[0].SecretAB != before[0].SecretAB {
			t.Fatalf("the restored edge differs: %+v vs %+v", after, before)
		}
		r2 := after[0]
		var rules []store.Rule
		f.s.View(context.Background(), func(tx store.ReadTx) error { rules, _ = tx.Rules(r2.Network); return nil })
		f.update(func(tx store.Tx) error { return f.p.DeleteRule(tx, f.now, "n", rules[0].ID) })
		f.update(func(tx store.Tx) error {
			_, err := f.p.Sweep(tx, f.now.Add(f.p.Config.PortQuarantine-time.Second))
			return err
		})
		if len(edges()) != 1 {
			t.Fatal("a dormant edge went before the quarantine passed")
		}
		f.update(func(tx store.Tx) error {
			_, err := f.p.Sweep(tx, f.now.Add(f.p.Config.PortQuarantine+time.Second))
			return err
		})
		if len(edges()) != 0 {
			t.Fatal("a dormant edge outlived the quarantine")
		}
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			ports, _ := tx.ReleasedPorts(relay, before[0].Ports[0].Addr, f.now.Add(time.Second), 10)
			if len(ports) != 2 {
				t.Errorf("%d ports free, want 2", len(ports))
			}
			return nil
		})
	})
}

func TestReleasedPortsWaitOutTheirQuarantine(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r") // 100 ports: 50 edges
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{relay}})
		f.service("n", "a", false)
		f.service("n", "b", false)
		f.rule("n", "a", "b", model.TCP, 1)
		b, _ := f.attach("hb", "n", "b")
		var as []store.Interface
		for i := range 50 {
			a, _ := f.attach(fmt.Sprintf("h%d", i), "n", "a")
			as = append(as, a)
		}
		f.update(func(tx store.Tx) error { return f.p.Revoke(tx, f.now, as[0].ID) })
		err := f.tryUpdate(func(tx store.Tx) error {
			_, err := f.p.Attach(tx, f.now.Add(time.Minute), f.host("h0"), api.AttachRequest{
				Interface: "if-late", Network: "n", Service: "a", PublicKey: model.Key{3}, ListenPort: 3,
			})
			return err
		})
		if err == nil {
			t.Fatal("reused a relay port inside its quarantine")
		}
		f.update(func(tx store.Tx) error {
			_, err := f.p.Attach(tx, f.now.Add(f.p.Config.PortQuarantine+time.Second), f.host("h0"), api.AttachRequest{
				Interface: "if-later", Network: "n", Service: "a", PublicKey: model.Key{4}, ListenPort: 4,
			})
			return err
		})
		_ = b
	})
}

func TestAttachIsIdempotentForTheSameKey(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "a", false)
		h := f.host("h")
		req := api.AttachRequest{Interface: "if-same", Network: "n", Service: "a", PublicKey: model.Key{7}, ListenPort: 7}
		var first, second store.Interface
		f.update(func(tx store.Tx) error { var err error; first, err = f.p.Attach(tx, f.now, h, req); return err })
		f.update(func(tx store.Tx) error { var err error; second, err = f.p.Attach(tx, f.now, h, req); return err })
		if first.Addr6 != second.Addr6 {
			t.Fatalf("retried attach got a second address %v, then %v", first.Addr6, second.Addr6)
		}
		req.PublicKey = model.Key{8}
		if err := f.tryUpdate(func(tx store.Tx) error { _, err := f.p.Attach(tx, f.now, h, req); return err }); err == nil {
			t.Fatal("a second key took over an interface")
		}
	})
}

// TestTheControlPlaneNeverStoresAPrivateKey attaches interfaces and checks
// that no record holds a private key the agents minted.
func TestTheControlPlaneNeverStoresAPrivateKey(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "a", false)
		f.rule("n", "a", "a", model.TCP, 1)
		var privs []model.Key
		for range 4 {
			_, priv := f.attach("h", "n", "a")
			privs = append(privs, priv)
		}
		var dump strings.Builder
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			nets, _ := tx.Networks()
			for _, n := range nets {
				for _, v := range []any{
					n, must(tx.Services(n.ID)), must(tx.Interfaces(n.ID)), must(tx.Rules(n.ID)), must(tx.Edges(n.ID)),
				} {
					b, _ := json.Marshal(v)
					dump.Write(b)
				}
			}
			return nil
		})
		u := f.state("h")
		b, _ := json.Marshal(u)
		dump.Write(b)
		for _, k := range privs {
			if strings.Contains(dump.String(), k.String()) {
				t.Fatal("a private key reached the control plane")
			}
			if !strings.Contains(dump.String(), k.Public().String()) {
				t.Fatal("dump lacks a public key, so the check proves nothing")
			}
		}
	})
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestExpiryWaitsOutTheControlPlanesDowntime(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "a", false)
		f.update(func(tx store.Tx) error { return f.p.Heartbeat(tx, f.now) })
		i, _ := f.attach("h", "n", "a")
		// The control plane goes down for ten minutes, far past the lease.
		down := 10 * time.Minute
		f.now = f.now.Add(down)
		f.update(func(tx store.Tx) error { _, err := f.p.Boot(tx, f.now); return err })
		f.update(func(tx store.Tx) error { _, err := f.p.Sweep(tx, f.now.Add(time.Minute)); return err })
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			got, _ := tx.Interface(i.ID)
			if got.State != api.Live {
				t.Errorf("revoked %s a minute after recovery", i.ID)
			}
			return nil
		})
		// An agent that never renews loses its lease once the wait ends.
		f.update(func(tx store.Tx) error { _, err := f.p.Sweep(tx, f.now.Add(down+time.Second)); return err })
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			got, _ := tx.Interface(i.ID)
			if got.State != api.Revoked {
				t.Errorf("state %s after the wait", got.State)
			}
			return nil
		})
	})
}

func TestStateUpdatesCarryOnlyChangedNetworks(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "a"})
		f.network(api.CreateNetwork{Name: "b"})
		f.service("a", "s", false)
		f.service("b", "s", false)
		f.attach("h", "a", "s")
		f.attach("h", "b", "s")
		h := api.NewHostState()
		full := f.state("h")
		if err := h.Apply(full); err != nil {
			t.Fatal(err)
		}
		f.attach("h", "b", "s")
		var delta api.StateUpdate
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			var err error
			delta, err = HostState(tx, NoCache{}, f.host("h"), h.Generation)
			return err
		})
		if len(delta.Networks) != 1 || delta.Networks[0].Name != "b" || len(delta.Present) != 2 {
			t.Fatalf("delta carries %d networks, presents %d", len(delta.Networks), len(delta.Present))
		}
		if err := h.Apply(delta); err != nil {
			t.Fatal(err)
		}
		again := api.NewHostState()
		again.Apply(f.state("h"))
		a, _ := json.Marshal(h.Networks)
		b, _ := json.Marshal(again.Networks)
		if string(a) != string(b) {
			t.Fatal("a full state and a delta applied to the previous state differ")
		}
	})
}
