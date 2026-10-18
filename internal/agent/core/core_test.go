package core

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/kernel"
	"sdn.sh/internal/model"
	"sdn.sh/internal/prng"
)

var (
	self = model.Key{7}
	peer = model.Key{9}
	pfx  = netip.MustParsePrefix
	ap   = netip.MustParseAddrPort
)

// adopted is a core that adopted one interface, if-a in sdn-a, from its
// journal and the kernel.
func adopted(t *testing.T) (*Core, time.Time) {
	t.Helper()
	c, now := New(DefaultConfig("h1"), prng.New(1)), time.Unix(1000, 0)
	e := JournalEntry{Interface: "if-a", Name: "w", Network: "net-1", Service: "svc-1", Kind: api.Workload, Namespace: "sdn-a", ListenPort: 40000, PublicKey: self}
	dev := kernel.Device{Name: c.cfg.Device, HasKey: true, PublicKey: self, ListenPort: 40000}
	c.Start(now, []JournalEntry{e}, kernel.Snapshot{Namespaces: []kernel.Namespace{{Name: "sdn-a", Devices: []kernel.Device{dev}}}})
	return c, now
}

// state is a host state holding net-1, where if-a has the peers given.
func state(rev uint64, relays []api.RelayRef, peers ...api.Peer) api.StateUpdate {
	n := api.NetworkState{Network: "net-1", Name: "n", Revision: rev, Prefix6: pfx("fd00::/64"), MTU: 1380, Relays: relays,
		Interfaces: []api.Interface{{ID: "if-a", Service: "svc-1", Kind: api.Workload, PublicKey: self, Addr6: netip.MustParseAddr("fd00::5"), ListenPort: 40000, State: api.Live, Peers: peers}}}
	return api.StateUpdate{Host: "h1", Generation: rev, Networks: []api.NetworkState{n}, Present: []api.NetworkRef{{Network: "net-1", Revision: rev}}}
}

// drive carries out the core's actions once: batches complete with the
// error fail returns, observations find the namespace gone, and probes to
// relays in up are answered. It returns the batches it ran.
func drive(c *Core, now time.Time, fail func(RunBatch) error, up ...model.RelayID) []RunBatch {
	var ran []RunBatch
	for _, a := range c.Actions(now) {
		switch a := a.(type) {
		case RunBatch:
			ran = append(ran, a)
			if err := fail(a); err != nil {
				c.BatchDone(now, a.Namespace, a.ID, 0, err)
			} else {
				c.BatchDone(now, a.Namespace, a.ID, len(a.Ops), nil)
			}
		case Observe:
			c.Observed(now, kernel.Namespace{Name: a.Namespace}, kernel.ErrNoNamespace)
		case SendProbe:
			if slices.Contains(up, a.Relay) {
				c.ProbeReply(now, a.Relay, a.Nonce)
			}
		}
	}
	return ran
}

func succeed(RunBatch) error { return nil }

func TestAHeldNamespaceIsReapedOnce(t *testing.T) {
	c, now := New(DefaultConfig("h1"), prng.New(1)), time.Unix(1000, 0)
	c.Start(now, nil, kernel.Snapshot{Namespaces: []kernel.Namespace{{Ref: "ns-1"}}})
	reaps := 0
	for range 10 {
		for _, b := range drive(c, now, succeed) {
			for _, op := range b.Ops {
				if op.Kind == kernel.Reap {
					reaps++
				}
			}
		}
		now = now.Add(time.Second)
	}
	if reaps != 1 {
		t.Fatalf("reaped %d times, want once", reaps)
	}
}

func TestAnInterfaceWhoseNamespaceVanishesIsTornDown(t *testing.T) {
	c, now := adopted(t)
	if err := c.State(now, state(3, nil)); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	c.Observed(now, kernel.Namespace{Name: "sdn-a"}, kernel.ErrNoNamespace)
	gone := func(RunBatch) error { return fmt.Errorf("op: %w", kernel.ErrNoNamespace) }
	for range 4 {
		now = now.Add(10 * time.Second)
		drive(c, now, gone)
	}
	if i, ok := c.ifaces["if-a"]; ok && !i.phase.tearingDown() {
		t.Fatalf("if-a is %s after its namespace vanished", i.phase)
	}
	if slices.Contains(c.Live(), "if-a") {
		t.Fatal("if-a is live after its namespace vanished")
	}
}

func TestAMachineAPeerStopsFrontingIsFlushed(t *testing.T) {
	c, now := adopted(t)
	gw := api.Peer{Interface: "if-g", Service: "svc-gw", PublicKey: peer, Allowed: []netip.Prefix{pfx("fd00::6/128")}}
	fronting := gw
	fronting.Fronts = []api.Fronted{{Interface: "if-l", Service: "svc-dev", Allowed: []netip.Prefix{pfx("fd00::99/128")}}}
	if err := c.State(now, state(3, nil, fronting)); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	if err := c.State(now, state(4, nil, gw)); err != nil {
		t.Fatal(err)
	}
	var shrunk, flushed bool
	for _, b := range drive(c, now, succeed) {
		for _, op := range b.Ops {
			switch op.Kind {
			case kernel.SetPeers:
				for _, u := range op.Peers {
					shrunk = shrunk || u.PublicKey == peer && slices.Equal(u.Allowed, gw.Allowed)
				}
			case kernel.Flush:
				if !shrunk {
					t.Fatal("a flush ran before the peer dropped the address")
				}
				flushed = flushed || slices.Contains(op.Addrs, netip.MustParseAddr("fd00::99"))
			}
		}
	}
	if !shrunk || !flushed {
		t.Fatalf("dropping a fronted machine: shrunk %v, flushed %v; want both", shrunk, flushed)
	}
}

func TestAnActiveRelayThatLeavesTheSetGivesUpThePath(t *testing.T) {
	c, now := adopted(t)
	relays := map[model.RelayID]int{"r1": 1, "r2": 2, "r3": 3}
	update := func(rev uint64, ids ...model.RelayID) api.StateUpdate {
		var refs []api.RelayRef
		p := api.Peer{Interface: "if-b", Service: "svc-2", PublicKey: peer, Allowed: []netip.Prefix{pfx("fd00::6/128")}}
		for _, id := range ids {
			refs = append(refs, api.RelayRef{Relay: id, Probe: ap(fmt.Sprintf("192.0.2.%d:9", relays[id]))})
			p.Relays = append(p.Relays, api.RelayPath{Relay: id, Send: ap(fmt.Sprintf("192.0.2.%d:7000", relays[id]))})
		}
		return state(rev, refs, p)
	}
	settle := func(up ...model.RelayID) {
		for range 10 {
			now = now.Add(200 * time.Millisecond)
			c.Tick(now)
			drive(c, now, succeed, up...)
		}
	}
	if err := c.State(now, update(3, "r1", "r2")); err != nil {
		t.Fatal(err)
	}
	settle("r1", "r3")
	if got := c.Active()["net-1"]; got != "r1" {
		t.Fatalf("active relay %q, want r1, the one answering", got)
	}
	if err := c.State(now, update(4, "r2", "r3")); err != nil {
		t.Fatal(err)
	}
	settle("r1", "r3")
	if got := c.Active()["net-1"]; got != "r3" {
		t.Fatalf("active relay %q after r1 left the set, want r3", got)
	}
	if got, want := c.ns["sdn-a"].peers[peer].Endpoint, ap("192.0.2.3:7000"); got != want {
		t.Fatalf("peer endpoint %v, want r3's %v", got, want)
	}
}
