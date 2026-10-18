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

func TestAPeerWaitsForTheHolderOfItsAddress(t *testing.T) {
	c, now := adopted(t)
	addrs := []netip.Prefix{pfx("fd00::6/128")}
	holder := api.Peer{Interface: "if-b", Service: "svc-2", PublicKey: peer, Allowed: addrs}
	if err := c.State(now, state(3, nil, holder)); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	// The holder ended and its address went to a new interface while this
	// agent lagged, so it learns both at once.
	next := model.Key{11}
	claimant := api.Peer{Interface: "if-c", Service: "svc-2", PublicKey: next, Allowed: addrs}
	if err := c.State(now, state(4, nil, claimant)); err != nil {
		t.Fatal(err)
	}
	var removed bool
	for _, b := range drive(c, now, succeed) {
		for _, op := range b.Ops {
			for _, u := range op.Peers {
				if u.PublicKey == next {
					t.Fatalf("the claimant went in while the holder still held %v", addrs)
				}
				removed = removed || u.PublicKey == peer && u.Remove
			}
		}
	}
	if !removed || c.Stats.Conflicts == 0 {
		t.Fatalf("holder removed %v, conflicts %d; want the holder gone and the claimant deferred", removed, c.Stats.Conflicts)
	}
	drive(c, now, succeed)
	if got := c.ns["sdn-a"].peers[next].Allowed; !slices.Equal(got, addrs) {
		t.Fatalf("after the holder left the claimant holds %v, want %v", got, addrs)
	}
}

// db is a service whose backends sit behind relay peers; a client reaches
// it on tcp/5432.
var (
	dbService = model.ServiceID("svc-db")
	relayAt   = ap("192.0.2.1:7000")
	relayRef  = api.RelayRef{Relay: "r1", Probe: ap("192.0.2.1:9")}
)

func backend(id model.InterfaceID, key model.Key, addr string) api.Peer {
	return api.Peer{Interface: id, Service: dbService, PublicKey: key,
		Allowed: []netip.Prefix{pfx(addr + "/128")}, Relays: []api.RelayPath{{Relay: "r1", Send: relayAt}}}
}

// client is a network where interface id, keyed pub, reaches db through
// the backends given.
func client(rev uint64, id model.InterfaceID, pub model.Key, backends ...api.Peer) api.NetworkState {
	svc := api.Service{ID: dbService, Name: "db", Addr6: netip.MustParseAddr("fd00::100")}
	for _, b := range backends {
		svc.Backends = append(svc.Backends, api.Backend{Interface: b.Interface, Addr6: b.Allowed[0].Addr()})
	}
	return api.NetworkState{Network: "net-1", Name: "n", Revision: rev, Prefix6: pfx("fd00::/64"), MTU: 1380,
		Relays: []api.RelayRef{relayRef}, Services: []api.Service{svc},
		Interfaces: []api.Interface{{ID: id, Service: "svc-1", Kind: api.Workload, PublicKey: pub, Addr6: netip.MustParseAddr("fd00::5"),
			ListenPort: 40000, State: api.Live, Peers: backends,
			Reach: []api.Reach{{Service: dbService, Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}}}}}
}

// slotted reports whether a namespace's rules give db any backend.
func slotted(c *Core, ns string) bool {
	st := c.ns[ns]
	return st.rules != nil && len(st.rules.Maps) > 0
}

// attaching runs an attach to the point its namespace is configured, and
// returns the interface and a driver that reports the replies it carries.
func attaching(t *testing.T, c *Core, now time.Time, backends ...api.Peer) (*iface, func(time.Time) []Reply) {
	t.Helper()
	run := func(now time.Time) []Reply {
		var replies []Reply
		for range 8 {
			acts := c.Actions(now)
			if len(acts) == 0 {
				break
			}
			for _, a := range acts {
				switch a := a.(type) {
				case RunBatch:
					c.BatchDone(now, a.Namespace, a.ID, len(a.Ops), nil)
				case CallAttach:
					n := client(3, a.Request.Interface, a.Request.PublicKey, backends...)
					c.AttachDone(now, a.Request.Interface, &api.AttachResponse{Interface: a.Request.Interface, State: n}, nil)
				case Reply:
					replies = append(replies, a)
				}
			}
		}
		return replies
	}
	c.Attach(now, 1, api.LocalAttach{Name: "web", Network: "n", Service: "web"})
	if r := run(now); len(r) > 0 {
		t.Fatalf("answered %+v before the relay acknowledged", r)
	}
	for _, i := range c.ifaces {
		return i, run
	}
	t.Fatal("no interface")
	return nil, nil
}

func TestAnAttachIsHandedOverOnceItsRelayAcknowledges(t *testing.T) {
	c, now := New(DefaultConfig("h1"), prng.New(1)), time.Unix(1000, 0)
	c.Start(now, nil, kernel.Snapshot{})
	i, run := attaching(t, c, now, backend("if-b", peer, "fd00::6"))
	if i.phase != configuring || slotted(c, i.ns) {
		t.Fatalf("before the ack: phase %s, slotted %v; want configuring with no slot", i.phase, slotted(c, i.ns))
	}
	if _, installed := c.ns[i.ns].peers[peer]; !installed {
		t.Fatal("the peer waits to be installed; only its slots should")
	}
	now = now.Add(10 * time.Millisecond)
	c.RegistrationAcked(now, i.port, relayAt)
	replies := run(now)
	if len(replies) != 1 || replies[0].Err != nil || !slotted(c, i.ns) {
		t.Fatalf("after the ack: replies %+v, slotted %v; want one answer and a slot", replies, slotted(c, i.ns))
	}
}

func TestAnAttachIsHandedOverWhenNoAckComesInTime(t *testing.T) {
	c, now := New(DefaultConfig("h1"), prng.New(1)), time.Unix(1000, 0)
	c.Start(now, nil, kernel.Snapshot{})
	i, run := attaching(t, c, now, backend("if-b", peer, "fd00::6"))
	by := c.NextWake(now)
	if want := now.Add(c.cfg.AckWait); by.After(want) {
		t.Fatalf("next wake %v, after the handover deadline %v", by, want)
	}
	now = now.Add(c.cfg.AckWait)
	c.Tick(now)
	if replies := run(now); len(replies) != 1 || !slotted(c, i.ns) {
		t.Fatalf("after the wait: replies %+v, slotted %v; want one answer and a slot", replies, slotted(c, i.ns))
	}
}

func TestANewRelayBackendJoinsAClientsMapOnceAcknowledged(t *testing.T) {
	c, now := adopted(t)
	if err := c.State(now, api.StateUpdate{Host: "h1", Generation: 3, Networks: []api.NetworkState{client(3, "if-a", self)},
		Present: []api.NetworkRef{{Network: "net-1", Revision: 3}}}); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	b := backend("if-b", peer, "fd00::6")
	if err := c.State(now, api.StateUpdate{Host: "h1", Generation: 4, Networks: []api.NetworkState{client(4, "if-a", self, b)},
		Present: []api.NetworkRef{{Network: "net-1", Revision: 4}}}); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	if slotted(c, "sdn-a") {
		t.Fatal("a backend new to the client joined its map before the relay acknowledged")
	}
	c.RegistrationAcked(now, 40000, relayAt)
	drive(c, now, succeed)
	if !slotted(c, "sdn-a") {
		t.Fatal("the acknowledged backend never joined the map")
	}
	// A failover moves an established backend's path, and holds back no
	// slot while it does.
	other := b
	other.Relays = []api.RelayPath{{Relay: "r2", Send: ap("192.0.2.2:7000")}}
	n := client(5, "if-a", self, other)
	n.Relays = []api.RelayRef{{Relay: "r2", Probe: ap("192.0.2.2:9")}}
	if err := c.State(now, api.StateUpdate{Host: "h1", Generation: 5, Networks: []api.NetworkState{n},
		Present: []api.NetworkRef{{Network: "net-1", Revision: 5}}}); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	if !slotted(c, "sdn-a") || len(c.ns["sdn-a"].awaiting) > 0 {
		t.Fatalf("after moving relays the map lost its backend: awaiting %v", c.ns["sdn-a"].awaiting)
	}
}

func TestAFreshDirectionIsRegisteredAgainOnASchedule(t *testing.T) {
	c, now := adopted(t)
	c.cfg.RegisterEvery = time.Hour
	if err := c.State(now, api.StateUpdate{Host: "h1", Generation: 3, Networks: []api.NetworkState{client(3, "if-a", self, backend("if-b", peer, "fd00::6"))},
		Present: []api.NetworkRef{{Network: "net-1", Revision: 3}}}); err != nil {
		t.Fatal(err)
	}
	// sent carries out the core's actions until none remain, counting the
	// registrations sent toward the relay.
	sent := func(now time.Time) int {
		n := 0
		for acts := c.Actions(now); len(acts) > 0; acts = c.Actions(now) {
			for _, a := range acts {
				switch a := a.(type) {
				case RunBatch:
					c.BatchDone(now, a.Namespace, a.ID, len(a.Ops), nil)
				case SendRegistration:
					if a.To == relayAt {
						n++
					}
				}
			}
		}
		return n
	}
	var times []time.Duration
	for at := now; at.Before(now.Add(2 * time.Second)); at = at.Add(5 * time.Millisecond) {
		c.Tick(at)
		if sent(at) > 0 {
			times = append(times, at.Sub(now))
		}
	}
	// Once as the batch installs the peer, then RegisterRetries more, the
	// gaps tripling from RegisterRetry.
	if len(times) != 1+c.cfg.RegisterRetries {
		t.Fatalf("registered at %v, want %d sends", times, 1+c.cfg.RegisterRetries)
	}
	if gap := times[1] - times[0]; gap < c.cfg.RegisterRetry || gap > c.cfg.RegisterRetry+10*time.Millisecond {
		t.Fatalf("the first resend came %v after the first send, want about %v", gap, c.cfg.RegisterRetry)
	}
}
