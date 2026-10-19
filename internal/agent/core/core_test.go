package core

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/kernel"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/prng"
	"github.com/danthegoodman1/wirenet/internal/regproto"
)

var (
	self = model.Key{7}
	peer = model.Key{9}
	pfx  = netip.MustParsePrefix
	ap   = netip.MustParseAddrPort
)

// adopted is a core that adopted one interface, if-a in wirenet-a, from its
// journal and the kernel.
func adopted(t *testing.T) (*Core, time.Time) {
	t.Helper()
	c, now := New(DefaultConfig("h1"), prng.New(1)), time.Unix(1000, 0)
	e := JournalEntry{Interface: "if-a", Name: "w", Network: "net-1", Service: "svc-1", Kind: api.Workload, Namespace: "wirenet-a", ListenPort: 40000, PublicKey: self}
	dev := kernel.Device{Name: c.cfg.Device, HasKey: true, PublicKey: self, ListenPort: 40000}
	c.Start(now, []JournalEntry{e}, kernel.Snapshot{Namespaces: []kernel.Namespace{{Name: "wirenet-a", Devices: []kernel.Device{dev}}}})
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
	u := state(3, nil)
	u.Networks[0].Interfaces[0].Egress = []api.Egress{{Proto: model.TCP, Ports: model.PortRange{Lo: 443, Hi: 443}}}
	if err := c.State(now, u); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	c.Observed(now, kernel.Namespace{Name: "wirenet-a"}, kernel.ErrNoNamespace)
	gone := func(RunBatch) error { return fmt.Errorf("op: %w", kernel.ErrNoNamespace) }
	var unlinked []uint16
	for range 4 {
		now = now.Add(10 * time.Second)
		for _, b := range drive(c, now, gone) {
			for _, op := range b.Ops {
				if op.Kind == kernel.SetEgress && op.Egress == nil {
					unlinked = append(unlinked, op.EgressIndex)
				}
			}
		}
	}
	// The host's filter for the namespace's egress link outlives the
	// namespace, so teardown removes it by index.
	if len(unlinked) == 0 || unlinked[0] != 40000 {
		t.Fatalf("teardown removed egress indexes %v, want 40000, the listen port", unlinked)
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

func TestAPeersRelayAnswersAndBelongsToTheSet(t *testing.T) {
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
	if got, want := c.ns["wirenet-a"].peers[peer].Endpoint, ap("192.0.2.1:7000"); got != want {
		t.Fatalf("peer endpoint %v, want r1's %v, the one relay of the set answering", got, want)
	}
	if err := c.State(now, update(4, "r2", "r3")); err != nil {
		t.Fatal(err)
	}
	settle("r1", "r3")
	if got, want := c.ns["wirenet-a"].peers[peer].Endpoint, ap("192.0.2.3:7000"); got != want {
		t.Fatalf("peer endpoint %v after r1 left the set, want r3's %v", got, want)
	}
}

// spread is a core holding n adopted interfaces, if-0 in wirenet-0 onward, each
// with one remote peer if-p<i> whose paths run through every relay given.
func spread(t *testing.T, n int, ids ...model.RelayID) (*Core, time.Time) {
	t.Helper()
	c, now, _ := adoptedMany(t, n)
	net := api.NetworkState{Network: "net-1", Name: "n", Revision: 3, Prefix6: pfx("fd00::/64"), MTU: 1380}
	for k, id := range ids {
		net.Relays = append(net.Relays, api.RelayRef{Relay: id, Probe: ap(fmt.Sprintf("192.0.2.%d:9", k+1))})
	}
	for i := range n {
		p := api.Peer{Interface: model.InterfaceID(fmt.Sprintf("if-p%d", i)), Service: "svc-2", PublicKey: model.Key{byte(100 + i)},
			Allowed: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 14: 1, 15: byte(i)}), 128)}}
		for k, id := range ids {
			p.Relays = append(p.Relays, api.RelayPath{Relay: id, Send: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(k + 1)}), uint16(7000+i))})
		}
		net.Interfaces = append(net.Interfaces, api.Interface{ID: model.InterfaceID(fmt.Sprintf("if-%d", i)), Service: "svc-1", Kind: api.Workload,
			PublicKey: model.Key{byte(20 + i)}, Addr6: netip.AddrFrom16([16]byte{0xfd, 15: byte(0x10 + i)}), ListenPort: uint16(40000 + i),
			State: api.Live, Peers: []api.Peer{p}})
	}
	// The control plane lists interfaces in ID order, which lookups rely on.
	slices.SortFunc(net.Interfaces, func(a, b api.Interface) int { return strings.Compare(string(a.ID), string(b.ID)) })
	if err := c.State(now, api.StateUpdate{Host: "h1", Generation: 3, Networks: []api.NetworkState{net},
		Present: []api.NetworkRef{{Network: "net-1", Revision: 3}}}); err != nil {
		t.Fatal(err)
	}
	return c, now
}

// relayOf names the relay each namespace's one peer sends through.
func relayOf(c *Core, n int) []model.RelayID {
	out := make([]model.RelayID, n)
	for i := range n {
		st := c.ns[fmt.Sprintf("wirenet-%d", i)]
		for _, p := range st.peers {
			out[i] = model.RelayID(fmt.Sprintf("r%d", p.Endpoint.Addr().As4()[3]))
		}
	}
	return out
}

// heaviest is the relay of highest weight for an edge among ids.
func heaviest(a, b model.InterfaceID, ids ...model.RelayID) model.RelayID {
	var best model.RelayID
	var w uint64
	for _, id := range ids {
		if x := model.RelayWeight(a, b, id); best == "" || x > w {
			best, w = id, x
		}
	}
	return best
}

func TestANetworksEdgesSpreadOverItsRelays(t *testing.T) {
	const n = 30
	c, now := spread(t, n, "r1", "r2", "r3")
	for range 4 {
		drive(c, now, succeed, "r1", "r2", "r3")
	}
	for i, r := range relayOf(c, n) {
		self, other := model.InterfaceID(fmt.Sprintf("if-%d", i)), model.InterfaceID(fmt.Sprintf("if-p%d", i))
		if want := heaviest(self, other, "r1", "r2", "r3"); r != want {
			t.Fatalf("edge %s-%s sends through %s, want %s, its heaviest relay", self, other, r, want)
		}
	}
	census := c.Census().RelayPeers
	for _, r := range []model.RelayID{"r1", "r2", "r3"} {
		if census[r] < n/6 {
			t.Fatalf("relays carry %v of %d edges; want each a fair share", census, n)
		}
	}
}

func TestARelaysLossMovesOnlyItsEdgesAndItsReturnBringsThemBack(t *testing.T) {
	const n = 30
	c, now := spread(t, n, "r1", "r2", "r3")
	settle := func(up ...model.RelayID) {
		for range 10 {
			now = now.Add(200 * time.Millisecond)
			c.Tick(now)
			drive(c, now, succeed, up...)
		}
	}
	settle("r1", "r2", "r3")
	before := relayOf(c, n)
	failovers := c.Stats.Failovers
	settle("r2", "r3")
	if c.Stats.Failovers != failovers+1 {
		t.Fatalf("counted %d failovers for one relay's loss", c.Stats.Failovers-failovers)
	}
	after := relayOf(c, n)
	moved := map[model.RelayID]int{}
	for i := range n {
		self, other := model.InterfaceID(fmt.Sprintf("if-%d", i)), model.InterfaceID(fmt.Sprintf("if-p%d", i))
		switch {
		case before[i] != "r1" && after[i] != before[i]:
			t.Fatalf("edge %d moved from %s to %s though r1 carried it not", i, before[i], after[i])
		case before[i] == "r1":
			if want := heaviest(self, other, "r2", "r3"); after[i] != want {
				t.Fatalf("edge %d moved from r1 to %s, want %s, its next relay", i, after[i], want)
			}
			moved[after[i]]++
		}
	}
	if moved["r2"] == 0 || moved["r3"] == 0 {
		t.Fatalf("r1's edges moved to %v; want them spread over both survivors", moved)
	}
	settle("r1", "r2", "r3")
	if back := relayOf(c, n); !slices.Equal(back, before) {
		t.Fatalf("after r1 returned, edges send through %v, want %v", back, before)
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
	if got := c.ns["wirenet-a"].peers[next].Allowed; !slices.Equal(got, addrs) {
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
	c.RegistrationAcked(now, i.port, relayAt, c.counter)
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
	if slotted(c, "wirenet-a") {
		t.Fatal("a backend new to the client joined its map before the relay acknowledged")
	}
	c.RegistrationAcked(now, 40000, relayAt, c.counter)
	drive(c, now, succeed)
	if !slotted(c, "wirenet-a") {
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
	if !slotted(c, "wirenet-a") || len(c.ns["wirenet-a"].awaiting) > 0 {
		t.Fatalf("after moving relays the map lost its backend: awaiting %v", c.ns["wirenet-a"].awaiting)
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

func TestAnAcknowledgedDirectionIsNotResentAndANewPeerResendsAlone(t *testing.T) {
	c, now := adopted(t)
	c.cfg.RegisterEvery = time.Hour
	other := backend("if-c", model.Key{12}, "fd00::7")
	other.Relays = []api.RelayPath{{Relay: "r1", Send: ap("192.0.2.1:7002")}}
	update := func(rev uint64, peers ...api.Peer) {
		t.Helper()
		if err := c.State(now, api.StateUpdate{Host: "h1", Generation: rev, Networks: []api.NetworkState{client(rev, "if-a", self, peers...)},
			Present: []api.NetworkRef{{Network: "net-1", Revision: rev}}}); err != nil {
			t.Fatal(err)
		}
	}
	// sends carries out actions until none remain, counting registrations
	// by the relay port they went to.
	sends := func(at time.Time) map[netip.AddrPort]int {
		out := map[netip.AddrPort]int{}
		for acts := c.Actions(at); len(acts) > 0; acts = c.Actions(at) {
			for _, a := range acts {
				switch a := a.(type) {
				case RunBatch:
					c.BatchDone(at, a.Namespace, a.ID, len(a.Ops), nil)
				case SendRegistration:
					out[a.To]++
				}
			}
		}
		return out
	}
	update(3, backend("if-b", peer, "fd00::6"))
	if n := sends(now)[relayAt]; n != 1 {
		t.Fatalf("registered %d times on install, want once", n)
	}
	c.RegistrationAcked(now, 40000, relayAt, c.counter)
	// A second peer arrives; only its direction is resent.
	update(4, backend("if-b", peer, "fd00::6"), other)
	total := map[netip.AddrPort]int{}
	for at := now; at.Before(now.Add(2 * time.Second)); at = at.Add(5 * time.Millisecond) {
		c.Tick(at)
		for to, n := range sends(at) {
			total[to] += n
		}
	}
	if total[relayAt] != 0 {
		t.Fatalf("the acknowledged direction was registered %d more times", total[relayAt])
	}
	if got := total[other.Relays[0].Send]; got != 1+c.cfg.RegisterRetries {
		t.Fatalf("the new direction was registered %d times, want %d", got, 1+c.cfg.RegisterRetries)
	}
}

// TestEveryServiceTheNamespaceDoesNotTranslateIsRejected gives a client
// db, then takes db away as a deny does, which moves it from the host's
// services to its unreached addresses: the namespace rejects db's address
// throughout, so a connection to the address the workload learned leaves
// no conntrack entry to outlast the deny.
func TestEveryServiceTheNamespaceDoesNotTranslateIsRejected(t *testing.T) {
	c, now := adopted(t)
	update := func(rev uint64, n api.NetworkState) {
		t.Helper()
		if err := c.State(now, api.StateUpdate{Host: "h1", Generation: rev, Networks: []api.NetworkState{n},
			Present: []api.NetworkRef{{Network: "net-1", Revision: rev}}}); err != nil {
			t.Fatal(err)
		}
		drive(c, now, succeed)
		c.RegistrationAcked(now, 40000, relayAt, c.counter)
		drive(c, now, succeed)
	}
	rejects := func() []netip.Addr { return c.ns["wirenet-a"].rules.Rules.Reject }
	db, other := netip.MustParseAddr("fd00::100"), netip.MustParseAddr("fd00::200")
	reaching := client(3, "if-a", self, backend("if-b", peer, "fd00::6"))
	reaching.Unreached = []netip.Addr{other}
	update(3, reaching)
	if !slotted(c, "wirenet-a") || !slices.Equal(rejects(), []netip.Addr{db, other}) {
		t.Fatalf("reaching db: slotted %v, rejecting %v", slotted(c, "wirenet-a"), rejects())
	}
	denied := client(4, "if-a", self)
	denied.Services, denied.Interfaces[0].Reach, denied.Unreached = nil, nil, []netip.Addr{db, other}
	update(4, denied)
	if rs := c.ns["wirenet-a"].rules; len(rs.Rules.Translate) != 0 || !slices.Equal(rejects(), []netip.Addr{db, other}) {
		t.Fatalf("denied db: translating %v, rejecting %v; want db's address and the other service's", rs.Rules.Translate, rejects())
	}
}

// pairOnOneHost is a core holding if-a in wirenet-a and if-b in wirenet-b,
// whose services reach each other, and a network state for them as the
// control plane compiles it: if-a, the lower ID, keeps the pair alive.
func pairOnOneHost(t *testing.T) (*Core, time.Time, api.StateUpdate) {
	t.Helper()
	c, now := New(DefaultConfig("h1"), prng.New(1)), time.Unix(1000, 0)
	keyB := model.Key{9}
	var journal []JournalEntry
	var snap kernel.Snapshot
	for _, e := range []JournalEntry{
		{Interface: "if-a", Name: "a", Network: "net-1", Service: "svc-1", Kind: api.Workload, Namespace: "wirenet-a", ListenPort: 40000, PublicKey: self},
		{Interface: "if-b", Name: "b", Network: "net-1", Service: "svc-2", Kind: api.Workload, Namespace: "wirenet-b", ListenPort: 40001, PublicKey: keyB},
	} {
		journal = append(journal, e)
		snap.Namespaces = append(snap.Namespaces, kernel.Namespace{Name: e.Namespace,
			Devices: []kernel.Device{{Name: c.cfg.Device, HasKey: true, PublicKey: e.PublicKey, ListenPort: e.ListenPort}}})
	}
	c.Start(now, journal, snap)
	a6, b6 := netip.MustParseAddr("fd00::5"), netip.MustParseAddr("fd00::6")
	svc1 := api.Service{ID: "svc-1", Name: "one", Addr6: netip.MustParseAddr("fd00::101"), Backends: []api.Backend{{Interface: "if-a", Addr6: a6}}}
	svc2 := api.Service{ID: "svc-2", Name: "two", Addr6: netip.MustParseAddr("fd00::102"), Backends: []api.Backend{{Interface: "if-b", Addr6: b6}}}
	tcp := model.PortRange{Lo: 80, Hi: 80}
	n := api.NetworkState{Network: "net-1", Name: "n", Revision: 3, Prefix6: pfx("fd00::/64"), MTU: 1380, Services: []api.Service{svc1, svc2},
		Interfaces: []api.Interface{
			{ID: "if-a", Service: "svc-1", Kind: api.Workload, PublicKey: self, Addr6: a6, ListenPort: 40000, State: api.Live,
				Peers:   []api.Peer{{Interface: "if-b", Service: "svc-2", PublicKey: keyB, Allowed: []netip.Prefix{pfx("fd00::6/128")}, Loopback: 40001, Keepalive: true}},
				Reach:   []api.Reach{{Service: "svc-2", Proto: model.TCP, Ports: tcp}},
				Inbound: []api.Inbound{{From: "svc-2", Proto: model.TCP, Ports: tcp}}},
			{ID: "if-b", Service: "svc-2", Kind: api.Workload, PublicKey: keyB, Addr6: b6, ListenPort: 40001, State: api.Live,
				Peers:   []api.Peer{{Interface: "if-a", Service: "svc-1", PublicKey: self, Allowed: []netip.Prefix{pfx("fd00::5/128")}, Loopback: 40000}},
				Reach:   []api.Reach{{Service: "svc-1", Proto: model.TCP, Ports: tcp}},
				Inbound: []api.Inbound{{From: "svc-1", Proto: model.TCP, Ports: tcp}}},
		}}
	return c, now, api.StateUpdate{Host: "h1", Generation: 3, Networks: []api.NetworkState{n}, Present: []api.NetworkRef{{Network: "net-1", Revision: 3}}}
}

// runPair carries out the core's batches and returns the session checks it
// asks for, unanswered.
func runPair(c *Core, now time.Time) []CheckSessions {
	var checks []CheckSessions
	for acts := c.Actions(now); len(acts) > 0; acts = c.Actions(now) {
		for _, a := range acts {
			switch a := a.(type) {
			case RunBatch:
				c.BatchDone(now, a.Namespace, a.ID, len(a.Ops), nil)
			case CheckSessions:
				checks = append(checks, a)
			}
		}
	}
	return checks
}

// TestAPeerWhoseNamespaceLostItsNameStopsTakingSlots forms a loopback pair,
// then has a scan find if-b's device in a namespace only a process holds,
// as when an operator deletes the name while the workload keeps it: the
// reap takes if-b's device, so if-a takes its slots for if-b away at once,
// and if-b detaches, deleting its namespace's name in case it still
// stands.
func TestAPeerWhoseNamespaceLostItsNameStopsTakingSlots(t *testing.T) {
	c, now, u := pairOnOneHost(t)
	if err := c.State(now, u); err != nil {
		t.Fatal(err)
	}
	runPair(c, now)
	if !slotted(c, "wirenet-a") {
		t.Fatal("a never slotted b")
	}
	c.Scanned(now, kernel.Snapshot{Namespaces: []kernel.Namespace{{Ref: "ns-1",
		Devices: []kernel.Device{{Name: c.cfg.Device, HasKey: true, PublicKey: model.Key{9}, ListenPort: 40001, Alias: kernel.Alias(c.cfg.AliasPrefix(), "if-b")}}}}}, nil)
	var deleted bool
	for acts := c.Actions(now); len(acts) > 0; acts = c.Actions(now) {
		for _, a := range acts {
			if b, ok := a.(RunBatch); ok {
				for _, op := range b.Ops {
					deleted = deleted || op.Kind == kernel.DeleteNamespace && op.Namespace == "wirenet-b"
				}
				c.BatchDone(now, b.Namespace, b.ID, len(b.Ops), nil)
			}
		}
	}
	if slotted(c, "wirenet-a") || !deleted {
		t.Fatalf("after the scan: a slotted %v, b's name deleted %v", slotted(c, "wirenet-a"), deleted)
	}
}

// TestTheSideWithoutKeepaliveSlotsAPeerOnceItHoldsASession forms a loopback
// pair whose ends each reach the other: if-a keeps the pair alive and gets
// its slot at once, while if-b's slot waits for its device to hold a
// session with if-a, asked of the kernel, and goes in when one shows.
func TestTheSideWithoutKeepaliveSlotsAPeerOnceItHoldsASession(t *testing.T) {
	c, now, u := pairOnOneHost(t)
	if err := c.State(now, u); err != nil {
		t.Fatal(err)
	}
	checks := runPair(c, now)
	if !slotted(c, "wirenet-a") || slotted(c, "wirenet-b") {
		t.Fatalf("slotted: a %v, b %v; want a alone before b's session", slotted(c, "wirenet-a"), slotted(c, "wirenet-b"))
	}
	if len(checks) != 1 || checks[0].Namespace != "wirenet-b" || !slices.Equal(checks[0].Keys, []model.Key{self}) {
		t.Fatalf("session checks %+v, want one in wirenet-b for if-a's key", checks)
	}
	c.SessionsSeen(now, "wirenet-b", nil, nil)
	if again := runPair(c, now); slotted(c, "wirenet-b") || len(again) != 1 {
		t.Fatalf("with no session yet: slotted %v, checks %+v", slotted(c, "wirenet-b"), again)
	}
	c.SessionsSeen(now, "wirenet-b", []model.Key{self}, nil)
	runPair(c, now)
	if !slotted(c, "wirenet-b") {
		t.Fatal("b's slot never went in once its session showed")
	}
}

// TestASessionWaitEndsAtAckWait never answers if-b's session checks, and
// checks its slot goes in once AckWait passes.
func TestASessionWaitEndsAtAckWait(t *testing.T) {
	c, now, u := pairOnOneHost(t)
	if err := c.State(now, u); err != nil {
		t.Fatal(err)
	}
	runPair(c, now)
	c.SessionsSeen(now, "wirenet-b", nil, nil)
	at := now.Add(c.cfg.AckWait)
	if wake := c.NextWake(now); wake.After(at) {
		t.Fatalf("next wake %v, after the wait ends at %v", wake, at)
	}
	c.Tick(at)
	runPair(c, at)
	if !slotted(c, "wirenet-b") || c.Stats.SessionTimeouts != 1 {
		t.Fatalf("after AckWait: slotted %v, %d session timeouts", slotted(c, "wirenet-b"), c.Stats.SessionTimeouts)
	}
}

// TestASessionWaitStartsOnceTheReverseIsHeld holds if-a's batches past
// AckWait, so if-a's device lacks if-b all that time: if-b's slot still
// waits for a session once if-a's batch lands, with a deadline counted
// from then.
func TestASessionWaitStartsOnceTheReverseIsHeld(t *testing.T) {
	c, now, u := pairOnOneHost(t)
	if err := c.State(now, u); err != nil {
		t.Fatal(err)
	}
	var held []RunBatch
	for acts := c.Actions(now); len(acts) > 0; acts = c.Actions(now) {
		for _, a := range acts {
			if b, ok := a.(RunBatch); ok {
				if b.Namespace == "wirenet-a" {
					held = append(held, b)
					continue
				}
				c.BatchDone(now, b.Namespace, b.ID, len(b.Ops), nil)
			}
		}
	}
	later := now.Add(2 * c.cfg.AckWait)
	c.Tick(later)
	for _, b := range held {
		c.BatchDone(later, b.Namespace, b.ID, len(b.Ops), nil)
	}
	checks := runPair(c, later)
	if slotted(c, "wirenet-b") {
		t.Fatal("b slotted a with no session, its wait spent before a's device held it")
	}
	if len(checks) != 1 || !checks[0].Until.Equal(later.Add(c.cfg.AckWait)) {
		t.Fatalf("session checks %+v, want one until %v", checks, later.Add(c.cfg.AckWait))
	}
}

// TestASessionCheckThatFailsEndsTheWait answers if-b's session check with
// an error: its slot goes in at once and no further check runs.
func TestASessionCheckThatFailsEndsTheWait(t *testing.T) {
	c, now, u := pairOnOneHost(t)
	if err := c.State(now, u); err != nil {
		t.Fatal(err)
	}
	runPair(c, now)
	c.SessionsSeen(now, "wirenet-b", nil, errors.New("read failed"))
	if checks := runPair(c, now); !slotted(c, "wirenet-b") || len(checks) != 0 {
		t.Fatalf("after a failed check: slotted %v, checks %+v", slotted(c, "wirenet-b"), checks)
	}
}

// sent carries out the core's actions until none remain, batches
// succeeding, and returns the registrations they sent.
func sent(c *Core, at time.Time) []SendRegistration {
	var out []SendRegistration
	for acts := c.Actions(at); len(acts) > 0; acts = c.Actions(at) {
		for _, a := range acts {
			switch a := a.(type) {
			case RunBatch:
				c.BatchDone(at, a.Namespace, a.ID, len(a.Ops), nil)
			case SendRegistration:
				out = append(out, a)
			}
		}
	}
	return out
}

// read verifies a registration under the relay's key for secret, and
// returns its counter and whether it withdraws.
func read(t *testing.T, secret model.Secret, relay model.RelayID, r SendRegistration) (uint64, bool) {
	t.Helper()
	counter, withdrawal, ok := regproto.Verify(regproto.RelayKey(secret, relay), r.To, r.Payload[:])
	if !ok {
		t.Fatalf("a registration to %v does not verify under %s's key", r.To, relay)
	}
	return counter, withdrawal
}

// withdrawable is db through two relays, and a driver that publishes
// if-a's peers.
func withdrawable(t *testing.T) (*Core, time.Time, api.Peer, func(rev uint64, peers ...api.Peer)) {
	t.Helper()
	c, now := adopted(t)
	c.cfg.RegisterEvery = time.Hour
	b := backend("if-b", peer, "fd00::6")
	b.Registration = model.Secret{1}
	b.Relays = append(b.Relays, api.RelayPath{Relay: "r2", Send: ap("192.0.2.2:7000")})
	update := func(rev uint64, peers ...api.Peer) {
		t.Helper()
		if err := c.State(now, api.StateUpdate{Host: "h1", Generation: rev, Networks: []api.NetworkState{client(rev, "if-a", self, peers...)},
			Present: []api.NetworkRef{{Network: "net-1", Revision: rev}}}); err != nil {
			t.Fatal(err)
		}
	}
	return c, now, b, update
}

// TestARemovedRelayPeerIsWithdrawnUntilAcknowledged installs db through
// two relays, then takes it away as a deny does. Once the batch removes
// the peer, each relay's direction is withdrawn above every claim sent
// before, and each withdrawal goes again unchanged until its relay
// acknowledges that counter: an acknowledgment of the earlier claim, which
// a relay sends after the withdrawal leaves if the claim arrives late,
// ends nothing.
func TestARemovedRelayPeerIsWithdrawnUntilAcknowledged(t *testing.T) {
	c, now, b, update := withdrawable(t)
	update(3, b)
	if got := sent(c, now); len(got) != 2 {
		t.Fatalf("installing db sent %+v, want a claim to each relay", got)
	}
	claimed := c.counter
	for _, rp := range b.Relays {
		c.RegistrationAcked(now, 40000, rp.Send, claimed)
	}
	update(4)
	got := sent(c, now)
	if len(got) != 2 {
		t.Fatalf("removing db sent %+v, want a withdrawal to each relay", got)
	}
	payload := map[netip.AddrPort][regproto.Size]byte{}
	var withdrawn uint64
	for i, r := range got {
		counter, withdrawal := read(t, b.Registration, b.Relays[i].Relay, r)
		if !withdrawal || counter <= claimed || r.To != b.Relays[i].Send || r.From != 40000 {
			t.Fatalf("removing db sent %+v at %d, withdrawal %v; want a withdrawal above %d from 40000", r, counter, withdrawal, claimed)
		}
		payload[r.To], withdrawn = r.Payload, counter
	}
	second := b.Relays[1].Send
	if c.RegistrationAcked(now, 40000, relayAt, claimed) {
		t.Fatal("the claim's late acknowledgment changed something")
	}
	if !c.RegistrationAcked(now, 40000, second, withdrawn) {
		t.Fatal("the withdrawal's acknowledgment changed nothing")
	}
	resent := map[netip.AddrPort]int{}
	for at := now; at.Before(now.Add(3 * time.Second)); at = at.Add(5 * time.Millisecond) {
		c.Tick(at)
		for _, r := range sent(c, at) {
			if r.Payload != payload[r.To] {
				t.Fatalf("a resend to %v changed: %x, want %x", r.To, r.Payload, payload[r.To])
			}
			resent[r.To]++
		}
	}
	if resent[relayAt] != c.cfg.RegisterRetries || resent[second] != 0 {
		t.Fatalf("resent %v, want %d to the relay that never acknowledged and none to the one that did", resent, c.cfg.RegisterRetries)
	}
}

// TestAPeerBackSoonAfterItsWithdrawalWaitsForItsOwnAcknowledgment removes
// db and installs it again before its relay acknowledges the withdrawal.
// The new claim outranks the withdrawal, which goes no more, and the
// withdrawal's late acknowledgment releases neither the slot nor the
// claim's resends: the relay may hold the withdrawal alone, and only an
// acknowledgment of the claim says otherwise.
func TestAPeerBackSoonAfterItsWithdrawalWaitsForItsOwnAcknowledgment(t *testing.T) {
	c, now, b, update := withdrawable(t)
	b.Relays = b.Relays[:1]
	update(3, b)
	sent(c, now)
	c.RegistrationAcked(now, 40000, relayAt, c.counter)
	drive(c, now, succeed)
	if !slotted(c, "wirenet-a") {
		t.Fatal("db never took its slot")
	}
	update(4)
	got := sent(c, now)
	if len(got) != 1 {
		t.Fatalf("removing db sent %+v, want one withdrawal", got)
	}
	withdrawn, _ := read(t, b.Registration, "r1", got[0])
	update(5, b)
	got = sent(c, now)
	if len(got) != 1 {
		t.Fatalf("restoring db sent %+v, want one claim", got)
	}
	if counter, withdrawal := read(t, b.Registration, "r1", got[0]); withdrawal || counter <= withdrawn {
		t.Fatalf("restoring db sent a registration at %d, withdrawal %v; want a claim above %d", counter, withdrawal, withdrawn)
	}
	c.RegistrationAcked(now, 40000, relayAt, withdrawn)
	drive(c, now, succeed)
	if slotted(c, "wirenet-a") {
		t.Fatal("the withdrawal's acknowledgment gave db its slot back")
	}
	claims := 0
	for at := now; at.Before(now.Add(500 * time.Millisecond)); at = at.Add(5 * time.Millisecond) {
		c.Tick(at)
		for _, r := range sent(c, at) {
			if _, withdrawal := read(t, b.Registration, "r1", r); withdrawal {
				t.Fatal("the withdrawal went again after the claim")
			}
			claims++
		}
	}
	if claims == 0 {
		t.Fatal("the withdrawal's acknowledgment ended the claim's resends")
	}
	c.RegistrationAcked(now, 40000, relayAt, c.counter)
	drive(c, now, succeed)
	if !slotted(c, "wirenet-a") {
		t.Fatal("the claim's acknowledgment never gave db its slot")
	}
}

// adoptedMany is a core that adopted n interfaces, if-0 in wirenet-0 onward,
// each a client of db through if-b's relay path.
func adoptedMany(t *testing.T, n int) (*Core, time.Time, func(rev uint64, backends ...api.Peer)) {
	t.Helper()
	c, now := New(DefaultConfig("h1"), prng.New(1)), time.Unix(1000, 0)
	var journal []JournalEntry
	var snap kernel.Snapshot
	for i := range n {
		id, ns, key, port := model.InterfaceID(fmt.Sprintf("if-%d", i)), fmt.Sprintf("wirenet-%d", i), model.Key{byte(20 + i)}, uint16(40000+i)
		journal = append(journal, JournalEntry{Interface: id, Name: fmt.Sprintf("w%d", i), Network: "net-1", Service: "svc-1",
			Kind: api.Workload, Namespace: ns, ListenPort: port, PublicKey: key})
		snap.Namespaces = append(snap.Namespaces, kernel.Namespace{Name: ns,
			Devices: []kernel.Device{{Name: c.cfg.Device, HasKey: true, PublicKey: key, ListenPort: port}}})
	}
	c.Start(now, journal, snap)
	update := func(rev uint64, backends ...api.Peer) {
		t.Helper()
		net := client(rev, "if-0", journal[0].PublicKey, backends...)
		x := net.Interfaces[0]
		net.Interfaces = nil
		for i, e := range journal {
			x.ID, x.PublicKey, x.ListenPort = e.Interface, e.PublicKey, e.ListenPort
			x.Addr6 = netip.AddrFrom16([16]byte{0xfd, 15: byte(0x10 + i)})
			net.Interfaces = append(net.Interfaces, x)
		}
		if err := c.State(now, api.StateUpdate{Host: "h1", Generation: rev, Networks: []api.NetworkState{net},
			Present: []api.NetworkRef{{Network: "net-1", Revision: rev}}}); err != nil {
			t.Fatal(err)
		}
	}
	return c, now, update
}

func TestABatchReplansOnlyTheNamespacesItCanRelease(t *testing.T) {
	const n = 8
	c, now, update := adoptedMany(t, n)
	update(3, backend("if-b", peer, "fd00::6"))
	for range 4 {
		drive(c, now, succeed)
	}
	for i := range n {
		if ns := fmt.Sprintf("wirenet-%d", i); len(c.ns[ns].awaiting) == 0 {
			t.Fatalf("%s holds its slot before the relay acknowledged", ns)
		}
	}
	idle := c.Stats.Idle
	c.RegistrationAcked(now, 40000, relayAt, c.counter)
	for range 4 {
		drive(c, now, succeed)
	}
	if !slotted(c, "wirenet-0") {
		t.Fatal("the acknowledged namespace never took its slot")
	}
	// The released namespace plans once after the ack and once after its
	// batch; the rest, still waiting on their own acks, plan nothing.
	if planned := c.Stats.Idle - idle; planned != 1 {
		t.Fatalf("%d idle plans after one namespace's ack, want 1", planned)
	}
}

// TestABackendHandsOverOnceItsRelayHoldsItsEdges attaches a backend whose
// one peer is a client no slot of its own names. Its answer waits for the
// relay's acknowledgment all the same: an orchestrator that removes the
// old backend once the new one answers must find every client able to
// reach it.
func TestABackendHandsOverOnceItsRelayHoldsItsEdges(t *testing.T) {
	c, now := New(DefaultConfig("h1"), prng.New(1)), time.Unix(1000, 0)
	c.Start(now, nil, kernel.Snapshot{})
	c.Attach(now, 1, api.LocalAttach{Name: "db", Network: "n", Service: "db"})
	var port uint16
	run := func(now time.Time) []Reply {
		var replies []Reply
		for range 8 {
			for _, a := range c.Actions(now) {
				switch a := a.(type) {
				case RunBatch:
					c.BatchDone(now, a.Namespace, a.ID, len(a.Ops), nil)
				case CallAttach:
					port = a.Request.ListenPort
					n := client(3, a.Request.Interface, a.Request.PublicKey, backend("if-web", peer, "fd00::6"))
					n.Interfaces[0].Reach = nil
					c.AttachDone(now, a.Request.Interface, &api.AttachResponse{Interface: a.Request.Interface, State: n}, nil)
				case Reply:
					replies = append(replies, a)
				}
			}
		}
		return replies
	}
	if replies := run(now); len(replies) > 0 {
		t.Fatalf("answered %+v before the relay acknowledged", replies)
	}
	now = now.Add(10 * time.Millisecond)
	c.RegistrationAcked(now, port, relayAt, c.counter)
	if replies := run(now); len(replies) != 1 || replies[0].Err != nil {
		t.Fatalf("after the ack: replies %+v, want one answer", replies)
	}
}

func TestOnlyAnAwaitedAcknowledgmentChangesAnything(t *testing.T) {
	c, now := adopted(t)
	if err := c.State(now, state(3, nil, backend("if-b", peer, "fd00::6"))); err != nil {
		t.Fatal(err)
	}
	if err := c.State(now, api.StateUpdate{Host: "h1", Generation: 4, Networks: []api.NetworkState{client(4, "if-a", self, backend("if-b", peer, "fd00::6"))},
		Present: []api.NetworkRef{{Network: "net-1", Revision: 4}}}); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	if c.RegistrationAcked(now, 40001, relayAt, c.counter) {
		t.Fatal("an acknowledgment for another port changed something")
	}
	if !c.RegistrationAcked(now, 40000, relayAt, c.counter) {
		t.Fatal("the awaited acknowledgment changed nothing")
	}
	if c.RegistrationAcked(now, 40000, relayAt, c.counter) {
		t.Fatal("a repeated acknowledgment changed something")
	}
}

func TestANetworkThatLeavesWhileAPeerWaitsLeavesNoWakeBehind(t *testing.T) {
	c, now := adopted(t)
	if err := c.State(now, api.StateUpdate{Host: "h1", Generation: 3, Networks: []api.NetworkState{client(3, "if-a", self, backend("if-b", peer, "fd00::6"))},
		Present: []api.NetworkRef{{Network: "net-1", Revision: 3}}}); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	if c.ns["wirenet-a"].ackBy.IsZero() {
		t.Fatal("the new peer waits on no acknowledgment")
	}
	if err := c.State(now, api.StateUpdate{Host: "h1", Generation: 4}); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	now = now.Add(2 * c.cfg.AckWait)
	for range 4 {
		c.Tick(now)
		drive(c, now, succeed)
	}
	if next := c.NextWake(now); !next.After(now) {
		t.Fatalf("next wake %v, at or before now %v: the loop would spin", next, now)
	}
}

func TestAResendScheduleEndsWithItsNamespace(t *testing.T) {
	c, now := adopted(t)
	if err := c.State(now, api.StateUpdate{Host: "h1", Generation: 3, Networks: []api.NetworkState{client(3, "if-a", self, backend("if-b", peer, "fd00::6"))},
		Present: []api.NetworkRef{{Network: "net-1", Revision: 3}}}); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	if len(c.resendAck) == 0 {
		t.Fatal("no resend scheduled for the new direction")
	}
	c.Detach(now, 2, "if-a")
	for range 8 {
		for _, a := range c.Actions(now) {
			switch a := a.(type) {
			case RunBatch:
				c.BatchDone(now, a.Namespace, a.ID, len(a.Ops), nil)
			case CallRelease:
				c.ReleaseDone(now, a.Interfaces, nil)
			}
		}
	}
	if _, ok := c.ns["wirenet-a"]; ok {
		t.Fatal("the detached namespace is still tracked")
	}
	for at := now; at.Before(now.Add(2 * time.Second)); at = at.Add(10 * time.Millisecond) {
		c.Tick(at)
		c.Actions(at)
	}
	if len(c.resends) > 0 || len(c.resendAck) > 0 {
		t.Fatalf("after the namespace went: resends %d, resendAck %d", len(c.resends), len(c.resendAck))
	}
}

// TestADetachTellsTheControlPlaneWhileItsDeviceIsDeleted checks that a
// detach releases its interface before teardown completes, retries a failed
// release meanwhile, and still answers its caller and frees its port only
// once the kernel state is gone.
func TestADetachTellsTheControlPlaneWhileItsDeviceIsDeleted(t *testing.T) {
	c, now := adopted(t)
	if err := c.State(now, state(3, nil)); err != nil {
		t.Fatal(err)
	}
	drive(c, now, succeed)
	c.Detach(now, 2, "if-a")
	var held *RunBatch
	releases := 0
	collect := func(now time.Time) (replied bool) {
		for _, a := range c.Actions(now) {
			switch a := a.(type) {
			case RunBatch:
				held = &a
			case CallRelease:
				releases++
			case Reply:
				replied = true
			}
		}
		return replied
	}
	if collect(now) {
		t.Fatal("the detach answered before its teardown ran")
	}
	if held == nil || releases != 1 {
		t.Fatalf("after the detach: teardown batch %v, releases %d; want both at once", held != nil, releases)
	}
	c.ReleaseDone(now, []model.InterfaceID{"if-a"}, fmt.Errorf("control plane unreachable"))
	now = now.Add(releaseRetry)
	c.Tick(now)
	collect(now)
	if releases != 2 {
		t.Fatalf("a failed release was sent %d times while teardown ran, want 2", releases)
	}
	c.ReleaseDone(now, []model.InterfaceID{"if-a"}, nil)
	if _, ok := c.ifaces["if-a"]; !ok {
		t.Fatal("the released interface was forgotten, and its port freed, before its device was deleted")
	}
	c.BatchDone(now, held.Namespace, held.ID, len(held.Ops), nil)
	replied := false
	for range 4 {
		replied = collect(now) || replied
	}
	if !replied || releases != 2 {
		t.Fatalf("after teardown: replied %v, releases %d; want a reply and no further release", replied, releases)
	}
	if _, ok := c.ifaces["if-a"]; ok {
		t.Fatal("the interface outlived its teardown and its release")
	}
}
