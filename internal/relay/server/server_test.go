package server

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/regproto"
	relaycore "github.com/danthegoodman1/wirenet/internal/relay/core"
)

// fakeCP serves one port table and parks every later poll.
type fakeCP struct {
	mu sync.Mutex
	st api.RelayState
}

func (f *fakeCP) RelayState(ctx context.Context, since uint64, wait time.Duration) (api.RelayState, error) {
	f.mu.Lock()
	st := f.st
	f.mu.Unlock()
	if st.Generation > since {
		return st, nil
	}
	select {
	case <-ctx.Done():
		return st, ctx.Err()
	case <-time.After(100 * time.Millisecond):
		return st, nil
	}
}

func freePort(t *testing.T) uint16 {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

type edge struct {
	ab, ba     netip.AddrPort
	keyA, keyB model.Secret
	st         api.RelayState
}

func newEdge(t *testing.T) edge {
	lo := netip.MustParseAddr("127.0.0.1")
	e := edge{
		ab: netip.AddrPortFrom(lo, freePort(t)), ba: netip.AddrPortFrom(lo, freePort(t)),
		keyA: model.Secret{1}, keyB: model.Secret{2},
	}
	e.st = api.RelayState{Relay: "r", Generation: 5, Ports: []api.RelayPort{
		{Local: e.ab, Peer: e.ba.Port(), Advertised: e.ab, Key: e.keyA},
		{Local: e.ba, Peer: e.ab.Port(), Advertised: e.ba, Key: e.keyB},
	}}
	return e
}

func start(t *testing.T, dir string, cp *fakeCP) (*Server, context.CancelFunc, chan error) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.SnapshotEvery = 50 * time.Millisecond
	cfg.SocketBuffer = 0
	srv, err := New(cfg, cp, dir, NewMetrics(prometheus.NewRegistry(), 16), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	<-srv.Ready()
	return srv, cancel, done
}

func udp(t *testing.T) *net.UDPConn {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func send(t *testing.T, c *net.UDPConn, to netip.AddrPort, b []byte) {
	if _, err := c.WriteToUDPAddrPort(b, to); err != nil {
		t.Fatal(err)
	}
}

// recv returns what arrives within d, or nil, passing over the
// acknowledgments committed registrations earn.
func recv(c *net.UDPConn, d time.Duration) ([]byte, netip.AddrPort) {
	for {
		b, from := recvAny(c, d)
		if _, ack := regproto.AckCounter(b); !ack {
			return b, from
		}
	}
}

// recvAny returns the next datagram within d, or nil.
func recvAny(c *net.UDPConn, d time.Duration) ([]byte, netip.AddrPort) {
	c.SetReadDeadline(time.Now().Add(d))
	b := make([]byte, 65536)
	n, from, err := c.ReadFromUDPAddrPort(b)
	if err != nil {
		return nil, netip.AddrPort{}
	}
	return b[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
}

func data(s string) []byte { return append([]byte{4, 0, 0, 0}, s...) }

// drain reads until nothing arrives for a while.
func drain(c *net.UDPConn) {
	for {
		if got, _ := recv(c, 200*time.Millisecond); got == nil {
			return
		}
	}
}

// spoofed reports whether an attacker's datagram reaches c within the
// time a waiting packet could take.
func spoofed(c *net.UDPConn) bool {
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got, _ := recv(c, 200*time.Millisecond); string(got) == string(data("spoof")) {
			return true
		}
	}
	return false
}

// register sends registrations until the relay forwards a probe datagram
// from the other side, which shows both directions committed.
func waitForward(t *testing.T, from, to *net.UDPConn, port netip.AddrPort, want netip.AddrPort) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		send(t, from, port, data("ping"))
		if b, src := recv(to, 100*time.Millisecond); string(b) == string(data("ping")) {
			if src != want {
				t.Fatalf("forwarded from %v, want %v", src, want)
			}
			return
		}
	}
	t.Fatal("nothing forwarded")
}

func TestARelayForwardsOnlyBetweenRegisteredEndpointsAndRemembersThem(t *testing.T) {
	e := newEdge(t)
	cp := &fakeCP{st: e.st}
	dir := t.TempDir()
	srv, cancel, done := start(t, dir, cp)
	waitBound(t, srv, e.ab, e.ba)
	a, b, attacker := udp(t), udp(t), udp(t)

	regA := regproto.Encode(e.keyA, e.ab, 100)
	regB := regproto.Encode(e.keyB, e.ba, 200)
	// Before either registers, data waits: a direction's first packets
	// race its registrations.
	send(t, a, e.ab, data("early"))
	if got, _ := recv(b, 200*time.Millisecond); got != nil {
		t.Fatal("forwarded before registration")
	}
	send(t, a, e.ab, regA[:])
	send(t, b, e.ba, regB[:])
	// Once both register, the waiting packet goes on.
	if got, from := recv(b, 2*time.Second); string(got) != string(data("early")) || from != e.ba {
		t.Fatalf("the waiting packet: %q from %v", got, from)
	}
	// A sends to its port; B receives it from the peer port, where B sends.
	waitForward(t, a, b, e.ab, e.ba)
	waitForward(t, b, a, e.ba, e.ab)
	drain(b)

	// An unregistered sender on A's port reaches nobody, and a replay of
	// A's registration from the attacker moves nothing.
	send(t, attacker, e.ab, data("spoof"))
	send(t, attacker, e.ab, regA[:])
	time.Sleep(100 * time.Millisecond)
	send(t, attacker, e.ab, data("spoof"))
	if spoofed(b) {
		t.Fatal("forwarded an attacker's packet")
	}
	// A registration under the other direction's key fails too.
	wrong := regproto.Encode(e.keyB, e.ab, 300)
	send(t, attacker, e.ab, wrong[:])
	time.Sleep(100 * time.Millisecond)
	waitForward(t, a, b, e.ab, e.ba)
	if spoofed(b) {
		t.Fatal("a registration under the wrong key let an attacker's packet through")
	}

	// Restart from disk: both directions still forward without registering
	// again.
	cancel()
	<-done
	time.Sleep(50 * time.Millisecond)
	_, cancel, done = start(t, dir, cp)
	defer func() { cancel(); <-done }()
	waitForward(t, a, b, e.ab, e.ba)
	drain(b)
	// The persisted counter still rejects the old registration's replay.
	send(t, attacker, e.ab, regA[:])
	time.Sleep(100 * time.Millisecond)
	send(t, attacker, e.ab, data("spoof"))
	if spoofed(b) {
		t.Fatal("a replay moved the endpoint after a restart")
	}
}

// TestARegistrationTheLogFailsToHoldMovesNoEndpoint breaks the registration
// log before a registration reaches the committer: the relay stops rather
// than commit an endpoint a crash would forget.
func TestARegistrationTheLogFailsToHoldMovesNoEndpoint(t *testing.T) {
	e := newEdge(t)
	srv, err := New(DefaultConfig(), &fakeCP{st: e.st}, t.TempDir(), NewMetrics(prometheus.NewRegistry(), 16), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	srv.table.Load(e.st)
	// The table is on disk; only the log fails.
	if err := srv.writeSnapshot(); err != nil {
		t.Fatal(err)
	}
	srv.disk.Close()
	reg := regproto.Encode(e.keyA, e.ab, 1)
	d := srv.table.Packet(time.Now(), e.ab, netip.MustParseAddrPort("127.0.0.1:40000"), reg[:])
	if d.Verdict != relaycore.Register {
		t.Fatalf("the registration did not verify: %+v", d)
	}
	srv.enqueue(d.Registration)
	if err := srv.committer(context.Background()); err == nil {
		t.Fatal("the committer carried on past a failed append")
	}
	for _, dir := range srv.Dirs() {
		if dir.Endpoint.IsValid() {
			t.Fatalf("%v committed endpoint %v, which the log never held", dir.Local, dir.Endpoint)
		}
	}
}

func TestARelayAnswersProbes(t *testing.T) {
	e := newEdge(t)
	cp := &fakeCP{st: e.st}
	cfg := DefaultConfig()
	cfg.Probe = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), freePort(t))
	srv, err := New(cfg, cp, t.TempDir(), NewMetrics(prometheus.NewRegistry(), 16), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	defer func() { cancel(); <-done }()
	<-srv.Ready()
	c := udp(t)
	p := regproto.Probe(42)
	send(t, c, cfg.Probe, p[:])
	got, _ := recv(c, time.Second)
	if n, ok := regproto.ProbeNonce(got); !ok || n != 42 {
		t.Fatalf("probe answer %x", got)
	}
}

// waitBound waits until the relay holds a socket for each port, so a
// datagram sent to one reaches the relay.
func waitBound(t *testing.T, srv *Server, ports ...netip.AddrPort) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for _, p := range ports {
		for srv.sockFor(p) == nil {
			if time.Now().After(deadline) {
				t.Fatalf("%v never bound", p)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// connect registers both directions of an edge, resending until a packet
// crosses each way, and drains what crossed.
func connect(t *testing.T, e edge, a, b *net.UDPConn) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for counter := uint64(1); ; counter++ {
		if time.Now().After(deadline) {
			t.Fatalf("edge %v-%v never connected", e.ab, e.ba)
		}
		regA := regproto.Encode(e.keyA, e.ab, counter)
		regB := regproto.Encode(e.keyB, e.ba, counter)
		send(t, a, e.ab, regA[:])
		send(t, b, e.ba, regB[:])
		time.Sleep(20 * time.Millisecond)
		send(t, a, e.ab, data("ping"))
		send(t, b, e.ba, data("pong"))
		gotB, _ := recv(b, 100*time.Millisecond)
		gotA, _ := recv(a, 100*time.Millisecond)
		if string(gotB) == string(data("ping")) && string(gotA) == string(data("pong")) {
			drain(a)
			drain(b)
			return
		}
	}
}

// metric reads one counter or gauge from a registry.
func metric(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		m := mf.GetMetric()[0]
		if m.GetCounter() != nil {
			return m.GetCounter().GetValue()
		}
		return m.GetGauge().GetValue()
	}
	t.Fatalf("no metric %s", name)
	return 0
}

// TestARelayForwardsADatagramWholeOrNotAtAll: the largest datagram an
// overlay MTU allows goes on whole, and a longer one, which the kernel cuts
// to the read buffer, drops rather than going on cut short.
func TestARelayForwardsADatagramWholeOrNotAtAll(t *testing.T) {
	e := newEdge(t)
	srv, cancel, done := start(t, t.TempDir(), &fakeCP{st: e.st})
	defer func() { cancel(); <-done }()
	a, b := udp(t), udp(t)
	connect(t, e, a, b)

	jumbo := data(strings.Repeat("j", srv.cfg.MaxDatagram-4))
	send(t, a, e.ab, jumbo)
	if got, _ := recv(b, time.Second); string(got) != string(jumbo) {
		t.Fatalf("a %d-byte datagram arrived as %d bytes", len(jumbo), len(got))
	}

	send(t, a, e.ab, data(strings.Repeat("o", srv.cfg.MaxDatagram)))
	send(t, a, e.ab, data("after"))
	for {
		got, _ := recv(b, time.Second)
		if got == nil {
			t.Fatal("nothing arrived after the oversized datagram")
		}
		if string(got) == string(data("after")) {
			break
		}
		t.Fatalf("forwarded %d bytes of an oversized datagram", len(got))
	}
}

// TestAPortThatFailsToBindLeavesTheRestServing: one port of the restored
// table is held by another program. The relay serves every other port, and
// binds that one once it frees.
func TestAPortThatFailsToBindLeavesTheRestServing(t *testing.T) {
	e1, e2 := newEdge(t), newEdge(t)
	st := api.RelayState{Relay: "r", Generation: 5, Ports: append(e1.st.Ports, e2.st.Ports...)}
	dir := t.TempDir()
	disk, _, _, err := OpenDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := disk.Snapshot(relaycore.State{Generation: st.Generation, Ports: st.Ports}); err != nil {
		t.Fatal(err)
	}
	disk.Close()
	blocker, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(e2.ab))
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	cfg := DefaultConfig()
	cfg.SocketBuffer = 0
	cfg.RebindEvery = 50 * time.Millisecond
	reg := prometheus.NewRegistry()
	srv, err := New(cfg, &fakeCP{st: st}, dir, NewMetrics(reg, 16), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	select {
	case <-srv.Ready():
	case err := <-done:
		cancel()
		t.Fatalf("the relay stopped over one port: %v", err)
	}
	defer func() { cancel(); <-done }()
	if n := metric(t, reg, "wirenet_relay_unbound_ports"); n != 1 {
		t.Fatalf("%v ports unbound, want 1", n)
	}
	a, b := udp(t), udp(t)
	connect(t, e1, a, b)

	blocker.Close()
	c, d := udp(t), udp(t)
	connect(t, e2, c, d)
	if n := metric(t, reg, "wirenet_relay_unbound_ports"); n != 0 {
		t.Fatalf("%v ports unbound after the port freed", n)
	}
	if n := metric(t, reg, "wirenet_relay_bind_failures_total"); n < 1 {
		t.Fatal("the failed bind went uncounted")
	}
}

// TestARegistrationUnderANewTableSurvivesACrash: the poll has loaded a
// table the state file lacks when a registration under it arrives. The
// relay crashes once the registration commits, and restarts with it.
func TestARegistrationUnderANewTableSurvivesACrash(t *testing.T) {
	e := newEdge(t)
	dir := t.TempDir()
	cfg := DefaultConfig()
	srv, err := New(cfg, &fakeCP{st: e.st}, dir, NewMetrics(prometheus.NewRegistry(), 16), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddrPort("127.0.0.1:40000")
	reg := regproto.Encode(e.keyA, e.ab, 1)
	srv.mu.Lock()
	srv.table.Load(e.st)
	d := srv.table.Packet(time.Now(), e.ab, src, reg[:])
	srv.mu.Unlock()
	if d.Verdict != relaycore.Register {
		t.Fatalf("the registration did not verify: %+v", d)
	}
	srv.enqueue(d.Registration)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.committer(ctx) }()
	committed := func() bool {
		return slices.ContainsFunc(srv.Dirs(), func(d relaycore.Dir) bool { return d.Local == e.ab && d.Endpoint == src })
	}
	for deadline := time.Now().Add(3 * time.Second); !committed(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the registration never committed")
		}
	}
	// The crash: nothing further reaches disk.
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	srv.disk.Close()

	again, err := New(cfg, &fakeCP{st: e.st}, dir, NewMetrics(prometheus.NewRegistry(), 16), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer again.disk.Close()
	if dir, ok := again.table.Dir(e.ab); !ok || dir.Endpoint != src {
		t.Fatalf("after the crash, %v holds %+v, want endpoint %v", e.ab, dir, src)
	}
}

// TestATornLogTailIsCutBeforeTheNextAppend: a crash mid-append leaves part
// of a line. The next run's appends start lines of their own, so the run
// after that reads them.
func TestATornLogTailIsCutBeforeTheNextAppend(t *testing.T) {
	dir := t.TempDir()
	r := func(counter uint64) relaycore.Registration {
		return relaycore.Registration{Local: netip.MustParseAddrPort("127.0.0.1:7001"), Endpoint: netip.MustParseAddrPort("127.0.0.1:40000"), Counter: counter}
	}
	disk, _, _, err := OpenDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := disk.Append([]relaycore.Registration{r(1), r(2)}); err != nil {
		t.Fatal(err)
	}
	disk.Close()
	f, err := os.OpenFile(filepath.Join(dir, logFile), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"local":"127.0.0.1:7001","endpo`)
	f.Close()

	disk, _, regs, err := OpenDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 2 {
		t.Fatalf("read %d registrations past a torn tail, want 2", len(regs))
	}
	if err := disk.Append([]relaycore.Registration{r(3)}); err != nil {
		t.Fatal(err)
	}
	disk.Close()
	disk, _, regs, err = OpenDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	disk.Close()
	var counters []uint64
	for _, r := range regs {
		counters = append(counters, r.Counter)
	}
	if !slices.Equal(counters, []uint64{1, 2, 3}) {
		t.Fatalf("read counters %v, want [1 2 3]", counters)
	}
}

// TestACommittedRegistrationIsAcknowledgedFromItsPort registers a direction
// and checks the relay acknowledges it from the direction's own port, and
// acknowledges neither a replay nor a registration that fails its MAC.
func TestACommittedRegistrationIsAcknowledgedFromItsPort(t *testing.T) {
	e := newEdge(t)
	srv, cancel, done := start(t, t.TempDir(), &fakeCP{st: e.st})
	defer func() { cancel(); <-done }()
	waitBound(t, srv, e.ab, e.ba)
	a := udp(t)
	reg := regproto.Encode(e.keyA, e.ab, 100)
	send(t, a, e.ab, reg[:])
	b, from := recvAny(a, 2*time.Second)
	if n, ok := regproto.AckCounter(b); !ok || n != 100 || from != e.ab {
		t.Fatalf("after registering: %x from %v, want an ack of 100 from %v", b, from, e.ab)
	}
	wrong := regproto.Encode(e.keyB, e.ab, 300)
	for _, r := range [][]byte{reg[:], wrong[:]} {
		send(t, a, e.ab, r)
		if b, from := recvAny(a, 300*time.Millisecond); b != nil {
			t.Fatalf("a replay or a forgery earned %x from %v", b, from)
		}
	}
}
