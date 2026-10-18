package server

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
	"sdn.sh/internal/regproto"
	relaycore "sdn.sh/internal/relay/core"
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

// recv returns what arrives within d, or nil.
func recv(c *net.UDPConn, d time.Duration) ([]byte, netip.AddrPort) {
	c.SetReadDeadline(time.Now().Add(d))
	b := make([]byte, 2048)
	n, from, err := c.ReadFromUDPAddrPort(b)
	if err != nil {
		return nil, netip.AddrPort{}
	}
	return b[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
}

func data(s string) []byte { return append([]byte{4, 0, 0, 0}, s...) }

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
	_, cancel, done := start(t, dir, cp)
	a, b, attacker := udp(t), udp(t), udp(t)

	regA := regproto.Encode(e.keyA, e.ab, 100)
	regB := regproto.Encode(e.keyB, e.ba, 200)
	// Before either registers, data goes nowhere.
	send(t, a, e.ab, data("early"))
	if got, _ := recv(b, 200*time.Millisecond); got != nil {
		t.Fatal("forwarded before registration")
	}
	send(t, a, e.ab, regA[:])
	send(t, b, e.ba, regB[:])
	// A sends to its port; B receives it from the peer port, where B sends.
	waitForward(t, a, b, e.ab, e.ba)
	waitForward(t, b, a, e.ba, e.ab)

	// An unregistered sender on A's port reaches nobody, and a replay of
	// A's registration from the attacker moves nothing.
	send(t, attacker, e.ab, data("spoof"))
	send(t, attacker, e.ab, regA[:])
	time.Sleep(100 * time.Millisecond)
	send(t, attacker, e.ab, data("spoof"))
	if got, _ := recv(b, 300*time.Millisecond); got != nil {
		t.Fatalf("forwarded an attacker's packet: %q", got)
	}
	// A registration under the other direction's key fails too.
	wrong := regproto.Encode(e.keyB, e.ab, 300)
	send(t, attacker, e.ab, wrong[:])
	time.Sleep(100 * time.Millisecond)
	waitForward(t, a, b, e.ab, e.ba)

	// Restart from disk: both directions still forward without registering
	// again.
	cancel()
	<-done
	time.Sleep(50 * time.Millisecond)
	_, cancel, done = start(t, dir, cp)
	defer func() { cancel(); <-done }()
	waitForward(t, a, b, e.ab, e.ba)
	// The persisted counter still rejects the old registration's replay.
	send(t, attacker, e.ab, regA[:])
	time.Sleep(100 * time.Millisecond)
	send(t, attacker, e.ab, data("spoof"))
	if got, _ := recv(b, 300*time.Millisecond); got != nil {
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
	srv.table.Load(time.Now(), e.st)
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
