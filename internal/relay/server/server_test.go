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
	_, cancel, done := start(t, dir, cp)
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
