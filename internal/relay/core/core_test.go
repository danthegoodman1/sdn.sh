package core

import (
	"net/netip"
	"testing"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
	"sdn.sh/internal/regproto"
)

var (
	t0       = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	local    = netip.MustParseAddr("10.0.0.1")
	adv      = netip.MustParseAddr("198.51.100.1")
	portAB   = netip.AddrPortFrom(local, 7001)
	portBA   = netip.AddrPortFrom(local, 7002)
	advAB    = netip.AddrPortFrom(adv, 7001)
	advBA    = netip.AddrPortFrom(adv, 7002)
	keyAB    = model.Secret{1}
	keyBA    = model.Secret{2}
	senderA  = netip.MustParseAddrPort("203.0.113.10:41000")
	senderB  = netip.MustParseAddrPort("203.0.113.20:42000")
	attacker = netip.MustParseAddrPort("192.0.2.66:5555")
	wg       = []byte{1, 0, 0, 0, 9, 9, 9}
)

func table() *Table {
	t := New(Config{EarlyHold: 5 * time.Second, EarlyMax: 16})
	t.Load(t0, api.RelayState{Generation: 1, Ports: []api.RelayPort{
		{Local: portAB, Peer: 7002, Advertised: advAB, Key: keyAB},
		{Local: portBA, Peer: 7001, Advertised: advBA, Key: keyBA},
	}})
	return t
}

func register(t *testing.T, tb *Table, port netip.AddrPort, key model.Secret, advertised, src netip.AddrPort, counter uint64) bool {
	t.Helper()
	b := regproto.Encode(key, advertised, counter)
	d := tb.Packet(t0, port, src, b[:])
	if d.Verdict != Register {
		return false
	}
	return tb.Commit(d.Registration)
}

func TestForwardingNeedsBothSidesRegistered(t *testing.T) {
	tb := table()
	if d := tb.Packet(t0, portAB, senderA, wg); d.Verdict != Drop || d.Reason != Unregistered {
		t.Fatalf("before registration: %+v", d)
	}
	if !register(t, tb, portAB, keyAB, advAB, senderA, 10) {
		t.Fatal("A's registration failed")
	}
	if d := tb.Packet(t0, portAB, senderA, wg); d.Verdict != Drop || d.Reason != PeerAbsent {
		t.Fatalf("before B registers: %+v", d)
	}
	if !register(t, tb, portBA, keyBA, advBA, senderB, 10) {
		t.Fatal("B's registration failed")
	}
	d := tb.Packet(t0, portAB, senderA, wg)
	if d.Verdict != Forward || d.From != portBA || d.To != senderB {
		t.Fatalf("A to B: %+v", d)
	}
	d = tb.Packet(t0, portBA, senderB, wg)
	if d.Verdict != Forward || d.From != portAB || d.To != senderA {
		t.Fatalf("B to A: %+v", d)
	}
}

func TestAnUnknownPortDrops(t *testing.T) {
	tb := table()
	if d := tb.Packet(t0, netip.AddrPortFrom(local, 9999), senderA, wg); d.Verdict != Drop || d.Reason != Unknown {
		t.Fatalf("%+v", d)
	}
}

func TestAnUnauthorizedSourceIsDropped(t *testing.T) {
	tb := table()
	register(t, tb, portAB, keyAB, advAB, senderA, 10)
	register(t, tb, portBA, keyBA, advBA, senderB, 10)
	if d := tb.Packet(t0, portAB, attacker, wg); d.Verdict != Drop || d.Reason != Unregistered {
		t.Fatalf("attacker's data: %+v", d)
	}
	if dir, _ := tb.Dir(portAB); dir.Endpoint != senderA {
		t.Fatal("a data packet moved an endpoint")
	}
}

// TestNoOneHijacksADirection covers a live direction and a dormant one: a
// sender without the key cannot claim either, nor can a replay.
func TestNoOneHijacksADirection(t *testing.T) {
	tb := table()
	register(t, tb, portAB, keyAB, advAB, senderA, 10)
	// Live direction: a forged registration, one keyed for the other
	// direction, and one for another relay all fail.
	for name, b := range map[string][regproto.Size]byte{
		"forged":       regproto.Encode(model.Secret{9}, advAB, 11),
		"other port":   regproto.Encode(keyAB, advBA, 11),
		"other relay":  regproto.Encode(keyAB, netip.MustParseAddrPort("198.51.100.2:7001"), 11),
		"replayed":     regproto.Encode(keyAB, advAB, 10),
		"older replay": regproto.Encode(keyAB, advAB, 9),
	} {
		if d := tb.Packet(t0, portAB, attacker, b[:]); d.Verdict == Register {
			t.Errorf("%s registration accepted", name)
		}
	}
	if dir, _ := tb.Dir(portAB); dir.Endpoint != senderA {
		t.Fatalf("live direction taken: %v", dir.Endpoint)
	}
	// Dormant direction: nothing registered yet, and still nobody without
	// the key takes it.
	forged := regproto.Encode(model.Secret{9}, advBA, 1)
	if d := tb.Packet(t0, portBA, attacker, forged[:]); d.Verdict == Register {
		t.Fatal("forged registration took a dormant direction")
	}
	if dir, _ := tb.Dir(portBA); dir.Endpoint.IsValid() {
		t.Fatal("dormant direction gained an endpoint")
	}
}

// TestARaceIsWonOnce checks that of two copies of one registration, only
// the first committed counts.
func TestARaceIsWonOnce(t *testing.T) {
	tb := table()
	b := regproto.Encode(keyAB, advAB, 5)
	first := tb.Packet(t0, portAB, senderA, b[:])
	second := tb.Packet(t0, portAB, attacker, b[:])
	if first.Verdict != Register || second.Verdict != Register {
		t.Fatal("both copies should verify before either commits")
	}
	if !tb.Commit(first.Registration) || tb.Commit(second.Registration) {
		t.Fatal("the replayed copy committed")
	}
	if dir, _ := tb.Dir(portAB); dir.Endpoint != senderA {
		t.Fatal("the later copy won")
	}
}

func TestAReloadKeepsRegistrationsOfUnchangedPorts(t *testing.T) {
	tb := table()
	register(t, tb, portAB, keyAB, advAB, senderA, 10)
	tb.Load(t0, api.RelayState{Generation: 2, Ports: []api.RelayPort{
		{Local: portAB, Peer: 7002, Advertised: advAB, Key: keyAB},
		{Local: portBA, Peer: 7001, Advertised: advBA, Key: model.Secret{7}},
	}})
	if dir, _ := tb.Dir(portAB); dir.Endpoint != senderA || dir.Counter != 10 {
		t.Fatal("an unchanged port lost its registration")
	}
	tb.Load(t0, api.RelayState{Generation: 3, Ports: []api.RelayPort{
		{Local: portAB, Peer: 7002, Advertised: advAB, Key: model.Secret{8}},
	}})
	if dir, _ := tb.Dir(portAB); dir.Endpoint.IsValid() || dir.Counter != 0 {
		t.Fatal("a reallocated port kept its old registration")
	}
}

func TestRestoreReplaysTheLog(t *testing.T) {
	tb := table()
	register(t, tb, portAB, keyAB, advAB, senderA, 10)
	st := tb.Persisted()
	again := New(DefaultConfig())
	again.Restore(st, []Registration{{Local: portBA, Endpoint: senderB, Counter: 4}})
	if dir, _ := again.Dir(portAB); dir.Endpoint != senderA || dir.Counter != 10 {
		t.Fatal("restore lost a registration")
	}
	if dir, _ := again.Dir(portBA); dir.Endpoint != senderB {
		t.Fatal("restore lost the log")
	}
	// A replay of the registration persisted before the restart fails.
	b := regproto.Encode(keyAB, advAB, 10)
	if d := again.Packet(t0, portAB, attacker, b[:]); d.Verdict == Register {
		t.Fatal("a replay verified after restart")
	}
}

func TestARegistrationForAPortNotYetPushedWaits(t *testing.T) {
	tb := New(Config{EarlyHold: 5 * time.Second, EarlyMax: 16})
	b := regproto.Encode(keyAB, advAB, 3)
	if d := tb.Packet(t0, portAB, senderA, b[:]); d.Verdict != Held {
		t.Fatalf("%+v", d)
	}
	regs := tb.Load(t0.Add(time.Second), api.RelayState{Ports: []api.RelayPort{{Local: portAB, Peer: 7002, Advertised: advAB, Key: keyAB}}})
	if len(regs) != 1 || regs[0].Endpoint != senderA {
		t.Fatalf("held registrations %+v", regs)
	}
	// One held past the hold is forgotten.
	tb2 := New(Config{EarlyHold: 5 * time.Second, EarlyMax: 16})
	tb2.Packet(t0, portAB, senderA, b[:])
	if regs := tb2.Load(t0.Add(6*time.Second), api.RelayState{Ports: []api.RelayPort{{Local: portAB, Peer: 7002, Advertised: advAB, Key: keyAB}}}); len(regs) != 0 {
		t.Fatal("a stale held registration verified")
	}
}

func TestRateLimitsHold(t *testing.T) {
	tb := New(Config{Rate: 10, Burst: 10, RegistrationRate: 2})
	tb.Load(t0, api.RelayState{Ports: []api.RelayPort{
		{Local: portAB, Peer: 7002, Advertised: advAB, Key: keyAB},
		{Local: portBA, Peer: 7001, Advertised: advBA, Key: keyBA},
	}})
	register(t, tb, portAB, keyAB, advAB, senderA, 1)
	register(t, tb, portBA, keyBA, advBA, senderB, 1)
	forwarded := 0
	for range 50 {
		if tb.Packet(t0, portAB, senderA, wg).Verdict == Forward {
			forwarded++
		}
	}
	if forwarded != 10 {
		t.Fatalf("forwarded %d of 50 within one burst of 10", forwarded)
	}
	limited := 0
	for c := uint64(2); c < 10; c++ {
		b := regproto.Encode(keyAB, advAB, c)
		if tb.Packet(t0, portAB, senderA, b[:]).Reason == Limited {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("registrations went unlimited")
	}
}

func TestProbesEchoTheirOwnBytes(t *testing.T) {
	p := regproto.Probe(7)
	out, ok := ProbeReply(p[:])
	if !ok || len(out) != regproto.ProbeSize {
		t.Fatal("probe not answered in kind")
	}
	if _, ok := ProbeReply(wg); ok {
		t.Fatal("answered a non-probe")
	}
}
