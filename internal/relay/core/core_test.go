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
	t := New(Config{})
	t.Load(api.RelayState{Generation: 1, Ports: []api.RelayPort{
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

// TestAnUnknownPortDrops covers data and registrations alike: the relay
// binds sockets only for the ports its table holds, so nothing waits for a
// port to arrive.
func TestAnUnknownPortDrops(t *testing.T) {
	tb := table()
	unknown := netip.AddrPortFrom(local, 9999)
	reg := regproto.Encode(keyAB, netip.AddrPortFrom(adv, 9999), 3)
	for name, b := range map[string][]byte{"data": wg, "registration": reg[:]} {
		if d := tb.Packet(t0, unknown, senderA, b); d.Verdict != Drop || d.Reason != Unknown {
			t.Fatalf("%s: %+v", name, d)
		}
	}
	if tb.Unknown != 2 {
		t.Fatalf("counted %d packets to unknown ports, want 2", tb.Unknown)
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
	tb.Load(api.RelayState{Generation: 2, Ports: []api.RelayPort{
		{Local: portAB, Peer: 7002, Advertised: advAB, Key: keyAB},
		{Local: portBA, Peer: 7001, Advertised: advBA, Key: model.Secret{7}},
	}})
	if dir, _ := tb.Dir(portAB); dir.Endpoint != senderA || dir.Counter != 10 {
		t.Fatal("an unchanged port lost its registration")
	}
	tb.Load(api.RelayState{Generation: 3, Ports: []api.RelayPort{
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
	again.Restore(st, []Registration{
		{Local: portBA, Endpoint: senderB, Counter: 4, Key: keyBA},
		// A claim verified under a key the port no longer has commits to
		// nothing.
		{Local: portAB, Endpoint: attacker, Counter: 11, Key: model.Secret{9}},
	})
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

func TestRateLimitsHold(t *testing.T) {
	tb := New(Config{Rate: 10, Burst: 10, RegistrationRate: 2})
	tb.Load(api.RelayState{Ports: []api.RelayPort{
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
	probes := NewProbes(Config{})
	p := regproto.Probe(7)
	if out, reason := probes.Reply(t0, p[:]); string(out) != string(p[:]) || reason != "" {
		t.Fatal("probe not answered in kind")
	}
	if out, reason := probes.Reply(t0, wg); out != nil || reason != "" {
		t.Fatal("answered a non-probe")
	}
}

// TestProbeAnswersAreCappedAcrossTheRelay: a probe's source can be forged,
// so the probe port answers at most ProbeRate a second, whoever asks.
func TestProbeAnswersAreCappedAcrossTheRelay(t *testing.T) {
	probes := NewProbes(Config{ProbeRate: 5})
	p := regproto.Probe(7)
	answered, limited := 0, 0
	for range 20 {
		switch out, reason := probes.Reply(t0, p[:]); {
		case out != nil:
			answered++
		case reason == Limited:
			limited++
		}
	}
	if answered != 5 || limited != 15 {
		t.Fatalf("answered %d and limited %d of 20 within a second, want 5 and 15", answered, limited)
	}
	if out, _ := probes.Reply(t0.Add(time.Second), p[:]); out == nil {
		t.Fatal("the cap never refilled")
	}
}

// TestJunkLeavesAnOwnerItsRegistrations: registrations that fail spend the
// relay's reject budget, never the port's, so a flood of junk at a port's
// registration rate still lets its owner move the endpoint.
func TestJunkLeavesAnOwnerItsRegistrations(t *testing.T) {
	tb := New(Config{RegistrationRate: 2, RejectRate: 1000})
	tb.Load(api.RelayState{Ports: []api.RelayPort{{Local: portAB, Peer: 7002, Advertised: advAB, Key: keyAB}}})
	for c := range uint64(100) {
		forged := regproto.Encode(model.Secret{9}, advAB, c+1)
		tb.Packet(t0, portAB, attacker, forged[:])
	}
	for c := range uint64(2) {
		if !register(t, tb, portAB, keyAB, advAB, senderA, c+1) {
			t.Fatalf("after junk, the owner's registration %d was refused", c+1)
		}
	}
	// The port's own budget still caps what verifies.
	b := regproto.Encode(keyAB, advAB, 3)
	if d := tb.Packet(t0, portAB, senderA, b[:]); d.Reason != Limited {
		t.Fatalf("a third registration within a second: %+v", d)
	}
}

// TestFailedVerificationsAreCappedAcrossTheRelay: once the reject budget is
// spent, no port verifies anything until it refills, which bounds the MACs a
// flood across many ports makes the relay compute.
func TestFailedVerificationsAreCappedAcrossTheRelay(t *testing.T) {
	tb := New(Config{RegistrationRate: 2, RejectRate: 10})
	tb.Load(api.RelayState{Ports: []api.RelayPort{
		{Local: portAB, Peer: 7002, Advertised: advAB, Key: keyAB},
		{Local: portBA, Peer: 7001, Advertised: advBA, Key: keyBA},
	}})
	for i := range 50 {
		port, a := portAB, advAB
		if i%2 == 1 {
			port, a = portBA, advBA
		}
		forged := regproto.Encode(model.Secret{9}, a, uint64(i+1))
		tb.Packet(t0, port, attacker, forged[:])
	}
	ab, _ := tb.Dir(portAB)
	ba, _ := tb.Dir(portBA)
	if macs := ab.Stats.BadMAC + ba.Stats.BadMAC; macs != 10 {
		t.Fatalf("verified %d junk registrations within a second, want 10", macs)
	}
	if limited := ab.Stats.Limited + ba.Stats.Limited; limited != 40 {
		t.Fatalf("limited %d, want 40", limited)
	}
	b := regproto.Encode(keyAB, advAB, 1)
	if d := tb.Packet(t0, portAB, senderA, b[:]); d.Reason != Limited {
		t.Fatalf("with the reject budget spent: %+v", d)
	}
	if d := tb.Packet(t0.Add(time.Second), portAB, senderA, b[:]); d.Verdict != Register {
		t.Fatalf("once the budget refilled: %+v", d)
	}
}

func waitTable() *Table {
	t := New(Config{WaitFor: 2 * time.Second, WaitMax: 2, WaitTotal: 16})
	t.Load(api.RelayState{Generation: 1, Ports: []api.RelayPort{
		{Local: portAB, Peer: 7002, Advertised: advAB, Key: keyAB},
		{Local: portBA, Peer: 7001, Advertised: advBA, Key: keyBA},
	}})
	return t
}

// TestAFirstPacketWaitsForTheRegistrationsItRaces: A's handshake arrives
// before either registration commits, and goes on once both have.
func TestAFirstPacketWaitsForTheRegistrationsItRaces(t *testing.T) {
	tb := waitTable()
	first := tb.Packet(t0, portAB, senderA, wg)
	if first.Verdict != Wait {
		t.Fatalf("a first packet: %+v", first)
	}
	register(t, tb, portAB, keyAB, advAB, senderA, 10)
	if rel := tb.Release(t0); len(rel) != 0 {
		t.Fatalf("released with the peer unregistered: %+v", rel)
	}
	register(t, tb, portBA, keyBA, advBA, senderB, 10)
	rel := tb.Release(t0)
	if len(rel) != 1 || rel[0].Token != first.Token || rel[0].Drop || rel[0].From != portBA || rel[0].To != senderB {
		t.Fatalf("after both registered: %+v", rel)
	}
}

// TestAPacketThatRacesThePeerDirectionWaitsForIt: a direction already
// registered sends before the other side's agent has installed the edge,
// so its packet waits for the peer direction's registration.
func TestAPacketThatRacesThePeerDirectionWaitsForIt(t *testing.T) {
	tb := waitTable()
	register(t, tb, portAB, keyAB, advAB, senderA, 10)
	first := tb.Packet(t0, portAB, senderA, wg)
	if first.Verdict != Wait || first.Reason != PeerAbsent {
		t.Fatalf("a packet before the peer registers: %+v", first)
	}
	register(t, tb, portBA, keyBA, advBA, senderB, 10)
	rel := tb.Release(t0)
	if len(rel) != 1 || rel[0].Token != first.Token || rel[0].Drop || rel[0].From != portBA || rel[0].To != senderB {
		t.Fatalf("after the peer registered: %+v", rel)
	}
}

// TestAWaitingPacketFromAnotherSourceNeverGoes: an attacker's packet waits
// like any other, but the registration that commits names someone else, so
// it expires instead of going on.
func TestAWaitingPacketFromAnotherSourceNeverGoes(t *testing.T) {
	tb := waitTable()
	spoof := tb.Packet(t0, portAB, attacker, wg)
	if spoof.Verdict != Wait {
		t.Fatalf("an attacker's packet: %+v", spoof)
	}
	register(t, tb, portAB, keyAB, advAB, senderA, 10)
	register(t, tb, portBA, keyBA, advBA, senderB, 10)
	if rel := tb.Release(t0); len(rel) != 0 {
		t.Fatalf("released an attacker's packet: %+v", rel)
	}
	rel := tb.Release(t0.Add(3 * time.Second))
	if len(rel) != 1 || rel[0].Token != spoof.Token || !rel[0].Drop {
		t.Fatalf("after the wait: %+v", rel)
	}
}

func TestAPortHoldsAFewWaitingPacketsAtMost(t *testing.T) {
	tb := waitTable()
	for i := range 4 {
		d := tb.Packet(t0, portAB, attacker, wg)
		if want := i < 2; (d.Verdict == Wait) != want {
			t.Fatalf("packet %d: %+v", i, d)
		}
	}
	if tb.Waiting() != 2 {
		t.Fatalf("%d waiting", tb.Waiting())
	}
}

// TestWaitSlotsFreeHoweverAWaitEnds: a port's slots and the relay's free
// when a waiting packet goes, when its port leaves the table, and when its
// wait runs out.
func TestWaitSlotsFreeHoweverAWaitEnds(t *testing.T) {
	portCD, portDC := netip.AddrPortFrom(local, 7003), netip.AddrPortFrom(local, 7004)
	ports := []api.RelayPort{
		{Local: portAB, Peer: 7002, Advertised: advAB, Key: keyAB},
		{Local: portBA, Peer: 7001, Advertised: advBA, Key: keyBA},
		{Local: portCD, Peer: 7004, Advertised: netip.AddrPortFrom(adv, 7003), Key: model.Secret{3}},
		{Local: portDC, Peer: 7003, Advertised: netip.AddrPortFrom(adv, 7004), Key: model.Secret{4}},
	}
	tb := New(Config{WaitFor: 2 * time.Second, WaitMax: 2, WaitTotal: 3})
	tb.Load(api.RelayState{Generation: 1, Ports: ports})
	waits := func(at time.Time, port, src netip.AddrPort) bool {
		return tb.Packet(at, port, src, wg).Verdict == Wait
	}
	if !waits(t0, portAB, senderA) || !waits(t0, portAB, attacker) || waits(t0, portAB, attacker) {
		t.Fatal("port AB should hold two")
	}
	if !waits(t0, portCD, attacker) || waits(t0, portDC, attacker) {
		t.Fatal("the relay should hold three")
	}

	register(t, tb, portAB, keyAB, advAB, senderA, 1)
	register(t, tb, portBA, keyBA, advBA, senderB, 1)
	if rel := tb.Release(t0); len(rel) != 1 || rel[0].Drop {
		t.Fatalf("released %+v, want A's packet", rel)
	}
	if tb.Waiting() != 2 || !waits(t0, portAB, attacker) || waits(t0, portAB, attacker) {
		t.Fatal("a packet that went kept its slot")
	}

	tb.Load(api.RelayState{Generation: 2, Ports: ports[:2]})
	if rel := tb.Release(t0); len(rel) != 1 || !rel[0].Drop {
		t.Fatalf("after CD left the table: %+v", rel)
	}
	tb.Load(api.RelayState{Generation: 3, Ports: ports})
	if tb.Waiting() != 2 || !waits(t0, portCD, attacker) || waits(t0, portDC, attacker) {
		t.Fatal("a packet whose port left the table kept its slot")
	}

	later := t0.Add(3 * time.Second)
	if rel := tb.Release(later); len(rel) != 3 {
		t.Fatalf("expired %+v, want three", rel)
	}
	if tb.Waiting() != 0 || !waits(later, portAB, attacker) || !waits(later, portAB, attacker) {
		t.Fatal("an expired packet kept its slot")
	}
}

// TestAWaitCostsTheSameHoweverManyWait: refusing a packet at a full port,
// and releasing after it, cost no more with 64,000 packets waiting than with
// 16, so junk spread across ports cannot stall forwarding.
func TestAWaitCostsTheSameHoweverManyWait(t *testing.T) {
	few, many := waitCost(16), waitCost(64000)
	if many > 10*few {
		t.Fatalf("a packet at a full port costs %v with 64,000 waiting and %v with 16", many, few)
	}
}

// waitCost is the least time, over a few runs, a junk packet to a full port
// and a release after it take with n packets waiting.
func waitCost(n int) time.Duration {
	const rounds = 500
	tb, full := fullTable(n)
	best := time.Duration(1<<63 - 1)
	for range 5 {
		start := time.Now()
		for range rounds {
			tb.Packet(t0, full, attacker, wg)
			tb.Release(t0)
		}
		best = min(best, time.Since(start))
	}
	return best / rounds
}

func BenchmarkAJunkPacketAt64000Waiting(b *testing.B) {
	tb, full := fullTable(64000)
	for b.Loop() {
		tb.Packet(t0, full, attacker, wg)
		tb.Release(t0)
	}
}

// fullTable returns a table with n packets waiting, eight on each of n/8
// ports, and one of those ports.
func fullTable(n int) (*Table, netip.AddrPort) {
	tb := New(DefaultConfig())
	var st api.RelayState
	for i := range n / 8 {
		port := uint16(10000 + i)
		st.Ports = append(st.Ports, api.RelayPort{Local: netip.AddrPortFrom(local, port), Peer: port ^ 1, Advertised: netip.AddrPortFrom(adv, port), Key: model.Secret{1}})
	}
	tb.Load(st)
	for _, p := range st.Ports {
		for range 8 {
			tb.Packet(t0, p.Local, attacker, wg)
		}
	}
	return tb, st.Ports[0].Local
}
