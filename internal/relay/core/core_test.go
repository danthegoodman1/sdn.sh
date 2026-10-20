package core

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/regproto"
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

func table() *Table { return tableWith(Config{}) }

func tableWith(cfg Config) *Table {
	t := New(cfg)
	t.Load(api.RelayState{Generation: 1, Ports: []api.RelayPort{
		{Local: portAB, Peer: 7002, Advertised: advAB, Key: keyAB},
		{Local: portBA, Peer: 7001, Advertised: advBA, Key: keyBA},
	}})
	return t
}

func register(t *testing.T, tb *Table, port netip.AddrPort, key model.Secret, advertised, src netip.AddrPort, counter uint64) bool {
	t.Helper()
	return registerAt(t, tb, t0, port, key, advertised, src, counter)
}

func registerAt(t *testing.T, tb *Table, at time.Time, port netip.AddrPort, key model.Secret, advertised, src netip.AddrPort, counter uint64) bool {
	t.Helper()
	b := regproto.Encode(key, advertised, counter)
	d := tb.Packet(at, port, src, b[:])
	if d.Verdict != Register {
		return false
	}
	return tb.Commit(at, d.Registration)
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
	if !tb.Commit(t0, first.Registration) || tb.Commit(t0, second.Registration) {
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

// TestAWithdrawalOutranksTheClaimSentBeforeIt replays the race a
// withdrawal closes. An agent's periodic claim leaves just before its edge
// goes dormant and arrives just after the agent's withdrawal, or just
// before: either way the direction ends withdrawn, so a returning sender's
// first initiation waits for the receiver's next claim instead of reaching
// a device that lacks the sender's key. The next claim then lets it go.
func TestAWithdrawalOutranksTheClaimSentBeforeIt(t *testing.T) {
	for _, staleFirst := range []bool{true, false} {
		tb := tableWith(Config{WaitFor: time.Second, WaitMax: 8, WaitTotal: 64})
		register(t, tb, portAB, keyAB, advAB, senderA, 10)
		register(t, tb, portBA, keyBA, advBA, senderB, 10)
		stale := regproto.Encode(keyBA, advBA, 11)
		withdrawal := regproto.EncodeWithdrawal(keyBA, advBA, 12)
		order := [][regproto.Size]byte{withdrawal, stale}
		if staleFirst {
			order = [][regproto.Size]byte{stale, withdrawal}
		}
		for _, b := range order {
			if d := tb.Packet(t0, portBA, senderB, b[:]); d.Verdict == Register {
				tb.Commit(t0, d.Registration)
			}
		}
		if dir, _ := tb.Dir(portBA); dir.Endpoint.IsValid() || dir.Counter != 12 {
			t.Fatalf("stale first %v: endpoint %v, counter %d, want withdrawn at 12", staleFirst, dir.Endpoint, dir.Counter)
		}
		d := tb.Packet(t0, portAB, senderA, wg)
		if d.Verdict != Wait {
			t.Fatalf("stale first %v: A's initiation got %+v, want a wait", staleFirst, d)
		}
		if !register(t, tb, portBA, keyBA, advBA, senderB, 13) {
			t.Fatalf("stale first %v: the claim after the withdrawal failed", staleFirst)
		}
		if rel := tb.Release(t0); len(rel) != 1 || rel[0].Token != d.Token || rel[0].To != senderB {
			t.Fatalf("stale first %v: released %+v", staleFirst, rel)
		}
	}
}

// TestTheHighestCounterDecidesTheEndpoint delivers every subset of a run
// of claims and withdrawals, one withdrawal resent, in every order, and
// finds the endpoint the highest counter delivered names: a claim's sender
// or, for a withdrawal, none. However the underlay loses and reorders an agent's registrations,
// the relay ends where the agent's latest one says once that one lands,
// so no interleaving leaves a direction stuck. A restart from the durable
// state agrees.
func TestTheHighestCounterDecidesTheEndpoint(t *testing.T) {
	other := netip.MustParseAddrPort("203.0.113.20:42999")
	type reg struct {
		counter  uint64
		withdraw bool
		from     netip.AddrPort
	}
	run := []reg{{11, false, senderB}, {12, true, senderB}, {12, true, senderB}, {13, false, other}, {14, true, other}, {15, false, senderB}}
	sequences := 0
	var walk func(sent, rest []reg)
	walk = func(sent, rest []reg) {
		sequences++
		tb := table()
		register(t, tb, portBA, keyBA, advBA, senderB, 10)
		want, top := senderB, uint64(10)
		for _, r := range sent {
			b := regproto.Encode(keyBA, advBA, r.counter)
			if r.withdraw {
				b = regproto.EncodeWithdrawal(keyBA, advBA, r.counter)
			}
			if d := tb.Packet(t0, portBA, r.from, b[:]); d.Verdict == Register {
				tb.Commit(t0, d.Registration)
			}
			if r.counter > top {
				top, want = r.counter, r.from
				if r.withdraw {
					want = netip.AddrPort{}
				}
			}
		}
		for _, tbl := range []*Table{tb, restart(t, tb)} {
			if dir, _ := tbl.Dir(portBA); dir.Endpoint != want || dir.Counter != top {
				t.Fatalf("after %+v: endpoint %v counter %d, want %v at %d", sent, dir.Endpoint, dir.Counter, want, top)
			}
		}
		for i := range rest {
			walk(append(slices.Clone(sent), rest[i]), slices.Delete(slices.Clone(rest), i, i+1))
		}
	}
	walk(nil, run)
	if sequences != 1957 {
		t.Fatalf("checked %d sequences, want every ordered subset of 6", sequences)
	}
}

// TestAResentWithdrawalIsAcknowledgedAgain resends a withdrawal the relay
// holds, as an agent does whose acknowledgment was lost: the relay answers
// it again, writes nothing and spends no reject budget, and once a later
// claim commits, the same bytes are a replay.
func TestAResentWithdrawalIsAcknowledgedAgain(t *testing.T) {
	tb := tableWith(Config{RejectRate: 1})
	register(t, tb, portBA, keyBA, advBA, senderB, 10)
	w := regproto.EncodeWithdrawal(keyBA, advBA, 11)
	if d := tb.Packet(t0, portBA, senderB, w[:]); d.Verdict != Register || !tb.Commit(t0, d.Registration) {
		t.Fatalf("the withdrawal: %+v", d)
	}
	for range 3 {
		d := tb.Packet(t0, portBA, senderB, w[:])
		if d.Verdict != Acknowledge || d.Registration.Counter != 11 || d.Registration.Endpoint != senderB {
			t.Fatalf("a resent withdrawal: %+v, want an acknowledgment at 11 to %v", d, senderB)
		}
	}
	if dir, _ := tb.Dir(portBA); dir.Endpoint.IsValid() || dir.Counter != 11 || dir.Stats.Replayed != 0 {
		t.Fatalf("after the resends: endpoint %v, counter %d, replays %d", dir.Endpoint, dir.Counter, dir.Stats.Replayed)
	}
	if !register(t, tb, portBA, keyBA, advBA, senderB, 12) {
		t.Fatal("a claim after the resends failed, as if they spent the reject budget")
	}
	if d := tb.Packet(t0, portBA, senderB, w[:]); d.Verdict != Drop || d.Reason != Replay {
		t.Fatalf("the withdrawal after a later claim: %+v, want a replay", d)
	}
}

// restart round-trips a table's durable state through JSON, as a relay's
// state file does, into a new table.
func restart(t *testing.T, tb *Table) *Table {
	t.Helper()
	b, err := json.Marshal(tb.Persisted())
	if err != nil {
		t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	out := New(Config{})
	out.Restore(st, nil)
	return out
}

// TestAWithdrawalLoggedBeforeACrashHoldsAfterIt restores a withdrawal
// from the registration log written since the last state file, and a
// replay of the claim it outranked still fails.
func TestAWithdrawalLoggedBeforeACrashHoldsAfterIt(t *testing.T) {
	tb := table()
	register(t, tb, portBA, keyBA, advBA, senderB, 10)
	st := tb.Persisted()
	w := regproto.EncodeWithdrawal(keyBA, advBA, 11)
	d := tb.Packet(t0, portBA, senderB, w[:])
	if d.Verdict != Register || !d.Registration.Withdraw {
		t.Fatalf("withdrawal: %+v", d)
	}
	restored := New(Config{})
	restored.Restore(st, []Registration{d.Registration})
	if dir, _ := restored.Dir(portBA); dir.Endpoint.IsValid() || dir.Counter != 11 {
		t.Fatalf("after a restart: endpoint %v, counter %d", dir.Endpoint, dir.Counter)
	}
	old := regproto.Encode(keyBA, advBA, 10)
	if d := restored.Packet(t0, portBA, senderB, old[:]); d.Verdict == Register {
		t.Fatal("a claim the withdrawal outranked was accepted")
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
	t := New(Config{WaitFor: 2 * time.Second, WaitMax: 2, WaitTotal: 16, CrossWithin: time.Second})
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

// handshake is a WireGuard handshake initiation's size and type, and data
// a transport packet's.
var (
	handshake = append([]byte{1, 0, 0, 0}, make([]byte, 144)...)
	data      = append([]byte{4, 0, 0, 0}, make([]byte, 60)...)
)

// TestOnlyOneOfTwoInitiationsOneRegistrationReleasesGoes: B's initiation
// waits for A to register, and A's own initiation, sent as its agent
// installed B, waits for A's registration, which lets both through at
// once. Crossed, both would fail, so only the one that waited longer goes,
// and the rest of each direction's packets go as they would.
func TestOnlyOneOfTwoInitiationsOneRegistrationReleasesGoes(t *testing.T) {
	for _, bFirst := range []bool{true, false} {
		tb := waitTable()
		register(t, tb, portBA, keyBA, advBA, senderB, 10)
		var fromA, fromB Decision
		if bFirst {
			fromB = tb.Packet(t0, portBA, senderB, handshake)
			fromA = tb.Packet(t0.Add(time.Millisecond), portAB, senderA, handshake)
		} else {
			fromA = tb.Packet(t0, portAB, senderA, handshake)
			fromB = tb.Packet(t0.Add(time.Millisecond), portBA, senderB, handshake)
		}
		trailing := tb.Packet(t0.Add(2*time.Millisecond), portBA, senderB, data)
		if fromA.Verdict != Wait || fromB.Verdict != Wait || trailing.Verdict != Wait {
			t.Fatalf("before A registers: %+v %+v %+v", fromA, fromB, trailing)
		}
		register(t, tb, portAB, keyAB, advAB, senderA, 10)
		older, newer := fromA, fromB
		if bFirst {
			older, newer = fromB, fromA
		}
		got := map[uint64]Release{}
		for _, r := range tb.Release(t0.Add(3 * time.Millisecond)) {
			got[r.Token] = r
		}
		if r, ok := got[older.Token]; !ok || r.Drop {
			t.Errorf("B first %v: the older initiation: %+v", bFirst, r)
		}
		if r, ok := got[newer.Token]; !ok || !r.Drop || !r.Crossed {
			t.Errorf("B first %v: the newer initiation: %+v, want dropped as crossed", bFirst, r)
		}
		if r, ok := got[trailing.Token]; !ok || r.Drop || r.To != senderA {
			t.Errorf("B first %v: B's data packet: %+v", bFirst, r)
		}
		var crossed uint64
		for _, d := range tb.Dirs() {
			crossed += d.Stats.Crossed
		}
		if crossed != 1 {
			t.Errorf("B first %v: %d crossed, want 1", bFirst, crossed)
		}
	}
}

// response is a WireGuard handshake response's size and type.
var response = append([]byte{2, 0, 0, 0}, make([]byte, 88)...)

// TestAnInitiationThatCrossesThePeersIsDropped: with both directions
// registered, B's initiation reaches the relay just after A's went on, so
// B sent it before A's arrived; the relay drops it, and B answers A's. An
// initiation from an end that has answered, or one well after the peer's,
// goes.
func TestAnInitiationThatCrossesThePeersIsDropped(t *testing.T) {
	tb := waitTable()
	register(t, tb, portAB, keyAB, advAB, senderA, 10)
	register(t, tb, portBA, keyBA, advBA, senderB, 10)
	step := func(at time.Duration, port, src netip.AddrPort, b []byte) Decision {
		return tb.Packet(t0.Add(at), port, src, b)
	}
	if d := step(0, portAB, senderA, handshake); d.Verdict != Forward {
		t.Fatalf("A's initiation: %+v", d)
	}
	if d := step(time.Millisecond, portBA, senderB, handshake); d.Verdict != Drop || d.Reason != Crossed {
		t.Fatalf("B's initiation, crossing A's: %+v", d)
	}
	if d := step(2*time.Millisecond, portBA, senderB, response); d.Verdict != Forward {
		t.Fatalf("B's answer: %+v", d)
	}
	if d := step(3*time.Millisecond, portBA, senderB, handshake); d.Verdict != Forward {
		t.Fatalf("an initiation from B once it answered: %+v", d)
	}
	// A has not answered B's, so A's next initiation crosses it.
	if d := step(4*time.Millisecond, portAB, senderA, handshake); d.Verdict != Drop || d.Reason != Crossed {
		t.Fatalf("A's initiation just after B's went on: %+v", d)
	}
	if d := step(2*time.Second, portAB, senderA, handshake); d.Verdict != Forward {
		t.Fatalf("A's initiation a while after B's: %+v", d)
	}
	if d := step(2*time.Second+time.Millisecond, portAB, senderA, data); d.Verdict != Forward {
		t.Fatalf("A's transport packet: %+v", d)
	}
	var crossed uint64
	for _, d := range tb.Dirs() {
		crossed += d.Stats.Crossed
	}
	if crossed != 2 {
		t.Fatalf("%d crossed, want 2", crossed)
	}
	// Long after either end gained its endpoint the relay judges nothing,
	// so a forged initiation cannot hold the other end's back.
	if d := step(10*time.Second, portAB, senderA, handshake); d.Verdict != Forward {
		t.Fatalf("A's initiation, long after the registrations: %+v", d)
	}
	if d := step(10*time.Second+time.Millisecond, portBA, senderB, handshake); d.Verdict != Forward {
		t.Fatalf("B's initiation, long after the registrations: %+v", d)
	}
	// B's new endpoint opens the window again, and A has not answered B's
	// initiation.
	moved := netip.MustParseAddrPort("203.0.113.20:42001")
	if !registerAt(t, tb, t0.Add(10*time.Second+2*time.Millisecond), portBA, keyBA, advBA, moved, 11) {
		t.Fatal("B's registration from its new endpoint failed")
	}
	if d := step(10*time.Second+3*time.Millisecond, portAB, senderA, handshake); d.Verdict != Drop || d.Reason != Crossed {
		t.Fatalf("A's initiation after B moved: %+v", d)
	}
}

// TestAnInitiationGoesWhenNoneWaitsTheOtherWay: A's initiation and B's
// transport packet wait for the same registration, and both go, as does
// an initiation that waited alone.
func TestAnInitiationGoesWhenNoneWaitsTheOtherWay(t *testing.T) {
	tb := waitTable()
	register(t, tb, portBA, keyBA, advBA, senderB, 10)
	fromA := tb.Packet(t0, portAB, senderA, handshake)
	fromB := tb.Packet(t0, portBA, senderB, data)
	register(t, tb, portAB, keyAB, advAB, senderA, 10)
	rel := tb.Release(t0)
	if len(rel) != 2 || rel[0].Drop || rel[1].Drop {
		t.Fatalf("A's initiation and B's data: %+v", rel)
	}
	tokens := []uint64{rel[0].Token, rel[1].Token}
	slices.Sort(tokens)
	if tokens[0] != fromA.Token || tokens[1] != fromB.Token {
		t.Fatalf("released %v, want %d and %d", tokens, fromA.Token, fromB.Token)
	}

	tb = waitTable()
	alone := tb.Packet(t0, portAB, senderA, handshake)
	register(t, tb, portAB, keyAB, advAB, senderA, 10)
	register(t, tb, portBA, keyBA, advBA, senderB, 10)
	if rel := tb.Release(t0); len(rel) != 1 || rel[0].Token != alone.Token || rel[0].Drop {
		t.Fatalf("an initiation waiting alone: %+v", rel)
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
