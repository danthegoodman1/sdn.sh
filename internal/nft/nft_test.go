package nft

import (
	"fmt"
	"net/netip"
	"testing"

	"sdn.sh/internal/model"
	"sdn.sh/internal/prng"
)

// randomRuleset draws a valid ruleset over a small universe of services and
// addresses, so two draws overlap.
func randomRuleset(r *prng.Rand) *Ruleset {
	rs := &Ruleset{}
	addr := func(f Family) netip.Addr {
		if f == IPv4 {
			return netip.AddrFrom4([4]byte{10, 0, 0, byte(r.Below(6))})
		}
		return netip.AddrFrom16([16]byte{0xfd, 15: byte(r.Below(6))})
	}
	for svc := range 3 {
		id := model.ServiceID(fmt.Sprintf("svc-%d", svc))
		for _, f := range []Family{IPv6, IPv4} {
			if r.Percent(50) {
				m := Map{Name: MapName(id, f), Family: f, Slots: make([]netip.Addr, Slots)}
				for i := range m.Slots {
					m.Slots[i] = addr(f)
				}
				rs.Maps = append(rs.Maps, m)
				rs.Rules.Translate = append(rs.Rules.Translate, Translate{
					Addr: addr(f), Proto: model.TCP, Ports: model.PortRange{Lo: 80, Hi: 80}, Map: m.Name,
				})
			}
			if r.Percent(50) {
				s := Set{Name: SetName(id, f), Family: f}
				for range r.Below(4) {
					s.Addrs = append(s.Addrs, addr(f))
				}
				rs.Sets = append(rs.Sets, s)
				rs.Rules.Accept = append(rs.Rules.Accept, Accept{Set: s.Name, Family: f, Proto: model.UDP})
			}
			if r.Percent(30) {
				rs.Rules.Reject = append(rs.Rules.Reject, addr(f))
			}
		}
	}
	rs.Normalize()
	return rs
}

func TestDiffThenApplyReachesTheTarget(t *testing.T) {
	r := prng.New(3)
	for i := range 2000 {
		a, b := randomRuleset(r), randomRuleset(r)
		if err := a.Validate(); err != nil {
			t.Fatalf("draw %d invalid: %v", i, err)
		}
		tx := Diff(a, b)
		got, err := Apply(a, tx)
		if err != nil {
			t.Fatalf("draw %d: %v", i, err)
		}
		if !Equal(got, b) {
			t.Fatalf("draw %d: diff applied to a does not give b", i)
		}
		if again := Diff(got, b); !again.Empty() {
			t.Fatalf("draw %d: a second diff is not empty", i)
		}
	}
}

func TestAnUnknownTableIsReplaced(t *testing.T) {
	b := randomRuleset(prng.New(4))
	tx := Diff(nil, b)
	if tx.Replace == nil {
		t.Fatal("no replacement for an unknown table")
	}
	got, err := Apply(nil, tx)
	if err != nil || !Equal(got, b) {
		t.Fatalf("replacement gives %v", err)
	}
}

func TestAPartialMapIsInvalid(t *testing.T) {
	rs := &Ruleset{Maps: []Map{{Name: "m", Family: IPv6, Slots: make([]netip.Addr, Slots-1)}}}
	if rs.Validate() == nil {
		t.Fatal("a short map validated")
	}
	full := make([]netip.Addr, Slots)
	for i := range full {
		full[i] = netip.MustParseAddr("fd00::1")
	}
	full[7] = netip.Addr{}
	rs.Maps[0].Slots = full
	if rs.Validate() == nil {
		t.Fatal("a map with an empty slot validated")
	}
	full[7] = netip.MustParseAddr("10.0.0.1")
	if rs.Validate() == nil {
		t.Fatal("an IPv6 map holding an IPv4 address validated")
	}
}

func TestApplyRejectsUpdatesToMissingObjects(t *testing.T) {
	rs := &Ruleset{}
	if _, err := Apply(rs, Transaction{Slots: []SlotUpdate{{Map: "nope", Slot: 1, Addr: netip.MustParseAddr("fd00::1")}}}); err == nil {
		t.Fatal("updated a missing map")
	}
	if _, err := Apply(rs, Transaction{Rules: &Rules{Translate: []Translate{{Addr: netip.MustParseAddr("fd00::9"), Map: "nope"}}}}); err == nil {
		t.Fatal("wrote a rule naming a missing map")
	}
}

func TestEvaluation(t *testing.T) {
	svc := netip.MustParseAddr("fd00::7")
	b1, b2 := netip.MustParseAddr("fd00::21"), netip.MustParseAddr("fd00::22")
	m := Map{Name: "s_x_6", Family: IPv6, Slots: make([]netip.Addr, Slots)}
	for i := range m.Slots {
		m.Slots[i] = []netip.Addr{b1, b2}[i%2]
	}
	client := netip.MustParseAddr("fd00::31")
	rs := &Ruleset{
		Maps: []Map{m},
		Sets: []Set{{Name: "f_y_6", Family: IPv6, Addrs: []netip.Addr{client}}},
		Rules: Rules{
			Translate: []Translate{{Addr: svc, Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}, Map: "s_x_6"}},
			Reject:    []netip.Addr{svc},
			Accept:    []Accept{{Set: "f_y_6", Family: IPv6, Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}},
		},
	}
	rs.Normalize()
	if got, ok := rs.TranslateOut(svc, model.TCP, 5432, 3); !ok || got != b2 {
		t.Fatalf("slot 3 → %v %v", got, ok)
	}
	if _, ok := rs.TranslateOut(svc, model.TCP, 22, 3); ok {
		t.Fatal("translated a port policy does not name")
	}
	if !rs.Rejected(svc) || rs.Rejected(b1) {
		t.Fatal("reject matches the wrong addresses")
	}
	if !rs.Admit(client, model.TCP, 5432) || rs.Admit(client, model.TCP, 22) || rs.Admit(b1, model.TCP, 5432) {
		t.Fatal("admission wrong")
	}
}
