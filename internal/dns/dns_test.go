package dns

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
)

func network() *api.NetworkState {
	return &api.NetworkState{
		Name: "shop",
		Services: []api.Service{
			{ID: "svc-api", Name: "api", Addr6: netip.MustParseAddr("fd00::10"), Addr4: netip.MustParseAddr("10.0.0.10")},
			{ID: "svc-db", Name: "db", Addr6: netip.MustParseAddr("fd00::20"), Addr4: netip.MustParseAddr("10.0.0.20")},
			{ID: "svc-v6", Name: "v6only", Addr6: netip.MustParseAddr("fd00::30")},
		},
	}
}

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}},
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ask(t *testing.T, z Zone, name string, typ dnsmessage.Type) (Verdict, dnsmessage.Message) {
	t.Helper()
	v, b := z.Answer(query(t, name, typ))
	var m dnsmessage.Message
	if v == Reply {
		if err := m.Unpack(b); err != nil {
			t.Fatal(err)
		}
		if m.ID != 7 || !m.Response {
			t.Fatalf("response header %+v", m.Header)
		}
	}
	return v, m
}

func TestAWorkloadResolvesOnlyWhatItMayReach(t *testing.T) {
	n := network()
	web := &api.Interface{Addr6: netip.MustParseAddr("fd00::100"), Addr4: netip.MustParseAddr("10.0.0.100"),
		Reach: []api.Reach{{Service: "svc-db", Proto: model.TCP}, {Service: "svc-v6", Proto: model.TCP}}}
	z := ZoneFor(n, web)
	_, m := ask(t, z, "db.shop.internal.", dnsmessage.TypeAAAA)
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA != netip.MustParseAddr("fd00::20").As16() {
		t.Fatalf("AAAA db: %+v", m.Answers)
	}
	_, m = ask(t, z, "DB.Shop.Internal.", dnsmessage.TypeA)
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 0, 0, 20} {
		t.Fatalf("A db, mixed case: %+v", m.Answers)
	}
	// A service it may not reach does not exist for it.
	if _, m = ask(t, z, "api.shop.internal.", dnsmessage.TypeAAAA); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("api: %v", m.RCode)
	}
	// An IPv6-only target has no A record, and the name still exists.
	if _, m = ask(t, z, "v6only.shop.internal.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("A v6only: %v %+v", m.RCode, m.Answers)
	}
	// Without egress, names outside the domain are refused.
	if v, m := ask(t, z, "example.com.", dnsmessage.TypeA); v != Reply || m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("example.com: %v %v", v, m.RCode)
	}
}

func TestAnIPv6OnlyClientReceivesNoARecord(t *testing.T) {
	n := network()
	client := &api.Interface{Addr6: netip.MustParseAddr("fd00::101"), Reach: []api.Reach{{Service: "svc-db"}}}
	z := ZoneFor(n, client)
	if _, m := ask(t, z, "db.shop.internal.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("A for an IPv6-only client: %v %+v", m.RCode, m.Answers)
	}
	if _, m := ask(t, z, "db.shop.internal.", dnsmessage.TypeAAAA); len(m.Answers) != 1 {
		t.Fatalf("AAAA: %+v", m.Answers)
	}
}

func TestEgressForwardsNamesOutsideTheDomain(t *testing.T) {
	n := network()
	client := &api.Interface{Addr6: netip.MustParseAddr("fd00::101"), Egress: []api.Egress{{Proto: model.TCP}}}
	z := ZoneFor(n, client)
	if v, _ := z.Answer(query(t, "example.com.", dnsmessage.TypeA)); v != Forward {
		t.Fatalf("verdict %v", v)
	}
	// The network's own names never leave the host.
	if v, m := ask(t, z, "db.shop.internal.", dnsmessage.TypeA); v != Reply || m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("db without reach: %v %v", v, m.RCode)
	}
}

func TestGarbageIsIgnoredOrRefusedNeverCrashes(t *testing.T) {
	z := ZoneFor(network(), &api.Interface{})
	for _, b := range [][]byte{nil, {1}, make([]byte, 12), {0, 7, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		z.Answer(b)
	}
}

// members gives db two named backends and one without a name.
func members() *api.NetworkState {
	n := network()
	n.Services[1].Backends = []api.Backend{
		{Interface: "if-1", Addr6: netip.MustParseAddr("fd00::21"), Addr4: netip.MustParseAddr("10.0.0.21"), Name: "db-1.db"},
		{Interface: "if-2", Addr6: netip.MustParseAddr("fd00::22"), Addr4: netip.MustParseAddr("10.0.0.22"), Name: "db-2.db"},
		{Interface: "if-3", Addr6: netip.MustParseAddr("fd00::23"), Addr4: netip.MustParseAddr("10.0.0.23")},
	}
	return n
}

func addrs(m dnsmessage.Message) []netip.Addr {
	var out []netip.Addr
	for _, a := range m.Answers {
		switch b := a.Body.(type) {
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(b.AAAA))
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(b.A))
		}
	}
	return out
}

func TestAMemberNameAnswersItsHoldersOwnAddresses(t *testing.T) {
	web := &api.Interface{Addr6: netip.MustParseAddr("fd00::100"), Addr4: netip.MustParseAddr("10.0.0.100"),
		Reach: []api.Reach{{Service: "svc-db", Proto: model.TCP}}}
	z := ZoneFor(members(), web)
	for name, want := range map[string]string{"db-1.db.shop.internal.": "fd00::21", "DB-2.db.shop.internal.": "fd00::22", "db.shop.internal.": "fd00::20"} {
		if _, m := ask(t, z, name, dnsmessage.TypeAAAA); len(addrs(m)) != 1 || addrs(m)[0] != netip.MustParseAddr(want) {
			t.Errorf("AAAA %s: %v %v, want %s", name, m.RCode, addrs(m), want)
		}
	}
	if _, m := ask(t, z, "db-1.db.shop.internal.", dnsmessage.TypeA); len(addrs(m)) != 1 || addrs(m)[0] != netip.MustParseAddr("10.0.0.21") {
		t.Errorf("A db-1: %v", addrs(m))
	}
	// Only a member's own name answers it.
	for _, name := range []string{"if-3.db.shop.internal.", "db-3.db.shop.internal.", "db-1.api.shop.internal.", "x.db-1.db.shop.internal."} {
		if _, m := ask(t, z, name, dnsmessage.TypeAAAA); m.RCode != dnsmessage.RCodeNameError {
			t.Errorf("%s: %v %v", name, m.RCode, addrs(m))
		}
	}

	// An IPv6-only client gets no A record for a member either.
	v6 := &api.Interface{Addr6: netip.MustParseAddr("fd00::101"), Reach: []api.Reach{{Service: "svc-db"}}}
	if _, m := ask(t, ZoneFor(members(), v6), "db-1.db.shop.internal.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Errorf("A db-1 for an IPv6-only client: %v %v", m.RCode, addrs(m))
	}

	// A client that may not reach db learns none of its members.
	other := &api.Interface{Addr6: netip.MustParseAddr("fd00::102"), Reach: []api.Reach{{Service: "svc-api"}}}
	if _, m := ask(t, ZoneFor(members(), other), "db-1.db.shop.internal.", dnsmessage.TypeAAAA); m.RCode != dnsmessage.RCodeNameError {
		t.Errorf("db-1 from a client that may not reach db: %v %v", m.RCode, addrs(m))
	}
}

func TestAMemberAnswersItsOwnNameWhateverItReaches(t *testing.T) {
	self := &api.Interface{Addr6: netip.MustParseAddr("fd00::21"), Addr4: netip.MustParseAddr("10.0.0.21"), Name: "db-1.db"}
	z := ZoneFor(members(), self)
	_, m := ask(t, z, "db-1.db.shop.internal.", dnsmessage.TypeALL)
	if got := addrs(m); len(got) != 2 || got[0] != self.Addr6 || got[1] != self.Addr4 {
		t.Fatalf("its own name: %v %v", m.RCode, got)
	}
	// Its service lies above its name, so the service's name exists with no
	// records, though the member may not reach it.
	if _, m := ask(t, z, "db.shop.internal.", dnsmessage.TypeAAAA); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("db from a member that may not reach it: %v %v", m.RCode, addrs(m))
	}
	// Its peers' names are another matter.
	if _, m := ask(t, z, "db-2.db.shop.internal.", dnsmessage.TypeAAAA); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("db-2 from a member that may not reach db: %v %v", m.RCode, addrs(m))
	}
}
