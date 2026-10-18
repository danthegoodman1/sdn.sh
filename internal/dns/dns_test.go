package dns

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
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
