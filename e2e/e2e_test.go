//go:build linux

// Package e2e runs the real daemons in a namespace lab. It needs root:
//
//	scripts/e2e            # builds as you, runs the tests under sudo
package e2e

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/lab"
	"sdn.sh/internal/model"
)

// newLab starts a lab for one test, named for it so a crashed run's leftovers
// are purged by the next.
func newLab(t *testing.T, name string, cpArgs ...string) *lab.Lab {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: scripts/e2e")
	}
	bin := os.Getenv("SDN_LAB_BIN")
	if bin == "" {
		var err error
		if bin, err = lab.Build(t.TempDir()); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	store := "memory"
	if dsn := os.Getenv("SDN_TEST_POSTGRES"); dsn != "" {
		store = dsn
	}
	l, err := lab.New(lab.Options{Name: name, Dir: dir, Bin: bin, Store: store, CPArgs: cpArgs, Log: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(l.Logs(40))
			if keep := os.Getenv("SDN_LAB_KEEP"); keep != "" {
				os.CopyFS(filepath.Join(keep, name), os.DirFS(dir))
			}
		}
		l.Close()
	})
	return l
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(b), "\n"))
	return len(b), nil
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// fastClocks keeps lease and drain clocks short enough for a test.
var fastClocks = []string{"--lease-ttl", "6s", "--drain-grace", "2s", "--quarantine4", "4s", "--retention", "30s", "--poll-timeout", "5s"}

// mustNotReach asserts a connection fails, both refused and silent drops
// counting as failure.
func mustNotReach(t *testing.T, ns string, addr netip.AddrPort, why string) {
	t.Helper()
	if got, err := lab.Dial(ns, addr, 1500*time.Millisecond); err == nil {
		t.Errorf("%s: reached %v, which answered %q", why, addr, got)
	}
}

func TestTwoHostsReachEachOtherThroughARelayAndNothingElse(t *testing.T) {
	l := newLab(t, "e2ea", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "prod", Prefix4: netip.MustParsePrefix("10.100.0.0/16"), Relays: []model.RelayID{relay.ID}}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "web", IPv4: true}))
	db := must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "db", IPv4: true}))
	must(l.Admin.CreateRule(ctx, "prod", api.CreateRule{From: "web", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))

	dbIf := must(h2.Attach(ctx, "db-1", "prod", "db"))
	webIf := must(h1.Attach(ctx, "web-1", "prod", "web"))
	t.Logf("db %s in %s at %v/%v; web %s in %s", dbIf.Interface, dbIf.Namespace, dbIf.Addr6, dbIf.Addr4, webIf.Interface, webIf.Namespace)
	for _, a := range []netip.Addr{dbIf.Addr6, dbIf.Addr4} {
		must(lab.Serve(dbIf.Namespace, netip.AddrPortFrom(a, 5432), "db"))
		must(lab.Serve(dbIf.Namespace, netip.AddrPortFrom(a, 2222), "secret"))
	}
	must(lab.Serve(webIf.Namespace, netip.AddrPortFrom(webIf.Addr6, 8080), "web"))

	// Through the service address in each family, and to the backend's own
	// address.
	for _, addr := range []netip.Addr{db.Addr6, db.Addr4, dbIf.Addr6, dbIf.Addr4} {
		got, err := lab.DialUntil(webIf.Namespace, netip.AddrPortFrom(addr, 5432), 20*time.Second)
		if err != nil || got != "db" {
			t.Fatalf("web to %v: %q %v", addr, got, err)
		}
	}

	// Policy names port 5432 alone, and web to db alone.
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(dbIf.Addr6, 2222), "a port the rule does not name, IPv6")
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(dbIf.Addr4, 2222), "a port the rule does not name, IPv4")
	mustNotReach(t, dbIf.Namespace, netip.AddrPortFrom(webIf.Addr6, 8080), "the reverse direction")
	// The underlay, the relay and the control plane are out of reach.
	mustNotReach(t, webIf.Namespace, netip.MustParseAddrPort("10.213.255.1:18443"), "the control plane, IPv4")
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(relay.Addr, 9092), "the relay, IPv4")
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(relay.Addr6, 9092), "the relay, IPv6")
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(h1.Addr, 9091), "its own host's agent, IPv4")

	// The data path ran through the relay, which forwarded and admitted
	// registrations.
	m := must(lab.Metrics(relay.Telemetry))
	if v := metric(m, `sdn_relay_forwarded_packets_total`); v == 0 {
		t.Errorf("the relay forwarded nothing:\n%s", grep(m, "sdn_relay"))
	}
	if v := metric(m, `sdn_relay_registrations_total{result="accepted"}`); v < 2 {
		t.Errorf("the relay accepted %v registrations, want both directions", v)
	}
	am := must(lab.Metrics(h1.Telemetry))
	if v := metric(am, `sdn_agent_local_calls_total{call="attach",result="ok"}`); v != 1 {
		t.Errorf("agent attach count %v", v)
	}

	// Revocation reaches the peer: db's host removes web, so web reaches
	// nothing, though its own host may still hold it.
	if err := l.Admin.Revoke(ctx, webIf.Interface); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := lab.Dial(webIf.Namespace, netip.AddrPortFrom(dbIf.Addr6, 5432), time.Second)
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a revoked interface still reaches db")
		}
		time.Sleep(200 * time.Millisecond)
	}
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(db.Addr4, 5432), "a revoked interface, IPv4 service")
}

// metric returns a sample's value from metrics text, summing every series
// whose name and labels start with sel.
func metric(text, sel string) float64 {
	var sum float64
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, strings.TrimSuffix(sel, "}")) {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(f[len(f)-1], 64)
		if err == nil {
			sum += v
		}
	}
	return sum
}

func grep(text, pattern string) string {
	re := regexp.MustCompile(pattern)
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if re.MatchString(line) && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

