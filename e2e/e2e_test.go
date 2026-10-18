//go:build linux

// Package e2e runs the real daemons in a namespace lab. It needs root:
//
//	scripts/e2e            # builds as you, runs the tests under sudo
package e2e

import (
	"context"
	"errors"
	"fmt"
	"net"
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
				keepFiles(dir, filepath.Join(keep, name))
			}
		}
		l.Close()
	})
	return l
}

// keepFiles copies a failed lab's regular files, its logs among them.
func keepFiles(from, to string) {
	filepath.WalkDir(from, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(from, path)
		b, err := os.ReadFile(path)
		if err == nil {
			os.MkdirAll(filepath.Dir(filepath.Join(to, rel)), 0o755)
			os.WriteFile(filepath.Join(to, rel), b, 0o644)
		}
		return nil
	})
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

	start := time.Now()
	dbIf := must(h2.Attach(ctx, "db-1", "prod", "db"))
	t.Logf("db attached in %v", time.Since(start))
	start = time.Now()
	webIf := must(h1.Attach(ctx, "web-1", "prod", "web"))
	t.Logf("web attached in %v", time.Since(start))
	t.Logf("db %s in %s at %v/%v; web %s in %s", dbIf.Interface, dbIf.Namespace, dbIf.Addr6, dbIf.Addr4, webIf.Interface, webIf.Namespace)
	for _, a := range []netip.Addr{dbIf.Addr6, dbIf.Addr4} {
		must(lab.Serve(dbIf.Namespace, netip.AddrPortFrom(a, 5432), "db"))
		must(lab.Serve(dbIf.Namespace, netip.AddrPortFrom(a, 2222), "secret"))
	}
	must(lab.Serve(webIf.Namespace, netip.AddrPortFrom(webIf.Addr6, 8080), "web"))

	// Through the service address in each family, and to the backend's own
	// address.
	for _, addr := range []netip.Addr{db.Addr6, db.Addr4, dbIf.Addr6, dbIf.Addr4} {
		took, got, err := timeToReach(webIf.Namespace, netip.AddrPortFrom(addr, 5432), 20*time.Second)
		if err != nil || got != "db" {
			t.Fatalf("web to %v: %q %v", addr, got, err)
		}
		t.Logf("web reached %v after %v", addr, took)
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

// webDB creates network prod over relays, with web allowed to reach db on
// 5432, IPv6 only.
func webDB(t *testing.T, l *lab.Lab, relays ...*lab.Relay) api.ServiceInfo {
	t.Helper()
	ctx := context.Background()
	var ids []model.RelayID
	for _, r := range relays {
		ids = append(ids, r.ID)
	}
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "prod", Relays: ids}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "web"}))
	db := must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "db"}))
	must(l.Admin.CreateRule(ctx, "prod", api.CreateRule{From: "web", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))
	return db
}

// attachDB attaches a db backend that answers with its name.
func attachDB(t *testing.T, h *lab.Host, name string) api.LocalInterface {
	t.Helper()
	i := must(h.Attach(context.Background(), name, "prod", "db"))
	must(lab.Serve(i.Namespace, netip.AddrPortFrom(i.Addr6, 5432), name))
	return i
}

// timeToReach measures how long until a fresh connection from ns reaches
// addr, trying every 50ms.
func timeToReach(ns string, addr netip.AddrPort, limit time.Duration) (time.Duration, string, error) {
	start := time.Now()
	for time.Since(start) < limit {
		got, err := lab.Dial(ns, addr, 300*time.Millisecond)
		if err == nil {
			return time.Since(start), got, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return 0, "", fmt.Errorf("unreachable for %v", limit)
}

func TestAnAgentKilledMidLifeAdoptsItsInterfacesAndLeaksNothing(t *testing.T) {
	l := newLab(t, "e2eb", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	svc := webDB(t, l, relay)
	attachDB(t, h2, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	portsBefore := must(h1.DevicePorts())

	// The data path outlives the agent.
	h1.Agent.Kill()
	if got, err := lab.Dial(web.Namespace, dbAddr, 2*time.Second); err != nil || got != "db-1" {
		t.Fatalf("with the agent dead: %q %v", got, err)
	}
	if err := h1.Restart(); err != nil {
		t.Fatal(err)
	}
	// Attaching the same workload name returns the interface it has.
	again := must(h1.Attach(ctx, "web-1", "prod", "web"))
	if again.Interface != web.Interface || again.Namespace != web.Namespace {
		t.Fatalf("a retried attach built %s, want %s", again.Interface, web.Interface)
	}
	web2 := must(h1.Attach(ctx, "web-2", "prod", "web"))
	for _, ns := range []string{web.Namespace, web2.Namespace} {
		if _, err := lab.DialUntil(ns, dbAddr, 20*time.Second); err != nil {
			t.Fatalf("%s after restart: %v", ns, err)
		}
	}
	// Detaching removes the namespace and frees the device's port.
	must(h1.Detach(ctx, web2.Interface))
	if ns := h1.Namespaces(); len(ns) != 1 || ns[0] != web.Namespace {
		t.Fatalf("namespaces after detach: %v", ns)
	}
	if ports := must(h1.DevicePorts()); !equalPorts(ports, portsBefore) {
		t.Fatalf("device ports %v after detach, %v before the second attach", ports, portsBefore)
	}
	// A detach the caller lost the answer to answers that the interface
	// is gone.
	var ae *api.Error
	if _, err := h1.Detach(ctx, web2.Interface); !errors.As(err, &ae) || ae.Code != api.CodeNotFound {
		t.Fatalf("a retried detach: %v", err)
	}
}

func equalPorts(a, b []uint16) bool {
	set := func(s []uint16) map[uint16]bool {
		m := map[uint16]bool{}
		for _, p := range s {
			m[p] = true
		}
		return m
	}
	x, y := set(a), set(b)
	if len(x) != len(y) {
		return false
	}
	for p := range x {
		if !y[p] {
			return false
		}
	}
	return true
}

func TestTrafficFailsOverWhenTheActiveRelayDies(t *testing.T) {
	l := newLab(t, "e2ec", fastClocks...)
	ctx := context.Background()
	r1 := must(l.AddRelay(ctx, "r1"))
	r2 := must(l.AddRelay(ctx, "r2"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	svc := webDB(t, l, r1, r2)
	attachDB(t, h2, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	if metric(must(lab.Metrics(r1.Telemetry)), "sdn_relay_forwarded_packets_total") == 0 {
		t.Fatal("traffic did not start on the first relay of the set")
	}
	r1.Kill()
	took, _, err := timeToReach(web.Namespace, dbAddr, 15*time.Second)
	if err != nil {
		t.Fatalf("no failover: %v", err)
	}
	t.Logf("failover: a new connection reached db %v after the active relay died", took)
	if metric(must(lab.Metrics(r2.Telemetry)), "sdn_relay_forwarded_packets_total") == 0 {
		t.Fatal("the standby relay forwarded nothing")
	}
	if took > 3*time.Second {
		t.Errorf("failover took %v", took)
	}
}

func TestARelayRestartsFromItsDisk(t *testing.T) {
	// A long registration period: only the relay's disk can restore the
	// directions within the test.
	l := newLab(t, "e2ed", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1", "--register-every", "5m"))
	h2 := must(l.AddHost(ctx, "h2", "--register-every", "5m"))
	svc := webDB(t, l, relay)
	attachDB(t, h2, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	relay.Kill()
	if err := relay.Start(); err != nil {
		t.Fatal(err)
	}
	took, _, err := timeToReach(web.Namespace, dbAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("after the relay restarted: %v", err)
	}
	t.Logf("a restarted relay carried traffic again after %v", took)
	m := must(lab.Metrics(relay.Telemetry))
	if v := metric(m, `sdn_relay_registrations_total{result="accepted"}`); v != 0 {
		t.Errorf("the restarted relay needed %v registrations", v)
	}
}

func TestCoLocatedInterfacesPeerOverTheHostLoopback(t *testing.T) {
	l := newLab(t, "e2ee", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	svc := webDB(t, l, relay)
	attachDB(t, h1, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	if _, err := lab.DialUntil(web.Namespace, netip.AddrPortFrom(svc.Addr6, 5432), 20*time.Second); err != nil {
		t.Fatal(err)
	}
	if v := metric(must(lab.Metrics(relay.Telemetry)), "sdn_relay_forwarded_packets_total"); v != 0 {
		t.Errorf("the relay forwarded %v packets between interfaces on one host", v)
	}
}

func TestAReplacedBackendKeepsItsConnectionsUntilTheGracePeriodEnds(t *testing.T) {
	l := newLab(t, "e2ef", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	svc := webDB(t, l, relay)
	old := attachDB(t, h2, "db-old")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	var held net.Conn
	if err := lab.InNS(web.Namespace, func() error {
		var err error
		held, err = net.DialTimeout("tcp", dbAddr.String(), 2*time.Second)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	attachDB(t, h2, "db-new")
	must(h2.Detach(ctx, old.Interface))
	// New connections reach the new backend.
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := lab.Dial(web.Namespace, dbAddr, time.Second)
		if err == nil && got == "db-new" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("new connections still reach %q (%v)", got, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := held.Write([]byte("still there")); err != nil {
		t.Fatalf("the held connection broke before the grace period ended: %v", err)
	}
}

func TestARelayPeerWithoutKeepaliveHoldsItsNATMappingByRegistering(t *testing.T) {
	l := newLab(t, "e2eg", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	// db sits behind a NAT that forgets an idle mapping after 3 seconds and
	// gives every new mapping a fresh port; its agent registers every
	// second.
	h2 := must(l.AddHostBehindNAT(ctx, "h2", lab.NAT{UDPTimeout: 3 * time.Second, Random: true}, "--register-every", "1s"))
	svc := webDB(t, l, relay)
	attachDB(t, h2, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	// Idle well past the NAT's timeout: no keepalive runs on relay peers,
	// so only registrations keep db reachable.
	time.Sleep(8 * time.Second)
	if took, _, err := timeToReach(web.Namespace, dbAddr, 5*time.Second); err != nil {
		t.Fatalf("db unreachable after idling behind its NAT: %v", err)
	} else {
		t.Logf("after idling: reached db in %v", took)
	}
	// The NAT forgets everything; db's next registration arrives from a new
	// port, and the relay follows it.
	if err := h2.FlushNAT(); err != nil {
		t.Fatal(err)
	}
	took, _, err := timeToReach(web.Namespace, dbAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("after the NAT rebound: %v", err)
	}
	t.Logf("after the NAT rebound: reached db in %v", took)
}
