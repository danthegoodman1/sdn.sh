//go:build linux

// Package e2e runs the real daemons in a namespace lab. It needs root:
//
//	scripts/e2e            # builds as you, runs the tests under sudo
package e2e

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"sdn.sh/internal/api"
	"sdn.sh/internal/devconf"
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
		}
		if keep := os.Getenv("SDN_LAB_KEEP"); keep != "" && (t.Failed() || os.Getenv("SDN_LAB_KEEP_ALWAYS") != "") {
			keepFiles(dir, filepath.Join(keep, name))
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

func TestWorkloadsResolveTheServicesTheyMayReach(t *testing.T) {
	l := newLab(t, "e2eh", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "shop", Prefix4: netip.MustParsePrefix("10.101.0.0/16"), Relays: []model.RelayID{relay.ID}}))
	must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "web", IPv4: true}))
	must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "edge"}))
	db := must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "db", IPv4: true}))
	must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "admin"}))
	for _, from := range []string{"web", "edge"} {
		must(l.Admin.CreateRule(ctx, "shop", api.CreateRule{From: from, To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))
	}
	dbIf := must(h2.Attach(ctx, "db-1", "shop", "db"))
	must(lab.Serve(dbIf.Namespace, netip.AddrPortFrom(dbIf.Addr6, 5432), "db"))
	web := must(h1.Attach(ctx, "web-1", "shop", "web"))
	edge := must(h1.Attach(ctx, "edge-1", "shop", "edge"))
	if web.Resolver.String() != "127.0.0.53" || web.Search != "shop.internal" {
		t.Fatalf("the agent told the runtime resolver %v, search %q", web.Resolver, web.Search)
	}
	name := "db.shop.internal."
	var got []netip.Addr
	deadline := time.Now().Add(10 * time.Second)
	for {
		var err error
		got, _, err = lab.Lookup(web.Namespace, name, dnsmessage.TypeAAAA)
		if err == nil && len(got) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("AAAA %s from web: %v %v", name, got, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got[0] != db.Addr6 {
		t.Fatalf("AAAA %s = %v, want %v", name, got, db.Addr6)
	}
	if a, _, err := lab.Lookup(web.Namespace, name, dnsmessage.TypeA); err != nil || len(a) != 1 || a[0] != db.Addr4 {
		t.Fatalf("A %s from an IPv4 client: %v %v", name, a, err)
	}
	// edge's service has no IPv4, so it gets no A record.
	if a, rc, err := lab.Lookup(edge.Namespace, name, dnsmessage.TypeA); err != nil || len(a) != 0 || rc != dnsmessage.RCodeSuccess {
		t.Fatalf("A %s from an IPv6-only client: %v %v %v", name, a, rc, err)
	}
	// No rule names admin, so it does not exist for web.
	if _, rc, err := lab.Lookup(web.Namespace, "admin.shop.internal.", dnsmessage.TypeAAAA); err != nil || rc != dnsmessage.RCodeNameError {
		t.Fatalf("admin from web: %v %v", rc, err)
	}
	// The resolved address carries traffic.
	if got, err := lab.DialUntil(web.Namespace, netip.AddrPortFrom(got[0], 5432), 10*time.Second); err != nil || got != "db" {
		t.Fatalf("dialing the resolved address: %q %v", got, err)
	}
	// A restarted agent serves names again.
	if err := h1.Restart(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		a, _, err := lab.Lookup(web.Namespace, name, dnsmessage.TypeAAAA)
		if err == nil && len(a) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the agent restarted: %v %v", a, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestAQuerySentWhileTheAgentRestartsWaitsAndIsAnswered runs the agent
// under systemd with a descriptor store: the resolver's sockets outlive the
// agent, so a query sent while it is down waits in the socket's buffer.
func TestAQuerySentWhileTheAgentRestartsWaitsAndIsAnswered(t *testing.T) {
	l := newLab(t, "e2ei", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddSystemdHost(ctx, "h1"))
	svc := webDB(t, l, relay)
	attachDB(t, h1, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	name := "db.prod.internal."
	lookup := func() ([]netip.Addr, error) {
		a, _, err := lab.Lookup(web.Namespace, name, dnsmessage.TypeAAAA)
		return a, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if a, err := lookup(); err == nil && len(a) == 1 && a[0] == svc.Addr6 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the resolver never answered")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := sh("systemctl", "kill", "--signal=KILL", "--kill-whom=main", h1.Unit); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	a, _, err := lab.LookupWithin(web.Namespace, name, dnsmessage.TypeAAAA, 10*time.Second)
	if err != nil || len(a) != 1 || a[0] != svc.Addr6 {
		t.Fatalf("a query sent during the restart: %v %v", a, err)
	}
	t.Logf("a query sent as the agent died was answered after %v", time.Since(start))
}

func sh(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %v: %s", args, err, out)
	}
	return nil
}

func TestAnEgressGrantReachesTheInternetOnItsPortsAlone(t *testing.T) {
	l := newLab(t, "e2ej", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "prod", Relays: []model.RelayID{relay.ID}}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "web"}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "batch"}))
	grant := must(l.Admin.CreateRule(ctx, "prod", api.CreateRule{From: "web", To: api.Internet, Proto: model.TCP, Ports: model.PortRange{Lo: 80, Hi: 80}}))
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	batch := must(h1.Attach(ctx, "batch-1", "prod", "batch"))
	for _, a := range []netip.Addr{lab.Internet4, lab.Internet6, netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("fd00:ec2::254")} {
		must(lab.Serve(l.Underlay(), netip.AddrPortFrom(a, 80), "internet"))
		must(lab.Serve(l.Underlay(), netip.AddrPortFrom(a, 22), "ssh"))
	}
	for _, a := range []netip.Addr{lab.Internet4, lab.Internet6} {
		got, err := lab.DialUntil(web.Namespace, netip.AddrPortFrom(a, 80), 10*time.Second)
		if err != nil || got != "internet" {
			t.Fatalf("web to %v:80: %q %v", a, got, err)
		}
		mustNotReach(t, web.Namespace, netip.AddrPortFrom(a, 22), "a port the grant does not name")
		mustNotReach(t, batch.Namespace, netip.AddrPortFrom(a, 80), "a workload with no grant")
	}
	for _, addr := range []netip.AddrPort{
		netip.MustParseAddrPort("169.254.169.254:80"),
		netip.MustParseAddrPort("[fd00:ec2::254]:80"),
		netip.AddrPortFrom(relay.Addr, 9092),
		netip.AddrPortFrom(relay.Addr6, 9092),
		netip.AddrPortFrom(h1.Addr, 9091),
		netip.AddrPortFrom(h2.Addr, 9091),
		netip.AddrPortFrom(h1.Addr6, 9091),
		netip.MustParseAddrPort("10.213.255.1:18443"),
	} {
		mustNotReach(t, web.Namespace, addr, "an egress link to what it must never reach")
	}
	// Taking the grant away closes the path.
	if err := l.Admin.DeleteRule(ctx, "prod", grant.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := lab.Dial(web.Namespace, netip.AddrPortFrom(lab.Internet4, 80), time.Second); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the internet stayed reachable after the grant went")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// laptop registers a development machine behind gw and brings it up from
// its generated config, minting the key here as sdnctl does.
func laptop(t *testing.T, l *lab.Lab, name string, gw model.InterfaceID, ttl time.Duration) (*lab.Laptop, api.DeviceConfig) {
	t.Helper()
	priv := must(model.NewPrivateKey(crand.Reader))
	cfg := must(l.Admin.CreateDevice(context.Background(), "prod", api.CreateDevice{Service: "dev", Gateway: gw, PublicKey: priv.Public(), TTL: ttl}))
	lp := must(l.AddLaptop(name, devconf.WGQuick(priv, cfg)))
	return lp, cfg
}

func TestADevelopmentMachineReachesServicesThroughItsGatewayAndLosesThemOnRevocation(t *testing.T) {
	l := newLab(t, "e2ek", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddGatewayHost(ctx, "h2"))
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "prod", Relays: []model.RelayID{relay.ID}}))
	db := must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "db"}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "gw"}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "dev"}))
	must(l.Admin.CreateRule(ctx, "prod", api.CreateRule{From: "dev", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))
	gw := must(h2.AttachGateway(ctx, "gw-1", "prod", "gw"))
	db1 := must(h1.Attach(ctx, "db-1", "prod", "db"))
	must(lab.ServeRemote(db1.Namespace, netip.AddrPortFrom(db1.Addr6, 5432)))
	must(lab.Serve(db1.Namespace, netip.AddrPortFrom(db1.Addr6, 2222), "secret"))

	lp, cfg := laptop(t, l, "lap1", gw.Interface, time.Hour)
	if cfg.DNS != gw.Addr6 || cfg.Domain != "prod.internal" {
		t.Fatalf("the config names resolver %v and domain %q", cfg.DNS, cfg.Domain)
	}
	// By name, through the gateway's resolver.
	var addrs []netip.Addr
	deadline := time.Now().Add(15 * time.Second)
	for {
		var err error
		addrs, _, err = lab.LookupAt(lp.NS, cfg.DNS, "db.prod.internal.", dnsmessage.TypeAAAA)
		if err == nil && len(addrs) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the laptop never resolved db: %v %v", addrs, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if addrs[0] != db.Addr6 {
		t.Fatalf("db resolved to %v, want %v", addrs[0], db.Addr6)
	}
	// The backend sees the laptop's own address as the source.
	got, err := lab.DialUntil(lp.NS, netip.AddrPortFrom(addrs[0], 5432), 15*time.Second)
	if err != nil || got != cfg.Addr6.String() {
		t.Fatalf("laptop to db: %q %v, want the source %v", got, err, cfg.Addr6)
	}
	mustNotReach(t, lp.NS, netip.AddrPortFrom(db1.Addr6, 2222), "a port policy does not name")
	// Laptops take replies alone: a backend cannot open a flow to one.
	must(lab.Serve(lp.NS, netip.AddrPortFrom(cfg.Addr6, 8080), "laptop"))
	mustNotReach(t, db1.Namespace, netip.AddrPortFrom(cfg.Addr6, 8080), "a backend opening a flow to a laptop")

	// A second laptop sending as the first is dropped at the gateway.
	spoof, cfg2 := laptop(t, l, "lap2", gw.Interface, time.Hour)
	if err := lab.Exec(spoof.NS, "ip", "addr", "replace", netip.PrefixFrom(cfg.Addr6, 128).String(), "dev", "wg0"); err != nil {
		t.Fatal(err)
	}
	if err := lab.Exec(spoof.NS, "ip", "addr", "del", netip.PrefixFrom(cfg2.Addr6, 128).String(), "dev", "wg0"); err != nil {
		t.Fatal(err)
	}
	mustNotReach(t, spoof.NS, netip.AddrPortFrom(db.Addr6, 5432), "one laptop sending as another")

	// A backend replacement needs no new config.
	db2 := must(h1.Attach(ctx, "db-2", "prod", "db"))
	must(lab.Serve(db2.Namespace, netip.AddrPortFrom(db2.Addr6, 5432), "db-2"))
	must(h1.Detach(ctx, db1.Interface))
	deadline = time.Now().Add(15 * time.Second)
	for {
		got, err := lab.Dial(lp.NS, netip.AddrPortFrom(db.Addr6, 5432), time.Second)
		if err == nil && got == "db-2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the replacement the laptop reached %q (%v)", got, err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Revocation, with no grace period.
	if err := l.Admin.Revoke(ctx, cfg.Interface); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, err := lab.Dial(lp.NS, netip.AddrPortFrom(db.Addr6, 5432), time.Second); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a revoked laptop still reaches db")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
