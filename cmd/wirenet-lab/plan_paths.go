package main

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/bench"
)

// pathResult is one path's measurements.
type pathResult struct {
	Path string `json:"path"`
	// One and Many are one stream and the configured stream count, each
	// with the middle box's CPU over the same window.
	One     bench.Stream `json:"one_stream"`
	CPUOne  bench.CPU    `json:"middle_cpu_one_stream"`
	Many    bench.Stream `json:"many_streams"`
	CPUMany bench.CPU    `json:"middle_cpu_many_streams"`
	// Idle is round trips alone; Loaded is round trips while Load
	// saturates the same path.
	Idle   bench.RR     `json:"rr_idle"`
	Loaded bench.RR     `json:"rr_loaded"`
	Load   bench.Stream `json:"loading_stream"`
}

// measurePath runs every measurement from a client in aNS on a to a server
// in bNS on b.
func (r *run) measurePath(name string, a Node, aNS string, b Node, bNS string, to netip.AddrPort) (pathResult, error) {
	res := pathResult{Path: name}
	srv, err := r.serve(b, bNS, to, b.Name)
	if err != nil {
		return res, err
	}
	defer srv.Stop(r.ctx)
	if _, err := r.reach(a, aNS, to, 30*time.Second); err != nil {
		return res, err
	}
	mid, d := r.env.Middle(), r.o.Duration
	stream := func(parallel int, d time.Duration, s *bench.Stream, extra ...string) error {
		return r.bench(a, s, append([]string{"stream", "--target", to.String(), "--netns=" + aNS, "--duration", d.String(), "--parallel", itoa(parallel)}, extra...)...)
	}
	// The stream and the middle box's CPU sample share one window.
	withCPU := func(parallel int, s *bench.Stream, c *bench.CPU) error {
		at := startAt()
		return together(
			func() error { return stream(parallel, d, s, "--at", at) },
			func() error { return r.bench(mid, c, "cpu", "--duration", d.String(), "--at", at) },
		)
	}
	rr := func(d time.Duration, out *bench.RR) error {
		return r.bench(a, out, "rr", "--target", to.String(), "--netns="+aNS, "--size", itoa(r.o.RRSize), "--duration", d.String())
	}
	r.logf("paths: %s, 1 stream", name)
	if err := withCPU(1, &res.One, &res.CPUOne); err != nil {
		return res, err
	}
	r.logf("paths: %s, %d streams", name, r.o.Streams)
	if err := withCPU(r.o.Streams, &res.Many, &res.CPUMany); err != nil {
		return res, err
	}
	r.logf("paths: %s, round trips idle and loaded", name)
	if err := rr(d, &res.Idle); err != nil {
		return res, err
	}
	// The round trips run inside the loading stream's window.
	lead := max(d/10, 300*time.Millisecond)
	if err := together(
		func() error { return stream(r.o.Streams, d, &res.Load) },
		func() error { r.sleep(lead); return rr(d-2*lead, &res.Loaded) },
	); err != nil {
		return res, err
	}
	r.check(res.Idle.Error == "" && res.Loaded.Error == "", "%s: round trips broke: idle %q, loaded %q", name, res.Idle.Error, res.Loaded.Error)
	return res, nil
}

func planPaths(r *run) error {
	hs := r.env.Hosts()
	a, b, mid := hs[0], hs[1], r.env.Middle()
	var results []pathResult
	// Whatever ran reaches the report, even when a later path fails.
	defer func() {
		r.data("paths", results)
		r.pathTables(results)
	}()

	// The plain-TCP ceiling comes first, between the hosts' own
	// addresses: every overlay figure is read against it.
	under, err := r.measurePath("plain TCP, no middle box", a, "", b, "", port(b.Addr))
	if err != nil {
		return err
	}
	r.setCeiling(a, b, under.One)
	r.setCeiling(a, b, under.Many)
	results = append(results, under)

	// The overlay through the relay on the middle box.
	if _, err := r.network("paths", []Node{mid}, []string{"client", "server"}, [2]string{"client", "server"}); err != nil {
		return err
	}
	srv, err := r.attach(b, "paths-server", "paths", "server")
	if err != nil {
		return err
	}
	cli, err := r.attach(a, "paths-client", "paths", "client")
	if err != nil {
		return err
	}
	before, err := r.metric(mid, "wirenet_relay_forwarded_bytes_total")
	if err != nil {
		return err
	}
	relay, err := r.measurePath("ciphertext relay", a, cli.Namespace, b, srv.Namespace, port(srv.Addr6))
	if err != nil {
		return err
	}
	results = append(results, relay)
	after, err := r.metric(mid, "wirenet_relay_forwarded_bytes_total")
	if err != nil {
		return err
	}
	// Verified by traffic: the relay forwarded at least what the
	// many-stream run carried.
	r.check(after-before >= float64(relay.Many.Bytes), "the relay on %s forwarded %.0f bytes, fewer than the %d its %d-stream run carried",
		mid.Name, after-before, relay.Many.Bytes, r.o.Streams)

	// The overlay through a WireGuard gateway on the same machine.
	gw, err := r.gateway(a, b, mid)
	defer r.gatewayDown(a, b, mid)
	if err != nil {
		return err
	}
	gate, err := r.measurePath("WireGuard-terminating gateway", a, gw.clientNS, b, gw.serverNS, gw.server)
	if err != nil {
		return err
	}
	results = append(results, gate)
	final, err := r.metric(mid, "wirenet_relay_forwarded_bytes_total")
	if err != nil {
		return err
	}
	r.check((final-after)*100 < float64(gate.Many.Bytes), "the relay forwarded %.0f bytes while the gateway path ran", final-after)
	return nil
}

func (r *run) pathTables(results []pathResult) {
	n := itoa(r.o.Streams)
	t := Table{
		Title:   "Throughput and middle-box CPU",
		Columns: []string{"Path", "1 stream", n + " streams", "Retransmits, " + n + " streams", "Middle-box CPU, " + n + " streams", "Carried per CPU-second"},
	}
	for _, p := range results {
		gbit := float64(p.Many.Bytes) * 8 / 1e9
		perCPU := "—"
		if p.CPUMany.Busy > 0 {
			perCPU = num(gbit/p.CPUMany.Busy, 2) + " Gbit"
		}
		t.Rows = append(t.Rows, []string{p.Path, mbit(p.One.BitsPerSecond), mbit(p.Many.BitsPerSecond),
			fmt.Sprint(p.Many.Retransmits), num(p.CPUMany.Busy, 1) + "s of " + num(p.CPUMany.Seconds, 0) + "s", perCPU})
	}
	t.Caption = fmt.Sprintf("Mean throughput over %v from bytes the server received. Middle-box CPU is busy time from /proc/stat on %s "+
		"(user, system, irq and softirq) over the same window; the plain-TCP row has the middle box off the path.", r.o.Duration, r.env.Middle().Name)
	r.rep.table(t)

	rt := Table{
		Title:   fmt.Sprintf("Round trips, %d-byte request and response", r.o.RRSize),
		Columns: []string{"Path", "p50 idle", "p99 idle", "max idle", "p50 loaded", "p99 loaded", "max loaded", "Loading stream"},
	}
	for _, p := range results {
		rt.Rows = append(rt.Rows, []string{p.Path, msec(p.Idle.Latency.P50), msec(p.Idle.Latency.P99), msec(p.Idle.Latency.Max),
			msec(p.Loaded.Latency.P50), msec(p.Loaded.Latency.P99), msec(p.Loaded.Latency.Max), mbit(p.Load.BitsPerSecond)})
	}
	rt.Caption = fmt.Sprintf("Loaded round trips run while %d streams saturate the same path. One connection each; its setup took %s.",
		r.o.Streams, connects(results))
	r.rep.table(rt)
	if len(results) >= 2 {
		r.rep.note("The relay added %s to the median idle round trip over plain TCP, and %s loaded.",
			msec(results[1].Idle.Latency.P50-results[0].Idle.Latency.P50), msec(results[1].Loaded.Latency.P50-results[0].Loaded.Latency.P50))
	}
	if len(results) == 3 {
		if g, rl := results[2].CPUMany.Busy, results[1].CPUMany.Busy; g > 0 && rl > 0 {
			rel := (float64(results[1].Many.Bytes) / rl) / (float64(results[2].Many.Bytes) / g)
			r.rep.note("The relay carried %.2f× the gateway's traffic per middle-box CPU-second.", rel)
		}
	}
	if r.env.Name() == "local" {
		r.rep.note("Every role shares one kernel in the local environment, so the middle-box CPU column is the whole machine's, both endpoints' encryption included, and the paths share its cores.")
	}
}

func connects(results []pathResult) string {
	var s []string
	for _, p := range results {
		s = append(s, msec(p.Idle.Connect))
	}
	return strings.Join(s, ", ")
}

// The gateway path: a WireGuard device on the middle box peers with one
// on each host and forwards between them, decrypting and re-encrypting.
// Its port lies above the relay's edge ports (10000-60000), the agents'
// listen ports (40000-59999) and the kernel's ephemeral range.
const (
	gwDev  = "wnbgw0"
	gwPort = 62000
)

type gatewayPath struct {
	clientNS, serverNS string
	server             netip.AddrPort
}

// gwKey is under /etc/wireguard, the one place AppArmor lets wg(8) read
// keys from on Ubuntu.
func gwKey(n Node) string { return "/etc/wireguard/wnbgw-" + n.Name + ".key" }

func (r *run) gateway(a, b, mid Node) (gatewayPath, error) {
	overlay := map[string]string{a.Name: "10.77.0.1", b.Name: "10.77.0.2", mid.Name: "10.77.0.254"}
	pub := map[string]string{}
	// Each machine mints its own key and shares only the public half.
	for _, n := range []Node{a, b, mid} {
		out, err := r.env.Exec(r.ctx, n, "sh", "-c", fmt.Sprintf("umask 077; mkdir -p /etc/wireguard && wg genkey > %[1]s && wg pubkey < %[1]s", gwKey(n)))
		if err != nil {
			return gatewayPath{}, err
		}
		pub[n.Name] = strings.TrimSpace(string(out))
	}
	endpoint := func(n Node) string { return netip.AddrPortFrom(n.Addr, gwPort).String() }
	type step struct {
		n    Node
		argv []string
	}
	steps := []step{
		{mid, []string{"ip", "link", "add", gwDev, "type", "wireguard"}},
		{mid, []string{"wg", "set", gwDev, "listen-port", itoa(gwPort), "private-key", gwKey(mid),
			"peer", pub[a.Name], "allowed-ips", overlay[a.Name] + "/32", "endpoint", endpoint(a),
			"peer", pub[b.Name], "allowed-ips", overlay[b.Name] + "/32", "endpoint", endpoint(b)}},
		{mid, []string{"ip", "addr", "add", overlay[mid.Name] + "/24", "dev", gwDev}},
		{mid, []string{"ip", "link", "set", gwDev, "mtu", itoa(r.o.MTU), "up"}},
		{mid, []string{"sysctl", "-qw", "net.ipv4.ip_forward=1"}},
	}
	for _, h := range []Node{a, b} {
		ns := r.env.ScratchNS(h)
		steps = append(steps,
			step{h, []string{"ip", "netns", "add", ns}},
			step{h, []string{"ip", "-n", ns, "link", "set", "lo", "up"}},
			// Created into the namespace from the host's, as the agent
			// creates a workload's device, so its socket stays on the host.
			step{h, []string{"ip", "link", "add", gwDev, "netns", ns, "type", "wireguard"}},
			step{h, []string{"ip", "netns", "exec", ns, "wg", "set", gwDev, "listen-port", itoa(gwPort), "private-key", gwKey(h),
				"peer", pub[mid.Name], "allowed-ips", "10.77.0.0/24", "endpoint", endpoint(mid)}},
			step{h, []string{"ip", "-n", ns, "addr", "add", overlay[h.Name] + "/24", "dev", gwDev}},
			step{h, []string{"ip", "-n", ns, "link", "set", gwDev, "mtu", itoa(r.o.MTU), "up"}},
		)
	}
	for _, s := range steps {
		if _, err := r.env.Exec(r.ctx, s.n, s.argv...); err != nil {
			return gatewayPath{}, err
		}
	}
	return gatewayPath{
		clientNS: r.env.ScratchNS(a), serverNS: r.env.ScratchNS(b),
		server: port(netip.MustParseAddr(overlay[b.Name])),
	}, nil
}

// gatewayDown removes the gateway path. The environment's purge removes
// anything a failed step leaves.
func (r *run) gatewayDown(a, b, mid Node) {
	steps := []struct {
		n    Node
		argv []string
	}{
		{a, []string{"ip", "netns", "del", r.env.ScratchNS(a)}},
		{b, []string{"ip", "netns", "del", r.env.ScratchNS(b)}},
		{mid, []string{"ip", "link", "del", gwDev}},
		{a, []string{"rm", "-f", gwKey(a)}},
		{b, []string{"rm", "-f", gwKey(b)}},
		{mid, []string{"rm", "-f", gwKey(mid)}},
	}
	for _, s := range steps {
		if _, err := r.env.Exec(r.ctx, s.n, s.argv...); err != nil {
			r.logf("removing the gateway path: %v", err)
		}
	}
}
