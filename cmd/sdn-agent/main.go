// Command sdn-agent runs the host agent: it builds workload interfaces on
// request, reconciles them against the control plane's desired state, and
// keeps their relay directions registered.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	agentcore "sdn.sh/internal/agent/core"
	"sdn.sh/internal/agent/daemon"
	"sdn.sh/internal/agent/journal"
	"sdn.sh/internal/agent/localapi"
	"sdn.sh/internal/agent/resolver"
	"sdn.sh/internal/agent/underlay"
	"sdn.sh/internal/api"
	"sdn.sh/internal/cpclient"
	"sdn.sh/internal/kernel/linux"
	"sdn.sh/internal/model"
	"sdn.sh/internal/telemetry"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sdn-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := daemon.DefaultConfig("")
	cpURL := flag.String("cp", "", "control plane URL")
	credsFile := flag.String("credentials", "/etc/sdn/host.json", `the host's credentials, {"id": ..., "token": ...}`)
	caFile := flag.String("ca-file", "", "trust only this CA for the control plane")
	journalDir := flag.String("journal", "/var/lib/sdn/journal", "journal directory")
	socket := flag.String("socket", "/run/sdn/agent.sock", "local API socket")
	telemetryAddr := flag.String("telemetry", ":9091", "metrics, health and pprof address")
	probeAddr := flag.String("probe-addr", ":0", "address relay probes are sent from")
	serveDNS := flag.Bool("resolver", true, "serve each workload's stub resolver on 127.0.0.53")
	egress := flag.Bool("egress", true, "serve internet egress grants: turns on IPv4 forwarding and installs the host's egress filter")
	var blocked prefixList
	flag.Var(&blocked, "egress-block", "a prefix egress links never reach, beyond the defaults and the host's own; repeatable")
	upstream := flag.String("upstream-resolver", "", "resolver for names outside every network (default: the first nameserver in /etc/resolv.conf)")
	logLevel := flag.String("log-level", "info", "debug, info, warn or error")
	logFormat := flag.String("log-format", "", "json or console (default: console on a terminal)")
	portLo := flag.Uint("port-lo", uint(cfg.Core.PortLo), "lowest listen port a device binds")
	portHi := flag.Uint("port-hi", uint(cfg.Core.PortHi), "highest listen port a device binds")
	flag.StringVar(&cfg.Core.Prefix, "prefix", cfg.Core.Prefix, "prefix of every namespace the agent creates")
	flag.DurationVar(&cfg.Core.DrainGrace, "drain-grace", cfg.Core.DrainGrace, "how long a released peer stays installed")
	flag.DurationVar(&cfg.RenewEvery, "renew-every", cfg.RenewEvery, "lease renewal period")
	flag.DurationVar(&cfg.Core.RegisterEvery, "register-every", cfg.Core.RegisterEvery, "registration period, which must undercut the shortest NAT idle timeout on the path")
	flag.IntVar(&cfg.Core.RegisterRetries, "register-retries", cfg.Core.RegisterRetries, "times a new direction's registration is sent again, in case it reached a relay before the relay bound the port")
	flag.DurationVar(&cfg.Core.Keepalive, "keepalive", cfg.Core.Keepalive, "persistent-keepalive interval on paths that carry one")
	flag.IntVar(&cfg.Workers, "workers", cfg.Workers, "namespaces configured at once")
	flag.Parse()
	cfg.Core.PortLo, cfg.Core.PortHi = uint16(*portLo), uint16(*portHi)

	log, err := telemetry.NewLogger("agent", telemetry.LogConfig{Level: *logLevel, Format: *logFormat})
	if err != nil {
		return err
	}
	if *cpURL == "" {
		return errors.New("--cp is required")
	}
	var creds api.Credentials
	b, err := os.ReadFile(*credsFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &creds); err != nil || creds.ID == "" || creds.Token == "" {
		return fmt.Errorf("%s: want {\"id\": ..., \"token\": ...}", *credsFile)
	}
	cfg.Core.Host = model.HostID(creds.ID)
	log = log.With().Str("host", creds.ID).Logger()

	kern, err := linux.New()
	if err != nil {
		return err
	}
	defer kern.Close()
	// Removing a peer destroys the sockets addressed to it; a kernel that
	// cannot would leave flows reaching whoever holds the address next.
	if err := kern.CheckDestroy(); err != nil {
		return fmt.Errorf("the kernel cannot destroy sockets (CONFIG_INET_DIAG_DESTROY): %w", err)
	}
	j, err := journal.Open(*journalDir)
	if err != nil {
		return err
	}
	cp, err := cpclient.New(*cpURL, creds.Token, cpclient.Options{CAFile: *caFile})
	if err != nil {
		return err
	}
	raw, err := underlay.NewRawSender()
	if err != nil {
		return err
	}
	defer raw.Close()
	prober, err := underlay.NewProber(*probeAddr)
	if err != nil {
		return err
	}
	if *egress {
		ipv6, err := linux.EnableForwarding()
		if err != nil {
			return fmt.Errorf("enabling forwarding for egress: %w", err)
		}
		kern.SetEgressIPv6(ipv6)
		if !ipv6 {
			log.Warn().Msg("the host does not forward IPv6; egress grants reach the IPv4 internet alone")
		}
		own, err := hostPrefixes()
		if err != nil {
			return err
		}
		// A filter an earlier run installed names relays that desired
		// state names again only once the control plane answers; until
		// then it keeps blocking them.
		kept, err := kern.EgressBlocked()
		if err != nil {
			return err
		}
		if err := kern.EnsureEgress(slices.Concat(kept, blocked, own)); err != nil {
			return fmt.Errorf("installing the egress filter: %w", err)
		}
	}
	reg := telemetry.NewRegistry()
	core := agentcore.New(cfg.Core, rand.Reader)
	d := daemon.New(cfg, core, kern, cp, j, raw, prober, daemon.NewMetrics(reg), log)
	if *egress {
		d.Egress, d.EgressBase, d.HostPrefixes = kern, blocked, hostPrefixes
	}
	if *serveDNS {
		up, err := resolver.Upstream("/etc/resolv.conf")
		if *upstream != "" {
			up, err = netip.ParseAddrPort(*upstream)
		}
		if err != nil {
			log.Warn().Err(err).Msg("no upstream resolver; names outside every network fail")
		}
		res := resolver.New(up, log, reg)
		defer res.Close()
		d.Resolver = res
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ready := func() error {
		select {
		case <-d.Up():
			return nil
		default:
			return errors.New("starting")
		}
	}
	tel := &telemetry.Server{Addr: *telemetryAddr, Registry: reg, Ready: ready, Log: log}
	errs := make(chan error, 4)
	go func() { errs <- tel.Serve(ctx) }()
	go func() { errs <- d.Run(ctx) }()
	select {
	case <-d.Up():
	case err := <-errs:
		return err
	}
	if err := os.MkdirAll(dirOf(*socket), 0o755); err != nil {
		return err
	}
	go func() { errs <- localapi.Serve(ctx, *socket, d) }()
	go watchUnderlay(ctx, d, log)
	log.Info().Str("socket", *socket).Msg("local API listening")
	select {
	case <-ctx.Done():
		log.Info().Msg("shutting down; interfaces stay as they are")
		return nil
	case err := <-errs:
		return err
	}
}

type prefixList []netip.Prefix

func (p *prefixList) String() string { return fmt.Sprint(*p) }

func (p *prefixList) Set(s string) error {
	v, err := netip.ParsePrefix(s)
	if err != nil {
		return err
	}
	*p = append(*p, v.Masked())
	return nil
}

// hostPrefixes lists the underlay the host sits on, which egress links must
// never reach: the prefix of each of its own addresses, and each route it
// reaches without a gateway, such as the /64 an EC2 host learns from router
// advertisements while its own address is a /128. Egress links' own
// addresses and routes are left out; the filter blocks them by default.
func hostPrefixes() ([]netip.Prefix, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok || linux.IsEgressAddr(ip.Unmap()) {
			continue
		}
		bits, _ := a.Mask.Size()
		out = append(out, netip.PrefixFrom(ip.Unmap(), bits).Masked())
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if r.Dst == nil || r.Gw != nil || len(r.MultiPath) > 0 || r.Type != unix.RTN_UNICAST {
			continue
		}
		ip, ok := netip.AddrFromSlice(r.Dst.IP)
		if !ok || linux.IsEgressAddr(ip.Unmap()) {
			continue
		}
		bits, _ := r.Dst.Mask.Size()
		if p := netip.PrefixFrom(ip.Unmap(), bits).Masked(); p.Bits() > 0 {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(out), nil
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// watchUnderlay tells the agent when the host's own addresses change, at
// most once a second, so it re-registers at once.
func watchUnderlay(ctx context.Context, d *daemon.Daemon, log zerolog.Logger) {
	updates := make(chan netlink.AddrUpdate, 64)
	if err := netlink.AddrSubscribe(updates, ctx.Done()); err != nil {
		log.Warn().Err(err).Msg("cannot watch underlay addresses; registrations follow their period alone")
		return
	}
	changes := make(chan struct{})
	go func() {
		defer close(changes)
		for u := range updates {
			ip, ok := netip.AddrFromSlice(u.LinkAddress.IP)
			if !ok || ip.IsLinkLocalUnicast() || ip.IsLoopback() || linux.IsEgressAddr(ip.Unmap()) {
				continue
			}
			select {
			case changes <- struct{}{}:
			case <-ctx.Done():
				return
			}
		}
	}()
	coalesce(ctx, changes, time.Second, d.UnderlayChanged)
}

// coalesce calls fn on the first event and then at most once per every. An
// event inside the window runs fn when the window ends, so fn always runs
// after the last event: an address added and removed within a second
// registers from the address that remains.
func coalesce(ctx context.Context, events <-chan struct{}, every time.Duration, fn func()) {
	var last time.Time
	var due <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-due:
			due = nil
			last = time.Now()
			fn()
		case _, ok := <-events:
			if !ok {
				return
			}
			if due != nil {
				continue
			}
			if wait := every - time.Since(last); wait > 0 {
				due = time.After(wait)
				continue
			}
			last = time.Now()
			fn()
		}
	}
}
