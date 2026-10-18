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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/vishvananda/netlink"

	agentcore "sdn.sh/internal/agent/core"
	"sdn.sh/internal/agent/daemon"
	"sdn.sh/internal/agent/journal"
	"sdn.sh/internal/agent/localapi"
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
	logLevel := flag.String("log-level", "info", "debug, info, warn or error")
	logFormat := flag.String("log-format", "", "json or console (default: console on a terminal)")
	portLo := flag.Uint("port-lo", uint(cfg.Core.PortLo), "lowest listen port a device binds")
	portHi := flag.Uint("port-hi", uint(cfg.Core.PortHi), "highest listen port a device binds")
	flag.StringVar(&cfg.Core.Prefix, "prefix", cfg.Core.Prefix, "prefix of every namespace the agent creates")
	flag.DurationVar(&cfg.Core.DrainGrace, "drain-grace", cfg.Core.DrainGrace, "how long a released peer stays installed")
	flag.DurationVar(&cfg.RenewEvery, "renew-every", cfg.RenewEvery, "lease renewal period")
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
	reg := telemetry.NewRegistry()
	core := agentcore.New(cfg.Core, rand.Reader)
	d := daemon.New(cfg, core, kern, cp, j, raw, prober, daemon.NewMetrics(reg), log)

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
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-updates:
			if !ok {
				return
			}
			if u.LinkAddress.IP.IsLinkLocalUnicast() || u.LinkAddress.IP.IsLoopback() {
				continue
			}
			if time.Since(last) > time.Second {
				last = time.Now()
				d.UnderlayChanged()
			}
		}
	}
}
