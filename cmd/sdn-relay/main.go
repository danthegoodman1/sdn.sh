// Command sdn-relay runs a relay: it forwards WireGuard ciphertext between
// the two ports of each directed edge the control plane pushes, and admits
// an endpoint only from an authenticated registration.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"sdn.sh/internal/api"
	"sdn.sh/internal/cpclient"
	"sdn.sh/internal/relay/server"
	"sdn.sh/internal/telemetry"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sdn-relay:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := server.DefaultConfig()
	cpURL := flag.String("cp", "", "control plane URL")
	credsFile := flag.String("credentials", "/etc/sdn/relay.json", `the relay's credentials, {"id": ..., "token": ...}`)
	caFile := flag.String("ca-file", "", "trust only this CA for the control plane")
	stateDir := flag.String("state", "/var/lib/sdn/relay", "state directory")
	probe := flag.String("probe", "", "address:port agents probe, the relay's first local address and its probe port")
	telemetryAddr := flag.String("telemetry", ":9092", "metrics, health and pprof address")
	perPort := flag.Int("per-port-metrics", 256, "ports, busiest first, that carry per-port series")
	logLevel := flag.String("log-level", "info", "debug, info, warn or error")
	logFormat := flag.String("log-format", "", "json or console (default: console on a terminal)")
	flag.IntVar(&cfg.Batch, "batch", cfg.Batch, "datagrams per read and write")
	flag.IntVar(&cfg.SocketBuffer, "socket-buffer", cfg.SocketBuffer, "bytes of receive and send buffer per socket; raise net.core.rmem_max to match")
	flag.Float64Var(&cfg.Core.Rate, "rate", cfg.Core.Rate, "data packets per second per port, 0 for no cap")
	flag.Float64Var(&cfg.Core.Burst, "burst", cfg.Core.Burst, "data packet burst per port")
	flag.Float64Var(&cfg.Core.RegistrationRate, "registration-rate", cfg.Core.RegistrationRate, "registrations per second per port")
	flag.Parse()

	log, err := telemetry.NewLogger("relay", telemetry.LogConfig{Level: *logLevel, Format: *logFormat})
	if err != nil {
		return err
	}
	if *cpURL == "" {
		return errors.New("--cp is required")
	}
	if *probe != "" {
		if cfg.Probe, err = netip.ParseAddrPort(*probe); err != nil {
			return fmt.Errorf("--probe: %w", err)
		}
	}
	var creds api.Credentials
	b, err := os.ReadFile(*credsFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &creds); err != nil || creds.ID == "" || creds.Token == "" {
		return fmt.Errorf("%s: want {\"id\": ..., \"token\": ...}", *credsFile)
	}
	log = log.With().Str("relay", creds.ID).Logger()
	cp, err := cpclient.New(*cpURL, creds.Token, cpclient.Options{CAFile: *caFile})
	if err != nil {
		return err
	}
	reg := telemetry.NewRegistry()
	srv, err := server.New(cfg, cp, *stateDir, server.NewMetrics(reg, *perPort), log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ready := func() error {
		select {
		case <-srv.Ready():
			return nil
		default:
			return errors.New("starting")
		}
	}
	tel := &telemetry.Server{Addr: *telemetryAddr, Registry: reg, Ready: ready, Log: log}
	errs := make(chan error, 2)
	go func() { errs <- tel.Serve(ctx) }()
	go func() { errs <- srv.Run(ctx) }()
	select {
	case <-ctx.Done():
		log.Info().Msg("shutting down; state is on disk")
		return nil
	case err := <-errs:
		return err
	}
}
