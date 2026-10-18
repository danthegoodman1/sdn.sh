// Package daemon runs the host agent: it carries the deterministic core's
// actions out against the kernel, the control plane, the journal and the
// underlay, and feeds the answers back.
//
// One goroutine owns the core. Kernel batches, control-plane calls and
// observations run on goroutines of their own and post their outcomes back
// as events, so the core sees one thing at a time, as in the simulator.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/rs/zerolog"

	agentcore "sdn.sh/internal/agent/core"
	"sdn.sh/internal/api"
	"sdn.sh/internal/kernel"
	"sdn.sh/internal/model"
	"sdn.sh/internal/regproto"
)

// ControlPlane is the agent's side of the control plane's API.
type ControlPlane interface {
	Attach(ctx context.Context, req api.AttachRequest) (*api.AttachResponse, error)
	Release(ctx context.Context, ids []model.InterfaceID) error
	Renew(ctx context.Context, ids []model.InterfaceID) (api.RenewResponse, error)
	HostState(ctx context.Context, since uint64, wait time.Duration) (api.StateUpdate, error)
}

// Journal persists entries durably.
type Journal interface {
	Load() ([]agentcore.JournalEntry, error)
	Write(agentcore.JournalEntry) error
	Delete(model.InterfaceID) error
}

// Sender sends a UDP datagram from a device's listen port.
type Sender interface {
	Send(fromPort uint16, to netip.AddrPort, payload []byte) error
}

// Prober sends relay probes and reports what comes back.
type Prober interface {
	Send(to netip.AddrPort, b []byte) error
	Receive(fn func(from netip.AddrPort, b []byte)) error
	Close() error
}

// Config holds the daemon's settings beyond the core's.
type Config struct {
	Core agentcore.Config
	// RenewEvery is how often live leases are renewed; a third of the
	// control plane's lease term.
	RenewEvery time.Duration
	// PollWait bounds one long poll; it exceeds the server's poll timeout.
	PollWait time.Duration
	// Workers bounds how many namespaces' batches run at once.
	Workers int
}

// DefaultConfig returns production settings for a host.
func DefaultConfig(host model.HostID) Config {
	return Config{Core: agentcore.DefaultConfig(host), RenewEvery: 10 * time.Second, PollWait: 40 * time.Second, Workers: 32}
}

// Daemon is one host's agent.
type Daemon struct {
	cfg     Config
	log     zerolog.Logger
	core    *agentcore.Core
	kern    kernel.Kernel
	cp      ControlPlane
	journal Journal
	raw     Sender
	prober  Prober
	m       *Metrics
	now     func() time.Time

	events chan func()
	sem    chan struct{}
	ctx    context.Context
	fatal  error

	// Owned by the loop goroutine.
	requests map[agentcore.RequestID]*request
	nextReq  agentcore.RequestID
	probes   map[uint64]probe
	stats    agentcore.Stats

	ready sync.Once
	up    chan struct{}
}

type request struct {
	ch    chan agentcore.Reply
	start time.Time
	kind  string
}

type probe struct {
	relay model.RelayID
	to    netip.AddrPort
	at    time.Time
}

// New returns a daemon. rand mints the private keys the kernel keeps.
func New(cfg Config, core *agentcore.Core, kern kernel.Kernel, cp ControlPlane, j Journal, raw Sender, prober Prober, m *Metrics, log zerolog.Logger) *Daemon {
	return &Daemon{
		cfg: cfg, log: log, core: core, kern: kern, cp: cp, journal: j, raw: raw, prober: prober, m: m,
		now:      time.Now,
		events:   make(chan func(), 4096),
		sem:      make(chan struct{}, max(cfg.Workers, 1)),
		requests: map[agentcore.RequestID]*request{},
		probes:   map[uint64]probe{},
		up:       make(chan struct{}),
	}
}

// Up closes once the daemon has adopted what the journal and kernel hold.
func (d *Daemon) Up() <-chan struct{} { return d.up }

// Run adopts the journal and the kernel, then serves until ctx ends or a
// journal write fails, which leaves the core unable to trust its record.
func (d *Daemon) Run(ctx context.Context) error {
	d.ctx = ctx
	entries, err := d.journal.Load()
	if err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	snap, err := d.kern.Snapshot(d.cfg.Core.Prefix, d.cfg.Core.AliasPrefix())
	if err != nil {
		return fmt.Errorf("observing the kernel: %w", err)
	}
	d.core.Start(d.now(), entries, snap)
	d.log.Info().Int("journaled", len(entries)).Int("namespaces", len(snap.Namespaces)).Msg("agent started")
	d.drive()
	d.ready.Do(func() { close(d.up) })

	go d.pollLoop(ctx)
	go d.renewLoop(ctx)
	if d.prober != nil {
		go d.prober.Receive(d.probeReply)
		defer d.prober.Close()
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		if d.fatal != nil {
			return d.fatal
		}
		next := d.core.NextWake(d.now())
		timer.Reset(max(time.Until(next), 0))
		select {
		case <-ctx.Done():
			return nil
		case fn := <-d.events:
			fn()
		case <-timer.C:
			d.core.Tick(d.now())
		}
		d.drive()
	}
}

// post runs fn on the loop goroutine.
func (d *Daemon) post(fn func()) {
	select {
	case d.events <- fn:
	case <-d.ctx.Done():
	}
}

// query runs fn on the loop and returns its result.
func query[T any](d *Daemon, ctx context.Context, fn func() T) (T, error) {
	ch := make(chan T, 1)
	d.post(func() { ch <- fn() })
	select {
	case v := <-ch:
		return v, nil
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// drive carries out everything the core has queued.
func (d *Daemon) drive() {
	for _, a := range d.core.Actions(d.now()) {
		if d.fatal != nil {
			return
		}
		d.carry(a)
	}
	d.noteStats()
}

func (d *Daemon) carry(a agentcore.Action) {
	switch a := a.(type) {
	case agentcore.RunBatch:
		d.runBatch(a)
	case agentcore.Observe:
		d.observe(a.Namespace)
	case agentcore.CallAttach:
		d.callAttach(a.Request)
	case agentcore.CallRelease:
		d.callRelease(a.Interfaces)
	case agentcore.WriteJournal:
		if err := d.journal.Write(a.Entry); err != nil {
			d.fatal = fmt.Errorf("journal write for %s: %w", a.Entry.Interface, err)
		}
	case agentcore.DeleteJournal:
		if err := d.journal.Delete(a.Interface); err != nil {
			d.fatal = fmt.Errorf("journal delete for %s: %w", a.Interface, err)
		}
	case agentcore.Reply:
		d.reply(a)
	case agentcore.SendRegistration:
		if err := d.raw.Send(a.From, a.To, a.Payload[:]); err != nil {
			d.m.registrations.WithLabelValues("error").Inc()
			d.log.Warn().Err(err).Uint16("port", a.From).Stringer("relay", a.To).Msg("registration send failed")
		} else {
			d.m.registrations.WithLabelValues("sent").Inc()
		}
	case agentcore.SendProbe:
		d.sendProbe(a)
	default:
		d.log.Error().Type("action", a).Msg("unknown action")
	}
}

// runBatch runs a namespace's operations in order on a goroutine, stopping
// at the first failure.
func (d *Daemon) runBatch(b agentcore.RunBatch) {
	d.log.Debug().Str("namespace", b.Namespace).Uint64("batch", b.ID).Int("ops", len(b.Ops)).Msg("batch")
	go func() {
		d.sem <- struct{}{}
		defer func() { <-d.sem }()
		start := time.Now()
		done := 0
		var err error
		for _, op := range b.Ops {
			if err = d.runOp(op); err != nil {
				break
			}
			done++
		}
		d.m.batchSeconds.Observe(time.Since(start).Seconds())
		if err != nil {
			d.m.batches.WithLabelValues("error").Inc()
			d.log.Warn().Err(err).Str("namespace", b.Namespace).Uint64("batch", b.ID).Str("op", string(b.Ops[done].Kind)).
				Int("done", done).Msg("batch failed")
		} else {
			d.m.batches.WithLabelValues("ok").Inc()
		}
		d.post(func() { d.core.BatchDone(d.now(), b.Namespace, b.ID, done, err) })
	}()
}

func (d *Daemon) runOp(op kernel.Op) error {
	start := time.Now()
	res, err := d.kern.Run(op)
	took := time.Since(start)
	result := "ok"
	if err != nil {
		result = "error"
	}
	kind := string(op.Kind)
	d.m.kernelOps.WithLabelValues(kind, result).Inc()
	d.m.kernelSeconds.WithLabelValues(kind).Observe(took.Seconds())
	if op.Rules != nil {
		d.m.nftSize.Observe(float64(op.Rules.Size()))
	}
	if res.Conntrack > 0 || res.Sockets > 0 {
		d.m.flushed.WithLabelValues("conntrack").Add(float64(res.Conntrack))
		d.m.flushed.WithLabelValues("sockets").Add(float64(res.Sockets))
	}
	ev := d.log.Debug()
	if err != nil {
		ev = d.log.Warn().Err(err)
	}
	ev.Str("namespace", op.Namespace).Str("op", kind).Int("peers", len(op.Peers)).Dur("took", took).Msg("kernel operation")
	return err
}

func (d *Daemon) observe(name string) {
	go func() {
		d.sem <- struct{}{}
		defer func() { <-d.sem }()
		ns, err := d.kern.Namespace(name, d.cfg.Core.AliasPrefix())
		ns.Name = name
		d.post(func() { d.core.Observed(d.now(), ns, err) })
	}()
}

// retryFloor spaces retries of a call that failed at once, as a refused
// connection does, so a retrying core does not spin.
const retryFloor = 250 * time.Millisecond

func (d *Daemon) callAttach(req api.AttachRequest) {
	go func() {
		start := time.Now()
		resp, err := d.cp.Attach(d.ctx, req)
		d.m.cpCalls.WithLabelValues("attach", callResult(err)).Inc()
		if err != nil {
			d.log.Warn().Err(err).Str("interface", string(req.Interface)).Msg("attach call failed")
			if wait := retryFloor - time.Since(start); wait > 0 {
				time.Sleep(wait)
			}
		}
		d.post(func() { d.core.AttachDone(d.now(), req.Interface, resp, err) })
	}()
}

func (d *Daemon) callRelease(ids []model.InterfaceID) {
	go func() {
		start := time.Now()
		err := d.cp.Release(d.ctx, ids)
		d.m.cpCalls.WithLabelValues("release", callResult(err)).Inc()
		if err != nil {
			d.log.Warn().Err(err).Int("interfaces", len(ids)).Msg("release call failed")
			if wait := retryFloor - time.Since(start); wait > 0 {
				time.Sleep(wait)
			}
		}
		d.post(func() { d.core.ReleaseDone(d.now(), ids, err) })
	}()
}

func callResult(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}

// pollLoop long-polls for desired state for as long as the agent runs.
func (d *Daemon) pollLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		since, err := query(d, ctx, func() uint64 { return d.core.Generation() })
		if err != nil {
			return
		}
		u, err := d.cp.HostState(ctx, since, d.cfg.PollWait)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.m.polls.WithLabelValues("error").Inc()
			d.log.Warn().Err(err).Dur("retry", backoff).Msg("desired-state poll failed; holding configuration")
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 15*time.Second)
			continue
		}
		backoff = time.Second
		d.m.polls.WithLabelValues("ok").Inc()
		received := time.Now()
		d.post(func() {
			if err := d.core.State(d.now(), u); err != nil {
				d.log.Error().Err(err).Uint64("generation", u.Generation).Msg("desired state rejected")
				return
			}
			d.m.generation.Set(float64(d.core.Generation()))
			if len(u.Networks) > 0 {
				d.log.Info().Uint64("generation", u.Generation).Int("networks", len(u.Networks)).
					Dur("queued", time.Since(received)).Msg("desired state received")
			}
		})
	}
}

// renewLoop renews live leases.
func (d *Daemon) renewLoop(ctx context.Context) {
	t := time.NewTicker(d.cfg.RenewEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ids, err := query(d, ctx, func() []model.InterfaceID { return d.core.Live() })
		if err != nil || len(ids) == 0 {
			continue
		}
		resp, err := d.cp.Renew(ctx, ids)
		d.m.cpCalls.WithLabelValues("renew", callResult(err)).Inc()
		if err != nil {
			d.log.Warn().Err(err).Int("interfaces", len(ids)).Msg("lease renewal failed")
			continue
		}
		if lost := len(ids) - len(resp.Expires); lost > 0 {
			d.log.Warn().Int("interfaces", lost).Msg("leases no longer live at the control plane")
		}
	}
}

func (d *Daemon) sendProbe(p agentcore.SendProbe) {
	if d.prober == nil {
		return
	}
	now := d.now()
	if len(d.probes) > 4096 {
		for nonce, sent := range d.probes {
			if now.Sub(sent.at) > 10*time.Second {
				delete(d.probes, nonce)
			}
		}
	}
	d.probes[p.Nonce] = probe{relay: p.Relay, to: p.To, at: now}
	b := regproto.Probe(p.Nonce)
	if err := d.prober.Send(p.To, b[:]); err != nil {
		d.log.Debug().Err(err).Str("relay", string(p.Relay)).Msg("probe send failed")
	}
	d.m.probes.WithLabelValues(string(p.Relay), "sent").Inc()
}

// probeReply takes a datagram on the probe socket.
func (d *Daemon) probeReply(from netip.AddrPort, b []byte) {
	nonce, ok := regproto.ProbeNonce(b)
	if !ok {
		return
	}
	d.post(func() {
		p, ok := d.probes[nonce]
		if !ok || p.to != from {
			return
		}
		delete(d.probes, nonce)
		d.m.probes.WithLabelValues(string(p.relay), "answered").Inc()
		d.m.probeRTT.WithLabelValues(string(p.relay)).Observe(d.now().Sub(p.at).Seconds())
		d.core.ProbeReply(d.now(), p.relay, nonce)
	})
}

// UnderlayChanged re-registers every direction, as after the host's address
// changes.
func (d *Daemon) UnderlayChanged() {
	d.post(func() {
		d.log.Info().Msg("underlay changed; registering every direction")
		d.core.UnderlayChanged(d.now())
	})
}

// noteStats turns the core's counters into metrics and logs failovers.
func (d *Daemon) noteStats() {
	s := d.core.Stats
	if s.Failovers > d.stats.Failovers {
		d.log.Info().Interface("active", d.core.Active()).Uint64("failovers", s.Failovers-d.stats.Failovers).Msg("relay failover")
	}
	d.m.coreStat("conflicts", s.Conflicts-d.stats.Conflicts)
	d.m.coreStat("preempted", s.Preempted-d.stats.Preempted)
	d.m.coreStat("failovers", s.Failovers-d.stats.Failovers)
	d.m.coreStat("failures", s.Failures-d.stats.Failures)
	d.stats = s
}

// The local API.

// ErrStopped answers a local call made while the daemon shuts down.
var ErrStopped = errors.New("agent stopping")

// Attach builds an interface for a workload and returns once its namespace
// is ready to hand over.
func (d *Daemon) Attach(ctx context.Context, a api.LocalAttach) (api.LocalInterface, error) {
	return d.call(ctx, "attach", func(id agentcore.RequestID) { d.core.Attach(d.now(), id, a) })
}

// Detach tears an interface down.
func (d *Daemon) Detach(ctx context.Context, id model.InterfaceID) (api.LocalInterface, error) {
	return d.call(ctx, "detach", func(req agentcore.RequestID) { d.core.Detach(d.now(), req, id) })
}

// Interfaces lists what the agent holds.
func (d *Daemon) Interfaces(ctx context.Context) ([]api.LocalInterface, error) {
	return query(d, ctx, func() []api.LocalInterface { return d.core.Interfaces() })
}

// Status is the agent's state for diagnostics.
type Status struct {
	Generation uint64                            `json:"generation"`
	Pending    []string                          `json:"pending,omitempty"`
	Active     map[model.NetworkID]model.RelayID `json:"active_relays,omitempty"`
	Stats      agentcore.Stats                   `json:"stats"`
}

// Status reports the agent's state.
func (d *Daemon) Status(ctx context.Context) (Status, error) {
	return query(d, ctx, func() Status {
		return Status{Generation: d.core.Generation(), Pending: d.core.Pending(), Active: d.core.Active(), Stats: d.core.Stats}
	})
}

func (d *Daemon) call(ctx context.Context, kind string, start func(agentcore.RequestID)) (api.LocalInterface, error) {
	r := &request{ch: make(chan agentcore.Reply, 1), start: time.Now(), kind: kind}
	d.post(func() {
		d.nextReq++
		d.requests[d.nextReq] = r
		start(d.nextReq)
	})
	select {
	case rep := <-r.ch:
		return rep.Interface, rep.Err
	case <-ctx.Done():
		return api.LocalInterface{}, ctx.Err()
	case <-d.ctx.Done():
		return api.LocalInterface{}, ErrStopped
	}
}

func (d *Daemon) reply(a agentcore.Reply) {
	r, ok := d.requests[a.Request]
	if !ok {
		return
	}
	delete(d.requests, a.Request)
	took := time.Since(r.start)
	result := "ok"
	ev := d.log.Info()
	if a.Err != nil {
		result = "error"
		ev = d.log.Warn().Err(a.Err)
	}
	d.m.localCalls.WithLabelValues(r.kind, result).Inc()
	d.m.localSeconds.WithLabelValues(r.kind).Observe(took.Seconds())
	ev.Str("interface", string(a.Interface.Interface)).Str("name", a.Interface.Name).Str("network", string(a.Interface.Network)).
		Str("service", string(a.Interface.Service)).Str("namespace", a.Interface.Namespace).Dur("took", took).Msg(r.kind)
	r.ch <- a
}
