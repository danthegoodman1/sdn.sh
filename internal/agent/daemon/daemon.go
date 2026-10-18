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
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog"

	agentcore "sdn.sh/internal/agent/core"
	"sdn.sh/internal/api"
	"sdn.sh/internal/dns"
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

// Sender sends a UDP datagram from a device's listen port, and passes on
// the relays' acknowledgments that come back to those ports until it
// closes.
type Sender interface {
	Send(fromPort uint16, to netip.AddrPort, payload []byte) error
	Receive(fn func(from netip.AddrPort, port uint16, payload []byte)) error
}

// Prober sends relay probes and reports what comes back.
type Prober interface {
	Send(to netip.AddrPort, b []byte) error
	Receive(fn func(from netip.AddrPort, b []byte)) error
	Close() error
}

// Resolver serves each namespace's stub resolver.
type Resolver interface {
	Sync(zones map[string]dns.Served, settled bool)
}

// EgressHost keeps the host's egress filter blocking what no egress link
// may reach.
type EgressHost interface {
	EnsureEgress(blocked []netip.Prefix) error
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
	// EgressRetry is how long a failed egress filter refresh waits to try
	// again.
	EgressRetry time.Duration
}

// DefaultConfig returns production settings for a host.
func DefaultConfig(host model.HostID) Config {
	return Config{Core: agentcore.DefaultConfig(host), RenewEvery: 10 * time.Second, PollWait: 40 * time.Second, Workers: 32, EgressRetry: 5 * time.Second}
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
	// Resolver, when set, serves workloads' names.
	Resolver Resolver
	// Egress, when set, has its blocked prefixes refreshed with every relay
	// address desired state names, on top of EgressBase and the host's own
	// prefixes, which HostPrefixes lists anew on every refresh. Until
	// desired state names the relays, a refresh keeps EgressKept, what an
	// earlier run's filter blocked.
	Egress       EgressHost
	EgressBase   []netip.Prefix
	EgressKept   []netip.Prefix
	HostPrefixes func() ([]netip.Prefix, error)
	m            *Metrics
	now          func() time.Time

	events chan func()
	sem    chan struct{}
	ctx    context.Context
	fatal  error

	// Owned by the loop goroutine.
	requests map[agentcore.RequestID]*request
	nextReq  agentcore.RequestID
	probes   map[uint64]probe
	stats    agentcore.Stats

	// resolverDirty marks zones that need recomputing; syncs carries the
	// latest set to the goroutine applying them. Each set sent takes the
	// next of resolverSeq, and resolved is the latest one applied.
	resolverDirty bool
	resolverGen   uint64
	syncs         chan resolverSync
	resolverSeq   uint64
	resolved      uint64
	// awaitingResolver holds attach replies until the sync that opens
	// their namespaces' resolver sockets has run; seq 0 marks one no sync
	// has carried yet.
	awaitingResolver []heldReply
	// egressSyncs carries the latest relay set to the goroutine refreshing
	// the filter; egressSent records that one has gone.
	egressGen    uint64
	egressRelays []netip.Prefix
	egressSent   bool
	egressSyncs  chan []netip.Prefix
	// reported is the network revision each interface last settled at, so
	// convergence is observed once per revision.
	reported map[model.InterfaceID]uint64
	// quiet marks an event that changed nothing, so the loop skips its pass.
	quiet bool

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
		now:           time.Now,
		events:        make(chan func(), 4096),
		sem:           make(chan struct{}, max(cfg.Workers, 1)),
		requests:      map[agentcore.RequestID]*request{},
		probes:        map[uint64]probe{},
		up:            make(chan struct{}),
		syncs:         make(chan resolverSync, 1),
		egressSyncs:   make(chan []netip.Prefix, 1),
		reported:      map[model.InterfaceID]uint64{},
		resolverDirty: true,
	}
}

type resolverSync struct {
	zones   map[string]dns.Served
	settled bool
	seq     uint64
}

type heldReply struct {
	reply agentcore.Reply
	seq   uint64
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
	go d.censusLoop(ctx)
	if d.Egress != nil {
		go d.egressLoop(ctx)
	}
	if d.Resolver != nil {
		go func() {
			// A socket that failed to open, as on an address not yet
			// configured, gets another try at the next sync or tick.
			tick := time.NewTicker(10 * time.Second)
			defer tick.Stop()
			var last *resolverSync
			for {
				select {
				case <-ctx.Done():
					return
				case s := <-d.syncs:
					last = &s
				case <-tick.C:
				}
				if last != nil {
					d.Resolver.Sync(last.zones, last.settled)
					seq := last.seq
					d.post(func() { d.resolverRan(seq) })
				}
			}
		}()
	}
	if d.prober != nil {
		go d.prober.Receive(d.probeReply)
		defer d.prober.Close()
	}
	if d.raw != nil {
		go d.raw.Receive(d.ack)
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	drove := true
	for {
		if d.fatal != nil {
			return d.fatal
		}
		if drove {
			next := d.core.NextWake(d.now())
			timer.Reset(max(time.Until(next), 0))
		}
		drove = true
		select {
		case <-ctx.Done():
			return nil
		case fn := <-d.events:
			fn()
			if d.quiet {
				// The event changed nothing the core plans from, so the
				// pass over every namespace and the next wake keep.
				d.quiet = false
				drove = false
				continue
			}
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
	idle := d.core.Stats.Idle != d.stats.Idle
	d.noteStats()
	d.syncResolver()
	d.syncEgress()
	if idle {
		d.noteConvergence()
	}
}

// noteConvergence observes, once per revision, how long each namespace took
// to settle on a network revision after the control plane committed it.
func (d *Daemon) noteConvergence() {
	now := d.now()
	desired := d.core.Desired()
	for _, s := range d.core.Settled() {
		if s.Revision == 0 || s.Revision <= d.reported[s.Interface] {
			continue
		}
		d.reported[s.Interface] = s.Revision
		n, ok := desired.Networks[s.Network]
		if !ok || n.Revision != s.Revision || n.Changed.IsZero() {
			continue
		}
		took := now.Sub(n.Changed)
		d.m.convergence.Observe(took.Seconds())
		d.log.Debug().Str("interface", string(s.Interface)).Str("network", string(s.Network)).
			Uint64("revision", s.Revision).Dur("took", took).Msg("converged")
	}
}

// syncEgress blocks every relay address desired state names from egress
// links, refreshing the host's filter when the set changes. A workload that
// could reach a relay could attack endpoint registration. Until the agent
// holds desired state, the filter keeps what the last run installed.
func (d *Daemon) syncEgress() {
	gen := d.core.Generation()
	if d.Egress == nil || gen == d.egressGen {
		return
	}
	d.egressGen = gen
	var relays []netip.Prefix
	desired := d.core.Desired()
	for _, id := range desired.NetworkIDs() {
		n := desired.Networks[id]
		for _, r := range n.Relays {
			relays = append(relays, netip.PrefixFrom(r.Probe.Addr(), r.Probe.Addr().BitLen()))
		}
		for _, x := range n.Interfaces {
			for _, p := range x.Peers {
				for _, rp := range p.Relays {
					relays = append(relays, netip.PrefixFrom(rp.Send.Addr(), rp.Send.Addr().BitLen()))
				}
			}
		}
	}
	slices.SortFunc(relays, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	relays = slices.Compact(relays)
	// The first refresh runs whatever the set, replacing what the last run
	// left.
	if d.egressSent && slices.Equal(relays, d.egressRelays) {
		return
	}
	d.egressRelays, d.egressSent = relays, true
	d.refreshEgress()
}

// refreshEgress hands the relay set to the egress goroutine, replacing one
// it has yet to take.
func (d *Daemon) refreshEgress() {
	select {
	case <-d.egressSyncs:
	default:
	}
	d.egressSyncs <- slices.Clone(d.egressRelays)
}

// egressLoop refreshes the filter with the latest relay set and the host's
// current prefixes, one refresh at a time, so an older set never lands
// after a newer one. A failed refresh retries until it succeeds or a newer
// set replaces it.
func (d *Daemon) egressLoop(ctx context.Context) {
	var relays []netip.Prefix
	var retry <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case relays = <-d.egressSyncs:
		case <-retry:
		}
		retry = nil
		if err := d.applyEgress(relays); err != nil {
			d.log.Error().Err(err).Dur("retry", d.cfg.EgressRetry).Msg("refreshing the egress filter")
			retry = time.After(d.cfg.EgressRetry)
			continue
		}
		d.log.Info().Int("relays", len(relays)).Msg("egress filter blocks every relay")
	}
}

func (d *Daemon) applyEgress(relays []netip.Prefix) error {
	var host []netip.Prefix
	if d.HostPrefixes != nil {
		var err error
		if host, err = d.HostPrefixes(); err != nil {
			return fmt.Errorf("host prefixes: %w", err)
		}
	}
	return d.Egress.EnsureEgress(slices.Concat(d.EgressBase, host, relays))
}

// syncResolver recomputes every ready namespace's zone after desired state
// changes or an attach or detach finishes, and hands the set over.
func (d *Daemon) syncResolver() {
	if d.Resolver == nil {
		return
	}
	gen := d.core.Generation()
	if !d.resolverDirty && gen == d.resolverGen {
		return
	}
	d.resolverDirty, d.resolverGen = false, gen
	zones := map[string]dns.Served{}
	desired := d.core.Desired()
	for _, li := range d.core.Interfaces() {
		if !li.Ready {
			continue
		}
		if n, x, ok := desired.Interface(li.Interface); ok {
			zones[li.Namespace] = dns.ServedFor(n, x)
		}
	}
	d.resolverSeq++
	for i := range d.awaitingResolver {
		if d.awaitingResolver[i].seq == 0 {
			d.awaitingResolver[i].seq = d.resolverSeq
		}
	}
	select {
	case <-d.syncs:
	default:
	}
	d.syncs <- resolverSync{zones: zones, settled: gen > 0, seq: d.resolverSeq}
}

// resolverRan answers the attach calls whose resolver sockets the sync seq
// opened, or tried to: a socket that failed retries at the next tick.
func (d *Daemon) resolverRan(seq uint64) {
	d.resolved = max(d.resolved, seq)
	d.awaitingResolver = slices.DeleteFunc(d.awaitingResolver, func(h heldReply) bool {
		if h.seq == 0 || h.seq > d.resolved {
			return false
		}
		d.reply(h.reply)
		return true
	})
}

func (d *Daemon) carry(a agentcore.Action) {
	switch a := a.(type) {
	case agentcore.RunBatch:
		d.runBatch(a)
	case agentcore.Observe:
		d.observe(a.Namespace)
	case agentcore.Scan:
		go func() {
			snap, err := d.kern.Snapshot(d.cfg.Core.Prefix, d.cfg.Core.AliasPrefix())
			if err != nil {
				d.log.Warn().Err(err).Msg("kernel scan failed")
			}
			d.post(func() { d.core.Scanned(d.now(), snap, err) })
		}()
	case agentcore.CallAttach:
		d.callAttach(a.Request)
	case agentcore.CallRelease:
		d.callRelease(a.Interfaces)
	case agentcore.WriteJournal:
		if err := d.journal.Write(a.Entry); err != nil {
			d.fatal = fmt.Errorf("journal write for %s: %w", a.Entry.Interface, err)
		}
	case agentcore.DeleteJournal:
		delete(d.reported, a.Interface)
		if err := d.journal.Delete(a.Interface); err != nil {
			d.fatal = fmt.Errorf("journal delete for %s: %w", a.Interface, err)
		}
	case agentcore.Reply:
		d.resolverDirty = true
		if d.Resolver != nil && a.Err == nil && a.Interface.Ready {
			// A workload may resolve the moment it holds its namespace,
			// so the reply waits for the resolver socket.
			d.awaitingResolver = append(d.awaitingResolver, heldReply{reply: a})
			return
		}
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
		d.post(func() {
			d.core.BatchDone(d.now(), b.Namespace, b.ID, done, err)
		})
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
		d.m.polls.WithLabelValues("ok").Inc()
		received := time.Now()
		rejected, err := query(d, ctx, func() error {
			if err := d.core.State(d.now(), u); err != nil {
				d.log.Error().Err(err).Uint64("generation", u.Generation).Msg("desired state rejected")
				return err
			}
			d.m.generation.Set(float64(d.core.Generation()))
			if len(u.Networks) > 0 {
				d.log.Info().Uint64("generation", u.Generation).Int("networks", len(u.Networks)).
					Dur("queued", time.Since(received)).Msg("desired state received")
			}
			return nil
		})
		if err != nil {
			return
		}
		if rejected == nil {
			backoff = time.Second
			continue
		}
		// The same generation would come back at once; wait before asking.
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 15*time.Second)
	}
}

// renewLoop renews live leases at a third of the soonest lease's remaining
// term, and at least every RenewEvery, so a control plane with short leases
// needs no agent setting to match. The term comes from the renewal's answer:
// desired state carries the expiry the network was compiled with, which goes
// stale while the network is idle.
func (d *Daemon) renewLoop(ctx context.Context) {
	wait := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = d.cfg.RenewEvery
		ids, err := query(d, ctx, d.core.Live)
		if err != nil {
			return
		}
		if len(ids) == 0 {
			wait = min(wait, time.Second)
			continue
		}
		resp, err := d.cp.Renew(ctx, ids)
		d.m.cpCalls.WithLabelValues("renew", callResult(err)).Inc()
		if err != nil {
			d.log.Warn().Err(err).Int("interfaces", len(ids)).Msg("lease renewal failed")
			wait = time.Second
			continue
		}
		if lost := len(ids) - len(resp.Expires); lost > 0 {
			d.log.Warn().Int("interfaces", lost).Msg("leases no longer live at the control plane")
		}
		var earliest time.Time
		for _, exp := range resp.Expires {
			if earliest.IsZero() || exp.Before(earliest) {
				earliest = exp
			}
		}
		if !earliest.IsZero() {
			wait = min(wait, max(time.Until(earliest)/3, 100*time.Millisecond))
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

// ack takes a relay's acknowledgment of a registration sent from a
// device's listen port.
func (d *Daemon) ack(from netip.AddrPort, port uint16, payload []byte) {
	if _, ok := regproto.AckCounter(payload); !ok {
		return
	}
	d.post(func() {
		d.m.registrations.WithLabelValues("acked").Inc()
		if !d.core.RegistrationAcked(d.now(), port, from) {
			d.quiet = true
		}
	})
}

// UnderlayChanged re-registers every direction, as after the host's address
// changes.
func (d *Daemon) UnderlayChanged() {
	d.post(func() {
		d.log.Info().Msg("underlay changed; registering every direction")
		d.core.UnderlayChanged(d.now())
		// The host's own prefixes may have moved with it.
		if d.Egress != nil {
			if !d.egressSent {
				d.egressRelays = d.EgressKept
			}
			d.refreshEgress()
		}
	})
}

// censusLoop refreshes the census gauges once a second, which counting on
// every event would cost more than it shows.
func (d *Daemon) censusLoop(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		c, err := query(d, ctx, d.core.Census)
		if err != nil {
			return
		}
		d.m.census(c)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// noteStats turns the core's counters into metrics and logs failovers.
func (d *Daemon) noteStats() {
	s := d.core.Stats
	if s.Failovers > d.stats.Failovers {
		d.log.Info().Interface("relays_up", d.core.RelaysUp()).Uint64("relays_lost", s.Failovers-d.stats.Failovers).Msg("relay failover")
	}
	d.m.coreStat("conflicts", s.Conflicts-d.stats.Conflicts)
	d.m.coreStat("preempted", s.Preempted-d.stats.Preempted)
	d.m.coreStat("failovers", s.Failovers-d.stats.Failovers)
	d.m.coreStat("failures", s.Failures-d.stats.Failures)
	d.m.coreStat("acked", s.Acked-d.stats.Acked)
	d.m.coreStat("ack_timeouts", s.AckTimeouts-d.stats.AckTimeouts)
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
	Generation uint64                 `json:"generation"`
	Pending    []string               `json:"pending,omitempty"`
	RelaysUp   map[model.RelayID]bool `json:"relays_up,omitempty"`
	RelayPeers map[model.RelayID]int  `json:"relay_peers,omitempty"`
	Stats      agentcore.Stats        `json:"stats"`
}

// Status reports the agent's state.
func (d *Daemon) Status(ctx context.Context) (Status, error) {
	return query(d, ctx, func() Status {
		c := d.core.Census()
		return Status{Generation: d.core.Generation(), Pending: d.core.Pending(), RelaysUp: c.RelaysUp, RelayPeers: c.RelayPeers, Stats: d.core.Stats}
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
