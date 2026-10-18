package daemon

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/rs/zerolog"

	agentcore "sdn.sh/internal/agent/core"
	"sdn.sh/internal/api"
	"sdn.sh/internal/dns"
	"sdn.sh/internal/kernel"
	"sdn.sh/internal/kernel/kmodel"
	"sdn.sh/internal/model"
	"sdn.sh/internal/prng"
)

// lockedKernel serializes the model, which the daemon's workers share.
type lockedKernel struct {
	mu sync.Mutex
	k  *kmodel.Kernel
}

func (l *lockedKernel) Snapshot(prefix, aliasPrefix string) (kernel.Snapshot, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.k.Snapshot(prefix, aliasPrefix)
}

func (l *lockedKernel) Namespace(name, aliasPrefix string) (kernel.Namespace, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.k.Namespace(name, aliasPrefix)
}

func (l *lockedKernel) Run(op kernel.Op) (kernel.Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.k.Run(op)
}

// soloCP answers an attach with a network holding the new interface alone,
// and parks every poll.
type soloCP struct{}

func (soloCP) Attach(ctx context.Context, req api.AttachRequest) (*api.AttachResponse, error) {
	n := api.NetworkState{Network: "net-1", Name: req.Network, Revision: 1, Prefix6: netip.MustParsePrefix("fd00::/64"), MTU: 1380,
		Changed: time.Now(),
		Interfaces: []api.Interface{{ID: req.Interface, Service: "svc-1", Kind: api.Workload, PublicKey: req.PublicKey,
			Addr6: netip.MustParseAddr("fd00::5"), ListenPort: req.ListenPort, State: api.Live}}}
	return &api.AttachResponse{Interface: req.Interface, State: n}, nil
}

func (soloCP) Release(context.Context, []model.InterfaceID) error { return nil }

func (soloCP) Renew(context.Context, []model.InterfaceID) (api.RenewResponse, error) {
	return api.RenewResponse{}, nil
}

func (soloCP) HostState(ctx context.Context, _ uint64, _ time.Duration) (api.StateUpdate, error) {
	<-ctx.Done()
	return api.StateUpdate{}, ctx.Err()
}

type memJournal struct{}

func (memJournal) Load() ([]agentcore.JournalEntry, error) { return nil, nil }
func (memJournal) Write(agentcore.JournalEntry) error      { return nil }
func (memJournal) Delete(model.InterfaceID) error          { return nil }

// gatedResolver holds the first sync that serves a namespace until the test
// opens the gate.
type gatedResolver struct {
	syncing chan struct{}
	gate    chan struct{}
	once    sync.Once
}

func (r *gatedResolver) Sync(zones map[string]dns.Served, settled bool) {
	if len(zones) == 0 {
		return
	}
	r.once.Do(func() {
		close(r.syncing)
		<-r.gate
	})
}

func TestAnAttachIsAnsweredOnceItsResolverListens(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core := agentcore.New(agentcore.DefaultConfig("h1"), prng.New(1))
	d := New(DefaultConfig("h1"), core, &lockedKernel{k: kmodel.New()}, soloCP{}, memJournal{}, nil, nil, NewMetrics(prometheus.NewRegistry()), zerolog.Nop())
	res := &gatedResolver{syncing: make(chan struct{}), gate: make(chan struct{})}
	d.Resolver = res
	go d.Run(ctx)
	<-d.Up()
	type answer struct {
		li  api.LocalInterface
		err error
	}
	done := make(chan answer, 1)
	go func() {
		li, err := d.Attach(ctx, api.LocalAttach{Name: "w", Network: "n", Service: "s"})
		done <- answer{li, err}
	}()
	select {
	case <-res.syncing:
	case a := <-done:
		t.Fatalf("attach answered (%+v, %v) before the resolver synced its namespace", a.li, a.err)
	case <-time.After(10 * time.Second):
		t.Fatal("the resolver never synced the new namespace")
	}
	select {
	case a := <-done:
		t.Fatalf("attach answered (%+v, %v) while its resolver socket was still opening", a.li, a.err)
	case <-time.After(100 * time.Millisecond):
	}
	close(res.gate)
	select {
	case a := <-done:
		if a.err != nil || !a.li.Ready {
			t.Fatalf("attach answered %+v, %v; want a ready interface", a.li, a.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("attach never answered after the resolver synced")
	}
	if n := testutil.ToFloat64(d.m.localCalls.WithLabelValues("attach", "ok")); n != 1 {
		t.Fatalf("sdn_agent_local_calls_total{call=attach,result=ok} = %v, want 1", n)
	}
	var conv dto.Metric
	if err := d.m.convergence.Write(&conv); err != nil {
		t.Fatal(err)
	}
	if n := conv.GetHistogram().GetSampleCount(); n != 1 {
		t.Fatalf("sdn_agent_convergence_seconds holds %d samples after one namespace settled, want 1", n)
	}
	// The census gauges refresh once a second.
	deadline := time.Now().Add(3 * time.Second)
	for testutil.ToFloat64(d.m.interfaces.WithLabelValues("ready")) != 1 || testutil.ToFloat64(d.m.namespaces.WithLabelValues("named")) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("census gauges: ready interfaces %v, named namespaces %v; want 1 and 1",
				testutil.ToFloat64(d.m.interfaces.WithLabelValues("ready")), testutil.ToFloat64(d.m.namespaces.WithLabelValues("named")))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// relayCP pushes one host state naming a relay at 192.0.2.1, then parks.
type relayCP struct {
	soloCP
	sent sync.Once
}

func (c *relayCP) HostState(ctx context.Context, since uint64, wait time.Duration) (api.StateUpdate, error) {
	var u api.StateUpdate
	pushed := false
	c.sent.Do(func() {
		n := api.NetworkState{Network: "net-1", Name: "n", Revision: 1, Prefix6: netip.MustParsePrefix("fd00::/64"), MTU: 1380,
			Relays: []api.RelayRef{{Relay: "r1", Probe: netip.MustParseAddrPort("192.0.2.1:9")}}}
		u = api.StateUpdate{Host: "h1", Generation: 1, Networks: []api.NetworkState{n}, Present: []api.NetworkRef{{Network: "net-1", Revision: 1}}}
		pushed = true
	})
	if pushed {
		return u, nil
	}
	return c.soloCP.HostState(ctx, since, wait)
}

// flakyEgress fails its first refresh and records each one that succeeds.
type flakyEgress struct {
	mu      sync.Mutex
	calls   int
	applied chan []netip.Prefix
}

func (e *flakyEgress) EnsureEgress(blocked []netip.Prefix) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	if e.calls == 1 {
		return errors.New("netlink: resource busy")
	}
	e.applied <- slices.Clone(blocked)
	return nil
}

func TestTheEgressFilterRetriesAndFollowsTheHostsPrefixes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core := agentcore.New(agentcore.DefaultConfig("h1"), prng.New(1))
	cfg := DefaultConfig("h1")
	cfg.EgressRetry = 20 * time.Millisecond
	d := New(cfg, core, &lockedKernel{k: kmodel.New()}, &relayCP{}, memJournal{}, nil, nil, NewMetrics(prometheus.NewRegistry()), zerolog.Nop())
	egress := &flakyEgress{applied: make(chan []netip.Prefix, 16)}
	var mu sync.Mutex
	host := netip.MustParsePrefix("198.51.100.0/24")
	d.Egress, d.EgressBase = egress, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	d.HostPrefixes = func() ([]netip.Prefix, error) {
		mu.Lock()
		defer mu.Unlock()
		return []netip.Prefix{host}, nil
	}
	go d.Run(ctx)
	next := func() []netip.Prefix {
		t.Helper()
		select {
		case b := <-egress.applied:
			return b
		case <-time.After(10 * time.Second):
			t.Fatal("the egress filter was never refreshed")
			return nil
		}
	}
	relay := netip.MustParsePrefix("192.0.2.1/32")
	got := next()
	for _, want := range []netip.Prefix{relay, host, d.EgressBase[0]} {
		if !slices.Contains(got, want) {
			t.Fatalf("the refresh after a failure blocks %v, which lacks %v", got, want)
		}
	}
	mu.Lock()
	host = netip.MustParsePrefix("198.51.101.0/24")
	mu.Unlock()
	d.UnderlayChanged()
	if got := next(); !slices.Contains(got, netip.MustParsePrefix("198.51.101.0/24")) || !slices.Contains(got, relay) {
		t.Fatalf("after the underlay moved the filter blocks %v; want the new host prefix and the relay", got)
	}
}

func TestAnUnderlayChangeBeforeDesiredStateKeepsTheEarlierFilter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core := agentcore.New(agentcore.DefaultConfig("h1"), prng.New(1))
	d := New(DefaultConfig("h1"), core, &lockedKernel{k: kmodel.New()}, soloCP{}, memJournal{}, nil, nil, NewMetrics(prometheus.NewRegistry()), zerolog.Nop())
	applied := make(chan []netip.Prefix, 16)
	kept, host := netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("198.51.101.0/24")
	d.Egress, d.EgressKept = egressFunc(func(b []netip.Prefix) error { applied <- b; return nil }), []netip.Prefix{kept}
	d.HostPrefixes = func() ([]netip.Prefix, error) { return []netip.Prefix{host}, nil }
	go d.Run(ctx)
	<-d.Up()
	d.UnderlayChanged()
	select {
	case got := <-applied:
		if !slices.Contains(got, kept) || !slices.Contains(got, host) {
			t.Fatalf("the filter blocks %v; want the earlier relay and the new host prefix", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an underlay change before desired state left the filter as it was")
	}
}

type egressFunc func([]netip.Prefix) error

func (f egressFunc) EnsureEgress(b []netip.Prefix) error { return f(b) }
