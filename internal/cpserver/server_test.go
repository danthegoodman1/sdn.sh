package cpserver

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"sdn.sh/internal/api"
	"sdn.sh/internal/cpclient"
	"sdn.sh/internal/model"
	"sdn.sh/internal/prng"
	"sdn.sh/internal/store"
	"sdn.sh/internal/store/locked"
	"sdn.sh/internal/store/mem"
	"sdn.sh/internal/store/pgstore/pgtest"
)

const adminToken = "test-admin-token-0123456789"

type env struct {
	t     *testing.T
	srv   *Server
	url   string
	admin *cpclient.Client
	ctx   context.Context
}

func testConfig() Config {
	cfg := DefaultConfig(adminToken)
	cfg.PollTimeout = 2 * time.Second
	cfg.SweepEvery = 50 * time.Millisecond
	return cfg
}

// eachStore runs a test against the in-memory store and, when
// SDN_TEST_POSTGRES names a database, against Postgres.
func eachStore(t *testing.T, fn func(t *testing.T, open func() store.Store)) {
	t.Run("mem", func(t *testing.T) {
		fn(t, func() store.Store { return locked.New(mem.New()) })
	})
	t.Run("postgres", func(t *testing.T) {
		pgtest.DSN(t)
		fn(t, func() store.Store { return pgtest.Open(t) })
	})
}

func newEnv(t *testing.T, st store.Store, cfg Config) *env {
	t.Helper()
	srv, err := New(cfg, st, zerolog.Nop(), prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Run(ctx)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	e := &env{t: t, srv: srv, url: hs.URL, ctx: ctx}
	e.admin = e.client(adminToken)
	return e
}

func (e *env) client(token string) *cpclient.Client {
	c, err := cpclient.New(e.url, token, cpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// must returns v, or panics with err, which fails the test with a trace.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func code(err error) string {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// attachReq builds an attach the way an agent does: its own identifier and
// a fresh public key.
func attachReq(t *testing.T, r *prng.Rand, net, svc string, port uint16) api.AttachRequest {
	priv, err := model.NewPrivateKey(r)
	if err != nil {
		t.Fatal(err)
	}
	id, err := model.NewID(model.InterfacePrefix, r)
	if err != nil {
		t.Fatal(err)
	}
	return api.AttachRequest{Interface: model.InterfaceID(id), Network: net, Service: svc, PublicKey: priv.Public(), ListenPort: port}
}

func TestTheAPIRefusesCallersWithoutTheirToken(t *testing.T) {
	eachStore(t, func(t *testing.T, open func() store.Store) {
		e := newEnv(t, open(), testConfig())
		if _, err := e.client("wrong-token").Networks(e.ctx); code(err) != api.CodeForbidden {
			t.Fatalf("a bad admin token: %v", err)
		}
		host := must(e.admin.CreateHost(e.ctx, api.CreateHost{Name: "h1"}))
		agent := e.client(host.Token)
		// A host token reaches the agent API and nothing else.
		if _, err := agent.Networks(e.ctx); code(err) != api.CodeForbidden {
			t.Fatalf("a host token on the operator's API: %v", err)
		}
		if _, err := agent.RelayState(e.ctx, 0, time.Second); code(err) != api.CodeForbidden {
			t.Fatalf("a host token on the relay API: %v", err)
		}
		if _, err := agent.HostState(e.ctx, 0, 5*time.Second); err != nil {
			t.Fatalf("the host's own poll: %v", err)
		}
	})
}

func TestErrorsMapToCodes(t *testing.T) {
	eachStore(t, func(t *testing.T, open func() store.Store) {
		e := newEnv(t, open(), testConfig())
		if _, err := e.admin.Network(e.ctx, "nope"); code(err) != api.CodeNotFound {
			t.Fatalf("a missing network: %v", err)
		}
		must(e.admin.CreateNetwork(e.ctx, api.CreateNetwork{Name: "prod"}))
		if _, err := e.admin.CreateNetwork(e.ctx, api.CreateNetwork{Name: "prod"}); code(err) != api.CodeConflict {
			t.Fatalf("a duplicate name: %v", err)
		}
		if _, err := e.admin.CreateNetwork(e.ctx, api.CreateNetwork{Name: "Not A Label"}); code(err) != api.CodeInvalid {
			t.Fatalf("a bad name: %v", err)
		}
	})
}

// TestALongPollWakesOnTheCommitThatConcernsIt parks one host's poll, then
// attaches on another host into the same network under a rule connecting
// the two: the parked poll answers well before its timeout.
func TestALongPollWakesOnTheCommitThatConcernsIt(t *testing.T) {
	eachStore(t, func(t *testing.T, open func() store.Store) {
		e := newEnv(t, open(), testConfig())
		r := prng.New(1)
		must(e.admin.CreateNetwork(e.ctx, api.CreateNetwork{Name: "prod"}))
		must(e.admin.CreateService(e.ctx, "prod", api.CreateService{Name: "web"}))
		must(e.admin.CreateService(e.ctx, "prod", api.CreateService{Name: "db"}))
		must(e.admin.CreateRule(e.ctx, "prod", api.CreateRule{From: "web", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))
		h1 := e.client(must(e.admin.CreateHost(e.ctx, api.CreateHost{Name: "h1"})).Token)
		h2 := e.client(must(e.admin.CreateHost(e.ctx, api.CreateHost{Name: "h2"})).Token)

		web := must(h1.Attach(e.ctx, attachReq(t, r, "prod", "web", 40001)))
		if len(web.State.Interfaces) != 1 || len(web.State.Interfaces[0].Peers) != 0 {
			t.Fatalf("web before db: %+v", web.State.Interfaces)
		}
		first := must(h1.HostState(e.ctx, 0, 5*time.Second))

		type answer struct {
			u   api.StateUpdate
			err error
			at  time.Duration
		}
		got := make(chan answer, 1)
		start := time.Now()
		go func() {
			u, err := h1.HostState(e.ctx, first.Generation, 5*time.Second)
			got <- answer{u, err, time.Since(start)}
		}()
		time.Sleep(200 * time.Millisecond)
		db := must(h2.Attach(e.ctx, attachReq(t, r, "prod", "db", 40002)))
		a := <-got
		if a.err != nil {
			t.Fatal(a.err)
		}
		if a.at > time.Second {
			t.Fatalf("the poll answered after %v, at its timeout rather than the commit", a.at)
		}
		if a.u.Generation <= first.Generation || len(a.u.Networks) != 1 {
			t.Fatalf("the woken poll carried %+v", a.u)
		}
		peers := a.u.Networks[0].Interfaces[0].Peers
		if len(peers) != 1 || peers[0].Interface != db.Interface {
			t.Fatalf("web's peers after db attached: %+v", peers)
		}

		// A poll at the current generation with nothing changing answers at
		// its timeout, carrying nothing new.
		start = time.Now()
		u := must(h1.HostState(e.ctx, a.u.Generation, 5*time.Second))
		if d := time.Since(start); d < time.Second || len(u.Networks) != 0 {
			t.Fatalf("an idle poll answered after %v with %d networks", d, len(u.Networks))
		}
	})
}

// TestRevocationReachesThePeerAndTheRelay attaches a pair across two hosts
// with a relay, revokes one side, and checks both the other host's state
// and the relay's port table drop it.
func TestRevocationReachesThePeerAndTheRelay(t *testing.T) {
	eachStore(t, func(t *testing.T, open func() store.Store) {
		e := newEnv(t, open(), testConfig())
		r := prng.New(2)
		relayCreds := must(e.admin.CreateRelay(e.ctx, api.CreateRelay{
			Name:      "r1",
			Addresses: []api.RelayAddress{{Local: netip.MustParseAddr("10.0.0.1"), Advertised: netip.MustParseAddr("198.51.100.1")}},
			PortLo:    20000, PortHi: 20099, ProbePort: 19999,
		}))
		relay := e.client(relayCreds.Token)
		must(e.admin.CreateNetwork(e.ctx, api.CreateNetwork{Name: "prod", Relays: []model.RelayID{model.RelayID(relayCreds.ID)}}))
		must(e.admin.CreateService(e.ctx, "prod", api.CreateService{Name: "web"}))
		must(e.admin.CreateService(e.ctx, "prod", api.CreateService{Name: "db"}))
		must(e.admin.CreateRule(e.ctx, "prod", api.CreateRule{From: "web", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))
		h1 := e.client(must(e.admin.CreateHost(e.ctx, api.CreateHost{Name: "h1"})).Token)
		h2 := e.client(must(e.admin.CreateHost(e.ctx, api.CreateHost{Name: "h2"})).Token)
		must(h1.Attach(e.ctx, attachReq(t, r, "prod", "web", 40001)))
		db := must(h2.Attach(e.ctx, attachReq(t, r, "prod", "db", 40002)))

		st := must(relay.RelayState(e.ctx, 0, 5*time.Second))
		if len(st.Ports) != 2 {
			t.Fatalf("the relay serves %d ports for one edge, want 2", len(st.Ports))
		}
		u := must(h1.HostState(e.ctx, 0, 5*time.Second))
		if peers := u.Networks[0].Interfaces[0].Peers; len(peers) != 1 || len(peers[0].Relays) != 1 {
			t.Fatalf("web's peers: %+v", peers)
		}

		relayWoke := make(chan api.RelayState, 1)
		go func() {
			st, _ := relay.RelayState(e.ctx, st.Generation, 5*time.Second)
			relayWoke <- st
		}()
		time.Sleep(100 * time.Millisecond)
		if err := e.admin.Revoke(e.ctx, db.Interface); err != nil {
			t.Fatal(err)
		}
		after := must(h1.HostState(e.ctx, u.Generation, 5*time.Second))
		if len(after.Networks) != 1 || len(after.Networks[0].Interfaces[0].Peers) != 0 {
			t.Fatalf("web still peers with the revoked interface: %+v", after.Networks)
		}
		// The relay keeps a revoked edge's ports dormant only while policy
		// still connects a live pair; a revocation ends the pair.
		select {
		case st2 := <-relayWoke:
			if st2.Generation <= st.Generation {
				t.Fatalf("the relay's poll answered without a newer table: %+v", st2)
			}
		case <-time.After(4 * time.Second):
			t.Fatal("the relay's poll did not wake on the revocation")
		}
		ifaces := must(e.admin.Interfaces(e.ctx, "prod"))
		for _, i := range ifaces {
			if i.ID == db.Interface && i.State != api.Revoked {
				t.Fatalf("db is %s", i.State)
			}
		}
	})
}

// TestALeaseLeftUnrenewedExpires runs the server's own sweep: an interface
// whose agent stops renewing is revoked once its lease ends, and one that
// renews stays live.
func TestALeaseLeftUnrenewedExpires(t *testing.T) {
	eachStore(t, func(t *testing.T, open func() store.Store) {
		cfg := testConfig()
		cfg.Plane.LeaseTTL = 500 * time.Millisecond
		cfg.Plane.DrainGrace = 200 * time.Millisecond
		cfg.Plane.Quarantine4 = time.Second
		cfg.Plane.Retention = time.Minute
		e := newEnv(t, open(), cfg)
		ctx := e.ctx
		r := prng.New(3)
		must(e.admin.CreateNetwork(ctx, api.CreateNetwork{Name: "prod"}))
		must(e.admin.CreateService(ctx, "prod", api.CreateService{Name: "web"}))
		h := e.client(must(e.admin.CreateHost(ctx, api.CreateHost{Name: "h1"})).Token)
		kept := must(h.Attach(ctx, attachReq(t, r, "prod", "web", 40001)))
		left := must(h.Attach(ctx, attachReq(t, r, "prod", "web", 40002)))
		// Boot holds expiry off for one lease term; renew the kept one
		// across it and past the other's expiry.
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			must(h.Renew(ctx, []model.InterfaceID{kept.Interface}))
			time.Sleep(100 * time.Millisecond)
		}
		states := map[model.InterfaceID]api.LeaseState{}
		for _, i := range must(e.admin.Interfaces(ctx, "prod")) {
			states[i.ID] = i.State
		}
		if states[kept.Interface] != api.Live || states[left.Interface] != api.Revoked {
			t.Fatalf("after expiry: kept %s, left %s", states[kept.Interface], states[left.Interface])
		}
	})
}

// TestAReplicaWakesForAnotherReplicasCommit runs two servers over one
// Postgres database: a poll parked on one answers when an attach commits
// through the other.
func TestAReplicaWakesForAnotherReplicasCommit(t *testing.T) {
	dsn := pgtest.NewSchema(t)
	a := newEnv(t, pgtest.OpenDSN(t, dsn), testConfig())
	b := newEnv(t, pgtest.OpenDSN(t, dsn), testConfig())
	r := prng.New(4)
	must(a.admin.CreateNetwork(a.ctx, api.CreateNetwork{Name: "prod"}))
	must(a.admin.CreateService(a.ctx, "prod", api.CreateService{Name: "web"}))
	must(a.admin.CreateRule(a.ctx, "prod", api.CreateRule{From: "web", To: "web", Proto: model.TCP, Ports: model.PortRange{Lo: 80, Hi: 80}}))
	creds1 := must(a.admin.CreateHost(a.ctx, api.CreateHost{Name: "h1"}))
	creds2 := must(a.admin.CreateHost(a.ctx, api.CreateHost{Name: "h2"}))
	h1a, h2b := a.client(creds1.Token), b.client(creds2.Token)
	must(h1a.Attach(a.ctx, attachReq(t, r, "prod", "web", 40001)))
	first := must(h1a.HostState(a.ctx, 0, 5*time.Second))
	done := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		h1a.HostState(a.ctx, first.Generation, 5*time.Second)
		done <- time.Since(start)
	}()
	time.Sleep(200 * time.Millisecond)
	must(h2b.Attach(b.ctx, attachReq(t, r, "prod", "web", 40002)))
	if d := <-done; d > time.Second {
		t.Fatalf("the poll on replica a answered after %v, at its timeout", d)
	}
}
