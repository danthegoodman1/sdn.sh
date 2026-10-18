// Package cpserver serves the control plane's HTTP API over a store: the
// operator's resources, the agents' attach, release, renew and long poll,
// and the relays' long poll. The decisions are cp.Plane's; this package
// authenticates callers, runs each decision in a transaction, wakes the
// long polls a commit touches, and runs the sweeps that expire leases.
package cpserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"sdn.sh/internal/api"
	"sdn.sh/internal/cp"
	"sdn.sh/internal/model"
	"sdn.sh/internal/store"
)

// Config holds what a server needs beyond its store.
type Config struct {
	Plane cp.Config
	// AdminToken authorizes the operator's API.
	AdminToken string
	// PollTimeout is how long a long poll parks before answering with what
	// is current.
	PollTimeout time.Duration
	// SweepEvery is how often the server heartbeats and sweeps leases.
	SweepEvery time.Duration
	// CacheNetworks bounds how many compiled networks stay cached.
	CacheNetworks int
}

// DefaultConfig returns production settings around an admin token.
func DefaultConfig(adminToken string) Config {
	return Config{
		Plane:         cp.DefaultConfig(),
		AdminToken:    adminToken,
		PollTimeout:   25 * time.Second,
		SweepEvery:    time.Second,
		CacheNetworks: 4096,
	}
}

// Watcher is a store that reports commits made through any handle, so
// every replica wakes its long polls for the others' writes. pgstore is
// one.
type Watcher interface {
	// Watch delivers each commit's change until ctx ends or the feed
	// breaks, then closes the channel. Changes may go unseen across a
	// break, so a caller that watches again re-reads what it serves.
	Watch(ctx context.Context) (<-chan store.Change, error)
}

// Server is one control-plane replica. Replicas share a store; a store
// that implements Watcher wakes each replica's polls for the others'
// commits.
type Server struct {
	cfg   Config
	store store.Store
	plane *cp.Plane
	cache *lockedCache
	hub   *hub
	log   zerolog.Logger
	m     *metrics
	now   func() time.Time

	tokens sync.Map // [32]byte -> principal, positive lookups only
}

type principal struct {
	host  model.HostID
	relay model.RelayID
}

// New returns a server. Call Run to boot it and serve its background work.
func New(cfg Config, st store.Store, log zerolog.Logger, reg prometheus.Registerer) (*Server, error) {
	if err := cfg.Plane.Validate(); err != nil {
		return nil, err
	}
	if len(cfg.AdminToken) < 16 {
		return nil, errors.New("admin token must be at least 16 characters")
	}
	s := &Server{
		cfg:   cfg,
		store: st,
		plane: &cp.Plane{Config: cfg.Plane, Rand: rand.Reader},
		cache: &lockedCache{lru: cp.NewLRU(cfg.CacheNetworks)},
		hub:   newHub(),
		log:   log,
		now:   time.Now,
	}
	s.m = newMetrics(reg, s.hub)
	return s, nil
}

// Run boots the plane and runs heartbeats, sweeps and the store's change
// feed until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	var down time.Duration
	if _, err := s.update(ctx, "boot", func(tx store.Tx) error {
		var err error
		down, err = s.plane.Boot(tx, s.now())
		return err
	}); err != nil {
		return fmt.Errorf("boot: %w", err)
	}
	s.log.Info().Dur("down", down).Msg("control plane booted; lease expiry held for at least one term")
	if w, ok := s.store.(Watcher); ok {
		go s.watch(ctx, w)
	}
	t := time.NewTicker(s.cfg.SweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.sweep(ctx)
		}
	}
}

// watch wakes polls for commits other replicas make. A break in the feed
// may hide changes, so every parked poll re-reads when the feed returns.
func (s *Server) watch(ctx context.Context, w Watcher) {
	for ctx.Err() == nil {
		ch, err := w.Watch(ctx)
		if err == nil {
			s.hub.wakeAll(s.now())
			for c := range ch {
				s.hub.publish(c, s.now())
			}
		}
		if ctx.Err() != nil {
			return
		}
		s.log.Warn().Err(err).Msg("store change feed broke; reconnecting")
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

// sweep heartbeats, then sweeps in batches until a batch comes back short.
func (s *Server) sweep(ctx context.Context) {
	if _, err := s.update(ctx, "heartbeat", func(tx store.Tx) error { return s.plane.Heartbeat(tx, s.now()) }); err != nil {
		s.log.Warn().Err(err).Msg("heartbeat failed")
		return
	}
	for {
		var n int
		if _, err := s.update(ctx, "sweep", func(tx store.Tx) error {
			var err error
			n, err = s.plane.Sweep(tx, s.now())
			return err
		}); err != nil {
			s.log.Warn().Err(err).Msg("sweep failed")
			return
		}
		s.m.swept.Add(float64(n))
		if n > 0 {
			s.log.Info().Int("interfaces", n).Msg("swept leases, drains and retention")
		}
		if n < cp.SweepBatch {
			return
		}
	}
}

// update runs one transaction and wakes the polls its commit touches.
func (s *Server) update(ctx context.Context, op string, fn func(store.Tx) error) (store.Change, error) {
	start := time.Now()
	ch, err := s.store.Update(ctx, fn)
	s.m.observeTx(op, err, time.Since(start))
	if err == nil {
		s.hub.publish(ch, s.now())
	}
	return ch, err
}

func (s *Server) view(ctx context.Context, op string, fn func(store.ReadTx) error) error {
	start := time.Now()
	err := s.store.View(ctx, fn)
	s.m.observeTx(op, err, time.Since(start))
	return err
}

// Handler returns the API's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, auth func(http.ResponseWriter, *http.Request) (principal, bool), h func(*http.Request, principal) (any, error)) {
		name := pattern
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			p, ok := auth(w, r)
			code := http.StatusUnauthorized
			if ok {
				out, err := h(r, p)
				code = s.respond(w, r, out, err)
			}
			s.m.requests.WithLabelValues(name, strconv.Itoa(code)).Inc()
			s.m.latency.WithLabelValues(name).Observe(time.Since(start).Seconds())
		})
	}
	admin, host, relay := s.authAdmin, s.authHost, s.authRelay

	route("POST /v1/networks", admin, s.createNetwork)
	route("GET /v1/networks", admin, s.listNetworks)
	route("GET /v1/networks/{net}", admin, s.getNetwork)
	route("DELETE /v1/networks/{net}", admin, s.deleteNetwork)
	route("POST /v1/networks/{net}/services", admin, s.createService)
	route("GET /v1/networks/{net}/services", admin, s.listServices)
	route("DELETE /v1/networks/{net}/services/{svc}", admin, s.deleteService)
	route("POST /v1/networks/{net}/rules", admin, s.createRule)
	route("GET /v1/networks/{net}/rules", admin, s.listRules)
	route("DELETE /v1/networks/{net}/rules/{rule}", admin, s.deleteRule)
	route("GET /v1/networks/{net}/interfaces", admin, s.listInterfaces)
	route("POST /v1/interfaces/{id}/revoke", admin, s.revoke)
	route("POST /v1/networks/{net}/devices", admin, s.createDevice)
	route("POST /v1/hosts", admin, s.createHost)
	route("POST /v1/relays", admin, s.createRelay)
	route("GET /v1/relays", admin, s.listRelays)

	route("POST /v1/agent/attach", host, s.attach)
	route("POST /v1/agent/release", host, s.release)
	route("POST /v1/agent/renew", host, s.renew)
	route("GET /v1/agent/state", host, s.hostPoll)

	route("GET /v1/relay/state", relay, s.relayPoll)
	return mux
}

// Serve serves the API on a listener until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	s.log.Info().Str("addr", ln.Addr().String()).Msg("API listening")
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// respond writes a result or an error and returns the status it sent.
func (s *Server) respond(w http.ResponseWriter, r *http.Request, out any, err error) int {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		code, body := errorBody(err)
		if code >= 500 {
			s.log.Error().Err(err).Str("route", r.Pattern).Msg("request failed")
		}
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(body)
		return code
	}
	if out == nil {
		out = struct{}{}
	}
	json.NewEncoder(w).Encode(out)
	return http.StatusOK
}

func errorBody(err error) (int, *api.Error) {
	var ae *api.Error
	switch {
	case errors.As(err, &ae):
	case errors.Is(err, store.ErrNotFound):
		ae = &api.Error{Code: api.CodeNotFound, Message: err.Error()}
	case errors.Is(err, store.ErrConflict):
		ae = &api.Error{Code: api.CodeConflict, Message: err.Error()}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		ae = &api.Error{Code: api.CodeUnavailable, Message: err.Error()}
	default:
		return http.StatusInternalServerError, &api.Error{Code: "internal", Message: "internal error"}
	}
	code := map[string]int{
		api.CodeNotFound:    http.StatusNotFound,
		api.CodeConflict:    http.StatusConflict,
		api.CodeInvalid:     http.StatusBadRequest,
		api.CodeExhausted:   http.StatusConflict,
		api.CodeForbidden:   http.StatusForbidden,
		api.CodeUnavailable: http.StatusServiceUnavailable,
	}[ae.Code]
	if code == 0 {
		code = http.StatusBadRequest
	}
	return code, ae
}

func decode[T any](r *http.Request) (T, error) {
	var v T
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, &api.Error{Code: api.CodeInvalid, Message: "body: " + err.Error()}
	}
	return v, nil
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(h, "Bearer "); ok {
		return t
	}
	return ""
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(&api.Error{Code: api.CodeForbidden, Message: "bad or missing bearer token"})
}

func (s *Server) authAdmin(w http.ResponseWriter, r *http.Request) (principal, bool) {
	if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.AdminToken)) != 1 {
		unauthorized(w)
		return principal{}, false
	}
	return principal{}, true
}

// lookup resolves a bearer token to its host or relay, caching hits.
func (s *Server) lookup(r *http.Request, find func(store.ReadTx, [32]byte) (principal, error)) (principal, bool) {
	t := bearer(r)
	if t == "" {
		return principal{}, false
	}
	hash := cp.HashToken(t)
	if p, ok := s.tokens.Load(hash); ok {
		return p.(principal), true
	}
	var p principal
	if err := s.view(r.Context(), "auth", func(tx store.ReadTx) error {
		var err error
		p, err = find(tx, hash)
		return err
	}); err != nil {
		return principal{}, false
	}
	s.tokens.Store(hash, p)
	return p, true
}

func (s *Server) authHost(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := s.lookup(r, func(tx store.ReadTx, h [32]byte) (principal, error) {
		host, err := tx.HostByToken(h)
		return principal{host: host.ID}, err
	})
	if !ok || p.host == "" {
		unauthorized(w)
		return principal{}, false
	}
	return p, true
}

func (s *Server) authRelay(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := s.lookup(r, func(tx store.ReadTx, h [32]byte) (principal, error) {
		relay, err := tx.RelayByToken(h)
		return principal{relay: relay.ID}, err
	})
	if !ok || p.relay == "" {
		unauthorized(w)
		return principal{}, false
	}
	return p, true
}

// lockedCache shares one compiled-network cache between requests.
type lockedCache struct {
	mu  sync.Mutex
	lru *cp.LRU
}

func (c *lockedCache) Get(n model.NetworkID, rev uint64) (cp.Compiled, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Get(n, rev)
}

func (c *lockedCache) Put(n model.NetworkID, rev uint64, v cp.Compiled) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru.Put(n, rev, v)
}
