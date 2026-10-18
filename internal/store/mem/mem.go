//sdn:deterministic

// Package mem is an in-memory store for the simulator and tests. One
// transaction runs at a time, so every schedule is serializable; it is not
// safe for concurrent use, and package locked wraps it for daemons.
package mem

import (
	"cmp"
	"context"
	"maps"
	"net/netip"
	"slices"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
	"sdn.sh/internal/store"
)

// Store holds every record in maps.
type Store struct {
	networks   table[model.NetworkID, store.Network]
	services   table[model.ServiceID, store.Service]
	interfaces table[model.InterfaceID, store.Interface]
	rules      table[model.RuleID, store.Rule]
	edges      table[edgeKey, store.Edge]
	hosts      table[model.HostID, store.Host]
	relays     table[model.RelayID, store.Relay]
	released4  table[addrKey, store.Released4]
	ports      table[portKey, store.ReleasedPort]
	cursors    table[addrKey, uint16]
	meta       table[string, string]
	revision   uint64
	// Updates counts transactions run.
	Updates uint64
	// FailNext makes the next n updates fail before committing, as a
	// database that loses its connection would.
	FailNext int
}

// ErrInjected is the failure FailNext produces.
var ErrInjected error = &api.Error{Code: api.CodeUnavailable, Message: "injected store failure"}

type edgeKey struct {
	net  model.NetworkID
	a, b model.InterfaceID
}

func (k edgeKey) compare(o edgeKey) int {
	return cmp.Or(cmp.Compare(k.net, o.net), cmp.Compare(k.a, o.a), cmp.Compare(k.b, o.b))
}

// addrKey keys a record by an owner and an address, rendered as a string so
// the key orders.
type addrKey string

func mkAddrKey(owner string, addr netip.Addr) addrKey {
	return addrKey(owner + "|" + addr.String())
}

type portKey struct {
	addr addrKey
	port uint16
}

// New returns an empty store.
func New() *Store {
	return &Store{
		networks:   newTable[model.NetworkID, store.Network](cmp.Compare[model.NetworkID]),
		services:   newTable[model.ServiceID, store.Service](cmp.Compare[model.ServiceID]),
		interfaces: newTable[model.InterfaceID, store.Interface](cmp.Compare[model.InterfaceID]),
		rules:      newTable[model.RuleID, store.Rule](cmp.Compare[model.RuleID]),
		edges:      newTable[edgeKey, store.Edge](edgeKey.compare),
		hosts:      newTable[model.HostID, store.Host](cmp.Compare[model.HostID]),
		relays:     newTable[model.RelayID, store.Relay](cmp.Compare[model.RelayID]),
		released4:  newTable[addrKey, store.Released4](cmp.Compare[addrKey]),
		ports: newTable[portKey, store.ReleasedPort](func(a, b portKey) int {
			return cmp.Or(cmp.Compare(a.addr, b.addr), cmp.Compare(a.port, b.port))
		}),
		cursors: newTable[addrKey, uint16](cmp.Compare[addrKey]),
		meta:    newTable[string, string](cmp.Compare[string]),
	}
}

// Update runs fn in a transaction and commits it if fn succeeds.
func (s *Store) Update(_ context.Context, fn func(store.Tx) error) (store.Change, error) {
	s.Updates++
	tx := s.begin()
	if err := fn(tx); err != nil {
		return store.Change{}, err
	}
	if s.FailNext > 0 {
		s.FailNext--
		return store.Change{}, ErrInjected
	}
	tx.commit()
	return tx.change, nil
}

// View runs fn over the committed records.
func (s *Store) View(_ context.Context, fn func(store.ReadTx) error) error {
	return fn(s.begin())
}

// Revision is the last revision committed.
func (s *Store) Revision() uint64 { return s.revision }

type tx struct {
	s          *Store
	networks   *overlay[model.NetworkID, store.Network]
	services   *overlay[model.ServiceID, store.Service]
	interfaces *overlay[model.InterfaceID, store.Interface]
	rules      *overlay[model.RuleID, store.Rule]
	edges      *overlay[edgeKey, store.Edge]
	hosts      *overlay[model.HostID, store.Host]
	relays     *overlay[model.RelayID, store.Relay]
	released4  *overlay[addrKey, store.Released4]
	ports      *overlay[portKey, store.ReleasedPort]
	cursors    *overlay[addrKey, uint16]
	meta       *overlay[string, string]
	revision   uint64
	change     store.Change
}

func (s *Store) begin() *tx {
	return &tx{
		s:          s,
		networks:   s.networks.overlay(),
		services:   s.services.overlay(),
		interfaces: s.interfaces.overlay(),
		rules:      s.rules.overlay(),
		edges:      s.edges.overlay(),
		hosts:      s.hosts.overlay(),
		relays:     s.relays.overlay(),
		released4:  s.released4.overlay(),
		ports:      s.ports.overlay(),
		cursors:    s.cursors.overlay(),
		meta:       s.meta.overlay(),
	}
}

func (t *tx) commit() {
	t.networks.commit()
	t.services.commit()
	t.interfaces.commit()
	t.rules.commit()
	t.edges.commit()
	t.hosts.commit()
	t.relays.commit()
	t.released4.commit()
	t.ports.commit()
	t.cursors.commit()
	t.meta.commit()
	if t.revision > 0 {
		t.s.revision = t.revision
		t.change.Revision = t.revision
	}
}

func found[V any](v V, ok bool) (V, error) {
	if !ok {
		var zero V
		return zero, store.ErrNotFound
	}
	return v, nil
}

func (t *tx) Network(id model.NetworkID) (store.Network, error) { return found(t.networks.get(id)) }
func (t *tx) NetworkByName(name string) (store.Network, error) {
	return first(t.networks.scan(func(n store.Network) bool { return n.Name == name }))
}
func (t *tx) Networks() ([]store.Network, error) { return t.networks.scan(nil), nil }

func (t *tx) Service(id model.ServiceID) (store.Service, error) { return found(t.services.get(id)) }
func (t *tx) ServiceByName(net model.NetworkID, name string) (store.Service, error) {
	return first(t.services.scan(func(s store.Service) bool { return s.Network == net && s.Name == name }))
}
func (t *tx) Services(net model.NetworkID) ([]store.Service, error) {
	return t.services.scan(func(s store.Service) bool { return s.Network == net }), nil
}

func (t *tx) Interface(id model.InterfaceID) (store.Interface, error) {
	return found(t.interfaces.get(id))
}
func (t *tx) Interfaces(net model.NetworkID) ([]store.Interface, error) {
	return t.interfaces.scan(func(i store.Interface) bool { return i.Network == net }), nil
}
func (t *tx) HostInterfaces(host model.HostID) ([]store.Interface, error) {
	return t.interfaces.scan(func(i store.Interface) bool { return i.Host == host }), nil
}
func (t *tx) Expired(at time.Time, limit int) ([]store.Interface, error) {
	out := t.interfaces.scan(func(i store.Interface) bool { return i.State == api.Live && i.Expires.Before(at) })
	slices.SortStableFunc(out, func(a, b store.Interface) int { return a.Expires.Compare(b.Expires) })
	return capped(out, limit), nil
}
func (t *tx) Undrained(at time.Time, limit int) ([]store.Interface, error) {
	out := t.interfaces.scan(func(i store.Interface) bool {
		return i.State == api.Released && !i.Drained && i.Ended.Before(at)
	})
	slices.SortStableFunc(out, func(a, b store.Interface) int { return a.Ended.Compare(b.Ended) })
	return capped(out, limit), nil
}
func (t *tx) Ended(at time.Time, limit int) ([]store.Interface, error) {
	out := t.interfaces.scan(func(i store.Interface) bool { return i.State != api.Live && i.Drained && i.Ended.Before(at) })
	slices.SortStableFunc(out, func(a, b store.Interface) int { return a.Ended.Compare(b.Ended) })
	return capped(out, limit), nil
}

func (t *tx) Rule(id model.RuleID) (store.Rule, error) { return found(t.rules.get(id)) }
func (t *tx) Rules(net model.NetworkID) ([]store.Rule, error) {
	return t.rules.scan(func(r store.Rule) bool { return r.Network == net }), nil
}

func (t *tx) Edges(net model.NetworkID) ([]store.Edge, error) {
	return t.edges.scan(func(e store.Edge) bool { return e.Network == net }), nil
}
func (t *tx) RelayEdges(relay model.RelayID) ([]store.Edge, error) {
	return t.edges.scan(func(e store.Edge) bool {
		return slices.ContainsFunc(e.Ports, func(p store.EdgePorts) bool { return p.Relay == relay })
	}), nil
}

func (t *tx) Host(id model.HostID) (store.Host, error) { return found(t.hosts.get(id)) }
func (t *tx) HostByName(name string) (store.Host, error) {
	return first(t.hosts.scan(func(h store.Host) bool { return h.Name == name }))
}
func (t *tx) HostByToken(hash [32]byte) (store.Host, error) {
	return first(t.hosts.scan(func(h store.Host) bool { return h.TokenHash == hash }))
}

func (t *tx) Relay(id model.RelayID) (store.Relay, error) { return found(t.relays.get(id)) }
func (t *tx) RelayByName(name string) (store.Relay, error) {
	return first(t.relays.scan(func(r store.Relay) bool { return r.Name == name }))
}
func (t *tx) RelayByToken(hash [32]byte) (store.Relay, error) {
	return first(t.relays.scan(func(r store.Relay) bool { return r.TokenHash == hash }))
}
func (t *tx) Relays() ([]store.Relay, error) { return t.relays.scan(nil), nil }

func (t *tx) Released4(net model.NetworkID, before time.Time, limit int) ([]store.Released4, error) {
	out := t.released4.scan(func(r store.Released4) bool { return r.Network == net && r.At.Before(before) })
	slices.SortStableFunc(out, func(a, b store.Released4) int {
		return cmp.Or(a.At.Compare(b.At), a.Addr.Compare(b.Addr))
	})
	return capped(out, limit), nil
}
func (t *tx) ReleasedPorts(relay model.RelayID, addr netip.Addr, before time.Time, limit int) ([]store.ReleasedPort, error) {
	out := t.ports.scan(func(p store.ReleasedPort) bool {
		return p.Relay == relay && p.Addr == addr && p.At.Before(before)
	})
	slices.SortStableFunc(out, func(a, b store.ReleasedPort) int {
		return cmp.Or(a.At.Compare(b.At), cmp.Compare(a.Port, b.Port))
	})
	return capped(out, limit), nil
}
func (t *tx) PortCursor(relay model.RelayID, addr netip.Addr) (uint16, error) {
	v, _ := t.cursors.get(mkAddrKey(string(relay), addr))
	return v, nil
}

func (t *tx) Meta(key string) (string, bool, error) {
	v, ok := t.meta.get(key)
	return v, ok, nil
}

func (t *tx) PutNetwork(n store.Network) error {
	if dup(t.networks.scan(func(o store.Network) bool { return o.Name == n.Name && o.ID != n.ID })) {
		return store.ErrConflict
	}
	t.networks.set(n.ID, n)
	return nil
}
func (t *tx) DeleteNetwork(id model.NetworkID) error { t.networks.delete(id); return nil }

func (t *tx) PutService(s store.Service) error {
	if dup(t.services.scan(func(o store.Service) bool {
		return o.Network == s.Network && o.Name == s.Name && o.ID != s.ID
	})) {
		return store.ErrConflict
	}
	t.services.set(s.ID, s)
	return nil
}
func (t *tx) DeleteService(id model.ServiceID) error { t.services.delete(id); return nil }

func (t *tx) PutInterface(i store.Interface) error { t.interfaces.set(i.ID, i); return nil }
func (t *tx) DeleteInterface(id model.InterfaceID) error {
	t.interfaces.delete(id)
	return nil
}

func (t *tx) PutRule(r store.Rule) error       { t.rules.set(r.ID, r); return nil }
func (t *tx) DeleteRule(id model.RuleID) error { t.rules.delete(id); return nil }
func (t *tx) PutEdge(e store.Edge) error       { t.edges.set(edgeKey{e.Network, e.A, e.B}, e); return nil }
func (t *tx) DeleteEdge(net model.NetworkID, a, b model.InterfaceID) error {
	t.edges.delete(edgeKey{net, a, b})
	return nil
}

func (t *tx) PutHost(h store.Host) error {
	if dup(t.hosts.scan(func(o store.Host) bool { return o.Name == h.Name && o.ID != h.ID })) {
		return store.ErrConflict
	}
	t.hosts.set(h.ID, h)
	return nil
}

func (t *tx) PutRelay(r store.Relay) error {
	if dup(t.relays.scan(func(o store.Relay) bool { return o.Name == r.Name && o.ID != r.ID })) {
		return store.ErrConflict
	}
	t.relays.set(r.ID, r)
	return nil
}

func (t *tx) PutReleased4(r store.Released4) error {
	t.released4.set(mkAddrKey(string(r.Network), r.Addr), r)
	return nil
}
func (t *tx) DeleteReleased4(net model.NetworkID, addr netip.Addr) error {
	t.released4.delete(mkAddrKey(string(net), addr))
	return nil
}
func (t *tx) PutReleasedPort(p store.ReleasedPort) error {
	t.ports.set(portKey{mkAddrKey(string(p.Relay), p.Addr), p.Port}, p)
	return nil
}
func (t *tx) DeleteReleasedPort(relay model.RelayID, addr netip.Addr, port uint16) error {
	t.ports.delete(portKey{mkAddrKey(string(relay), addr), port})
	return nil
}
func (t *tx) SetPortCursor(relay model.RelayID, addr netip.Addr, next uint16) error {
	t.cursors.set(mkAddrKey(string(relay), addr), next)
	return nil
}

func (t *tx) SetMeta(key, value string) error { t.meta.set(key, value); return nil }

func (t *tx) Bump() (uint64, error) {
	if t.revision == 0 {
		t.revision = t.s.revision + 1
	}
	return t.revision, nil
}

func (t *tx) Touch(c store.Change) { t.change.Merge(c) }

func first[V any](vs []V) (V, error) {
	if len(vs) == 0 {
		var zero V
		return zero, store.ErrNotFound
	}
	return vs[0], nil
}

func dup[V any](vs []V) bool { return len(vs) > 0 }

func capped[V any](vs []V, limit int) []V {
	if limit > 0 && len(vs) > limit {
		return vs[:limit]
	}
	return vs
}

// table is one record type's committed rows.
type table[K comparable, V any] struct {
	rows    map[K]V
	compare func(K, K) int
}

func newTable[K comparable, V any](compare func(K, K) int) table[K, V] {
	return table[K, V]{rows: map[K]V{}, compare: compare}
}

func (t *table[K, V]) overlay() *overlay[K, V] {
	return &overlay[K, V]{base: t, put: map[K]V{}, del: map[K]bool{}}
}

// overlay buffers one transaction's writes over a table.
type overlay[K comparable, V any] struct {
	base *table[K, V]
	put  map[K]V
	del  map[K]bool
}

func (o *overlay[K, V]) get(k K) (V, bool) {
	if o.del[k] {
		var zero V
		return zero, false
	}
	if v, ok := o.put[k]; ok {
		return v, true
	}
	v, ok := o.base.rows[k]
	return v, ok
}

func (o *overlay[K, V]) set(k K, v V) {
	delete(o.del, k)
	o.put[k] = v
}

func (o *overlay[K, V]) delete(k K) {
	delete(o.put, k)
	o.del[k] = true
}

// scan returns the rows match accepts, every row when match is nil, in key
// order.
func (o *overlay[K, V]) scan(match func(V) bool) []V {
	keys := slices.SortedFunc(maps.Keys(o.base.rows), o.base.compare)
	keys = append(keys, slices.SortedFunc(maps.Keys(o.put), o.base.compare)...)
	slices.SortFunc(keys, o.base.compare)
	keys = slices.CompactFunc(keys, func(a, b K) bool { return o.base.compare(a, b) == 0 })
	var out []V
	for _, k := range keys {
		if v, ok := o.get(k); ok && (match == nil || match(v)) {
			out = append(out, v)
		}
	}
	return out
}

func (o *overlay[K, V]) commit() {
	for _, k := range slices.SortedFunc(maps.Keys(o.del), o.base.compare) {
		delete(o.base.rows, k)
	}
	for _, k := range slices.SortedFunc(maps.Keys(o.put), o.base.compare) {
		o.base.rows[k] = o.put[k]
	}
}
