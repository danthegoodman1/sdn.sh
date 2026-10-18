//sdn:deterministic

// Package cp is the control plane's logic: allocation, leases, policy and
// edges, as transitions over a store transaction. It reads no clock and draws
// randomness only from the source it is given, so the simulator runs the
// same transitions a daemon does.
package cp

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
	"sdn.sh/internal/store"
)

// Config holds the control plane's clocks.
type Config struct {
	// LeaseTTL is how long a lease lasts unless renewed.
	LeaseTTL time.Duration
	// DrainGrace is how long peers keep a released interface installed, so
	// its established connections finish.
	DrainGrace time.Duration
	// Quarantine4 is how long a released IPv4 address waits before reuse.
	// It covers the grace period plus convergence.
	Quarantine4 time.Duration
	// PortQuarantine is how long a released relay port waits before reuse,
	// so a stale sender's packets stop arriving first.
	PortQuarantine time.Duration
	// Retention is how long an ended interface stays visible to its own
	// host, so the host learns its state.
	Retention time.Duration
	// MTU is a new network's overlay MTU unless it names one.
	MTU int
}

// DefaultConfig returns the production clocks.
func DefaultConfig() Config {
	return Config{
		LeaseTTL:       30 * time.Second,
		DrainGrace:     30 * time.Second,
		Quarantine4:    2 * time.Minute,
		PortQuarantine: 5 * time.Minute,
		Retention:      10 * time.Minute,
		MTU:            1380,
	}
}

// Validate checks that the clocks keep their promises to each other.
func (c Config) Validate() error {
	switch {
	case c.LeaseTTL <= 0 || c.DrainGrace <= 0:
		return errors.New("lease TTL and drain grace must be positive")
	case c.Quarantine4 <= c.DrainGrace:
		return errors.New("IPv4 quarantine must outlast the drain grace period")
	case c.Retention < c.DrainGrace:
		return errors.New("retention must cover the drain grace period")
	case c.MTU < 1280:
		return errors.New("MTU must be at least 1280, the IPv6 minimum")
	}
	return nil
}

// Plane carries out control-plane transitions.
type Plane struct {
	Config Config
	// Rand supplies identifiers, prefixes, secrets and tokens.
	Rand io.Reader
}

// Meta keys.
const (
	metaHeartbeat     = "heartbeat"
	metaExpiryResumes = "expiry_resumes"
)

// First host indexes handed out in each family. IPv6 keeps the low 256
// addresses of a network's /64 for its own infrastructure.
const (
	first6 = 0x100
	first4 = 1
)

func apiErr(code, format string, args ...any) error {
	return &api.Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// notFound turns a store miss into an API error naming what was missing.
func notFound(err error, what string) error {
	if errors.Is(err, store.ErrNotFound) {
		return apiErr(api.CodeNotFound, "%s not found", what)
	}
	return err
}

func conflict(err error, what string) error {
	if errors.Is(err, store.ErrConflict) {
		return apiErr(api.CodeConflict, "%s already exists", what)
	}
	return err
}

// ValidName reports whether s is a lowercase DNS label.
func ValidName(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (p *Plane) id(prefix string) (string, error) {
	return model.NewID(prefix, p.Rand)
}

// HashToken returns what the store keeps of a bearer token.
func HashToken(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func (p *Plane) token() (string, [32]byte, error) {
	var b [32]byte
	if _, err := io.ReadFull(p.Rand, b[:]); err != nil {
		return "", [32]byte{}, err
	}
	t := base64.RawURLEncoding.EncodeToString(b[:])
	return t, HashToken(t), nil
}

// bump gives the network, and the hosts whose interface set changed, this
// transaction's revision, and records the touch.
func bump(tx store.Tx, n *store.Network, hosts ...model.HostID) error {
	rev, err := tx.Bump()
	if err != nil {
		return err
	}
	n.Revision = rev
	if err := tx.PutNetwork(*n); err != nil {
		return err
	}
	ch := store.Change{Networks: []model.NetworkID{n.ID}}
	for _, id := range hosts {
		h, err := tx.Host(id)
		if err != nil {
			return notFound(err, "host "+string(id))
		}
		h.Revision = rev
		if err := tx.PutHost(h); err != nil {
			return err
		}
		ch.Hosts = append(ch.Hosts, id)
	}
	tx.Touch(ch)
	return nil
}

// ResolveNetwork finds a network by identifier or name.
func ResolveNetwork(tx store.ReadTx, ref string) (store.Network, error) {
	var n store.Network
	var err error
	if strings.HasPrefix(ref, model.NetworkPrefix) {
		n, err = tx.Network(model.NetworkID(ref))
	} else {
		n, err = tx.NetworkByName(ref)
	}
	return n, notFound(err, "network "+ref)
}

// ResolveService finds a service of a network by identifier or name.
func ResolveService(tx store.ReadTx, net model.NetworkID, ref string) (store.Service, error) {
	if strings.HasPrefix(ref, model.ServicePrefix) {
		s, err := tx.Service(model.ServiceID(ref))
		if err == nil && s.Network != net {
			err = store.ErrNotFound
		}
		return s, notFound(err, "service "+ref)
	}
	s, err := tx.ServiceByName(net, ref)
	return s, notFound(err, "service "+ref)
}

// CreateNetwork creates an address space.
func (p *Plane) CreateNetwork(tx store.Tx, now time.Time, req api.CreateNetwork) (store.Network, error) {
	if !ValidName(req.Name) {
		return store.Network{}, apiErr(api.CodeInvalid, "network name %q is not a DNS label", req.Name)
	}
	prefix6 := req.Prefix6
	if !prefix6.IsValid() {
		var b [16]byte
		b[0] = 0xfd
		if _, err := io.ReadFull(p.Rand, b[1:6]); err != nil {
			return store.Network{}, err
		}
		prefix6 = netip.PrefixFrom(netip.AddrFrom16(b), 64)
	}
	if !prefix6.Addr().Is6() || prefix6.Addr().Is4In6() || prefix6.Bits() != 64 || prefix6.Masked() != prefix6 {
		return store.Network{}, apiErr(api.CodeInvalid, "IPv6 prefix %s must be a /64", prefix6)
	}
	if req.Prefix4.IsValid() {
		if !req.Prefix4.Addr().Is4() || req.Prefix4.Bits() < 8 || req.Prefix4.Bits() > 30 || req.Prefix4.Masked() != req.Prefix4 {
			return store.Network{}, apiErr(api.CodeInvalid, "IPv4 prefix %s must be between /8 and /30", req.Prefix4)
		}
	}
	mtu := req.MTU
	if mtu == 0 {
		mtu = p.Config.MTU
	}
	if mtu < 1280 || mtu > 9000 {
		return store.Network{}, apiErr(api.CodeInvalid, "MTU %d must be between 1280 and 9000", mtu)
	}
	for _, r := range req.Relays {
		if _, err := tx.Relay(r); err != nil {
			return store.Network{}, notFound(err, "relay "+string(r))
		}
	}
	id, err := p.id(model.NetworkPrefix)
	if err != nil {
		return store.Network{}, err
	}
	n := store.Network{
		ID:      model.NetworkID(id),
		Name:    req.Name,
		Prefix6: prefix6,
		Prefix4: req.Prefix4,
		MTU:     mtu,
		Relays:  req.Relays,
		Next6:   first6,
		Next4:   first4,
		Created: now,
	}
	if err := tx.PutNetwork(n); err != nil {
		return store.Network{}, conflict(err, "network "+req.Name)
	}
	return n, bump(tx, &n)
}

// DeleteNetwork removes a network with nothing connected to it.
func (p *Plane) DeleteNetwork(tx store.Tx, ref string) error {
	n, err := ResolveNetwork(tx, ref)
	if err != nil {
		return err
	}
	ifaces, err := tx.Interfaces(n.ID)
	if err != nil {
		return err
	}
	for _, i := range ifaces {
		if i.State == api.Live || !i.Drained {
			return apiErr(api.CodeConflict, "network %s still has interface %s", n.Name, i.ID)
		}
	}
	for _, i := range ifaces {
		if err := tx.DeleteInterface(i.ID); err != nil {
			return err
		}
	}
	rules, err := tx.Rules(n.ID)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if err := tx.DeleteRule(r.ID); err != nil {
			return err
		}
	}
	svcs, err := tx.Services(n.ID)
	if err != nil {
		return err
	}
	for _, s := range svcs {
		if err := tx.DeleteService(s.ID); err != nil {
			return err
		}
	}
	tx.Touch(store.Change{Networks: []model.NetworkID{n.ID}})
	return tx.DeleteNetwork(n.ID)
}

// CreateService declares a service and gives it its addresses.
func (p *Plane) CreateService(tx store.Tx, now time.Time, netRef string, req api.CreateService) (store.Service, error) {
	n, err := ResolveNetwork(tx, netRef)
	if err != nil {
		return store.Service{}, err
	}
	if !ValidName(req.Name) || req.Name == api.Internet {
		return store.Service{}, apiErr(api.CodeInvalid, "service name %q is not a DNS label", req.Name)
	}
	mode := req.Mode
	if mode == "" {
		mode = api.Flip
	}
	if mode != api.Flip && mode != api.Cutover {
		return store.Service{}, apiErr(api.CodeInvalid, "mode %q must be flip or cutover", mode)
	}
	if _, err := tx.ServiceByName(n.ID, req.Name); err == nil {
		return store.Service{}, apiErr(api.CodeConflict, "service %s already exists", req.Name)
	}
	id, err := p.id(model.ServicePrefix)
	if err != nil {
		return store.Service{}, err
	}
	s := store.Service{ID: model.ServiceID(id), Network: n.ID, Name: req.Name, IPv4: req.IPv4, Mode: mode, Created: now}
	s.Addr6 = alloc6(&n)
	if req.IPv4 {
		if s.Addr4, err = p.alloc4(tx, &n, now); err != nil {
			return store.Service{}, err
		}
	}
	if err := tx.PutService(s); err != nil {
		return store.Service{}, conflict(err, "service "+req.Name)
	}
	return s, bump(tx, &n)
}

// DeleteService removes a service with no connected interfaces, and the
// rules naming it.
func (p *Plane) DeleteService(tx store.Tx, now time.Time, netRef, ref string) error {
	n, err := ResolveNetwork(tx, netRef)
	if err != nil {
		return err
	}
	s, err := ResolveService(tx, n.ID, ref)
	if err != nil {
		return err
	}
	ifaces, err := tx.Interfaces(n.ID)
	if err != nil {
		return err
	}
	for _, i := range ifaces {
		if i.Service == s.ID && (i.State == api.Live || !i.Drained) {
			return apiErr(api.CodeConflict, "service %s still has interface %s", s.Name, i.ID)
		}
	}
	rules, err := tx.Rules(n.ID)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.From == s.ID || r.To == s.ID {
			if err := tx.DeleteRule(r.ID); err != nil {
				return err
			}
		}
	}
	if s.Addr4.IsValid() {
		if err := tx.PutReleased4(store.Released4{Network: n.ID, Addr: s.Addr4, At: now}); err != nil {
			return err
		}
	}
	if err := tx.DeleteService(s.ID); err != nil {
		return err
	}
	return bump(tx, &n)
}

// CreateRule permits a flow from one service to another, or to the
// internet.
func (p *Plane) CreateRule(tx store.Tx, now time.Time, netRef string, req api.CreateRule) (store.Rule, error) {
	n, err := ResolveNetwork(tx, netRef)
	if err != nil {
		return store.Rule{}, err
	}
	from, err := ResolveService(tx, n.ID, req.From)
	if err != nil {
		return store.Rule{}, err
	}
	var to model.ServiceID
	if req.To != api.Internet {
		svc, err := ResolveService(tx, n.ID, req.To)
		if err != nil {
			return store.Rule{}, err
		}
		to = svc.ID
	}
	if !req.Proto.Valid() {
		return store.Rule{}, apiErr(api.CodeInvalid, "protocol %q must be tcp, udp or any", req.Proto)
	}
	if req.Proto == model.AnyProto && !req.Ports.All() {
		return store.Rule{}, apiErr(api.CodeInvalid, "a rule for any protocol takes no ports")
	}
	if !req.Ports.All() && (req.Ports.Lo == 0 || req.Ports.Hi < req.Ports.Lo) {
		return store.Rule{}, apiErr(api.CodeInvalid, "bad port range %s", req.Ports)
	}
	rules, err := tx.Rules(n.ID)
	if err != nil {
		return store.Rule{}, err
	}
	for _, r := range rules {
		if r.From == from.ID && r.To == to && r.Proto == req.Proto && r.Ports == req.Ports {
			return r, nil
		}
	}
	id, err := p.id(model.RulePrefix)
	if err != nil {
		return store.Rule{}, err
	}
	r := store.Rule{ID: model.RuleID(id), Network: n.ID, From: from.ID, To: to, Proto: req.Proto, Ports: req.Ports, Created: now}
	if err := tx.PutRule(r); err != nil {
		return store.Rule{}, err
	}
	if to != "" {
		if err := p.reconcileEdges(tx, now, &n, servicesScope(from.ID, to)); err != nil {
			return store.Rule{}, err
		}
	}
	return r, bump(tx, &n)
}

// DeleteRule removes a rule, and the edges no other rule keeps.
func (p *Plane) DeleteRule(tx store.Tx, now time.Time, netRef string, id model.RuleID) error {
	n, err := ResolveNetwork(tx, netRef)
	if err != nil {
		return err
	}
	r, err := tx.Rule(id)
	if err != nil || r.Network != n.ID {
		return notFound(store.ErrNotFound, "rule "+string(id))
	}
	if err := tx.DeleteRule(id); err != nil {
		return err
	}
	if r.To != "" {
		if err := p.reconcileEdges(tx, now, &n, servicesScope(r.From, r.To)); err != nil {
			return err
		}
	}
	return bump(tx, &n)
}

// CreateHost registers a host and returns its token.
func (p *Plane) CreateHost(tx store.Tx, now time.Time, req api.CreateHost) (store.Host, string, error) {
	if !ValidName(req.Name) {
		return store.Host{}, "", apiErr(api.CodeInvalid, "host name %q is not a DNS label", req.Name)
	}
	id, err := p.id(model.HostPrefix)
	if err != nil {
		return store.Host{}, "", err
	}
	token, hash, err := p.token()
	if err != nil {
		return store.Host{}, "", err
	}
	h := store.Host{ID: model.HostID(id), Name: req.Name, TokenHash: hash, Endpoint: req.Endpoint, Created: now}
	if err := tx.PutHost(h); err != nil {
		return store.Host{}, "", conflict(err, "host "+req.Name)
	}
	return h, token, nil
}

// CreateRelay registers a relay and returns its token.
func (p *Plane) CreateRelay(tx store.Tx, now time.Time, req api.CreateRelay) (store.Relay, string, error) {
	if !ValidName(req.Name) {
		return store.Relay{}, "", apiErr(api.CodeInvalid, "relay name %q is not a DNS label", req.Name)
	}
	if len(req.Addresses) == 0 {
		return store.Relay{}, "", apiErr(api.CodeInvalid, "a relay needs an address")
	}
	for _, a := range req.Addresses {
		if !a.Local.IsValid() || !a.Advertised.IsValid() || a.Local.Is4() != a.Advertised.Is4() {
			return store.Relay{}, "", apiErr(api.CodeInvalid, "relay address %v needs a local and an advertised address of one family", a)
		}
	}
	// A port range ending at 65534 leaves the allocation cursor room to
	// pass its end without wrapping.
	if req.PortLo < 1024 || req.PortHi > 65534 || req.PortHi <= req.PortLo {
		return store.Relay{}, "", apiErr(api.CodeInvalid, "relay ports %d-%d must lie within 1024-65534", req.PortLo, req.PortHi)
	}
	if req.ProbePort == 0 || req.ProbePort >= req.PortLo && req.ProbePort <= req.PortHi {
		return store.Relay{}, "", apiErr(api.CodeInvalid, "probe port %d must lie outside the edge ports", req.ProbePort)
	}
	id, err := p.id(model.RelayPrefix)
	if err != nil {
		return store.Relay{}, "", err
	}
	token, hash, err := p.token()
	if err != nil {
		return store.Relay{}, "", err
	}
	// A revision from birth, so a relay's first poll, from generation zero,
	// always finds its table newer and every later one parks.
	rev, err := tx.Bump()
	if err != nil {
		return store.Relay{}, "", err
	}
	r := store.Relay{
		ID: model.RelayID(id), Name: req.Name, TokenHash: hash, Addresses: req.Addresses,
		PortLo: req.PortLo, PortHi: req.PortHi, ProbePort: req.ProbePort, Revision: rev, Created: now,
	}
	if err := tx.PutRelay(r); err != nil {
		return store.Relay{}, "", conflict(err, "relay "+req.Name)
	}
	return r, token, nil
}

// Attach issues an interface and its lease to a host. The agent chose the
// interface's identifier, so attaching the same identifier again with the
// same key returns the interface already issued.
func (p *Plane) Attach(tx store.Tx, now time.Time, host model.HostID, req api.AttachRequest) (store.Interface, error) {
	if !strings.HasPrefix(string(req.Interface), model.InterfacePrefix) || len(req.Interface) <= len(model.InterfacePrefix) {
		return store.Interface{}, apiErr(api.CodeInvalid, "interface identifier %q must start with %s", req.Interface, model.InterfacePrefix)
	}
	if req.PublicKey.IsZero() || req.ListenPort == 0 {
		return store.Interface{}, apiErr(api.CodeInvalid, "attach needs a public key and a listen port")
	}
	if existing, err := tx.Interface(req.Interface); err == nil {
		if existing.Host == host && existing.PublicKey == req.PublicKey && existing.State == api.Live {
			return existing, nil
		}
		return store.Interface{}, apiErr(api.CodeConflict, "interface %s already exists", req.Interface)
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.Interface{}, err
	}
	kind := req.Kind
	if kind == "" {
		kind = api.Workload
	}
	if kind != api.Workload && kind != api.Gateway {
		return store.Interface{}, apiErr(api.CodeInvalid, "an agent attaches workloads and gateways, not %q", kind)
	}
	n, err := ResolveNetwork(tx, req.Network)
	if err != nil {
		return store.Interface{}, err
	}
	svc, err := ResolveService(tx, n.ID, req.Service)
	if err != nil {
		return store.Interface{}, err
	}
	if _, err := tx.Host(host); err != nil {
		return store.Interface{}, notFound(err, "host "+string(host))
	}
	iface := store.Interface{
		ID:         req.Interface,
		Network:    n.ID,
		Service:    svc.ID,
		Host:       host,
		Kind:       kind,
		PublicKey:  req.PublicKey,
		ListenPort: req.ListenPort,
		State:      api.Live,
		Expires:    now.Add(p.Config.LeaseTTL),
		Created:    now,
	}
	iface.Addr6 = alloc6(&n)
	if svc.IPv4 {
		if iface.Addr4, err = p.alloc4(tx, &n, now); err != nil {
			return store.Interface{}, err
		}
	}
	if err := tx.PutInterface(iface); err != nil {
		return store.Interface{}, err
	}
	if err := p.reconcileEdges(tx, now, &n, interfaceScope(iface.ID)); err != nil {
		return store.Interface{}, err
	}
	return iface, bump(tx, &n, host)
}

// Release ends a host's interfaces as a planned removal: peers drain them
// over the grace period. Releasing an interface already ended, or one the
// host does not hold, changes nothing.
func (p *Plane) Release(tx store.Tx, now time.Time, host model.HostID, ids []model.InterfaceID) error {
	for _, id := range ids {
		i, err := tx.Interface(id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		} else if err != nil {
			return err
		}
		if i.Host != host || i.State != api.Live {
			continue
		}
		i.State, i.Ended = api.Released, now
		if err := p.end(tx, now, i, true); err != nil {
			return err
		}
	}
	return nil
}

// Revoke ends an interface at once: peers remove it with no grace period.
func (p *Plane) Revoke(tx store.Tx, now time.Time, id model.InterfaceID) error {
	i, err := tx.Interface(id)
	if err != nil {
		return notFound(err, "interface "+string(id))
	}
	if i.State == api.Revoked {
		return nil
	}
	wasLive := i.State == api.Live
	if wasLive {
		i.Ended = now
	}
	i.State, i.Drained = api.Revoked, true
	// A released interface's IPv4 address went into quarantine when it was
	// released.
	return p.end(tx, now, i, wasLive)
}

// end writes an interface that just left the live state, quarantines its
// IPv4 address if asked, drops its edges once it is drained, and bumps its
// network.
func (p *Plane) end(tx store.Tx, now time.Time, i store.Interface, quarantine bool) error {
	if quarantine && i.Addr4.IsValid() {
		if err := tx.PutReleased4(store.Released4{Network: i.Network, Addr: i.Addr4, At: now}); err != nil {
			return err
		}
	}
	if err := tx.PutInterface(i); err != nil {
		return err
	}
	n, err := tx.Network(i.Network)
	if err != nil {
		return err
	}
	if i.Drained {
		if err := p.reconcileEdges(tx, now, &n, interfaceScope(i.ID)); err != nil {
			return err
		}
	}
	return bump(tx, &n, i.Host)
}

// Renew extends the leases of a host's live interfaces and returns their
// new expiries. Interfaces it leaves out are no longer live.
func (p *Plane) Renew(tx store.Tx, now time.Time, host model.HostID, ids []model.InterfaceID) (map[model.InterfaceID]time.Time, error) {
	out := map[model.InterfaceID]time.Time{}
	for _, id := range ids {
		i, err := tx.Interface(id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		} else if err != nil {
			return nil, err
		}
		if i.Host != host || i.State != api.Live {
			continue
		}
		i.Expires = now.Add(p.Config.LeaseTTL)
		if err := tx.PutInterface(i); err != nil {
			return nil, err
		}
		out[id] = i.Expires
	}
	return out, nil
}

// SweepBatch bounds how much one sweep transaction changes.
const SweepBatch = 64

// Sweep revokes expired leases, ends drains whose grace period has passed,
// and deletes interfaces past retention. It reports how many interfaces it
// changed; a caller sweeps again while that is SweepBatch.
func (p *Plane) Sweep(tx store.Tx, now time.Time) (int, error) {
	changed := 0
	resumes, err := metaTime(tx, metaExpiryResumes)
	if err != nil {
		return 0, err
	}
	if !now.Before(resumes) {
		expired, err := tx.Expired(now, SweepBatch)
		if err != nil {
			return 0, err
		}
		for _, i := range expired {
			if err := p.Revoke(tx, now, i.ID); err != nil {
				return 0, err
			}
			changed++
		}
	}
	if changed >= SweepBatch {
		return changed, nil
	}
	draining, err := tx.Undrained(now.Add(-p.Config.DrainGrace), SweepBatch-changed)
	if err != nil {
		return 0, err
	}
	for _, i := range draining {
		i.Drained = true
		if err := tx.PutInterface(i); err != nil {
			return 0, err
		}
		n, err := tx.Network(i.Network)
		if err != nil {
			return 0, err
		}
		if err := p.reconcileEdges(tx, now, &n, interfaceScope(i.ID)); err != nil {
			return 0, err
		}
		if err := bump(tx, &n, i.Host); err != nil {
			return 0, err
		}
		changed++
	}
	if changed >= SweepBatch {
		return changed, nil
	}
	n, err := p.expireDormant(tx, now, SweepBatch-changed)
	if err != nil {
		return 0, err
	}
	changed += n
	if changed >= SweepBatch {
		return changed, nil
	}
	old, err := tx.Ended(now.Add(-p.Config.Retention), SweepBatch-changed)
	if err != nil {
		return 0, err
	}
	for _, i := range old {
		if err := tx.DeleteInterface(i.ID); err != nil {
			return 0, err
		}
		n, err := tx.Network(i.Network)
		if err != nil {
			return 0, err
		}
		if err := bump(tx, &n, i.Host); err != nil {
			return 0, err
		}
		changed++
	}
	return changed, nil
}

// Boot runs when a control plane starts. Leases could not be renewed while
// it was down, so it holds off expiry for at least as long as it was down,
// and never less than one lease term.
func (p *Plane) Boot(tx store.Tx, now time.Time) (time.Duration, error) {
	last, err := metaTime(tx, metaHeartbeat)
	if err != nil {
		return 0, err
	}
	down := time.Duration(0)
	if !last.IsZero() && now.After(last) {
		down = now.Sub(last)
	}
	resumes := now.Add(max(down, p.Config.LeaseTTL))
	if err := tx.SetMeta(metaExpiryResumes, resumes.UTC().Format(time.RFC3339Nano)); err != nil {
		return 0, err
	}
	return down, p.Heartbeat(tx, now)
}

// Heartbeat records that a control plane is up, so the next boot knows how
// long the outage lasted.
func (p *Plane) Heartbeat(tx store.Tx, now time.Time) error {
	return tx.SetMeta(metaHeartbeat, now.UTC().Format(time.RFC3339Nano))
}

// ExpiryResumes reports when lease expiry resumes after a boot.
func ExpiryResumes(tx store.ReadTx) (time.Time, error) { return metaTime(tx, metaExpiryResumes) }

func metaTime(tx store.ReadTx, key string) (time.Time, error) {
	v, ok, err := tx.Meta(key)
	if err != nil || !ok {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, v)
}
