//sdn:deterministic

// Package core is the relay's logic: which packets to forward, from which
// port, to whom, and which registrations move an endpoint. It holds no key
// that decrypts or forges traffic, only each direction's registration key for
// this relay.
//
// A packet arriving on a direction's port from endpoint E:
//
//  1. drops if the port is unknown;
//  2. if it is a registration, verifies against the direction's key, the
//     port's advertised address and the highest counter accepted, and on
//     success becomes a pending registration the shell makes durable before
//     committing — a registration never moves an endpoint the relay could
//     forget in a crash;
//  3. otherwise forwards from the opposite direction's port to the endpoint
//     that direction registered, and drops while either side has yet to
//     register or E is not this direction's registered endpoint.
//
// A data packet never moves an endpoint, and a packet that loses an
// endpoint race drops, so the relay reflects nothing to anyone who merely
// knows a port.
package core

import (
	"maps"
	"net/netip"
	"slices"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
	"sdn.sh/internal/regproto"
)

// Config bounds what one direction may cost the relay.
type Config struct {
	// Rate and Burst cap data packets per second per port; zero means no
	// cap.
	Rate  float64
	Burst float64
	// RegistrationRate caps registrations per second per port, bounding
	// the MACs an attacker can make the relay compute.
	RegistrationRate float64
	// EarlyHold is how long a registration for a port not yet pushed waits
	// for the port to arrive, and EarlyMax how many may wait.
	EarlyHold time.Duration
	EarlyMax  int
}

// DefaultConfig returns production limits.
func DefaultConfig() Config {
	return Config{Rate: 0, Burst: 0, RegistrationRate: 20, EarlyHold: 5 * time.Second, EarlyMax: 4096}
}

// Verdict is what to do with a packet.
type Verdict int

const (
	Drop Verdict = iota
	// Forward sends the packet from one local port to an endpoint.
	Forward
	// Register is a verified registration to make durable, then Commit.
	Register
	// Held is a registration for an unknown port, kept until the port
	// arrives or the hold ends.
	Held
)

// Reason says why a packet dropped, for metrics.
type Reason string

const (
	Unknown      Reason = "unknown_port"
	BadMAC       Reason = "bad_mac"
	Replay       Reason = "replay"
	Unregistered Reason = "unregistered_sender"
	PeerAbsent   Reason = "peer_unregistered"
	Limited      Reason = "rate_limited"
)

// Decision is the verdict on one packet.
type Decision struct {
	Verdict Verdict
	Reason  Reason
	// From is the local port to send from, and To the endpoint.
	From, To netip.AddrPort
	// Registration is set for Register.
	Registration Registration
}

// Registration is a verified endpoint claim. Key is the direction's key it
// verified under, so a claim made durable after its port was reallocated
// commits to nothing.
type Registration struct {
	Local    netip.AddrPort `json:"local"`
	Endpoint netip.AddrPort `json:"endpoint"`
	Counter  uint64         `json:"counter"`
	Key      model.Secret   `json:"key"`
}

// Counters are one direction's packet counts.
type Counters struct {
	Forwarded, Bytes, Unregistered, PeerAbsent, Limited, Registered, Replayed, BadMAC uint64
}

// Table is the relay's port table and what each direction registered.
type Table struct {
	cfg        Config
	ports      map[netip.AddrPort]*Dir
	generation uint64
	early      []early
	// Unknown counts packets to ports the table lacks.
	Unknown uint64
}

// Dir is one direction's port.
type Dir struct {
	api.RelayPort
	Endpoint netip.AddrPort
	Counter  uint64
	Stats    Counters
	tokens   float64
	regs     float64
	last     time.Time
}

type early struct {
	at    time.Time
	local netip.AddrPort
	src   netip.AddrPort
	b     [regproto.Size]byte
}

// New returns an empty table.
func New(cfg Config) *Table {
	return &Table{cfg: cfg, ports: map[netip.AddrPort]*Dir{}}
}

// Generation is the port table's control-plane generation.
func (t *Table) Generation() uint64 { return t.generation }

// Dirs returns every direction, ordered by local port.
func (t *Table) Dirs() []*Dir {
	var out []*Dir
	for _, k := range slices.SortedFunc(maps.Keys(t.ports), netip.AddrPort.Compare) {
		out = append(out, t.ports[k])
	}
	return out
}

// Dir returns one direction.
func (t *Table) Dir(local netip.AddrPort) (*Dir, bool) {
	d, ok := t.ports[local]
	return d, ok
}

// Load replaces the pushed table. A direction whose key is unchanged keeps
// its endpoint and counter; one whose key changed starts over, since its
// port was reallocated. It returns registrations held for ports that just
// arrived and now verify.
func (t *Table) Load(now time.Time, st api.RelayState) []Registration {
	next := map[netip.AddrPort]*Dir{}
	for _, p := range st.Ports {
		d := &Dir{RelayPort: p}
		if old, ok := t.ports[p.Local]; ok && old.Key == p.Key && old.Advertised == p.Advertised {
			d.Endpoint, d.Counter, d.Stats = old.Endpoint, old.Counter, old.Stats
		}
		next[p.Local] = d
	}
	t.ports = next
	t.generation = st.Generation
	var out []Registration
	kept := t.early[:0]
	for _, e := range t.early {
		if now.Sub(e.at) > t.cfg.EarlyHold {
			continue
		}
		d, ok := t.ports[e.local]
		if !ok {
			kept = append(kept, e)
			continue
		}
		if r, reason := t.verify(d, e.src, e.b[:]); reason == "" {
			out = append(out, r)
		}
	}
	t.early = kept
	return out
}

// Packet decides one packet's fate. It changes no endpoint; a Register
// verdict commits only through Commit.
func (t *Table) Packet(now time.Time, local, src netip.AddrPort, b []byte) Decision {
	d, ok := t.ports[local]
	if !ok {
		t.Unknown++
		if regproto.IsRegistration(b) && t.cfg.EarlyMax > 0 {
			t.hold(now, local, src, b)
			return Decision{Verdict: Held, Reason: Unknown}
		}
		return Decision{Reason: Unknown}
	}
	t.refill(d, now)
	if regproto.IsRegistration(b) {
		if t.cfg.RegistrationRate > 0 {
			if d.regs < 1 {
				d.Stats.Limited++
				return Decision{Reason: Limited}
			}
			d.regs--
		}
		r, reason := t.verify(d, src, b)
		if reason != "" {
			return Decision{Reason: reason}
		}
		return Decision{Verdict: Register, Registration: r}
	}
	if !d.Endpoint.IsValid() || src != d.Endpoint {
		d.Stats.Unregistered++
		return Decision{Reason: Unregistered}
	}
	if t.cfg.Rate > 0 {
		if d.tokens < 1 {
			d.Stats.Limited++
			return Decision{Reason: Limited}
		}
		d.tokens--
	}
	peer, ok := t.ports[netip.AddrPortFrom(local.Addr(), d.Peer)]
	if !ok || !peer.Endpoint.IsValid() {
		d.Stats.PeerAbsent++
		return Decision{Reason: PeerAbsent}
	}
	d.Stats.Forwarded++
	d.Stats.Bytes += uint64(len(b))
	return Decision{Verdict: Forward, From: peer.Local, To: peer.Endpoint}
}

// verify checks a registration and returns it, or why it fails.
func (t *Table) verify(d *Dir, src netip.AddrPort, b []byte) (Registration, Reason) {
	counter, ok := regproto.Verify(d.Key, d.Advertised, b)
	if !ok {
		d.Stats.BadMAC++
		return Registration{}, BadMAC
	}
	if counter <= d.Counter {
		d.Stats.Replayed++
		return Registration{}, Replay
	}
	return Registration{Local: d.Local, Endpoint: src, Counter: counter, Key: d.Key}, ""
}

// Commit applies a durable registration, unless a later one won meanwhile.
func (t *Table) Commit(r Registration) bool {
	d, ok := t.ports[r.Local]
	if !ok || r.Key != d.Key || r.Counter <= d.Counter {
		return false
	}
	d.Counter, d.Endpoint = r.Counter, r.Endpoint
	d.Stats.Registered++
	return true
}

func (t *Table) hold(now time.Time, local, src netip.AddrPort, b []byte) {
	for len(t.early) > 0 && (len(t.early) >= t.cfg.EarlyMax || now.Sub(t.early[0].at) > t.cfg.EarlyHold) {
		t.early = t.early[1:]
	}
	e := early{at: now, local: local, src: src}
	copy(e.b[:], b)
	t.early = append(t.early, e)
}

func (t *Table) refill(d *Dir, now time.Time) {
	if d.last.IsZero() {
		d.tokens, d.regs, d.last = t.cfg.Burst, t.cfg.RegistrationRate, now
		return
	}
	dt := now.Sub(d.last).Seconds()
	if dt <= 0 {
		return
	}
	d.last = now
	d.tokens = min(t.cfg.Burst, d.tokens+dt*t.cfg.Rate)
	d.regs = min(t.cfg.RegistrationRate, d.regs+dt*t.cfg.RegistrationRate)
}

// State is what survives a restart: the pushed table and what each direction
// registered.
type State struct {
	Generation    uint64          `json:"generation"`
	Ports         []api.RelayPort `json:"ports"`
	Registrations []Registration  `json:"registrations"`
}

// Persisted returns the table's durable state.
func (t *Table) Persisted() State {
	st := State{Generation: t.generation, Ports: []api.RelayPort{}, Registrations: []Registration{}}
	for _, d := range t.Dirs() {
		st.Ports = append(st.Ports, d.RelayPort)
		if d.Counter > 0 {
			st.Registrations = append(st.Registrations, Registration{Local: d.Local, Endpoint: d.Endpoint, Counter: d.Counter, Key: d.Key})
		}
	}
	return st
}

// Restore loads durable state after a restart, then replays registrations
// logged since it was written.
func (t *Table) Restore(st State, log []Registration) {
	t.ports = map[netip.AddrPort]*Dir{}
	t.generation = st.Generation
	for _, p := range st.Ports {
		t.ports[p.Local] = &Dir{RelayPort: p}
	}
	for _, r := range st.Registrations {
		t.Commit(r)
	}
	for _, r := range log {
		t.Commit(r)
	}
}

// ProbeReply answers a probe with its own bytes, so an answer is never
// larger than what asked for it.
func ProbeReply(b []byte) ([]byte, bool) {
	if _, ok := regproto.ProbeNonce(b); !ok {
		return nil, false
	}
	return b, true
}
