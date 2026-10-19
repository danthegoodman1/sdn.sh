//wirenet:deterministic

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
//  3. otherwise, if E is this direction's registered endpoint and the
//     opposite direction has registered, forwards from the opposite
//     direction's port to the endpoint it registered;
//  4. otherwise waits, briefly and in bounded numbers, for the registration
//     that would admit it, and drops when the wait ends.
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

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/regproto"
)

// Config bounds what one port, and the relay as a whole, may cost. A zero
// rate means no cap.
type Config struct {
	// Rate and Burst cap data packets per second per port.
	Rate  float64
	Burst float64
	// RegistrationRate caps the registrations per second a port accepts.
	// Only a registration that verifies spends it, so junk sent to a port
	// leaves its owner's budget whole.
	RegistrationRate float64
	// RejectRate caps, across the relay, the registrations per second that
	// fail verification. Once it is spent the relay verifies none until it
	// refills, which bounds the MACs a flood can make the relay compute.
	RejectRate float64
	// ProbeRate caps probe answers per second across the relay. A probe's
	// source can be forged, so the cap bounds what the probe port sends to
	// whoever a probe names.
	ProbeRate float64
	// WaitFor is how long a data packet waits for its sender's or its
	// peer's registration to commit, WaitMax how many may wait on one
	// port, and WaitTotal how many on the relay. A direction's first
	// packets race its registrations; without the wait, a lost handshake
	// initiation costs WireGuard a five-second retry.
	WaitFor   time.Duration
	WaitMax   int
	WaitTotal int
}

// DefaultConfig returns production limits. Agents probe each relay every
// 200ms, so the probe cap answers 10,000 hosts.
func DefaultConfig() Config {
	return Config{Rate: 0, Burst: 0, RegistrationRate: 20, RejectRate: 50000, ProbeRate: 50000,
		WaitFor: 2 * time.Second, WaitMax: 8, WaitTotal: 65536}
}

// Verdict is what to do with a packet.
type Verdict int

const (
	Drop Verdict = iota
	// Forward sends the packet from one local port to an endpoint.
	Forward
	// Register is a verified registration to make durable, then Commit.
	Register
	// Wait is a data packet kept, under Decision.Token, until a
	// registration lets it through or its wait ends. The shell keeps the
	// bytes; Release says what to send.
	Wait
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
	// Token names a Wait packet.
	Token uint64
}

// Release is a waiting packet to send, or, with Drop set, one whose wait
// ended.
type Release struct {
	Token    uint64
	From, To netip.AddrPort
	Drop     bool
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
	// oldest and newest end the relay's list of waiting packets in arrival
	// order, which expiry walks from the front, and held counts them. Each
	// packet is also on its port's list, so admission counts a port's
	// packets without looking at any other port's.
	oldest, newest *waiting
	held           int
	// touched names ports whose waiting packets a commit or a load may
	// have let through, and dropped holds the tokens of waits that ended.
	// Release reads only these, so its cost follows what changed rather
	// than how many packets wait.
	touched   []netip.AddrPort
	dropped   []uint64
	nextToken uint64
	rejects   bucket
	// Unknown counts packets to ports the table lacks.
	Unknown uint64
}

// Dir is one direction's port.
type Dir struct {
	api.RelayPort
	Endpoint netip.AddrPort
	Counter  uint64
	Stats    Counters
	data     bucket
	regs     bucket
	// waits holds the packets waiting on this port, oldest first.
	waits []*waiting
}

// waiting is a data packet kept for the registration that would admit it.
type waiting struct {
	token      uint64
	at         time.Time
	local, src netip.AddrPort
	bytes      int
	prev, next *waiting
}

// New returns an empty table.
func New(cfg Config) *Table {
	return &Table{cfg: cfg, ports: map[netip.AddrPort]*Dir{}, rejects: bucket{rate: cfg.RejectRate, burst: cfg.RejectRate}}
}

func (t *Table) newDir(p api.RelayPort) *Dir {
	return &Dir{
		RelayPort: p,
		data:      bucket{rate: t.cfg.Rate, burst: t.cfg.Burst},
		regs:      bucket{rate: t.cfg.RegistrationRate, burst: t.cfg.RegistrationRate},
	}
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
// its counter, and its endpoint too unless its epoch moved, as when its
// edge went dormant: both ends then register afresh before it forwards,
// while a registration replayed from before still fails. One whose key
// changed starts over, since its port was reallocated. Packets waiting on
// a port the table keeps go on waiting, and those on a port it drops end.
func (t *Table) Load(st api.RelayState) {
	next := map[netip.AddrPort]*Dir{}
	for _, p := range st.Ports {
		d := t.newDir(p)
		if old, ok := t.ports[p.Local]; ok {
			if old.Key == p.Key && old.Advertised == p.Advertised {
				d.Counter, d.Stats = old.Counter, old.Stats
				if old.Epoch == p.Epoch {
					d.Endpoint = old.Endpoint
				}
			}
			d.waits = old.waits
			t.touch(d)
		}
		next[p.Local] = d
	}
	t.ports = next
	t.generation = st.Generation
	for w := t.oldest; w != nil; {
		after := w.next
		if _, ok := t.ports[w.local]; !ok {
			t.unlink(w)
			t.dropped = append(t.dropped, w.token)
		}
		w = after
	}
}

// Packet decides one packet's fate. It changes no endpoint; a Register
// verdict commits only through Commit.
func (t *Table) Packet(now time.Time, local, src netip.AddrPort, b []byte) Decision {
	d, ok := t.ports[local]
	if !ok {
		t.Unknown++
		return Decision{Reason: Unknown}
	}
	if regproto.IsRegistration(b) {
		return t.register(now, d, src, b)
	}
	if !d.Endpoint.IsValid() || src != d.Endpoint {
		// The sender's registration may still be committing; the packet
		// goes nowhere unless one from this source commits.
		if t.wait(now, d, src, len(b)) {
			return Decision{Verdict: Wait, Reason: Unregistered, Token: t.nextToken}
		}
		d.Stats.Unregistered++
		return Decision{Reason: Unregistered}
	}
	if !d.data.take(now) {
		d.Stats.Limited++
		return Decision{Reason: Limited}
	}
	peer, ok := t.ports[netip.AddrPortFrom(local.Addr(), d.Peer)]
	if !ok || !peer.Endpoint.IsValid() {
		if ok && t.wait(now, d, src, len(b)) {
			return Decision{Verdict: Wait, Reason: PeerAbsent, Token: t.nextToken}
		}
		d.Stats.PeerAbsent++
		return Decision{Reason: PeerAbsent}
	}
	d.Stats.Forwarded++
	d.Stats.Bytes += uint64(len(b))
	return Decision{Verdict: Forward, From: peer.Local, To: peer.Endpoint}
}

// register verifies a registration under two budgets. One that fails
// spends the relay's reject budget, which bounds the MACs junk can make the
// relay compute; one that verifies spends its port's budget, which junk
// cannot reach. While either is empty the port verifies nothing, so only a
// flood past the relay-wide budget delays an owner's registration.
func (t *Table) register(now time.Time, d *Dir, src netip.AddrPort, b []byte) Decision {
	if !t.rejects.ready(now) || !d.regs.ready(now) {
		d.Stats.Limited++
		return Decision{Reason: Limited}
	}
	r, reason := t.verify(d, src, b)
	if reason != "" {
		t.rejects.spend()
		return Decision{Reason: reason}
	}
	d.regs.spend()
	return Decision{Verdict: Register, Registration: r}
}

// wait keeps a data packet, if its port and the relay have room.
func (t *Table) wait(now time.Time, d *Dir, src netip.AddrPort, n int) bool {
	if t.cfg.WaitFor <= 0 {
		return false
	}
	t.expire(now)
	if t.held >= t.cfg.WaitTotal || len(d.waits) >= t.cfg.WaitMax {
		return false
	}
	t.nextToken++
	w := &waiting{token: t.nextToken, at: now, local: d.Local, src: src, bytes: n, prev: t.newest}
	if t.newest != nil {
		t.newest.next = w
	} else {
		t.oldest = w
	}
	t.newest = w
	t.held++
	d.waits = append(d.waits, w)
	return true
}

// unlink takes w out of the relay's arrival order. Its port's list is the
// caller's to update.
func (t *Table) unlink(w *waiting) {
	if w.prev != nil {
		w.prev.next = w.next
	} else {
		t.oldest = w.next
	}
	if w.next != nil {
		w.next.prev = w.prev
	} else {
		t.newest = w.prev
	}
	w.prev, w.next = nil, nil
	t.held--
}

// expire ends the waits that ran out, oldest first, keeping their tokens
// for Release.
func (t *Table) expire(now time.Time) {
	for w := t.oldest; w != nil && now.Sub(w.at) > t.cfg.WaitFor; w = t.oldest {
		t.unlink(w)
		if d, ok := t.ports[w.local]; ok {
			d.waits = slices.DeleteFunc(d.waits, func(x *waiting) bool { return x == w })
		}
		t.dropped = append(t.dropped, w.token)
	}
}

// touch marks a port whose waiting packets may now go.
func (t *Table) touch(d *Dir) {
	if len(d.waits) > 0 {
		t.touched = append(t.touched, d.Local)
	}
}

// Release returns the waiting packets a registration has let through, in
// the order they arrived on each port, and those whose wait ended. A packet
// goes only once its source is its direction's registered endpoint and the
// peer has registered, exactly as Packet would forward it now.
func (t *Table) Release(now time.Time) []Release {
	t.expire(now)
	var out []Release
	for _, tok := range t.dropped {
		out = append(out, Release{Token: tok, Drop: true})
	}
	t.dropped = t.dropped[:0]
	for _, local := range t.touched {
		d, ok := t.ports[local]
		if !ok {
			continue
		}
		peer, pok := t.ports[netip.AddrPortFrom(local.Addr(), d.Peer)]
		if !d.Endpoint.IsValid() || !pok || !peer.Endpoint.IsValid() {
			continue
		}
		kept := d.waits[:0]
		for _, w := range d.waits {
			if w.src != d.Endpoint {
				kept = append(kept, w)
				continue
			}
			t.unlink(w)
			d.Stats.Forwarded++
			d.Stats.Bytes += uint64(w.bytes)
			out = append(out, Release{Token: w.token, From: peer.Local, To: peer.Endpoint})
		}
		clear(d.waits[len(kept):])
		d.waits = kept
	}
	t.touched = t.touched[:0]
	return out
}

// Waiting reports how many packets wait, for metrics.
func (t *Table) Waiting() int { return t.held }

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
	// Packets waiting on this port, and on its peer for this port to
	// register, may now go.
	t.touch(d)
	if peer, ok := t.ports[netip.AddrPortFrom(r.Local.Addr(), d.Peer)]; ok {
		t.touch(peer)
	}
	return true
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

// Restore loads durable state into a new table after a restart, then
// replays registrations logged since it was written.
func (t *Table) Restore(st State, log []Registration) {
	t.ports = map[netip.AddrPort]*Dir{}
	t.generation = st.Generation
	for _, p := range st.Ports {
		t.ports[p.Local] = t.newDir(p)
	}
	for _, r := range st.Registrations {
		t.Commit(r)
	}
	for _, r := range log {
		t.Commit(r)
	}
}

// Probes answers the probe port under the relay-wide cap.
type Probes struct {
	b bucket
}

// NewProbes returns a probe answerer capped at cfg.ProbeRate.
func NewProbes(cfg Config) *Probes {
	return &Probes{b: bucket{rate: cfg.ProbeRate, burst: cfg.ProbeRate}}
}

// Reply answers a probe with its own bytes, so an answer is never larger
// than what asked for it. It answers nothing that is not a probe, and
// returns Limited for a probe the cap leaves unanswered.
func (p *Probes) Reply(now time.Time, b []byte) ([]byte, Reason) {
	if _, ok := regproto.ProbeNonce(b); !ok {
		return nil, ""
	}
	if !p.b.take(now) {
		return nil, Limited
	}
	return b, ""
}

// bucket is a token bucket that starts full. A zero rate means no cap.
type bucket struct {
	rate, burst float64
	tokens      float64
	last        time.Time
}

// ready refills the bucket for the time since it last did, and reports
// whether a token is left to spend.
func (b *bucket) ready(now time.Time) bool {
	if b.rate <= 0 {
		return true
	}
	switch {
	case b.last.IsZero():
		b.tokens, b.last = b.burst, now
	case now.After(b.last):
		b.tokens, b.last = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate), now
	}
	return b.tokens >= 1
}

// spend takes the token ready reported.
func (b *bucket) spend() {
	if b.rate > 0 {
		b.tokens--
	}
}

// take spends a token, if one is left.
func (b *bucket) take(now time.Time) bool {
	if !b.ready(now) {
		return false
	}
	b.spend()
	return true
}
