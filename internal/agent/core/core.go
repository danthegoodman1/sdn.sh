//sdn:deterministic

// Package core is the host agent's logic. It decides which kernel operations
// to run, in what order, and when; it runs none itself. The agent daemon
// carries its actions out against Linux and the control plane, and the
// simulator against its models.
//
// One namespace runs at most one batch of operations at a time, and a batch
// orders its operations so every state between them is safe:
//
//  1. the device's addresses, routes and MTU;
//  2. peers added and changed;
//  3. one nftables transaction, so slots name only installed peers;
//  4. peers removed, then their conntrack entries and sockets flushed.
//
// A peer that would claim an address another installed peer still holds
// waits until a later batch has removed the holder, so no allowed IP ever
// moves between peers.
package core

import (
	"io"
	"maps"
	"net/netip"
	"slices"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/kernel"
	"sdn.sh/internal/model"
	"sdn.sh/internal/nft"
	"sdn.sh/internal/regproto"
)

// Config holds the agent's identity and clocks.
type Config struct {
	Host model.HostID
	// Prefix starts the name of every namespace the agent creates.
	Prefix string
	// Device names the WireGuard device in every namespace.
	Device string
	// PortLo and PortHi bound the listen ports devices bind on the host.
	PortLo, PortHi uint16
	// DrainGrace is how long a released peer stays installed.
	DrainGrace time.Duration
	// Keepalive is the interval for peers that carry one.
	Keepalive time.Duration
	// AttachTimeout bounds how long an attach waits on the control plane.
	AttachTimeout time.Duration
	// RetryMin and RetryMax bound the backoff after a failed batch.
	RetryMin, RetryMax time.Duration
	// RegisterEvery is the registration datagram's period, which holds a
	// NAT mapping open on the relay path.
	RegisterEvery time.Duration
	// RegisterRetries sends a new direction's registration again this many
	// times, the first after RegisterRetry and each gap three times the
	// last: a relay drops one that arrives before it binds the port.
	RegisterRetries int
	RegisterRetry   time.Duration
	// ProbeEvery is how often each relay is probed; a relay that misses
	// ProbeMisses probes in a row is down.
	ProbeEvery  time.Duration
	ProbeMisses int
	// ResyncEvery is how often every namespace is observed again, to catch
	// changes made behind the agent's back.
	ResyncEvery time.Duration
	// AckWait bounds how long a relay peer new to a namespace waits for
	// the active relay to acknowledge the namespace's registration before
	// a slot names it, and how long an attach waits on that, or on a
	// co-located device, before its namespace is handed over.
	AckWait time.Duration
}

// DefaultConfig returns the production settings for a host.
func DefaultConfig(host model.HostID) Config {
	return Config{
		Host:            host,
		Prefix:          "sdn-",
		Device:          "sdn0",
		PortLo:          40000,
		PortHi:          59999,
		DrainGrace:      30 * time.Second,
		Keepalive:       25 * time.Second,
		AttachTimeout:   10 * time.Second,
		RetryMin:        50 * time.Millisecond,
		RetryMax:        5 * time.Second,
		RegisterEvery:   25 * time.Second,
		RegisterRetries: 5,
		RegisterRetry:   10 * time.Millisecond,
		ProbeEvery:      200 * time.Millisecond,
		ProbeMisses:     3,
		ResyncEvery:     5 * time.Minute,
		AckWait:         time.Second,
	}
}

// AliasPrefix marks devices this agent made, so it reaps only its own.
func (c Config) AliasPrefix() string { return "sdn:" + string(c.Host) + ":" }

// RequestID names a local API call awaiting an answer.
type RequestID uint64

// JournalEntry is what the agent persists about an interface it built. It
// holds no private key: the key lives in the kernel device, and an
// interface whose device is gone is lost.
type JournalEntry struct {
	Interface  model.InterfaceID `json:"interface"`
	Name       string            `json:"name"`
	Network    model.NetworkID   `json:"network"`
	Service    model.ServiceID   `json:"service"`
	Kind       api.Kind          `json:"kind"`
	Namespace  string            `json:"namespace"`
	ListenPort uint16            `json:"listen_port"`
	PublicKey  model.Key         `json:"public_key"`
	Detaching  bool              `json:"detaching,omitempty"`
}

// Action is something the core asks its driver to do.
type Action interface{ isAction() }

// RunBatch runs operations in order on one namespace, stopping at the first
// failure, and reports back through BatchDone.
type RunBatch struct {
	ID        uint64
	Namespace string
	Ops       []kernel.Op
}

// CallAttach asks the control plane for an interface; the answer comes back
// through AttachDone.
type CallAttach struct {
	Request api.AttachRequest
}

// CallRelease tells the control plane interfaces are gone; the answer comes
// back through ReleaseDone.
type CallRelease struct {
	Interfaces []model.InterfaceID
}

// WriteJournal persists an entry durably before the driver carries out any
// later action.
type WriteJournal struct{ Entry JournalEntry }

// DeleteJournal removes an entry.
type DeleteJournal struct{ Interface model.InterfaceID }

// Reply answers a local API call.
type Reply struct {
	Request   RequestID
	Interface api.LocalInterface
	Err       error
}

// SendRegistration sends a registration datagram from a device's listen
// port, so the NAT mapping it opens is the one WireGuard's traffic uses.
type SendRegistration struct {
	From    uint16
	To      netip.AddrPort
	Payload [regproto.Size]byte
}

// SendProbe probes a relay; an answer comes back through ProbeReply.
type SendProbe struct {
	Relay model.RelayID
	To    netip.AddrPort
	Nonce uint64
}

// Observe asks for one namespace's kernel state, which comes back through
// Observed.
type Observe struct{ Namespace string }

// Scan asks for a snapshot of the kernel, which comes back through Scanned,
// to find devices the agent made in namespaces only a process holds.
type Scan struct{}

func (RunBatch) isAction()         {}
func (CallAttach) isAction()       {}
func (CallRelease) isAction()      {}
func (WriteJournal) isAction()     {}
func (DeleteJournal) isAction()    {}
func (Reply) isAction()            {}
func (SendRegistration) isAction() {}
func (SendProbe) isAction()        {}
func (Observe) isAction()          {}
func (Scan) isAction()             {}

type phase int

const (
	// creating: the namespace and keyed device are being made.
	creating phase = iota
	// registering: the control plane is issuing the interface.
	registering
	// configuring: peers, addresses and rules are going in before handover.
	configuring
	// ready: handed over and reconciled against desired state.
	ready
	// detaching: torn down at the workload's request.
	detaching
	// aborting: an attach failed and its pieces are being removed.
	aborting
	// orphan: found in the kernel with no journal entry.
	orphan
)

func (p phase) String() string {
	return [...]string{"creating", "registering", "configuring", "ready", "detaching", "aborting", "orphan"}[p]
}

// tearingDown reports whether a phase removes the interface's kernel state.
func (p phase) tearingDown() bool { return p == detaching || p == aborting || p == orphan }

// iface is one interface the agent manages.
type iface struct {
	id      model.InterfaceID
	name    string
	phase   phase
	ns      string
	port    uint16
	pub     model.Key
	priv    model.Key
	netRef  string
	svcRef  string
	kind    api.Kind
	network model.NetworkID
	service model.ServiceID
	// deadline is when an attach gives up waiting on the control plane;
	// handoverBy, when a configured namespace is handed over whatever its
	// slots still wait for.
	deadline   time.Time
	handoverBy time.Time
	// waiting holds attach calls answered once the interface is ready, or
	// with an error if it aborts; detachers, detach calls answered once it
	// is torn down.
	waiting   []RequestID
	detachers []RequestID
	// attachSent records that the control plane may have issued it.
	attachSent bool
	// release tracks the control plane's knowledge of a removal.
	releasing, released bool
	tornDown            bool
	err                 error
	addr6, addr4        netip.Addr
}

// nsState is what the agent believes one namespace holds.
type nsState struct {
	name  string
	iface model.InterfaceID
	// ref names an unnamed namespace a process holds, which only Reap
	// clears; reaped records that it has, so the namespace is forgotten.
	ref    string
	reaped bool
	exists bool
	device bool
	link   *kernel.LinkConfig
	// egress is the namespace's egress link as installed, nil for none;
	// egressClear records that the host holds no filter for its index
	// either, since none was installed or a removal ran.
	egress      *kernel.EgressConfig
	egressClear bool
	peers       map[model.Key]kernel.Peer
	rules       *nft.Ruleset
	chosen      map[model.Key]netip.AddrPort
	drain       map[model.Key]time.Time
	fresh       map[model.Key]bool
	// unflushed holds addresses of removed peers whose flows have yet to
	// be flushed; sweep asks for a sweep of every flow no installed peer
	// accounts for, after a restart lost track.
	unflushed []netip.Addr
	sweep     bool
	// awaiting names the interfaces slots wait for: co-located ones whose
	// devices have yet to hold this namespace's interface as a peer, and
	// relay peers a slot names, new to the namespace, whose active relay
	// has yet to acknowledge its registration. Keepalive toward a
	// co-located one waits too. reverse holds the co-located ones, which
	// only their own namespaces' batches release.
	awaiting []model.InterfaceID
	reverse  []model.InterfaceID
	// acks holds each relay peer new to the namespace until the active
	// relay acknowledges it or AckWait passes; ackBy is the earliest
	// deadline among those still waiting.
	acks    map[model.Key]*ackWait
	ackBy   time.Time
	busy    bool
	dirty   bool
	observe bool
	// revision is the network revision last reconciled against.
	revision uint64
	// nextDrain is when the earliest draining peer's grace ends.
	nextDrain time.Time
	failures  int
	retryAt   time.Time
	batch     *RunBatch
}

func newNS(name string, id model.InterfaceID) *nsState {
	return &nsState{
		name: name, iface: id, dirty: true, egressClear: true,
		peers:  map[model.Key]kernel.Peer{},
		chosen: map[model.Key]netip.AddrPort{},
		drain:  map[model.Key]time.Time{},
		fresh:  map[model.Key]bool{},
		acks:   map[model.Key]*ackWait{},
	}
}

// ackWait is a relay peer waiting for the active relay to acknowledge the
// namespace's registration on path, the relay port the peer is sent to.
type ackWait struct {
	path  netip.AddrPort
	until time.Time
	acked bool
}

// ackKey names a registration's direction from the host's side: the
// device's listen port and the relay port it registers at.
type ackKey struct {
	port uint16
	path netip.AddrPort
}

// relayHealth tracks one relay's probes.
type relayHealth struct {
	up          bool
	lastReply   time.Time
	outstanding map[uint64]time.Time
	misses      int
}

// Core is one host's agent logic.
type Core struct {
	cfg     Config
	rand    io.Reader
	desired *api.HostState
	// synced records a poll answered since start; until then, interfaces
	// adopted from the kernel keep what they hold.
	synced  bool
	ifaces  map[model.InterfaceID]*iface
	ns      map[string]*nsState
	relays  map[model.RelayID]*relayHealth
	active  map[model.NetworkID]model.RelayID
	badPort map[uint16]bool
	actions []Action
	batches uint64
	counter uint64
	nonce   uint64
	// nextRelease is when releases the control plane failed to take are
	// sent again.
	nextRelease  time.Time
	lastRegister time.Time
	// resends holds each namespace's fresh directions awaiting another
	// registration, and resendAck finds the one an acknowledgment ends.
	resends   map[string]map[model.Key]*resend
	resendAck map[ackKey]resendRef
	// awaitingAck finds the namespace a relay's acknowledgment is for,
	// holding only directions a peer waits on, so acknowledgments nobody
	// awaits cost nothing to ignore.
	awaitingAck map[ackKey]string
	// reverseWait finds the namespaces waiting for a co-located
	// interface's device to hold their reverse peers.
	reverseWait map[model.InterfaceID]map[string]bool
	lastProbe   time.Time
	lastResync  time.Time
	// scanning records a Scan awaiting its answer, and rescan one wanted
	// meanwhile.
	scanning, rescan bool
	// Stats counts what the core decided, for metrics.
	Stats Stats
	// Debug, when set, receives a line per reconcile plan.
	Debug func(string)
}

// Stats counts the core's decisions.
type Stats struct {
	Batches, Failures, Conflicts, Preempted, Registrations, Failovers uint64
	// Acked counts acknowledgments that released a new peer's wait, and
	// AckTimeouts waits that ended at AckWait instead.
	Acked, AckTimeouts uint64
	// Idle counts plans that found a namespace with nothing to do, after
	// which it may count as settled.
	Idle uint64
}

// Census counts what the core manages, for the agent's gauges.
type Census struct {
	// Interfaces counts interfaces by phase, every phase present.
	Interfaces map[string]int
	// Namespaces counts the named namespaces the core tracks, and Held
	// those only something else holds, awaiting their reap.
	Namespaces, Held int
	// Peers counts the peers the core believes its devices hold.
	Peers int
}

// Census counts interfaces, namespaces and peers.
func (c *Core) Census() Census {
	out := Census{Interfaces: map[string]int{}}
	for p := creating; p <= orphan; p++ {
		out.Interfaces[p.String()] = 0
	}
	for _, id := range slices.Sorted(maps.Keys(c.ifaces)) {
		out.Interfaces[c.ifaces[id].phase.String()]++
	}
	for _, name := range slices.Sorted(maps.Keys(c.ns)) {
		st := c.ns[name]
		if st.ref != "" {
			out.Held++
			continue
		}
		out.Namespaces++
		out.Peers += len(st.peers)
	}
	return out
}

// New returns a core for a host. Call Start before anything else.
func New(cfg Config, rand io.Reader) *Core {
	return &Core{
		cfg:     cfg,
		rand:    rand,
		desired: api.NewHostState(),
		ifaces:  map[model.InterfaceID]*iface{},
		ns:      map[string]*nsState{},
		relays:  map[model.RelayID]*relayHealth{},
		active:  map[model.NetworkID]model.RelayID{},
		badPort: map[uint16]bool{},
		resends: map[string]map[model.Key]*resend{},

		awaitingAck: map[ackKey]string{},
		resendAck:   map[ackKey]resendRef{},
		reverseWait: map[model.InterfaceID]map[string]bool{},
	}
}

// Generation is the desired-state generation the core holds, which the next
// poll asks from.
func (c *Core) Generation() uint64 { return c.desired.Generation }

// Desired returns the merged desired state.
func (c *Core) Desired() *api.HostState { return c.desired }

func (c *Core) emit(a Action) { c.actions = append(c.actions, a) }
