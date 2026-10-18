//wirenet:deterministic

// Package kernel names the kernel operations the agent performs and the
// state it observes, behind one interface. The Linux implementation speaks
// netlink, wgctrl and nftables; the simulator's model plays the same
// operations over maps.
package kernel

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/nft"
)

// Errors a Kernel returns for conditions the agent handles.
var (
	// ErrPortInUse reports a listen port another socket holds.
	ErrPortInUse = errors.New("listen port in use")
	// ErrNoNamespace reports an operation on a namespace that is gone.
	ErrNoNamespace = errors.New("no such namespace")
	// ErrNoDevice reports an operation on a device that is gone.
	ErrNoDevice = errors.New("no such device")
)

// Kernel carries out the agent's operations on one host.
type Kernel interface {
	// Snapshot lists the namespaces named with prefix, and every namespace
	// a process holds that contains a device whose alias starts with
	// aliasPrefix.
	Snapshot(prefix, aliasPrefix string) (Snapshot, error)
	// Namespace observes one named namespace.
	Namespace(name, aliasPrefix string) (Namespace, error)
	// Run carries out one operation.
	Run(Op) (Result, error)
}

// Snapshot is the kernel state the agent owns or may have leaked.
type Snapshot struct {
	Namespaces []Namespace `json:"namespaces"`
}

// Namespace is one network namespace.
type Namespace struct {
	// Name is the namespace's bind-mounted name, or empty for one only a
	// process holds.
	Name string `json:"name,omitempty"`
	// Ref identifies a namespace without a name, for Reap.
	Ref     string   `json:"ref,omitempty"`
	Devices []Device `json:"devices,omitempty"`
	// Egress is the namespace's link to the host's egress NAT, if any.
	Egress *EgressConfig `json:"egress,omitempty"`
}

// Device is a WireGuard device as observed.
type Device struct {
	Name       string    `json:"name"`
	Alias      string    `json:"alias,omitempty"`
	PublicKey  model.Key `json:"public_key"`
	HasKey     bool      `json:"has_key"`
	ListenPort uint16    `json:"listen_port"`
	Peers      []Peer    `json:"peers,omitempty"`
}

// Peer is one entry of a device's peer table.
type Peer struct {
	PublicKey model.Key      `json:"public_key"`
	Allowed   []netip.Prefix `json:"allowed"`
	Endpoint  netip.AddrPort `json:"endpoint,omitzero"`
	Keepalive time.Duration  `json:"keepalive,omitempty"`
}

// OpKind names an operation.
type OpKind string

const (
	CreateNamespace OpKind = "create_namespace"
	DeleteNamespace OpKind = "delete_namespace"
	CreateDevice    OpKind = "create_device"
	ConfigureLink   OpKind = "configure_link"
	SetPeers        OpKind = "set_peers"
	ApplyRules      OpKind = "apply_rules"
	Flush           OpKind = "flush"
	Sweep           OpKind = "sweep"
	DeleteDevice    OpKind = "delete_device"
	SetEgress       OpKind = "set_egress"
	Reap            OpKind = "reap"
)

// Op is one kernel operation. Every operation is idempotent where the
// kernel allows: creating what exists, or deleting what is gone, succeeds.
type Op struct {
	Kind      OpKind `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	// Device names the device, for every device operation.
	Device string `json:"device,omitempty"`
	// Create configures CreateDevice: the device is created straight into
	// the namespace, keyed and bound, or not at all.
	Create *DeviceConfig `json:"create,omitempty"`
	// Link configures ConfigureLink.
	Link *LinkConfig `json:"link,omitempty"`
	// Peers configures SetPeers, as one call.
	Peers []PeerUpdate `json:"peers,omitempty"`
	// Rules configures ApplyRules, as one transaction.
	Rules *nft.Transaction `json:"rules,omitempty"`
	// Addrs configures Flush: conntrack entries translated to these
	// addresses and sockets addressed to them. For Sweep, it is the
	// addresses to keep.
	Addrs []netip.Addr `json:"addrs,omitempty"`
	// Prefixes bounds Sweep: it flushes flows to addresses inside them
	// that Addrs does not keep, and leaves flows elsewhere, such as to the
	// internet, alone.
	Prefixes []netip.Prefix `json:"prefixes,omitempty"`
	// Egress configures SetEgress: the namespace's link to the host's
	// egress NAT and the flows it may open, or nil to remove the link.
	Egress *EgressConfig `json:"egress,omitempty"`
	// EgressIndex names, for a SetEgress that removes, the host's filter
	// to remove with the link; it outlives a namespace deleted without it,
	// so it goes even when the namespace is gone.
	EgressIndex uint16 `json:"egress_index,omitempty"`
	// Ref names the namespace Reap clears.
	Ref string `json:"ref,omitempty"`
	// AliasPrefix limits Reap to devices this agent made.
	AliasPrefix string `json:"alias_prefix,omitempty"`
}

func (o Op) String() string {
	switch o.Kind {
	case SetPeers:
		return fmt.Sprintf("%s %s (%d peers)", o.Kind, o.Namespace, len(o.Peers))
	case Flush:
		return fmt.Sprintf("%s %s %v", o.Kind, o.Namespace, o.Addrs)
	case Reap:
		return fmt.Sprintf("%s %s", o.Kind, o.Ref)
	}
	return fmt.Sprintf("%s %s", o.Kind, o.Namespace)
}

// Result reports what an operation did that the agent records.
type Result struct {
	// Conntrack and Sockets count what a Flush removed.
	Conntrack int `json:"conntrack,omitempty"`
	Sockets   int `json:"sockets,omitempty"`
}

// DeviceConfig creates a device.
type DeviceConfig struct {
	// PrivateKey never serializes, so no log line or journal carries it.
	PrivateKey model.Key `json:"-"`
	ListenPort uint16    `json:"listen_port"`
	// Alias marks the device as this agent's, naming its interface.
	Alias string `json:"alias"`
}

// LinkConfig is a device's addresses, routes and MTU, which the agent sets
// whole.
type LinkConfig struct {
	Addrs  []netip.Prefix `json:"addrs"`
	Routes []netip.Prefix `json:"routes"`
	MTU    int            `json:"mtu"`
	// Forward turns on forwarding in the namespace, for a gateway.
	Forward bool `json:"forward,omitempty"`
}

// Equal reports whether two configurations match.
func (l *LinkConfig) Equal(o *LinkConfig) bool {
	return l != nil && o != nil && slices.Equal(l.Addrs, o.Addrs) && slices.Equal(l.Routes, o.Routes) && l.MTU == o.MTU &&
		l.Forward == o.Forward
}

// EgressConfig is an interface's internet egress grant: a veth pair to
// the host, whose host side the host's egress filter and NAT apply to.
type EgressConfig struct {
	// Index names the link's host side and picks its addresses. The
	// device's listen port serves, being unique on the host.
	Index uint16 `json:"index"`
	// Rules are the flows the workload may open, sorted.
	Rules []EgressRule `json:"rules"`
}

// EgressRule permits flows of one protocol to a port range.
type EgressRule struct {
	Proto model.Proto     `json:"proto"`
	Ports model.PortRange `json:"ports"`
}

// Equal reports whether two grants match; nil is no grant.
func (e *EgressConfig) Equal(o *EgressConfig) bool {
	if e == nil || o == nil {
		return e == nil && o == nil
	}
	return e.Index == o.Index && slices.Equal(e.Rules, o.Rules)
}

// Clone copies a grant.
func (e *EgressConfig) Clone() *EgressConfig {
	if e == nil {
		return nil
	}
	return &EgressConfig{Index: e.Index, Rules: slices.Clone(e.Rules)}
}

// PeerUpdate changes one peer within a SetPeers call. An update replaces
// the peer's allowed IPs and keepalive; it rewrites the endpoint only when
// Endpoint is set, so a roamed endpoint survives every other change.
type PeerUpdate struct {
	PublicKey model.Key      `json:"public_key"`
	Remove    bool           `json:"remove,omitempty"`
	Allowed   []netip.Prefix `json:"allowed,omitempty"`
	Endpoint  netip.AddrPort `json:"endpoint,omitzero"`
	Keepalive time.Duration  `json:"keepalive,omitempty"`
}

// SortPrefixes orders allowed IPs as the kernel reports them, so desired and
// observed peers compare equal.
func SortPrefixes(p []netip.Prefix) []netip.Prefix {
	out := slices.Clone(p)
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out
}

// Alias is the alias a device made for an interface carries.
func Alias(prefix string, iface model.InterfaceID) string { return prefix + string(iface) }

// AliasInterface returns the interface a device's alias names.
func AliasInterface(prefix, alias string) (model.InterfaceID, bool) {
	if !strings.HasPrefix(alias, prefix) {
		return "", false
	}
	return model.InterfaceID(strings.TrimPrefix(alias, prefix)), true
}
