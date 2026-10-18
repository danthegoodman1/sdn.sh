//wirenet:deterministic

package api

import (
	"net/netip"
	"time"

	"github.com/danthegoodman1/wirenet/internal/model"
)

// Error is the body of every failed API call.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Error codes.
const (
	CodeNotFound    = "not_found"
	CodeConflict    = "conflict"
	CodeInvalid     = "invalid"
	CodeExhausted   = "exhausted"
	CodeForbidden   = "forbidden"
	CodeUnavailable = "unavailable"
)

// Admin API.

// CreateNetwork creates an address space.
type CreateNetwork struct {
	Name string `json:"name"`
	// Prefix6 defaults to a random ULA /64.
	Prefix6 netip.Prefix `json:"prefix6,omitzero"`
	// Prefix4 is optional; services that opt into IPv4 draw from it.
	Prefix4 netip.Prefix `json:"prefix4,omitzero"`
	MTU     int          `json:"mtu,omitempty"`
	// Relays names the relay set, in preference order.
	Relays []model.RelayID `json:"relays,omitempty"`
}

// Network describes a network.
type Network struct {
	ID       model.NetworkID `json:"id"`
	Name     string          `json:"name"`
	Prefix6  netip.Prefix    `json:"prefix6"`
	Prefix4  netip.Prefix    `json:"prefix4,omitzero"`
	MTU      int             `json:"mtu"`
	Relays   []model.RelayID `json:"relays,omitempty"`
	Revision uint64          `json:"revision"`
}

// CreateService declares a service.
type CreateService struct {
	Name string `json:"name"`
	IPv4 bool   `json:"ipv4,omitempty"`
	Mode Mode   `json:"mode,omitempty"`
}

// ServiceInfo describes a service.
type ServiceInfo struct {
	ID      model.ServiceID `json:"id"`
	Network model.NetworkID `json:"network"`
	Name    string          `json:"name"`
	Addr6   netip.Addr      `json:"addr6"`
	Addr4   netip.Addr      `json:"addr4,omitzero"`
	Mode    Mode            `json:"mode"`
}

// CreateRule permits a flow between services. To may name "internet".
type CreateRule struct {
	From  string          `json:"from"`
	To    string          `json:"to"`
	Proto model.Proto     `json:"proto"`
	Ports model.PortRange `json:"ports"`
}

// Internet is the rule target that grants egress.
const Internet = "internet"

// Rule describes a policy rule.
type Rule struct {
	ID      model.RuleID    `json:"id"`
	Network model.NetworkID `json:"network"`
	From    model.ServiceID `json:"from"`
	// To is a service, or empty for internet egress.
	To    model.ServiceID `json:"to,omitempty"`
	Proto model.Proto     `json:"proto"`
	Ports model.PortRange `json:"ports"`
}

// InterfaceInfo describes an interface to an operator.
type InterfaceInfo struct {
	ID         model.InterfaceID `json:"id"`
	Network    model.NetworkID   `json:"network"`
	Service    model.ServiceID   `json:"service"`
	Host       model.HostID      `json:"host"`
	Kind       Kind              `json:"kind"`
	PublicKey  model.Key         `json:"public_key"`
	Addr6      netip.Addr        `json:"addr6"`
	Addr4      netip.Addr        `json:"addr4,omitzero"`
	ListenPort uint16            `json:"listen_port"`
	State      LeaseState        `json:"state"`
	Expires    time.Time         `json:"expires"`
}

// CreateHost registers a host and returns its token once.
type CreateHost struct {
	Name string `json:"name"`
	// Endpoint is where development machines reach a gateway on this host.
	Endpoint netip.AddrPort `json:"endpoint,omitzero"`
}

// Credentials carry a new principal's identity and bearer token.
type Credentials struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

// RelayInfo describes a relay to an operator.
type RelayInfo struct {
	ID        model.RelayID  `json:"id"`
	Name      string         `json:"name"`
	Addresses []RelayAddress `json:"addresses"`
	PortLo    uint16         `json:"port_lo"`
	PortHi    uint16         `json:"port_hi"`
	ProbePort uint16         `json:"probe_port"`
	Revision  uint64         `json:"revision"`
}

// RelayAddress is one address a relay serves edges on: the local address it
// binds and the address agents send to, which differ behind a cloud NAT.
type RelayAddress struct {
	Local      netip.Addr `json:"local"`
	Advertised netip.Addr `json:"advertised"`
}

// CreateRelay registers a relay and returns its token once.
type CreateRelay struct {
	Name      string         `json:"name"`
	Addresses []RelayAddress `json:"addresses"`
	PortLo    uint16         `json:"port_lo"`
	PortHi    uint16         `json:"port_hi"`
	// ProbePort answers agents' probes on the first address.
	ProbePort uint16 `json:"probe_port"`
}

// CreateDevice registers a development machine behind a gateway. The caller
// mints the key and sends only its public half.
type CreateDevice struct {
	Service   string            `json:"service"`
	Gateway   model.InterfaceID `json:"gateway"`
	PublicKey model.Key         `json:"public_key"`
	// TTL is the lease's fixed term; the config is regenerated to extend it.
	TTL time.Duration `json:"ttl"`
}

// DeviceConfig is what a development machine's WireGuard config needs.
type DeviceConfig struct {
	Interface      model.InterfaceID `json:"interface"`
	Addr6          netip.Addr        `json:"addr6"`
	Addr4          netip.Addr        `json:"addr4,omitzero"`
	DNS            netip.Addr        `json:"dns"`
	Domain         string            `json:"domain"`
	MTU            int               `json:"mtu"`
	GatewayKey     model.Key         `json:"gateway_key"`
	GatewayAddress netip.AddrPort    `json:"gateway_address"`
	Routes         []netip.Prefix    `json:"routes"`
	Expires        time.Time         `json:"expires"`
}

// Agent API.

// AttachRequest asks for an interface on the calling host. The agent picks
// the identifier, so a retried attach is the same attach.
type AttachRequest struct {
	Interface  model.InterfaceID `json:"interface"`
	Network    string            `json:"network"`
	Service    string            `json:"service"`
	Kind       Kind              `json:"kind,omitempty"`
	PublicKey  model.Key         `json:"public_key"`
	ListenPort uint16            `json:"listen_port"`
}

// AttachResponse carries the new interface's network as it stands for the
// host, so the agent configures it without waiting for a poll.
type AttachResponse struct {
	Interface model.InterfaceID `json:"interface"`
	State     NetworkState      `json:"state"`
}

// ReleaseRequest ends interfaces the host holds: a planned removal, which
// peers drain over the grace period.
type ReleaseRequest struct {
	Interfaces []model.InterfaceID `json:"interfaces"`
}

// RenewRequest extends the leases of interfaces the host holds.
type RenewRequest struct {
	Interfaces []model.InterfaceID `json:"interfaces"`
}

// RenewResponse reports each lease's new expiry. Interfaces it leaves out
// are no longer live.
type RenewResponse struct {
	Expires map[model.InterfaceID]time.Time `json:"expires"`
}

// Relay API.

// RelayState is the port table one relay serves.
type RelayState struct {
	Relay      model.RelayID `json:"relay"`
	Generation uint64        `json:"generation"`
	Ports      []RelayPort   `json:"ports"`
}

// RelayPort is one direction's port: packets arriving on Local come from the
// direction's sender and go out from Peer, the opposite direction's port on
// the same address.
type RelayPort struct {
	Local netip.AddrPort `json:"local"`
	Peer  uint16         `json:"peer"`
	// Advertised is the address and port agents send to, which the
	// registration MAC covers.
	Advertised netip.AddrPort `json:"advertised"`
	// Key is this relay's registration key for the direction.
	Key model.Secret `json:"key"`
}

// Agent local API, on the agent's unix socket.

// LocalAttach asks the agent to build an interface for a workload.
type LocalAttach struct {
	// Name identifies the workload on this host. Attaching a name again
	// returns the interface already built for it, so a caller that lost an
	// answer retries without leaking an interface.
	Name    string `json:"name"`
	Network string `json:"network"`
	Service string `json:"service"`
	Kind    Kind   `json:"kind,omitempty"`
}

// LocalInterface describes an interface the agent built: the namespace to
// hand the workload and the addresses it holds.
type LocalInterface struct {
	Interface model.InterfaceID `json:"interface"`
	Name      string            `json:"name"`
	Network   model.NetworkID   `json:"network"`
	Service   model.ServiceID   `json:"service"`
	Namespace string            `json:"namespace"`
	Addr6     netip.Addr        `json:"addr6"`
	Addr4     netip.Addr        `json:"addr4,omitzero"`
	PublicKey model.Key         `json:"public_key"`
	Ready     bool              `json:"ready"`
	// Resolver is the stub resolver's address inside the namespace, and
	// Search the domain its names resolve under: a workload's resolv.conf
	// names both.
	Resolver netip.Addr `json:"resolver,omitzero"`
	Search   string     `json:"search,omitempty"`
}

// LocalDetach asks the agent to tear an interface down.
type LocalDetach struct {
	Interface model.InterfaceID `json:"interface"`
}
