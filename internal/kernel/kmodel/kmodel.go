//sdn:deterministic

// Package kmodel is the simulator's model of one host's kernel: namespaces,
// WireGuard devices and their peer tables, the nftables table in each
// namespace, and the flows conntrack and sockets hold. It follows the kernel
// where the agent's correctness depends on it:
//
//   - every device's UDP socket lives in the host namespace, so listen ports
//     are unique per host;
//   - giving a peer an allowed IP another peer holds moves it, silently, as
//     wg_allowedips_insert does;
//   - a namespace whose name is deleted lives on while a process holds it,
//     or while the agent holds sockets it opened inside, with its devices
//     still bound;
//   - an nftables transaction applies whole or not at all.
package kmodel

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"sdn.sh/internal/kernel"
	"sdn.sh/internal/model"
	"sdn.sh/internal/nft"
)

// Kernel models one host.
type Kernel struct {
	named map[string]*Netns
	anon  map[string]*Netns
	ports map[uint16]*Device
	// Foreign holds listen ports other software has bound.
	Foreign map[uint16]bool
	nextRef int
	// Fail, when set, decides whether an operation fails before it runs.
	Fail func(op kernel.Op) error
	// Moves records every allowed IP a SetPeers took from another peer.
	Moves []Move
	// Flushed records every flow a Flush or Sweep removed, with its
	// namespace, until the simulator reads and clears it.
	Flushed []Flushed
	// Ran counts operations carried out.
	Ran uint64
	// EgressChains are the host's per-link egress filters, by index. One
	// outlives a namespace destroyed without SetEgress removing it first,
	// as on Linux, where it filters a link that no longer exists.
	EgressChains map[uint16][]kernel.EgressRule
	// egressLinks names which namespace holds each index's link.
	egressLinks map[uint16]*Netns
}

// flush removes every flow match selects, and its socket with it, as Linux
// does: a Flush by the address the flow dialed or the address it was
// translated to, a Sweep by the translated address alone, the one its far
// end sends from. Loopback is never matched.
func (k *Kernel) flush(ns *Netns, match func(netip.Addr) bool, sweep bool) kernel.Result {
	var r kernel.Result
	hit := func(a netip.Addr) bool { return a.IsValid() && !a.IsLoopback() && match(a) }
	for _, id := range slices.Sorted(maps.Keys(ns.Flows)) {
		f := ns.Flows[id]
		if hit(f.Remote) || !sweep && hit(f.Dialed) {
			k.Flushed = append(k.Flushed, Flushed{Namespace: ns.Name, Flow: *f})
			delete(ns.Flows, id)
			r.Conntrack++
			r.Sockets++
		}
	}
	return r
}

// Move is an allowed IP that changed peers on one device.
type Move struct {
	Namespace string
	Prefix    netip.Prefix
	From, To  model.Key
}

// Flushed is a flow a Flush or Sweep removed.
type Flushed struct {
	Namespace string
	Flow      Flow
}

// Netns is one network namespace.
type Netns struct {
	Name string
	Ref  string
	// Held counts processes inside the namespace.
	Held int
	// opened is the name the agent opened sockets inside by, while it
	// holds them. They outlive the name, and hold the namespace as a
	// process does.
	opened  string
	Devices map[string]*Device
	Rules   *nft.Ruleset
	// Flows are the connections conntrack and sockets hold, keyed by an
	// identifier the simulator assigns.
	Flows map[uint64]*Flow
	// Egress is the namespace's link to the host's egress NAT.
	Egress *kernel.EgressConfig
}

// Flow is one connection a namespace's conntrack and sockets hold.
type Flow struct {
	ID uint64
	// Remote is the far end's address after translation: the address
	// conntrack translated the flow to, and the socket's peer.
	Remote netip.Addr
	// Dialed is what the workload connected to, such as a service address.
	Dialed netip.Addr
	// Peer is the peer the flow's packets went through when it opened.
	Peer model.Key
}

// Device is one WireGuard device.
type Device struct {
	ns      *Netns
	Name    string
	Alias   string
	Private model.Key
	Port    uint16
	Link    *kernel.LinkConfig
	Peers   map[model.Key]*Peer
	owner   map[netip.Prefix]model.Key
}

// Peer is one peer of a device.
type Peer struct {
	kernel.Peer
}

// New returns a host with no namespaces.
func New() *Kernel {
	return &Kernel{
		named:        map[string]*Netns{},
		anon:         map[string]*Netns{},
		ports:        map[uint16]*Device{},
		Foreign:      map[uint16]bool{},
		EgressChains: map[uint16][]kernel.EgressRule{},
		egressLinks:  map[uint16]*Netns{},
	}
}

// Reboot loses everything, as a host restart does: namespaces live in
// memory and their names on a tmpfs.
func (k *Kernel) Reboot() {
	foreign := k.Foreign
	*k = *New()
	k.Foreign = foreign
}

// Named returns a named namespace.
func (k *Kernel) Named(name string) (*Netns, bool) {
	ns, ok := k.named[name]
	return ns, ok
}

// All returns every namespace, named ones first, in order.
func (k *Kernel) All() []*Netns {
	var out []*Netns
	for _, name := range slices.Sorted(maps.Keys(k.named)) {
		out = append(out, k.named[name])
	}
	for _, ref := range slices.Sorted(maps.Keys(k.anon)) {
		out = append(out, k.anon[ref])
	}
	return out
}

// Hold records a process entering a named namespace.
func (k *Kernel) Hold(name string) bool {
	ns, ok := k.named[name]
	if ok {
		ns.Held++
	}
	return ok
}

// Unhold records a process leaving a namespace. A namespace this kernel no
// longer holds, as one from before a reboot, is gone already.
func (k *Kernel) Unhold(ns *Netns) {
	if ns.Held > 0 {
		ns.Held--
	}
	k.collect(ns)
}

// Unname deletes a namespace's name, as `ip netns del` does; a namespace a
// process or the agent's sockets hold lives on without one.
func (k *Kernel) Unname(name string) {
	ns, ok := k.named[name]
	if !ok {
		return
	}
	delete(k.named, name)
	k.nextRef++
	ns.Name, ns.Ref = "", fmt.Sprintf("ns-%d", k.nextRef)
	k.anon[ns.Ref] = ns
	k.collect(ns)
}

// AgentExit closes every socket the agent held, as its process ending does.
func (k *Kernel) AgentExit() {
	for _, name := range slices.Sorted(maps.Keys(k.named)) {
		k.named[name].opened = ""
	}
	for _, ref := range slices.Sorted(maps.Keys(k.anon)) {
		ns := k.anon[ref]
		ns.opened = ""
		k.collect(ns)
	}
}

// open records the agent opening sockets inside a named namespace, as its
// first operation or look there does. Sockets it held in a namespace the
// name used to open close then, as the Linux implementation replaces them.
func (k *Kernel) open(ns *Netns) {
	if ns.opened == ns.Name {
		return
	}
	k.release(ns.Name)
	ns.opened = ns.Name
}

// release closes the sockets the agent opened by name, as deleting the
// namespace does first.
func (k *Kernel) release(name string) {
	if ns, ok := k.named[name]; ok && ns.opened == name {
		ns.opened = ""
	}
	for _, ref := range slices.Sorted(maps.Keys(k.anon)) {
		if ns := k.anon[ref]; ns.opened == name {
			ns.opened = ""
			k.collect(ns)
		}
	}
}

// collect destroys a namespace that has no name, no process and no socket
// of the agent's, and its devices with it.
func (k *Kernel) collect(ns *Netns) {
	if ns.Held == 0 && ns.opened == "" && ns.Name == "" && k.anon[ns.Ref] == ns {
		k.destroy(ns)
		delete(k.anon, ns.Ref)
	}
}

// PortOwner returns the device bound to a host UDP port.
func (k *Kernel) PortOwner(port uint16) (*Device, bool) {
	d, ok := k.ports[port]
	return d, ok
}

// DeviceList returns a namespace's devices in name order.
func (ns *Netns) DeviceList() []*Device {
	var out []*Device
	for _, name := range slices.Sorted(maps.Keys(ns.Devices)) {
		out = append(out, ns.Devices[name])
	}
	return out
}

// Namespace returns the namespace a device lives in.
func (d *Device) Namespace() *Netns { return d.ns }

// PeerList returns a device's peers ordered by key.
func (d *Device) PeerList() []*Peer {
	var out []*Peer
	for _, key := range slices.SortedFunc(maps.Keys(d.Peers), compareKey) {
		out = append(out, d.Peers[key])
	}
	return out
}

// Route returns the peer whose allowed IPs hold addr, as WireGuard routes an
// outgoing packet.
func (d *Device) Route(addr netip.Addr) (*Peer, bool) {
	key, ok := d.owner[netip.PrefixFrom(addr, addr.BitLen())]
	if !ok {
		return nil, false
	}
	return d.Peers[key], true
}

// Roam records an authenticated packet from a peer arriving from src, which
// moves the peer's endpoint there.
func (d *Device) Roam(key model.Key, src netip.AddrPort) {
	if p, ok := d.Peers[key]; ok {
		p.Endpoint = src
	}
}

func compareKey(a, b model.Key) int {
	return strings.Compare(string(a[:]), string(b[:]))
}

// Snapshot lists named namespaces with prefix and unnamed namespaces
// holding a device of this agent's.
func (k *Kernel) Snapshot(prefix, aliasPrefix string) (kernel.Snapshot, error) {
	var s kernel.Snapshot
	for _, name := range slices.Sorted(maps.Keys(k.named)) {
		if strings.HasPrefix(name, prefix) {
			k.open(k.named[name])
			s.Namespaces = append(s.Namespaces, observe(k.named[name], aliasPrefix))
		}
	}
	for _, ref := range slices.Sorted(maps.Keys(k.anon)) {
		ns := observe(k.anon[ref], aliasPrefix)
		if len(ns.Devices) > 0 {
			s.Namespaces = append(s.Namespaces, ns)
		}
	}
	return s, nil
}

// Namespace observes one named namespace.
func (k *Kernel) Namespace(name, aliasPrefix string) (kernel.Namespace, error) {
	ns, ok := k.named[name]
	if !ok {
		return kernel.Namespace{}, kernel.ErrNoNamespace
	}
	k.open(ns)
	return observe(ns, aliasPrefix), nil
}

// observe reports a namespace's devices. In a named namespace every device
// shows, so the agent sees what it must clear; in an unnamed one only this
// agent's do.
func observe(ns *Netns, aliasPrefix string) kernel.Namespace {
	out := kernel.Namespace{Name: ns.Name, Ref: ns.Ref}
	for _, d := range ns.DeviceList() {
		if ns.Name == "" && !strings.HasPrefix(d.Alias, aliasPrefix) {
			continue
		}
		dev := kernel.Device{Name: d.Name, Alias: d.Alias, ListenPort: d.Port, HasKey: !d.Private.IsZero()}
		if dev.HasKey {
			dev.PublicKey = d.Private.Public()
		}
		for _, p := range d.PeerList() {
			dev.Peers = append(dev.Peers, kernel.Peer{
				PublicKey: p.PublicKey, Allowed: slices.Clone(p.Allowed), Endpoint: p.Endpoint, Keepalive: p.Keepalive,
			})
		}
		out.Devices = append(out.Devices, dev)
	}
	if ns.Name != "" {
		out.Egress = ns.Egress.Clone()
	}
	return out
}

// Run carries out one operation.
func (k *Kernel) Run(op kernel.Op) (kernel.Result, error) {
	if k.Fail != nil {
		if err := k.Fail(op); err != nil {
			return kernel.Result{}, err
		}
	}
	k.Ran++
	switch op.Kind {
	case kernel.CreateNamespace:
		if _, ok := k.named[op.Namespace]; !ok {
			k.named[op.Namespace] = &Netns{Name: op.Namespace, Devices: map[string]*Device{}, Flows: map[uint64]*Flow{}}
		}
		return kernel.Result{}, nil
	case kernel.DeleteNamespace:
		k.release(op.Namespace)
		k.Unname(op.Namespace)
		return kernel.Result{}, nil
	case kernel.Reap:
		ns, ok := k.anon[op.Ref]
		if !ok {
			return kernel.Result{}, nil
		}
		for _, d := range ns.DeviceList() {
			if strings.HasPrefix(d.Alias, op.AliasPrefix) {
				k.deleteDevice(d)
			}
		}
		return kernel.Result{}, nil
	}
	ns, ok := k.named[op.Namespace]
	if !ok {
		switch {
		case op.Kind == kernel.DeleteDevice:
			return kernel.Result{}, nil
		case op.Kind == kernel.SetEgress && op.Egress == nil:
			k.removeEgressFilter(op.EgressIndex)
			return kernel.Result{}, nil
		}
		return kernel.Result{}, kernel.ErrNoNamespace
	}
	k.open(ns)
	switch op.Kind {
	case kernel.CreateDevice:
		return kernel.Result{}, k.createDevice(ns, op.Device, *op.Create)
	case kernel.DeleteDevice:
		if d, ok := ns.Devices[op.Device]; ok {
			k.deleteDevice(d)
		}
		return kernel.Result{}, nil
	case kernel.SetEgress:
		k.setEgress(ns, op.Egress)
		if op.Egress == nil {
			k.removeEgressFilter(op.EgressIndex)
		}
		return kernel.Result{}, nil
	case kernel.ApplyRules:
		rs, err := nft.Apply(ns.Rules, *op.Rules)
		if err != nil {
			return kernel.Result{}, err
		}
		ns.Rules = rs
		return kernel.Result{}, nil
	case kernel.Flush:
		return k.flush(ns, func(a netip.Addr) bool { return slices.Contains(op.Addrs, a) }, false), nil
	case kernel.Sweep:
		return k.flush(ns, func(a netip.Addr) bool {
			inside := slices.ContainsFunc(op.Prefixes, func(p netip.Prefix) bool { return p.Contains(a) })
			return inside && !slices.Contains(op.Addrs, a)
		}, true), nil
	}
	d, ok := ns.Devices[op.Device]
	if !ok {
		return kernel.Result{}, kernel.ErrNoDevice
	}
	switch op.Kind {
	case kernel.ConfigureLink:
		l := *op.Link
		d.Link = &l
	case kernel.SetPeers:
		k.setPeers(d, op.Peers)
	default:
		return kernel.Result{}, fmt.Errorf("kmodel: unknown operation %q", op.Kind)
	}
	return kernel.Result{}, nil
}

func (k *Kernel) createDevice(ns *Netns, name string, cfg kernel.DeviceConfig) error {
	if d, ok := ns.Devices[name]; ok {
		if d.Private == cfg.PrivateKey && d.Port == cfg.ListenPort {
			return nil
		}
		return errors.New("kmodel: device exists with another key or port")
	}
	if _, taken := k.ports[cfg.ListenPort]; taken || k.Foreign[cfg.ListenPort] {
		return kernel.ErrPortInUse
	}
	d := &Device{
		ns: ns, Name: name, Alias: cfg.Alias, Private: cfg.PrivateKey, Port: cfg.ListenPort,
		Peers: map[model.Key]*Peer{}, owner: map[netip.Prefix]model.Key{},
	}
	ns.Devices[name] = d
	k.ports[cfg.ListenPort] = d
	return nil
}

func (k *Kernel) deleteDevice(d *Device) {
	delete(d.ns.Devices, d.Name)
	if k.ports[d.Port] == d {
		delete(k.ports, d.Port)
	}
}

func (k *Kernel) destroy(ns *Netns) {
	for _, d := range ns.DeviceList() {
		k.deleteDevice(d)
	}
	// The link goes with the namespace; its host filter stays.
	if ns.Egress != nil && k.egressLinks[ns.Egress.Index] == ns {
		delete(k.egressLinks, ns.Egress.Index)
	}
	ns.Egress = nil
}

// setEgress installs, changes or removes a namespace's egress link and its
// host filter. A link left at the same index by another namespace is
// replaced, as the Linux implementation deletes a stale host side.
// EgressLinked reports whether an egress index's link exists.
func (k *Kernel) EgressLinked(idx uint16) bool {
	_, ok := k.egressLinks[idx]
	return ok
}

// removeEgressFilter removes the host's filter and link for an index, as a
// removal that names it does on Linux: deleting the host end of the pair
// takes the end in the namespace with it, wherever that namespace is.
func (k *Kernel) removeEgressFilter(idx uint16) {
	if idx == 0 {
		return
	}
	if ns, ok := k.egressLinks[idx]; ok {
		ns.Egress = nil
		delete(k.egressLinks, idx)
	}
	delete(k.EgressChains, idx)
}

func (k *Kernel) setEgress(ns *Netns, cfg *kernel.EgressConfig) {
	if ns.Egress != nil && (cfg == nil || ns.Egress.Index != cfg.Index) {
		delete(k.EgressChains, ns.Egress.Index)
		delete(k.egressLinks, ns.Egress.Index)
		ns.Egress = nil
	}
	if cfg == nil {
		return
	}
	if other, ok := k.egressLinks[cfg.Index]; ok && other != ns {
		other.Egress = nil
	}
	ns.Egress = cfg.Clone()
	k.egressLinks[cfg.Index] = ns
	k.EgressChains[cfg.Index] = slices.Clone(cfg.Rules)
}

func (k *Kernel) setPeers(d *Device, updates []kernel.PeerUpdate) {
	for _, u := range updates {
		if u.Remove {
			if p, ok := d.Peers[u.PublicKey]; ok {
				for _, a := range p.Allowed {
					if d.owner[a] == u.PublicKey {
						delete(d.owner, a)
					}
				}
				delete(d.Peers, u.PublicKey)
			}
			continue
		}
		p, ok := d.Peers[u.PublicKey]
		if !ok {
			p = &Peer{kernel.Peer{PublicKey: u.PublicKey}}
			d.Peers[u.PublicKey] = p
		}
		for _, a := range p.Allowed {
			if d.owner[a] == u.PublicKey {
				delete(d.owner, a)
			}
		}
		p.Allowed = nil
		for _, a := range u.Allowed {
			if prev, held := d.owner[a]; held && prev != u.PublicKey {
				k.Moves = append(k.Moves, Move{Namespace: d.ns.Name, Prefix: a, From: prev, To: u.PublicKey})
				if q, ok := d.Peers[prev]; ok {
					q.Allowed = slices.DeleteFunc(q.Allowed, func(x netip.Prefix) bool { return x == a })
				}
			}
			d.owner[a] = u.PublicKey
			p.Allowed = append(p.Allowed, a)
		}
		p.Allowed = kernel.SortPrefixes(p.Allowed)
		if u.Endpoint.IsValid() {
			p.Endpoint = u.Endpoint
		}
		p.Keepalive = u.Keepalive
	}
}

// AddFlow records a connection a workload in ns opened.
func (ns *Netns) AddFlow(f Flow) { ns.Flows[f.ID] = &f }

var _ kernel.Kernel = (*Kernel)(nil)
