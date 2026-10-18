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
//     with its devices still bound;
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
	// Ran counts operations carried out.
	Ran uint64
}

// Move is an allowed IP that changed peers on one device.
type Move struct {
	Namespace string
	Prefix    netip.Prefix
	From, To  model.Key
}

// Netns is one network namespace.
type Netns struct {
	Name string
	Ref  string
	// Held counts processes inside the namespace.
	Held    int
	Devices map[string]*Device
	Rules   *nft.Ruleset
	// Flows are the connections conntrack and sockets hold, keyed by an
	// identifier the simulator assigns.
	Flows map[uint64]*Flow
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
		named:   map[string]*Netns{},
		anon:    map[string]*Netns{},
		ports:   map[uint16]*Device{},
		Foreign: map[uint16]bool{},
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

// Unhold records a process leaving a namespace. A namespace with no name
// and no process dies, and its devices with it.
func (k *Kernel) Unhold(ns *Netns) {
	if ns.Held > 0 {
		ns.Held--
	}
	if ns.Held == 0 && ns.Name == "" {
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
		ns, ok := k.named[op.Namespace]
		if !ok {
			return kernel.Result{}, nil
		}
		delete(k.named, op.Namespace)
		if ns.Held == 0 {
			k.destroy(ns)
			return kernel.Result{}, nil
		}
		k.nextRef++
		ns.Name, ns.Ref = "", fmt.Sprintf("ns-%d", k.nextRef)
		k.anon[ns.Ref] = ns
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
		if op.Kind == kernel.DeleteDevice {
			return kernel.Result{}, nil
		}
		return kernel.Result{}, kernel.ErrNoNamespace
	}
	switch op.Kind {
	case kernel.CreateDevice:
		return kernel.Result{}, k.createDevice(ns, op.Device, *op.Create)
	case kernel.DeleteDevice:
		if d, ok := ns.Devices[op.Device]; ok {
			k.deleteDevice(d)
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
		var r kernel.Result
		for _, id := range slices.Sorted(maps.Keys(ns.Flows)) {
			if slices.Contains(op.Addrs, ns.Flows[id].Remote) {
				delete(ns.Flows, id)
				r.Conntrack++
				r.Sockets++
			}
		}
		return r, nil
	case kernel.Sweep:
		var r kernel.Result
		for _, id := range slices.Sorted(maps.Keys(ns.Flows)) {
			remote := ns.Flows[id].Remote
			inside := slices.ContainsFunc(op.Prefixes, func(p netip.Prefix) bool { return p.Contains(remote) })
			if inside && !slices.Contains(op.Addrs, remote) {
				delete(ns.Flows, id)
				r.Conntrack++
				r.Sockets++
			}
		}
		return r, nil
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
