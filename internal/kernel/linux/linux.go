//go:build linux

// Package linux carries out the agent's kernel operations on Linux: network
// namespaces, kernel WireGuard over netlink and wgctrl, nftables over
// netlink, conntrack, and sock_diag.
//
// Every workload namespace gets one netlink, wgctrl, nftables and sock_diag
// socket, opened inside it once and kept, so configuring a namespace pays no
// namespace switch after the first.
package linux

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"sdn.sh/internal/kernel"
	"sdn.sh/internal/model"
)

// Kernel is the host's kernel, from the namespace the agent runs in.
type Kernel struct {
	root   netns.NsHandle
	rootNL *netlink.Handle

	mu      sync.Mutex
	handles map[string]*nsHandles
}

// nsHandles are the sockets held open inside one namespace.
type nsHandles struct {
	fd   netns.NsHandle
	nl   *netlink.Handle
	wg   *wgctrl.Client
	nft  *nftables.Conn
	diag *sockDiag
}

func (h *nsHandles) close() {
	if h.wg != nil {
		h.wg.Close()
	}
	if h.nft != nil {
		h.nft.CloseLasting()
	}
	if h.diag != nil {
		h.diag.close()
	}
	if h.nl != nil {
		h.nl.Close()
	}
	h.fd.Close()
}

// New opens the kernel from the calling process's namespace, which becomes
// the root: devices' sockets live there.
func New() (*Kernel, error) {
	runtime.LockOSThread()
	root, err := netns.Get()
	runtime.UnlockOSThread()
	if err != nil {
		return nil, fmt.Errorf("root namespace: %w", err)
	}
	nl, err := netlink.NewHandle()
	if err != nil {
		return nil, err
	}
	return &Kernel{root: root, rootNL: nl, handles: map[string]*nsHandles{}}, nil
}

// Close releases every held socket.
func (k *Kernel) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for name, h := range k.handles {
		h.close()
		delete(k.handles, name)
	}
	k.rootNL.Close()
	k.root.Close()
}

// open returns a namespace's held sockets, opening them on first use.
func (k *Kernel) open(name string) (*nsHandles, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if h, ok := k.handles[name]; ok {
		return h, nil
	}
	fd, err := netns.GetFromPath(filepath.Join(netnsDir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, kernel.ErrNoNamespace
	}
	if err != nil {
		return nil, err
	}
	h, err := k.openAt(fd)
	if err != nil {
		fd.Close()
		return nil, err
	}
	k.handles[name] = h
	return h, nil
}

// openAt opens the sockets inside a namespace handle.
func (k *Kernel) openAt(fd netns.NsHandle) (*nsHandles, error) {
	h := &nsHandles{fd: fd}
	var err error
	if h.nl, err = netlink.NewHandleAt(fd); err != nil {
		return nil, fmt.Errorf("netlink in namespace: %w", err)
	}
	if err := k.inNS(fd, func() error {
		var err error
		if h.wg, err = wgctrl.New(); err != nil {
			return fmt.Errorf("wgctrl in namespace: %w", err)
		}
		if h.diag, err = openSockDiag(); err != nil {
			return err
		}
		return nil
	}); err != nil {
		h.close()
		return nil, err
	}
	if h.nft, err = nftables.New(nftables.WithNetNSFd(int(fd)), nftables.AsLasting()); err != nil {
		h.close()
		return nil, fmt.Errorf("nftables in namespace: %w", err)
	}
	return h, nil
}

func (k *Kernel) forget(name string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if h, ok := k.handles[name]; ok {
		h.close()
		delete(k.handles, name)
	}
}

// Run carries out one operation.
func (k *Kernel) Run(op kernel.Op) (kernel.Result, error) {
	switch op.Kind {
	case kernel.CreateNamespace:
		return kernel.Result{}, k.createNamed(op.Namespace)
	case kernel.DeleteNamespace:
		k.forget(op.Namespace)
		return kernel.Result{}, deleteNamed(op.Namespace)
	case kernel.Reap:
		return kernel.Result{}, k.reap(op.Ref, op.AliasPrefix)
	}
	h, err := k.open(op.Namespace)
	if err != nil {
		if errors.Is(err, kernel.ErrNoNamespace) && op.Kind == kernel.DeleteDevice {
			return kernel.Result{}, nil
		}
		return kernel.Result{}, err
	}
	switch op.Kind {
	case kernel.CreateDevice:
		return kernel.Result{}, k.createDevice(h, op.Device, *op.Create)
	case kernel.DeleteDevice:
		return kernel.Result{}, deleteDevice(h, op.Device)
	case kernel.ConfigureLink:
		return kernel.Result{}, configureLink(h, op.Device, *op.Link)
	case kernel.SetPeers:
		return kernel.Result{}, setPeers(h, op.Device, op.Peers)
	case kernel.ApplyRules:
		return kernel.Result{}, applyTransaction(h.nft, *op.Rules)
	case kernel.Flush:
		return flush(h, func(a netip.Addr) bool { return slices.Contains(op.Addrs, a) })
	case kernel.Sweep:
		return flush(h, func(a netip.Addr) bool {
			inside := slices.ContainsFunc(op.Prefixes, func(p netip.Prefix) bool { return p.Contains(a) })
			return inside && !slices.Contains(op.Addrs, a)
		})
	}
	return kernel.Result{}, fmt.Errorf("unknown operation %q", op.Kind)
}

// createDevice creates a WireGuard device straight into the namespace, so
// its UDP socket stays in the root namespace, then keys it, binds it and
// brings it up. The device exists keyed and bound, or not at all.
func (k *Kernel) createDevice(h *nsHandles, name string, cfg kernel.DeviceConfig) error {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	attrs.Namespace = netlink.NsFd(int(h.fd))
	if err := k.rootNL.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("create %s: %w", name, err)
		}
		dev, derr := h.wg.Device(name)
		if derr == nil && model.Key(dev.PrivateKey) == cfg.PrivateKey && dev.ListenPort == int(cfg.ListenPort) {
			return nil
		}
		return fmt.Errorf("create %s: exists with another key or port", name)
	}
	link, err := h.nl.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find %s: %w", name, err)
	}
	cleanup := func(cause error) error {
		if err := h.nl.LinkDel(link); err != nil {
			return errors.Join(cause, fmt.Errorf("clean up %s: %w", name, err))
		}
		return cause
	}
	if err := h.nl.LinkSetAlias(link, cfg.Alias); err != nil {
		return cleanup(fmt.Errorf("alias %s: %w", name, err))
	}
	key := wgtypes.Key(cfg.PrivateKey)
	port := int(cfg.ListenPort)
	if err := h.wg.ConfigureDevice(name, wgtypes.Config{PrivateKey: &key, ListenPort: &port}); err != nil {
		return cleanup(portError(err))
	}
	// The device opens its socket, and binds the port, when it comes up.
	if err := h.nl.LinkSetUp(link); err != nil {
		return cleanup(portError(err))
	}
	return nil
}

func portError(err error) error {
	if errors.Is(err, unix.EADDRINUSE) {
		return fmt.Errorf("%w: %w", kernel.ErrPortInUse, err)
	}
	return err
}

func deleteDevice(h *nsHandles, name string) error {
	link, err := h.nl.LinkByName(name)
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := h.nl.LinkDel(link); err != nil && !errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}

// configureLink sets a device's addresses, routes and MTU whole: anything
// else on the device goes.
func configureLink(h *nsHandles, name string, cfg kernel.LinkConfig) error {
	link, err := h.nl.LinkByName(name)
	if err != nil {
		return noDevice(name, err)
	}
	if link.Attrs().MTU != cfg.MTU {
		if err := h.nl.LinkSetMTU(link, cfg.MTU); err != nil {
			return fmt.Errorf("mtu %s: %w", name, err)
		}
	}
	have, err := h.nl.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, a := range have {
		p, _ := netip.ParsePrefix(a.IPNet.String())
		if !slices.Contains(cfg.Addrs, p) {
			if err := h.nl.AddrDel(link, &a); err != nil {
				return fmt.Errorf("remove address %v: %w", p, err)
			}
		}
	}
	for _, p := range cfg.Addrs {
		addr := &netlink.Addr{IPNet: ipNet(p)}
		if p.Addr().Is6() {
			// A point-to-point device has no neighbours to clash with, and
			// duplicate detection would leave the address unusable for a
			// second after handover.
			addr.Flags = unix.IFA_F_NODAD
		}
		if err := h.nl.AddrReplace(link, addr); err != nil {
			return fmt.Errorf("address %v: %w", p, err)
		}
	}
	if err := h.nl.LinkSetUp(link); err != nil {
		return fmt.Errorf("up %s: %w", name, err)
	}
	routes, err := h.nl.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Dst == nil || r.Protocol != unix.RTPROT_STATIC {
			continue
		}
		p, _ := netip.ParsePrefix(r.Dst.String())
		if !slices.Contains(cfg.Routes, p) {
			if err := h.nl.RouteDel(&r); err != nil {
				return fmt.Errorf("remove route %v: %w", p, err)
			}
		}
	}
	for _, p := range cfg.Routes {
		r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipNet(p), Scope: netlink.SCOPE_LINK, Protocol: unix.RTPROT_STATIC}
		if err := h.nl.RouteReplace(r); err != nil {
			return fmt.Errorf("route %v: %w", p, err)
		}
	}
	return nil
}

func noDevice(name string, err error) error {
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return fmt.Errorf("%w: %s", kernel.ErrNoDevice, name)
	}
	return err
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// setPeers applies every update in one wgctrl call, which splits large
// changes into messages and releases RTNL between them.
func setPeers(h *nsHandles, name string, updates []kernel.PeerUpdate) error {
	cfg := wgtypes.Config{}
	for _, u := range updates {
		pc := wgtypes.PeerConfig{PublicKey: wgtypes.Key(u.PublicKey), Remove: u.Remove}
		if !u.Remove {
			pc.ReplaceAllowedIPs = true
			for _, p := range u.Allowed {
				pc.AllowedIPs = append(pc.AllowedIPs, *ipNet(p))
			}
			ka := u.Keepalive
			pc.PersistentKeepaliveInterval = &ka
			if u.Endpoint.IsValid() {
				pc.Endpoint = net.UDPAddrFromAddrPort(u.Endpoint)
			}
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	if err := h.wg.ConfigureDevice(name, cfg); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", kernel.ErrNoDevice, name)
		}
		return fmt.Errorf("peers of %s: %w", name, err)
	}
	return nil
}

// flush deletes conntrack entries with any address match accepts, and
// destroys sockets addressed to one.
func flush(h *nsHandles, match func(netip.Addr) bool) (kernel.Result, error) {
	var r kernel.Result
	for _, family := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
		n, err := h.nl.ConntrackDeleteFilters(netlink.ConntrackTable, family, conntrackMatch{match})
		if err != nil {
			return r, fmt.Errorf("conntrack: %w", err)
		}
		r.Conntrack += int(n)
	}
	n, err := h.diag.destroyMatching(match)
	r.Sockets = n
	return r, err
}

// conntrackMatch selects a flow by any of its four addresses.
type conntrackMatch struct{ match func(netip.Addr) bool }

func (c conntrackMatch) MatchConntrackFlow(f *netlink.ConntrackFlow) bool {
	for _, ip := range []net.IP{f.Forward.SrcIP, f.Forward.DstIP, f.Reverse.SrcIP, f.Reverse.DstIP} {
		if a, ok := netip.AddrFromSlice(ip); ok && c.match(a.Unmap()) {
			return true
		}
	}
	return false
}

// Snapshot lists named namespaces with prefix and held namespaces with a
// device whose alias starts with aliasPrefix.
func (k *Kernel) Snapshot(prefix, aliasPrefix string) (kernel.Snapshot, error) {
	var s kernel.Snapshot
	names, err := namedWithPrefix(prefix)
	if err != nil {
		return s, err
	}
	for _, name := range names {
		ns, err := k.Namespace(name, aliasPrefix)
		if err != nil {
			return s, fmt.Errorf("observe %s: %w", name, err)
		}
		s.Namespaces = append(s.Namespaces, ns)
	}
	held, err := k.heldNamespaces()
	if err != nil {
		return s, err
	}
	for _, ino := range sortedInodes(held) {
		fd, err := netns.GetFromPath(held[ino])
		if err != nil {
			continue
		}
		devs, err := k.observeHeld(fd, aliasPrefix)
		fd.Close()
		if err != nil || len(devs) == 0 {
			continue
		}
		s.Namespaces = append(s.Namespaces, kernel.Namespace{Ref: refFor(ino), Devices: devs})
	}
	return s, nil
}

func sortedInodes(m map[uint64]string) []uint64 {
	out := make([]uint64, 0, len(m))
	for ino := range m {
		out = append(out, ino)
	}
	slices.Sort(out)
	return out
}

// Namespace observes one named namespace's WireGuard devices.
func (k *Kernel) Namespace(name, aliasPrefix string) (kernel.Namespace, error) {
	h, err := k.open(name)
	if err != nil {
		return kernel.Namespace{Name: name}, err
	}
	devs, err := observe(h, "")
	return kernel.Namespace{Name: name, Devices: devs}, err
}

// observeHeld lists this agent's devices in a namespace a process holds,
// with sockets opened just for the look.
func (k *Kernel) observeHeld(fd netns.NsHandle, aliasPrefix string) ([]kernel.Device, error) {
	nl, err := netlink.NewHandleAt(fd)
	if err != nil {
		return nil, err
	}
	defer nl.Close()
	links, err := nl.LinkList()
	if err != nil {
		return nil, err
	}
	var out []kernel.Device
	for _, l := range links {
		if l.Type() == "wireguard" && strings.HasPrefix(l.Attrs().Alias, aliasPrefix) {
			out = append(out, kernel.Device{Name: l.Attrs().Name, Alias: l.Attrs().Alias})
		}
	}
	return out, nil
}

// observe reports every WireGuard device in a namespace, or those whose
// alias starts with aliasPrefix when it is set.
func observe(h *nsHandles, aliasPrefix string) ([]kernel.Device, error) {
	links, err := h.nl.LinkList()
	if err != nil {
		return nil, err
	}
	var out []kernel.Device
	for _, l := range links {
		if l.Type() != "wireguard" || !strings.HasPrefix(l.Attrs().Alias, aliasPrefix) {
			continue
		}
		d, err := h.wg.Device(l.Attrs().Name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", l.Attrs().Name, err)
		}
		dev := kernel.Device{
			Name: d.Name, Alias: l.Attrs().Alias, ListenPort: uint16(d.ListenPort),
			HasKey: d.PrivateKey != wgtypes.Key{}, PublicKey: model.Key(d.PublicKey),
		}
		for _, p := range d.Peers {
			kp := kernel.Peer{PublicKey: model.Key(p.PublicKey), Keepalive: p.PersistentKeepaliveInterval}
			for _, a := range p.AllowedIPs {
				if pfx, err := netip.ParsePrefix(a.String()); err == nil {
					kp.Allowed = append(kp.Allowed, pfx)
				}
			}
			kp.Allowed = kernel.SortPrefixes(kp.Allowed)
			if p.Endpoint != nil {
				kp.Endpoint = p.Endpoint.AddrPort()
				kp.Endpoint = netip.AddrPortFrom(kp.Endpoint.Addr().Unmap(), kp.Endpoint.Port())
			}
			dev.Peers = append(dev.Peers, kp)
		}
		slices.SortFunc(dev.Peers, func(a, b kernel.Peer) int { return strings.Compare(string(a.PublicKey[:]), string(b.PublicKey[:])) })
		out = append(out, dev)
	}
	return out, nil
}

// reap deletes this agent's devices from a namespace only a process holds,
// so their sockets stop holding listen ports and keepaliving.
func (k *Kernel) reap(ref, aliasPrefix string) error {
	fd, err := k.openRef(ref)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer fd.Close()
	nl, err := netlink.NewHandleAt(fd)
	if err != nil {
		return err
	}
	defer nl.Close()
	links, err := nl.LinkList()
	if err != nil {
		return err
	}
	for _, l := range links {
		if l.Type() == "wireguard" && strings.HasPrefix(l.Attrs().Alias, aliasPrefix) {
			if err := nl.LinkDel(l); err != nil && !errors.Is(err, unix.ENODEV) {
				return fmt.Errorf("reap %s: %w", l.Attrs().Name, err)
			}
		}
	}
	return nil
}

// CheckDestroy confirms the kernel can destroy sockets (CONFIG_INET_DIAG_
// DESTROY), without which a removed peer's sockets outlive it and a later
// write reaches whoever holds the address next.
func (k *Kernel) CheckDestroy() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(time.Second):
		return errors.New("socket check: no connection")
	}
	runtime.LockOSThread()
	d, err := openSockDiag()
	runtime.UnlockOSThread()
	if err != nil {
		return err
	}
	defer d.close()
	local := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	socks, err := d.list(unix.AF_INET, unix.IPPROTO_TCP)
	if err != nil {
		return err
	}
	for _, s := range socks {
		if s.local == local {
			if err := d.destroy(s); err != nil {
				if errors.Is(err, unix.EOPNOTSUPP) {
					return errors.New("the kernel lacks CONFIG_INET_DIAG_DESTROY")
				}
				return fmt.Errorf("socket check: %w", err)
			}
			return nil
		}
	}
	return errors.New("socket check: the test socket is missing from sock_diag")
}

var _ kernel.Kernel = (*Kernel)(nil)
