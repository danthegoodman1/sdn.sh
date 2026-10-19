//wirenet:deterministic

package sim

import (
	"net/netip"
	"time"

	"github.com/danthegoodman1/wirenet/internal/kernel"
	"github.com/danthegoodman1/wirenet/internal/kernel/kmodel"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/nft"
	"github.com/danthegoodman1/wirenet/internal/regproto"
)

// packet is one underlay datagram: a registration, a relay's
// acknowledgment of one, a probe, or WireGuard.
type packet struct {
	reg *[regproto.Size]byte
	// ack marks an acknowledgment, of the registration at counter.
	ack     bool
	counter uint64
	isProbe bool
	probe   uint64
	wg      *wgPacket
	raw     []byte
}

// wgPacket is a WireGuard packet as far as the model needs: who sealed it,
// for whom, and the inner packet. A receiver opens it only with the private
// key it was sealed for.
type wgPacket struct {
	from, to model.Key
	src, dst netip.Addr
	proto    model.Proto
	port     uint16
	flow     uint64
	reply    bool
	// data marks a packet of an established flow, which conntrack admits.
	data bool
}

// underlayNode is anything with an underlay address.
type underlayNode interface {
	receive(src, dst netip.AddrPort, p packet)
	node() Node
}

func (a *attacker) node() Node { return "attacker" }

// underlay sends a datagram across the internet between public addresses.
func (w *World) underlay(src, dst netip.AddrPort, p packet) {
	to, ok := w.byPublic[dst.Addr()]
	if !ok {
		return
	}
	if from, ok := w.byPublic[src.Addr()]; ok && w.net.Partitioned(from.node()) {
		return
	}
	if w.faultsOn && w.opts.LossPercent > 0 && w.under.Percent(w.opts.LossPercent) {
		return
	}
	if p.wg != nil {
		w.dbg("flow %d: underlay %v -> %v", p.wg.flow, src, dst)
	}
	w.loop.After(w.under.Duration(w.opts.UnderlayDelayMin, w.opts.UnderlayDelayMax), func() {
		if w.net.Partitioned(to.node()) {
			return
		}
		to.receive(src, dst, p)
	})
}

func loopbackAddr() netip.Addr { return netip.AddrFrom4([4]byte{127, 0, 0, 1}) }

// flowState is where a connection attempt stands.
type flowState int

const (
	pending flowState = iota
	established
	refused
	dropped
)

// flow is one connection a workload opens.
type flow struct {
	id     uint64
	client model.InterfaceID
	host   *hostNode
	ns     *kmodel.Netns
	dialed netip.Addr
	proto  model.Proto
	port   uint16
	state  flowState
	server model.InterfaceID
}

// serverFlow offsets the identifier a server's conntrack keeps for a flow.
const serverFlow = 1 << 62

// open starts a connection from an interface's namespace, as a workload
// dialing an address does: through the namespace's nftables table, then
// WireGuard.
func (w *World) open(x *ifIntent, dialed netip.Addr, proto model.Proto, port uint16) *flow {
	w.nextFlow++
	f := &flow{id: w.nextFlow, client: x.id, host: x.host, dialed: dialed, proto: proto, port: port}
	w.flows[f.id] = f
	h := x.host
	ns, ok := h.kernel.Named(x.ns)
	if !ok {
		f.state = dropped
		return f
	}
	f.ns = ns
	dev, ok := ns.Devices[h.cfg.Device]
	if !ok {
		f.state = dropped
		return f
	}
	remote := dialed
	if ns.Rules != nil {
		translated := false
		remote, translated = ns.Rules.TranslateOut(dialed, proto, port, w.work.Index(nft.Slots))
		if !translated && ns.Rules.Rejected(dialed) {
			f.state = refused
			return f
		}
	}
	if remote == x.addr6 || remote == x.addr4 {
		f.state = established
		return f
	}
	src := x.addr6
	if remote.Is4() {
		src = x.addr4
	}
	if !src.IsValid() {
		f.state = dropped
		return f
	}
	peer, ok := dev.Route(remote)
	if !ok || !w.sendWG(h, dev, &wgPacket{src: src, dst: remote, proto: proto, port: port, flow: f.id}) {
		f.state = dropped
		return f
	}
	ns.AddFlow(kmodel.Flow{ID: f.id, Remote: remote, Dialed: dialed, Peer: peer.PublicKey})
	w.loop.After(2*time.Second, func() {
		if f.state == pending {
			f.state = dropped
		}
	})
	return f
}

// sendData sends a packet on an established flow, which needs its
// conntrack entry on both sides.
func (w *World) sendData(f *flow) {
	if f.state != established || f.ns == nil {
		return
	}
	entry, ok := f.ns.Flows[f.id]
	if !ok {
		f.state = dropped
		return
	}
	x := w.orch.ifaces[f.client]
	dev, ok := f.ns.Devices[f.host.cfg.Device]
	if x == nil || !ok {
		f.state = dropped
		return
	}
	src := x.addr6
	if entry.Remote.Is4() {
		src = x.addr4
	}
	f.state = pending
	if !w.sendWG(f.host, dev, &wgPacket{src: src, dst: entry.Remote, proto: f.proto, port: f.port, flow: f.id, data: true}) {
		f.state = dropped
		return
	}
	w.loop.After(2*time.Second, func() {
		if f.state == pending {
			f.state = dropped
		}
	})
}

// sendWG routes an inner packet through a device: the peer whose allowed
// IPs hold the destination, to that peer's endpoint.
func (w *World) sendWG(h *hostNode, dev *kmodel.Device, p *wgPacket) bool {
	peer, ok := dev.Route(p.dst)
	if !ok || !peer.Endpoint.IsValid() || dev.Private.IsZero() {
		w.dbg("flow %d: %s has no route to %v (route=%v)", p.flow, h.name, p.dst, ok)
		return false
	}
	w.dbg("flow %d: %s sends %v->%v reply=%v via %v", p.flow, h.name, p.src, p.dst, p.reply, peer.Endpoint)
	p.from, p.to = dev.Private.Public(), peer.PublicKey
	if peer.Endpoint.Addr() == loopbackAddr() {
		src := netip.AddrPortFrom(loopbackAddr(), dev.Port)
		port := peer.Endpoint.Port()
		w.loop.After(10*time.Microsecond, func() { h.receiveOnPort(port, src, packet{wg: p}) })
		return true
	}
	h.sendUnderlay(dev.Port, peer.Endpoint, packet{wg: p})
	return true
}

// receiveWG is a device receiving a WireGuard packet: it opens only what was
// sealed for its key, from a peer it holds, with a source that peer's
// allowed IPs hold; then the namespace's input chain decides.
func (w *World) receiveWG(h *hostNode, dev *kmodel.Device, src netip.AddrPort, p *wgPacket) {
	if dev.Private.IsZero() || dev.Private.Public() != p.to {
		w.dbg("flow %d: %s drops: sealed for another key", p.flow, h.name)
		return
	}
	peer, ok := dev.Peers[p.from]
	if !ok || !holds(peer.Allowed, p.src) {
		w.dbg("flow %d: %s drops: unknown peer or source %v (peer=%v)", p.flow, h.name, p.src, ok)
		return
	}
	if peer.Endpoint != src {
		w.dbg("%s roams peer %s from %v to %v (flow %d)", h.name, w.byKey[p.from], peer.Endpoint, src, p.flow)
	}
	dev.Roam(p.from, src)
	ns := dev.Namespace()
	if p.reply {
		if f, ok := w.flows[p.flow]; ok && f.state == pending && f.ns == ns {
			f.state = established
		}
		return
	}
	if p.data {
		if _, ok := ns.Flows[p.flow+serverFlow]; !ok {
			return
		}
	} else if ns.Rules == nil || !ns.Rules.Admit(p.src, p.proto, p.port) {
		w.dbg("flow %d: %s drops: policy refuses %v %s/%d", p.flow, h.name, p.src, p.proto, p.port)
		return
	}
	w.checkDelivery(dev, p)
	ns.AddFlow(kmodel.Flow{ID: p.flow + serverFlow, Remote: p.src, Peer: p.from})
	if f, ok := w.flows[p.flow]; ok {
		if id, ok := kernel.AliasInterface(h.cfg.AliasPrefix(), dev.Alias); ok {
			f.server = id
		}
	}
	w.sendWG(h, dev, &wgPacket{src: p.dst, dst: p.src, proto: p.proto, port: p.port, flow: p.flow, reply: true})
}

func holds(allowed []netip.Prefix, a netip.Addr) bool {
	for _, p := range allowed {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// checkDelivery checks a packet a namespace accepted against the
// orchestrator's record: its sender's key and source address belong to one
// interface, in the receiver's network.
func (w *World) checkDelivery(dev *kmodel.Device, p *wgPacket) {
	sender, ok := w.byKey[p.from]
	if !ok {
		w.fail("a namespace accepted a packet from unknown key %s", p.from)
		return
	}
	s := w.orch.ifaces[sender]
	recvID, _ := kernel.AliasInterface(dev.Alias[:aliasHostLen(dev.Alias)], dev.Alias)
	r := w.orch.ifaces[recvID]
	if s == nil || r == nil {
		return
	}
	if s.network != r.network {
		w.fail("%s in %s accepted a packet from %s in %s", r.id, r.network, s.id, s.network)
	}
	if p.src != s.addr6 && p.src != s.addr4 {
		w.fail("%s accepted a packet from %s claiming source %v", r.id, s.id, p.src)
	}
}

// aliasHostLen returns the length of an alias's prefix up to and including
// the colon before the interface identifier.
func aliasHostLen(alias string) int {
	for i := len(alias) - 1; i >= 0; i-- {
		if alias[i] == ':' {
			return i + 1
		}
	}
	return 0
}
