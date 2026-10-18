//sdn:deterministic

package sim

import (
	"fmt"
	"net/netip"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
	"sdn.sh/internal/prng"
	"sdn.sh/internal/regproto"
	relaycore "sdn.sh/internal/relay/core"
)

const relayProbePort = 7000

// relayDisk is what a relay's disk holds: a state file and the registration
// log written since.
type relayDisk struct {
	state relaycore.State
	log   []relaycore.Registration
}

// relayNode is one relay. Its table lives in memory; registrations reach
// its disk before they move an endpoint.
type relayNode struct {
	w          *World
	idx        int
	id         model.RelayID
	name       string
	local      netip.Addr
	advertised netip.Addr
	table      *relaycore.Table
	disk       relayDisk
	up         bool
	inc        int
	pollSeq    int
	// diskFree is when the disk finishes the writes queued so far; writes
	// complete in the order they were queued, as a group commit does.
	diskFree time.Time
	// waiting holds the packets the table keeps waiting, by token.
	waiting map[uint64]waitingPacket
}

type waitingPacket struct {
	p packet
}

func newRelay(w *World, idx int) *relayNode {
	r := &relayNode{
		w:          w,
		idx:        idx,
		name:       fmt.Sprintf("relay%d", idx),
		local:      netip.AddrFrom4([4]byte{10, 255, byte(idx), 1}),
		advertised: netip.AddrFrom4([4]byte{203, 0, 113, byte(10 + idx)}),
	}
	w.byPublic[r.advertised] = r
	return r
}

func (r *relayNode) node() Node { return Node(r.name) }

func (r *relayNode) address() api.RelayAddress {
	return api.RelayAddress{Local: r.local, Advertised: r.advertised}
}

func (r *relayNode) boot() { r.start() }

func (r *relayNode) start() {
	r.inc++
	r.up = true
	r.table = relaycore.New(relaycore.Config{RegistrationRate: 50, WaitFor: 2 * time.Second, WaitMax: 8, WaitTotal: 1024})
	r.waiting = map[uint64]waitingPacket{}
	r.table.Restore(r.disk.state, r.disk.log)
	r.w.logf("%s starts with %d ports", r.name, len(r.disk.state.Ports))
	r.poll()
	inc := r.inc
	var snapshot func()
	snapshot = func() {
		if r.inc != inc || !r.up {
			return
		}
		r.disk = relayDisk{state: r.table.Persisted()}
		r.release()
		r.w.loop.After(time.Second, snapshot)
	}
	r.w.loop.After(time.Second, snapshot)
}

func (r *relayNode) crash(d time.Duration) {
	if !r.up {
		return
	}
	r.w.summary.RelayCrashes++
	r.w.logf("%s crashes for %v", r.name, d)
	r.up = false
	r.inc++
	r.table = nil
	inc := r.inc
	r.w.loop.After(d, func() {
		if r.inc == inc && !r.up {
			r.start()
		}
	})
}

func (r *relayNode) restart() {
	if !r.up {
		r.start()
	}
}

func (r *relayNode) poll() {
	r.pollSeq++
	seq, inc := r.pollSeq, r.inc
	since := r.table.Generation()
	answered := false
	r.w.net.Send(r.node(), cpNodeName, func() {
		r.w.cp.handleRelayPoll(r.id, since, func(st api.RelayState) {
			r.w.net.Send(cpNodeName, r.node(), func() {
				if r.inc != inc || !r.up {
					return
				}
				r.table.Load(st)
				r.disk.state = r.table.Persisted()
				r.disk.log = nil
				if seq == r.pollSeq && !answered {
					answered = true
					r.poll()
				}
			})
		})
	})
	r.w.loop.After(pollTimeout+callTimeout, func() {
		if r.inc == inc && r.up && seq == r.pollSeq && !answered {
			answered = true
			r.poll()
		}
	})
}

// persist writes a verified registration to disk, then commits it. A crash
// in between loses it whole.
func (r *relayNode) persist(reg relaycore.Registration, raw *[regproto.Size]byte) {
	inc := r.inc
	done := r.w.now().Add(r.w.faults.Duration(100*time.Microsecond, 3*time.Millisecond))
	if done.Before(r.diskFree) {
		done = r.diskFree
	}
	r.diskFree = done
	r.w.loop.At(done, func() {
		if r.inc != inc || !r.up {
			return
		}
		r.disk.log = append(r.disk.log, reg)
		committed := r.table.Commit(reg)
		defer r.release()
		if r.w.attacker != nil && reg.Endpoint.Addr() == r.w.attacker.addr {
			r.w.fail("%s registered the attacker at %v for %v", r.name, reg.Endpoint, reg.Local)
		}
		if committed && raw != nil && r.w.attacker != nil {
			// An attacker on a shared segment captures what it can see; it
			// replays only after the relay has the original, since one that
			// races the original on its path can already drop traffic.
			r.w.attacker.saw(netip.AddrPortFrom(r.advertised, reg.Local.Port()), *raw)
		}
	})
}

// receive takes an underlay packet addressed to the relay.
func (r *relayNode) receive(src, dst netip.AddrPort, p packet) {
	if !r.up {
		return
	}
	if dst.Port() == relayProbePort {
		if p.isProbe {
			r.w.underlay(dst, src, p)
		}
		return
	}
	local := netip.AddrPortFrom(r.local, dst.Port())
	// The relay binds a socket per port its table holds; a datagram to any
	// other port finds none, and the kernel drops it.
	if _, ok := r.table.Dir(local); !ok {
		return
	}
	var b []byte
	switch {
	case p.reg != nil:
		b = p.reg[:]
	case p.wg != nil:
		b = wireguardBytes()
	default:
		b = p.raw
	}
	d := r.table.Packet(r.w.now(), local, src, b)
	if p.wg != nil {
		r.w.dbg("flow %d: %s %v from %v: verdict %d %s", p.wg.flow, r.name, local, src, d.Verdict, d.Reason)
	}
	switch d.Verdict {
	case relaycore.Forward:
		if r.w.attacker != nil && d.To.Addr() == r.w.attacker.addr {
			r.w.fail("%s forwarded to the attacker at %v", r.name, d.To)
		}
		r.w.underlay(netip.AddrPortFrom(r.advertised, d.From.Port()), d.To, p)
	case relaycore.Wait:
		r.waiting[d.Token] = waitingPacket{p: p}
	case relaycore.Register:
		var raw *[regproto.Size]byte
		if src.Addr() != r.attackerAddr() {
			raw = p.reg
		}
		r.persist(d.Registration, raw)
	}
}

// release sends what the table lets through and forgets expired waits.
func (r *relayNode) release() {
	for _, rel := range r.table.Release(r.w.now()) {
		wp, ok := r.waiting[rel.Token]
		delete(r.waiting, rel.Token)
		if !ok || rel.Drop {
			continue
		}
		if r.w.attacker != nil && rel.To.Addr() == r.w.attacker.addr {
			r.w.fail("%s released a waiting packet to the attacker at %v", r.name, rel.To)
		}
		r.w.underlay(netip.AddrPortFrom(r.advertised, rel.From.Port()), rel.To, wp.p)
	}
}

func (r *relayNode) attackerAddr() netip.Addr {
	if r.w.attacker == nil {
		return netip.Addr{}
	}
	return r.w.attacker.addr
}

// wireguardBytes stands in for a WireGuard transport message: type 4 and
// three zero bytes.
func wireguardBytes() []byte { return []byte{4, 0, 0, 0, 0, 0, 0, 0} }

// attacker sends packets to relay ports it has seen, and replays every
// registration it has seen delivered, from its own address.
type attacker struct {
	w    *World
	addr netip.Addr
	rng  *prng.Rand
	seen []netip.AddrPort
	regs []captured
}

type captured struct {
	to  netip.AddrPort
	reg [regproto.Size]byte
}

func newAttacker(w *World) *attacker {
	a := &attacker{w: w, addr: netip.MustParseAddr("192.0.2.66"), rng: prng.Stream(w.seed, "attacker")}
	w.byPublic[a.addr] = a
	w.every(150*time.Millisecond, a.act)
	return a
}

// saw records a registration a relay accepted, which an off-path attacker
// on a shared segment could capture.
func (a *attacker) saw(to netip.AddrPort, reg [regproto.Size]byte) {
	a.seen = append(a.seen, to)
	a.regs = append(a.regs, captured{to, reg})
	if len(a.regs) > 64 {
		a.regs = a.regs[1:]
	}
	if len(a.seen) > 64 {
		a.seen = a.seen[1:]
	}
}

func (a *attacker) act() {
	if len(a.seen) == 0 {
		return
	}
	from := netip.AddrPortFrom(a.addr, uint16(30000+a.rng.Below(1000)))
	switch a.rng.Below(3) {
	case 0:
		to := a.seen[a.rng.Index(len(a.seen))]
		a.w.underlay(from, to, packet{wg: &wgPacket{}})
	case 1:
		c := a.regs[a.rng.Index(len(a.regs))]
		reg := c.reg
		a.w.underlay(from, c.to, packet{reg: &reg})
	case 2:
		to := a.seen[a.rng.Index(len(a.seen))]
		forged := regproto.Encode(model.Secret{byte(a.rng.Uint64())}, to, uint64(a.w.now().UnixMilli())+1000)
		a.w.underlay(from, to, packet{reg: &forged})
	}
	a.w.summary.AttackerSent++
}

func (a *attacker) receive(src, dst netip.AddrPort, p packet) {
	if p.wg != nil {
		a.w.fail("the attacker received a WireGuard packet from %v", src)
	}
}
