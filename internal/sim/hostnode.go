//sdn:deterministic

package sim

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	agentcore "sdn.sh/internal/agent/core"
	"sdn.sh/internal/api"
	"sdn.sh/internal/kernel"
	"sdn.sh/internal/kernel/kmodel"
	"sdn.sh/internal/model"
	"sdn.sh/internal/prng"
)

// callTimeout is how long an agent waits on the control plane for a call.
const callTimeout = 2 * time.Second

// natIdle is how long a NAT mapping outlives its last outbound packet.
const natIdle = 8 * time.Second

// probePort is the host port agents probe relays from.
const probePort = 39999

func agentConfig(host model.HostID) agentcore.Config {
	c := agentcore.DefaultConfig(host)
	c.PortLo, c.PortHi = 40000, 40047
	c.DrainGrace = simConfig().DrainGrace
	c.Keepalive = 5 * time.Second
	c.AttachTimeout = 3 * time.Second
	c.RetryMin, c.RetryMax = 20*time.Millisecond, time.Second
	c.RegisterEvery = 5 * time.Second
	c.ResyncEvery = 10 * time.Second
	return c
}

type mapping struct {
	public   uint16
	lastSent time.Time
}

// hostNode is one host: a kernel, an agent that crashes and restarts, a
// journal that survives both, and a NAT in front of it.
type hostNode struct {
	w       *World
	idx     int
	id      model.HostID
	name    string
	kernel  *kmodel.Kernel
	journal map[model.InterfaceID]agentcore.JournalEntry
	cfg     agentcore.Config
	core    *agentcore.Core
	up      bool
	inc     int
	pollSeq int

	public  netip.Addr
	nat     map[uint16]*mapping
	natRev  map[uint16]uint16
	natNext uint16

	requests map[agentcore.RequestID]func(api.LocalInterface, error)
	nextReq  agentcore.RequestID
	probes   map[uint64]model.RelayID
	tickAt   time.Time
	tickSeq  int
	opFail   *prng.Rand
	// unnamed holds the namespaces an operator deleted the names of.
	unnamed map[string]bool
}

func newHost(w *World, idx int) *hostNode {
	h := &hostNode{
		w:        w,
		idx:      idx,
		name:     fmt.Sprintf("host%d", idx),
		kernel:   kmodel.New(),
		journal:  map[model.InterfaceID]agentcore.JournalEntry{},
		public:   netip.AddrFrom4([4]byte{198, 18, byte(idx), 1}),
		nat:      map[uint16]*mapping{},
		natRev:   map[uint16]uint16{},
		natNext:  20000,
		requests: map[agentcore.RequestID]func(api.LocalInterface, error){},
		probes:   map[uint64]model.RelayID{},
		opFail:   prng.Stream(w.seed, fmt.Sprintf("opfail-%d", idx)),
		unnamed:  map[string]bool{},
	}
	r := prng.Stream(w.seed, fmt.Sprintf("foreign-%d", idx))
	for range w.opts.ForeignPorts {
		h.kernel.Foreign[uint16(40000+r.Below(48))] = true
	}
	h.kernel.Fail = func(op kernel.Op) error {
		if w.faultsOn && w.opts.OpFailPermille > 0 && h.opFail.Permille(w.opts.OpFailPermille) {
			return fmt.Errorf("injected failure of %s", op.Kind)
		}
		return nil
	}
	w.byPublic[h.public] = h
	return h
}

func (h *hostNode) node() Node { return Node(h.name) }

// boot starts the agent for the first time.
func (h *hostNode) boot() {
	h.cfg = agentConfig(h.id)
	h.start()
}

func (h *hostNode) start() {
	h.inc++
	h.up = true
	h.core = agentcore.New(h.cfg, prng.Stream(h.w.seed, fmt.Sprintf("agent-%d-%d", h.idx, h.inc)))
	snap, _ := h.kernel.Snapshot(h.cfg.Prefix, h.cfg.AliasPrefix())
	var entries []agentcore.JournalEntry
	for _, id := range sortedKeys(h.journal) {
		entries = append(entries, h.journal[id])
	}
	if h.w.debugNS != "" {
		h.core.Debug = func(line string) { h.w.logf("%s %s", h.name, line) }
	}
	h.core.Start(h.w.now(), entries, snap)
	h.w.logf("%s agent starts (incarnation %d, %d journaled, %d namespaces)", h.name, h.inc, len(entries), len(snap.Namespaces))
	inc := h.inc
	h.drive()
	if h.inc != inc {
		// The agent died carrying its first actions.
		return
	}
	h.poll()
	h.renew()
}

// crash kills the agent. The kernel, the journal and the workloads stay;
// the sockets the agent held close.
func (h *hostNode) crash() {
	if !h.up {
		return
	}
	h.w.summary.AgentCrashes++
	h.w.logf("%s agent crashes", h.name)
	h.up = false
	h.kernel.AgentExit()
	h.inc++
	h.core = nil
	for _, id := range slices.Sorted(maps.Keys(h.requests)) {
		cb := h.requests[id]
		delete(h.requests, id)
		h.w.loop.After(0, func() { cb(api.LocalInterface{}, errDown) })
	}
	inc := h.inc
	d := time.Duration(0)
	if h.w.faultsOn {
		d = h.w.faults.Duration(50*time.Millisecond, 2*time.Second)
	}
	h.w.loop.After(d, func() {
		if h.inc == inc && !h.up {
			h.start()
		}
	})
}

func (h *hostNode) restart() {
	if !h.up {
		h.start()
	}
}

// reboot loses the kernel and every workload, keeping the journal on disk.
func (h *hostNode) reboot() {
	h.w.summary.Reboots++
	h.w.logf("%s reboots", h.name)
	h.w.orch.hostLost(h)
	h.kernel.Reboot()
	h.nat = map[uint16]*mapping{}
	h.natRev = map[uint16]uint16{}
	if h.up {
		h.crash()
	}
}

// rebind gives every NAT mapping a new public port, as a NAT that reassigns
// does. The host itself sees nothing change.
func (h *hostNode) rebind() {
	h.w.summary.Rebinds++
	h.w.logf("%s NAT rebinds", h.name)
	h.nat = map[uint16]*mapping{}
	h.natRev = map[uint16]uint16{}
}

// drive carries out every action the core has queued.
func (h *hostNode) drive() {
	if !h.up {
		return
	}
	inc := h.inc
	for _, a := range h.core.Actions(h.w.now()) {
		if h.inc != inc {
			// The agent crashed carrying an earlier action; the rest die
			// with it.
			return
		}
		h.carry(a)
	}
	if h.inc == inc {
		h.scheduleTick()
	}
}

func (h *hostNode) scheduleTick() {
	next := h.core.NextWake(h.w.now())
	if !h.tickAt.IsZero() && !h.tickAt.After(next) && h.tickAt.After(h.w.now()) {
		return
	}
	h.tickAt = next
	h.tickSeq++
	seq, inc := h.tickSeq, h.inc
	h.w.loop.At(next, func() {
		if h.tickSeq != seq || h.inc != inc || !h.up {
			return
		}
		h.tickAt = time.Time{}
		h.core.Tick(h.w.now())
		h.drive()
	})
}

// later runs fn on the agent at once, unless the agent restarted meanwhile.
func (h *hostNode) later(d time.Duration, fn func()) {
	inc := h.inc
	h.w.loop.After(d, func() {
		if h.inc == inc && h.up {
			fn()
			h.drive()
		}
	})
}

func (h *hostNode) carry(a agentcore.Action) {
	now := h.w.now
	switch a := a.(type) {
	case agentcore.RunBatch:
		h.w.checkColocated(h, a)
		if h.w.debugNS != "" {
			for _, op := range a.Ops {
				for _, p := range op.Peers {
					h.w.logf("  %s batch %d %s %s peer %s remove=%v allowed=%v endpoint=%v", h.name, a.ID, a.Namespace, op.Kind, h.w.byKey[p.PublicKey], p.Remove, p.Allowed, p.Endpoint)
				}
			}
		}
		h.runBatch(a, 0, h.inc)
	case agentcore.CallAttach:
		h.callAttach(a.Request)
	case agentcore.CallRelease:
		h.callRelease(a.Interfaces)
	case agentcore.WriteJournal:
		h.w.checkJournal(h, a.Entry)
		h.journal[a.Entry.Interface] = a.Entry
	case agentcore.DeleteJournal:
		delete(h.journal, a.Interface)
	case agentcore.Reply:
		if cb, ok := h.requests[a.Request]; ok {
			delete(h.requests, a.Request)
			h.w.loop.After(0, func() { cb(a.Interface, a.Err) })
		}
	case agentcore.SendRegistration:
		payload := a.Payload
		h.sendUnderlay(a.From, a.To, packet{reg: &payload})
	case agentcore.SendProbe:
		h.probes[a.Nonce] = a.Relay
		nonce := a.Nonce
		h.sendUnderlay(probePort, a.To, packet{probe: nonce, isProbe: true})
	case agentcore.Observe:
		name := a.Namespace
		h.later(0, func() {
			ns, err := h.kernel.Namespace(name, h.cfg.AliasPrefix())
			ns.Name = name
			h.core.Observed(now(), ns, err)
		})
	case agentcore.Scan:
		h.later(0, func() {
			snap, err := h.kernel.Snapshot(h.cfg.Prefix, h.cfg.AliasPrefix())
			h.core.Scanned(now(), snap, err)
		})
	}
}

// runBatch runs a batch's operations one at a time, each taking time, with a
// chance of the agent dying between any two.
func (h *hostNode) runBatch(b agentcore.RunBatch, i, inc int) {
	if h.inc != inc || !h.up {
		return
	}
	if i == len(b.Ops) {
		h.core.BatchDone(h.w.now(), b.Namespace, b.ID, i, nil)
		h.drive()
		return
	}
	if h.w.faultsOn && h.w.opts.AgentCrashPermille > 0 && h.w.faults.Permille(h.w.opts.AgentCrashPermille) {
		h.crash()
		return
	}
	d := h.w.faults.Duration(10*time.Microsecond, h.w.opts.OpDelayMax)
	h.w.loop.After(d, func() {
		if h.inc != inc || !h.up {
			return
		}
		op := b.Ops[i]
		_, err := h.kernel.Run(op)
		h.w.logf("%s %s: %v", h.name, op, err)
		h.w.checkMoves(h)
		h.w.checkTables(h, op.Namespace)
		h.w.checkFlushed(h)
		if err != nil {
			h.core.BatchDone(h.w.now(), b.Namespace, b.ID, i, err)
			h.drive()
			return
		}
		h.runBatch(b, i+1, inc)
	})
}

func (h *hostNode) callAttach(req api.AttachRequest) {
	answered := false
	h.w.net.Send(h.node(), cpNodeName, func() {
		h.w.cp.handleAttach(h.id, req, func(resp *api.AttachResponse, err error) {
			h.w.net.Send(cpNodeName, h.node(), func() {
				if !answered {
					h.later(0, func() {
						answered = true
						h.core.AttachDone(h.w.now(), req.Interface, resp, err)
					})
				}
			})
		})
	})
	h.later(callTimeout, func() {
		if !answered {
			answered = true
			h.core.AttachDone(h.w.now(), req.Interface, nil, errDown)
		}
	})
}

func (h *hostNode) callRelease(ids []model.InterfaceID) {
	answered := false
	h.w.net.Send(h.node(), cpNodeName, func() {
		h.w.cp.handleRelease(h.id, ids, func(err error) {
			h.w.net.Send(cpNodeName, h.node(), func() {
				if !answered {
					h.later(0, func() {
						answered = true
						h.core.ReleaseDone(h.w.now(), ids, err)
					})
				}
			})
		})
	})
	h.later(callTimeout, func() {
		if !answered {
			answered = true
			h.core.ReleaseDone(h.w.now(), ids, errDown)
		}
	})
}

// poll long-polls the control plane for desired state, for as long as the
// agent runs.
func (h *hostNode) poll() {
	h.pollSeq++
	seq, inc := h.pollSeq, h.inc
	since := h.core.Generation()
	answered := false
	h.w.net.Send(h.node(), cpNodeName, func() {
		h.w.cp.handlePoll(h.id, since, func(u api.StateUpdate) {
			h.w.net.Send(cpNodeName, h.node(), func() {
				h.later(0, func() {
					if h.inc != inc {
						// The answer is for an agent that has since died.
						return
					}
					if h.w.debugNS != "" {
						var carried []string
						for _, n := range u.Networks {
							carried = append(carried, fmt.Sprintf("%s@%d", n.Network, n.Revision))
						}
						h.w.logf("%s poll answer since=%d gen=%d holds=%d carried=%v present=%v", h.name, since, u.Generation, h.core.Generation(), carried, u.Present)
					}
					if err := h.core.State(h.w.now(), u); err != nil {
						h.w.fail("%s: state update: %v", h.name, err)
					}
					if seq == h.pollSeq && !answered {
						answered = true
						h.poll()
					}
				})
			})
		})
	})
	h.later(pollTimeout+callTimeout, func() {
		if seq == h.pollSeq && !answered {
			answered = true
			h.poll()
		}
	})
}

// renew renews the agent's leases every third of a term.
func (h *hostNode) renew() {
	h.later(simConfig().LeaseTTL/3, func() {
		ids := h.core.Live()
		if len(ids) > 0 {
			h.w.net.Send(h.node(), cpNodeName, func() {
				h.w.cp.handleRenew(h.id, ids, func(api.RenewResponse, error) {})
			})
		}
		h.renew()
	})
}

// localAttach is the orchestrator calling the agent's local API.
func (h *hostNode) localAttach(req api.LocalAttach, cb func(api.LocalInterface, error)) bool {
	if !h.up {
		return false
	}
	h.nextReq++
	h.requests[h.nextReq] = cb
	h.core.Attach(h.w.now(), h.nextReq, req)
	h.drive()
	return true
}

func (h *hostNode) localDetach(id model.InterfaceID, cb func(api.LocalInterface, error)) bool {
	if !h.up {
		return false
	}
	h.nextReq++
	h.requests[h.nextReq] = cb
	h.core.Detach(h.w.now(), h.nextReq, id)
	h.drive()
	return true
}

// publicFor returns the NAT's public endpoint for a host port, opening a
// mapping or refreshing one.
func (h *hostNode) publicFor(port uint16) netip.AddrPort {
	m, ok := h.nat[port]
	if !ok || h.w.now().Sub(m.lastSent) > natIdle {
		if ok {
			delete(h.natRev, m.public)
		}
		h.natNext++
		if h.natNext < 20000 {
			h.natNext = 20000
		}
		m = &mapping{public: h.natNext}
		h.nat[port] = m
		h.natRev[m.public] = port
	}
	m.lastSent = h.w.now()
	return netip.AddrPortFrom(h.public, m.public)
}

func (h *hostNode) sendUnderlay(fromPort uint16, to netip.AddrPort, p packet) {
	h.w.underlay(h.publicFor(fromPort), to, p)
}

// receive takes an underlay packet addressed to the host's public address.
func (h *hostNode) receive(src, dst netip.AddrPort, p packet) {
	port, ok := h.natRev[dst.Port()]
	if !ok {
		if p.wg != nil {
			h.w.dbg("flow %d: %s NAT has no mapping for %v", p.wg.flow, h.name, dst)
		}
		return
	}
	if m := h.nat[port]; m == nil || h.w.now().Sub(m.lastSent) > natIdle {
		// The mapping expired: the NAT drops what arrives for it.
		if p.wg != nil {
			h.w.dbg("flow %d: %s NAT mapping for %v expired", p.wg.flow, h.name, dst)
		}
		return
	}
	h.receiveOnPort(port, src, p)
}

func (h *hostNode) receiveOnPort(port uint16, src netip.AddrPort, p packet) {
	if port == probePort && p.isProbe {
		if relay, ok := h.probes[p.probe]; ok && h.up {
			delete(h.probes, p.probe)
			h.core.ProbeReply(h.w.now(), relay, p.probe)
			h.drive()
		}
		return
	}
	if p.ack {
		if h.up {
			h.core.RegistrationAcked(h.w.now(), port, src)
			h.drive()
		}
		return
	}
	if p.wg == nil {
		return
	}
	dev, ok := h.kernel.PortOwner(port)
	if !ok {
		return
	}
	h.w.receiveWG(h, dev, src, p.wg)
}
