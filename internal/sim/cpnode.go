//sdn:deterministic

package sim

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/compile"
	"sdn.sh/internal/cp"
	"sdn.sh/internal/model"
	"sdn.sh/internal/prng"
	"sdn.sh/internal/store"
	"sdn.sh/internal/store/mem"
)

const cpNodeName Node = "cp"

// pollTimeout is how long the control plane parks a long poll.
const pollTimeout = 10 * time.Second

// errDown is what a call to a node that is down gets, once its caller gives
// up waiting.
var errDown error = &api.Error{Code: api.CodeUnavailable, Message: "no answer"}

type hostPoll struct {
	since  uint64
	parked time.Time
	reply  func(api.StateUpdate)
}

type relayPoll struct {
	since  uint64
	parked time.Time
	reply  func(api.RelayState)
}

// addrHolder is who last held an IPv4 address and when they let it go.
type addrHolder struct {
	iface model.InterfaceID
	ended time.Time
}

// cpNode is the control plane over an in-memory store that survives its
// crashes, as a database would.
type cpNode struct {
	w     *World
	store *mem.Store
	plane *cp.Plane
	cache *cp.LRU
	up    bool
	inc   int
	polls map[model.HostID]hostPoll
	rpoll map[model.RelayID]relayPoll
	// snaps holds each network's interfaces at every revision, for the
	// oracle.
	snaps map[model.NetworkID]map[uint64][]store.Interface
	// ever6 and holder4 check allocation.
	ever6   map[model.NetworkID]map[netip.Addr]model.InterfaceID
	holder4 map[model.NetworkID]map[netip.Addr]addrHolder
	ports   map[model.RelayID]map[netip.AddrPort]portHolder
}

type portHolder struct {
	edge  [2]model.InterfaceID
	ended time.Time
}

// Clocks the simulator runs the control plane on, short so a run covers many
// lease terms and grace periods.
func simConfig() cp.Config {
	return cp.Config{
		LeaseTTL:       4 * time.Second,
		DrainGrace:     2 * time.Second,
		Quarantine4:    6 * time.Second,
		PortQuarantine: 8 * time.Second,
		Retention:      5 * time.Second,
		MTU:            1380,
	}
}

func newCP(w *World) *cpNode {
	c := &cpNode{
		w:       w,
		store:   mem.New(),
		plane:   &cp.Plane{Config: simConfig(), Rand: prng.Stream(w.seed, "cp")},
		up:      true,
		snaps:   map[model.NetworkID]map[uint64][]store.Interface{},
		ever6:   map[model.NetworkID]map[netip.Addr]model.InterfaceID{},
		holder4: map[model.NetworkID]map[netip.Addr]addrHolder{},
		ports:   map[model.RelayID]map[netip.AddrPort]portHolder{},
	}
	c.start()
	return c
}

func (c *cpNode) start() {
	c.up = true
	c.inc++
	c.cache = cp.NewLRU(256)
	c.polls = map[model.HostID]hostPoll{}
	c.rpoll = map[model.RelayID]relayPoll{}
	c.update(func(tx store.Tx) error { _, err := c.plane.Boot(tx, c.w.now()); return err })
	inc := c.inc
	var tick func()
	tick = func() {
		if !c.up || c.inc != inc {
			return
		}
		c.update(func(tx store.Tx) error { return c.plane.Heartbeat(tx, c.w.now()) })
		for {
			var n int
			if _, err := c.update(func(tx store.Tx) error {
				var err error
				n, err = c.plane.Sweep(tx, c.w.now())
				return err
			}); err != nil || n < cp.SweepBatch {
				break
			}
		}
		c.expirePolls()
		c.w.loop.After(500*time.Millisecond, tick)
	}
	c.w.loop.After(500*time.Millisecond, tick)
}

func (c *cpNode) crash(d time.Duration) {
	if !c.up {
		return
	}
	c.w.summary.CPCrashes++
	c.w.logf("cp crashes for %v", d)
	c.up = false
	c.inc++
	c.w.loop.After(d, c.restart)
}

func (c *cpNode) restart() {
	if c.up {
		return
	}
	c.w.logf("cp restarts")
	c.start()
}

// update runs a transaction, then records what the oracle and the
// allocation checks need and wakes the long polls it affects.
func (c *cpNode) update(fn func(store.Tx) error) (store.Change, error) {
	ch, err := c.store.Update(context.Background(), fn)
	if err != nil {
		return ch, err
	}
	for _, id := range ch.Networks {
		c.record(id)
	}
	if !ch.Empty() {
		c.checkPorts()
		c.wake()
	}
	return ch, nil
}

func (c *cpNode) view(fn func(store.ReadTx) error) error {
	return c.store.View(context.Background(), fn)
}

// record snapshots a network's interfaces at its revision and checks that
// addresses are unique among connected interfaces, that IPv6 addresses are
// never reused, and that IPv4 addresses wait out their quarantine.
func (c *cpNode) record(id model.NetworkID) {
	now := c.w.now()
	c.view(func(tx store.ReadTx) error {
		n, err := tx.Network(id)
		if err != nil {
			return nil
		}
		ifaces, _ := tx.Interfaces(id)
		svcs, _ := tx.Services(id)
		if c.snaps[id] == nil {
			c.snaps[id] = map[uint64][]store.Interface{}
			c.ever6[id] = map[netip.Addr]model.InterfaceID{}
			c.holder4[id] = map[netip.Addr]addrHolder{}
		}
		c.snaps[id][n.Revision] = ifaces
		held := map[netip.Addr]string{}
		for _, s := range svcs {
			held[s.Addr6] = string(s.ID)
			if s.Addr4.IsValid() {
				held[s.Addr4] = string(s.ID)
			}
		}
		for _, i := range ifaces {
			if prev, ok := c.ever6[id][i.Addr6]; ok && prev != i.ID {
				c.w.fail("IPv6 address %v reused: %s after %s", i.Addr6, i.ID, prev)
			}
			c.ever6[id][i.Addr6] = i.ID
			if !compile.Connected(i) {
				if i.Addr4.IsValid() {
					if h := c.holder4[id][i.Addr4]; h.iface == i.ID && h.ended.IsZero() {
						c.holder4[id][i.Addr4] = addrHolder{iface: i.ID, ended: i.Ended}
					}
				}
				continue
			}
			for _, a := range []netip.Addr{i.Addr6, i.Addr4} {
				if !a.IsValid() {
					continue
				}
				if other, ok := held[a]; ok {
					c.w.fail("address %v held by both %s and %s", a, other, i.ID)
				}
				held[a] = string(i.ID)
			}
			if i.Addr4.IsValid() {
				h, ok := c.holder4[id][i.Addr4]
				if ok && h.iface != i.ID {
					if h.ended.IsZero() || now.Sub(h.ended) < c.plane.Config.Quarantine4 {
						c.w.fail("IPv4 address %v reused by %s %v after %s let it go", i.Addr4, i.ID, now.Sub(h.ended), h.iface)
					}
				}
				if !ok || h.iface != i.ID {
					c.holder4[id][i.Addr4] = addrHolder{iface: i.ID}
				}
			}
		}
		return nil
	})
}

// checkPorts checks that no relay port serves two edges, and that a port
// waits out its quarantine before serving another.
func (c *cpNode) checkPorts() {
	now := c.w.now()
	c.view(func(tx store.ReadTx) error {
		relays, _ := tx.Relays()
		for _, r := range relays {
			if c.ports[r.ID] == nil {
				c.ports[r.ID] = map[netip.AddrPort]portHolder{}
			}
			edges, _ := tx.RelayEdges(r.ID)
			live := map[netip.AddrPort][2]model.InterfaceID{}
			for _, e := range edges {
				pair := [2]model.InterfaceID{e.A, e.B}
				for _, p := range e.Ports {
					if p.Relay != r.ID {
						continue
					}
					for _, port := range []uint16{p.AB, p.BA} {
						ap := netip.AddrPortFrom(p.Addr, port)
						if other, ok := live[ap]; ok {
							c.w.fail("relay port %v serves edges %v and %v", ap, other, pair)
						}
						live[ap] = pair
						h, seen := c.ports[r.ID][ap]
						if seen && h.edge != pair {
							if h.ended.IsZero() || now.Sub(h.ended) < c.plane.Config.PortQuarantine {
								c.w.fail("relay port %v moved from %v to %v after %v", ap, h.edge, pair, now.Sub(h.ended))
							}
						}
						c.ports[r.ID][ap] = portHolder{edge: pair}
					}
				}
			}
			for _, ap := range sortedAddrPorts(c.ports[r.ID]) {
				h := c.ports[r.ID][ap]
				if _, ok := live[ap]; !ok && h.ended.IsZero() {
					h.ended = now
					c.ports[r.ID][ap] = h
				}
			}
		}
		return nil
	})
}

// wake answers every parked poll whose host or relay has news.
func (c *cpNode) wake() {
	for _, id := range sortedKeys(c.polls) {
		p := c.polls[id]
		var u api.StateUpdate
		var err error
		c.view(func(tx store.ReadTx) error {
			gen, _, e := cp.HostGeneration(tx, id)
			if e != nil || gen <= p.since {
				err = errors.New("nothing new")
				return nil
			}
			u, err = cp.HostState(tx, c.cache, id, p.since)
			return nil
		})
		if err == nil {
			delete(c.polls, id)
			p.reply(u)
		}
	}
	for _, id := range sortedKeys(c.rpoll) {
		p := c.rpoll[id]
		var st api.RelayState
		var ok bool
		c.view(func(tx store.ReadTx) error {
			r, err := tx.Relay(id)
			if err != nil || r.Revision <= p.since {
				return nil
			}
			st, err = cp.RelayState(tx, id)
			ok = err == nil
			return nil
		})
		if ok {
			delete(c.rpoll, id)
			p.reply(st)
		}
	}
}

// expirePolls answers polls parked past the timeout with what is current.
func (c *cpNode) expirePolls() {
	now := c.w.now()
	for _, id := range sortedKeys(c.polls) {
		p := c.polls[id]
		if now.Sub(p.parked) < pollTimeout {
			continue
		}
		delete(c.polls, id)
		var u api.StateUpdate
		if c.view(func(tx store.ReadTx) error {
			var err error
			u, err = cp.HostState(tx, c.cache, id, p.since)
			return err
		}) == nil {
			p.reply(u)
		}
	}
	for _, id := range sortedKeys(c.rpoll) {
		p := c.rpoll[id]
		if now.Sub(p.parked) < pollTimeout {
			continue
		}
		delete(c.rpoll, id)
		var st api.RelayState
		if c.view(func(tx store.ReadTx) error {
			var err error
			st, err = cp.RelayState(tx, id)
			return err
		}) == nil {
			p.reply(st)
		}
	}
}

// Requests from agents and relays. Each arrives over the network; a control
// plane that is down never answers, and the caller times out.

func (c *cpNode) handleAttach(host model.HostID, req api.AttachRequest, reply func(*api.AttachResponse, error)) {
	if !c.up {
		return
	}
	var iface store.Interface
	_, err := c.update(func(tx store.Tx) error {
		var err error
		iface, err = c.plane.Attach(tx, c.w.now(), host, req)
		return err
	})
	if err != nil {
		reply(nil, err)
		return
	}
	var ns api.NetworkState
	err = c.view(func(tx store.ReadTx) error {
		var err error
		ns, err = cp.NetworkStateFor(tx, c.cache, iface.Network, host)
		return err
	})
	reply(&api.AttachResponse{Interface: iface.ID, State: ns}, err)
}

func (c *cpNode) handleRelease(host model.HostID, ids []model.InterfaceID, reply func(error)) {
	if !c.up {
		return
	}
	_, err := c.update(func(tx store.Tx) error { return c.plane.Release(tx, c.w.now(), host, ids) })
	reply(err)
}

func (c *cpNode) handleRenew(host model.HostID, ids []model.InterfaceID, reply func(api.RenewResponse, error)) {
	if !c.up {
		return
	}
	var exp map[model.InterfaceID]time.Time
	_, err := c.update(func(tx store.Tx) error {
		var err error
		exp, err = c.plane.Renew(tx, c.w.now(), host, ids)
		return err
	})
	reply(api.RenewResponse{Expires: exp}, err)
}

func (c *cpNode) handlePoll(host model.HostID, since uint64, reply func(api.StateUpdate)) {
	if !c.up {
		return
	}
	var gen uint64
	c.view(func(tx store.ReadTx) error {
		gen, _, _ = cp.HostGeneration(tx, host)
		return nil
	})
	if gen > since {
		var u api.StateUpdate
		if c.view(func(tx store.ReadTx) error {
			var err error
			u, err = cp.HostState(tx, c.cache, host, since)
			return err
		}) == nil {
			reply(u)
		}
		return
	}
	c.polls[host] = hostPoll{since: since, parked: c.w.now(), reply: reply}
}

func (c *cpNode) handleRelayPoll(relay model.RelayID, since uint64, reply func(api.RelayState)) {
	if !c.up {
		return
	}
	var st api.RelayState
	var rev uint64
	if c.view(func(tx store.ReadTx) error {
		r, err := tx.Relay(relay)
		if err != nil {
			return err
		}
		rev = r.Revision
		st, err = cp.RelayState(tx, relay)
		return err
	}) != nil {
		return
	}
	if rev > since || since == 0 {
		reply(st)
		return
	}
	c.rpoll[relay] = relayPoll{since: since, parked: c.w.now(), reply: reply}
}

func sortedAddrPorts[V any](m map[netip.AddrPort]V) []netip.AddrPort {
	return slices.SortedFunc(maps.Keys(m), netip.AddrPort.Compare)
}
