//wirenet:deterministic

package core

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/dns"
	"github.com/danthegoodman1/wirenet/internal/kernel"
	"github.com/danthegoodman1/wirenet/internal/model"
)

// Start adopts what the journal and the kernel hold. Journaled interfaces
// whose devices survive are adopted as they stand; anything else the agent
// made — a namespace with its prefix and no entry, or a device of its own in
// a namespace only a process holds — is torn down.
func (c *Core) Start(now time.Time, journal []JournalEntry, snap kernel.Snapshot) {
	byName := map[string]kernel.Namespace{}
	for _, ns := range snap.Namespaces {
		if ns.Name != "" {
			byName[ns.Name] = ns
			continue
		}
		st := newNS("", "")
		st.ref = ns.Ref
		c.ns["ref:"+ns.Ref] = st
		for _, d := range ns.Devices {
			if id, ok := kernel.AliasInterface(c.cfg.AliasPrefix(), d.Alias); ok {
				c.releaseLater(id)
			}
		}
	}
	slices.SortFunc(journal, func(a, b JournalEntry) int { return strings.Compare(string(a.Interface), string(b.Interface)) })
	for _, e := range journal {
		i := &iface{
			id: e.Interface, name: e.Name, phase: ready, ns: e.Namespace, port: e.ListenPort, pub: e.PublicKey,
			kind: e.Kind, network: e.Network, service: e.Service, member: e.Member, attachSent: true,
		}
		c.ifaces[i.id] = i
		st := newNS(e.Namespace, i.id)
		c.ns[e.Namespace] = st
		observed, ok := byName[e.Namespace]
		delete(byName, e.Namespace)
		st.exists = ok
		st.egress = observed.Egress.Clone()
		st.egressClear = ok && observed.Egress == nil
		dev, hasDev := findDevice(observed, c.cfg.Device)
		if e.Detaching || !hasDev || !dev.HasKey || dev.PublicKey != e.PublicKey {
			// A journaled interface whose device is gone lost its key with
			// it; tear down what is left and release it.
			i.phase = detaching
			st.device = hasDev
			continue
		}
		st.device = true
		st.adopt(dev)
	}
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		id := model.InterfaceID(model.InterfacePrefix + strings.TrimPrefix(name, c.cfg.Prefix))
		i := &iface{id: id, phase: orphan, ns: name, attachSent: true}
		c.ifaces[id] = i
		st := newNS(name, id)
		st.exists = true
		st.egress = byName[name].Egress.Clone()
		st.egressClear = st.egress == nil
		_, st.device = findDevice(byName[name], c.cfg.Device)
		c.ns[name] = st
	}
	c.lastRegister, c.lastProbe, c.lastResync = now, now, now
}

// scan asks for a Scan, or for another once the one in flight answers.
func (c *Core) scan() {
	if c.scanning {
		c.rescan = true
		return
	}
	c.scanning = true
	c.emit(Scan{})
}

// Scanned takes the snapshot a Scan asked for. A namespace only a process
// holds that carries a device of the agent's is reaped, as at Start. A scan
// that failed waits for the next resync.
func (c *Core) Scanned(now time.Time, snap kernel.Snapshot, err error) {
	c.scanning = false
	if c.rescan {
		c.rescan = false
		c.scan()
	}
	if err != nil {
		return
	}
	for _, ns := range snap.Namespaces {
		if ns.Name != "" {
			continue
		}
		if _, ok := c.ns["ref:"+ns.Ref]; ok {
			continue
		}
		st := newNS("", "")
		st.ref = ns.Ref
		c.ns["ref:"+ns.Ref] = st
		for _, d := range ns.Devices {
			id, ok := kernel.AliasInterface(c.cfg.AliasPrefix(), d.Alias)
			if !ok {
				continue
			}
			i, held := c.ifaces[id]
			if !held {
				c.releaseLater(id)
				continue
			}
			// An interface the agent holds whose device sits where only a
			// process holds it lost its namespace's name, or its device
			// left that namespace, and the reap takes the device:
			// co-located peers must stop counting on it at once. The name
			// may still stand, and the detach deletes it if it does.
			if named, ok := c.ns[i.ns]; ok {
				c.lost(named)
			}
		}
	}
}

// lost takes a namespace's device as gone behind the agent's back, with
// the namespace or into one only a process holds: the key is gone either
// way, and so is the interface, which detaches. Every namespace holding it
// as a peer replans, so a co-located client takes its slots away at once.
// It reports whether the interface was live.
func (c *Core) lost(st *nsState) bool {
	st.device, st.egress = false, nil
	st.peers = map[model.Key]kernel.Peer{}
	st.link, st.rules = nil, nil
	st.dirty = true
	i, ok := c.ifaces[st.iface]
	if !ok || i.phase != ready && i.phase != configuring {
		return false
	}
	i.phase = detaching
	c.emit(WriteJournal{Entry: c.entry(i)})
	for _, name := range slices.Sorted(maps.Keys(c.ns)) {
		if _, peer := c.ns[name].peers[i.pub]; peer {
			c.ns[name].dirty = true
		}
	}
	return true
}

func findDevice(ns kernel.Namespace, name string) (kernel.Device, bool) {
	for _, d := range ns.Devices {
		if d.Name == name {
			return d, true
		}
	}
	return kernel.Device{}, false
}

// adopt takes an observed device's peers as installed. Endpoints count as
// chosen only once a reconcile sees them acceptable for the desired path.
func (st *nsState) adopt(d kernel.Device) {
	st.peers = map[model.Key]kernel.Peer{}
	for _, p := range d.Peers {
		st.peers[p.PublicKey] = p
	}
	st.chosen = map[model.Key]netip.AddrPort{}
	st.link, st.rules = nil, nil
	// A crash between removing a peer and flushing its flows leaves them
	// behind, so the first batch sweeps before any peer may claim their
	// addresses.
	st.sweep = true
}

// releaseLater asks the control plane to release an interface no journal
// entry accounts for, as a crash between issuing and journaling leaves.
func (c *Core) releaseLater(id model.InterfaceID) {
	c.emit(CallRelease{Interfaces: []model.InterfaceID{id}})
}

// ErrAttachFailed wraps why an attach gave up.
var ErrAttachFailed = errors.New("attach failed")

// ErrNoInterface answers a detach of an interface the agent does not hold,
// which a caller retrying a detach takes as done.
var ErrNoInterface = errors.New("no such interface")

// Attach starts building an interface for a workload. The answer comes as a
// Reply once the namespace is ready to hand over, or the attach fails.
func (c *Core) Attach(now time.Time, req RequestID, a api.LocalAttach) {
	reply := func(err error) {
		c.emit(Reply{Request: req, Err: fmt.Errorf("%w: %w", ErrAttachFailed, err)})
	}
	if a.Name == "" || a.Network == "" || a.Service == "" {
		reply(errors.New("attach needs a workload name, a network and a service"))
		return
	}
	for _, id := range slices.Sorted(maps.Keys(c.ifaces)) {
		i := c.ifaces[id]
		if i.name != a.Name || i.phase.tearingDown() {
			continue
		}
		if i.netRef != "" && (i.netRef != a.Network || i.svcRef != a.Service) {
			reply(fmt.Errorf("workload %q is attached to another service", a.Name))
			return
		}
		// The journal keeps the member, so an adopted interface is judged
		// too.
		if i.member != a.Member {
			reply(fmt.Errorf("workload %q is attached as another member", a.Name))
			return
		}
		if i.phase == ready {
			c.emit(Reply{Request: req, Interface: c.describe(i)})
		} else {
			i.waiting = append(i.waiting, req)
		}
		return
	}
	idStr, err := model.NewID(model.InterfacePrefix, c.rand)
	if err != nil {
		reply(err)
		return
	}
	priv, err := model.NewPrivateKey(c.rand)
	if err != nil {
		reply(err)
		return
	}
	port, ok := c.freePort()
	if !ok {
		reply(errors.New("no free listen port"))
		return
	}
	id := model.InterfaceID(idStr)
	kind := a.Kind
	if kind == "" {
		kind = api.Workload
	}
	i := &iface{
		id: id, name: a.Name, phase: creating, ns: c.cfg.Prefix + model.Short(idStr), port: port,
		priv: priv, pub: priv.Public(), netRef: a.Network, svcRef: a.Service, kind: kind,
		member: a.Member, replace: a.Replace,
		deadline: now.Add(c.cfg.AttachTimeout), waiting: []RequestID{req},
	}
	c.ifaces[id] = i
	c.ns[i.ns] = newNS(i.ns, id)
}

// freePort picks the lowest listen port no interface of this agent holds
// and no bind has failed on.
func (c *Core) freePort() (uint16, bool) {
	used := map[uint16]bool{}
	for _, id := range slices.Sorted(maps.Keys(c.ifaces)) {
		used[c.ifaces[id].port] = true
	}
	for p := uint32(c.cfg.PortLo); p <= uint32(c.cfg.PortHi); p++ {
		if !used[uint16(p)] && !c.badPort[uint16(p)] {
			return uint16(p), true
		}
	}
	return 0, false
}

// Detach tears an interface down at its workload's request. Detaching an
// interface already torn down answers at once, so a caller that lost an
// answer can retry.
func (c *Core) Detach(now time.Time, req RequestID, id model.InterfaceID) {
	i, ok := c.ifaces[id]
	if !ok {
		c.emit(Reply{Request: req, Err: fmt.Errorf("%w: %s", ErrNoInterface, id)})
		return
	}
	if i.phase.tearingDown() {
		if i.tornDown {
			c.emit(Reply{Request: req, Interface: c.describe(i)})
		} else {
			i.detachers = append(i.detachers, req)
		}
		return
	}
	i.detachers = append(i.detachers, req)
	if i.phase != ready {
		c.abort(i, errors.New("detached before it was ready"))
		return
	}
	i.phase = detaching
	c.emit(WriteJournal{Entry: c.entry(i)})
	c.ns[i.ns].dirty = true
	// Peers stop routing to the interface as soon as the control plane
	// knows, so it learns while the device is deleted rather than after:
	// deleting a device waits a grace period per peer it holds.
	c.release(i)
}

// release tells the control plane an interface is ending, unless it knows
// or is being told.
func (c *Core) release(i *iface) {
	if i.attachSent && !i.released && !i.releasing {
		i.releasing = true
		c.emit(CallRelease{Interfaces: []model.InterfaceID{i.id}})
	}
}

func (c *Core) entry(i *iface) JournalEntry {
	return JournalEntry{
		Interface: i.id, Name: i.name, Network: i.network, Service: i.service, Kind: i.kind, Member: i.member,
		Namespace: i.ns, ListenPort: i.port, PublicKey: i.pub, Detaching: i.phase == detaching,
	}
}

// abort gives up an attach and removes what it built.
func (c *Core) abort(i *iface, err error) {
	i.phase, i.err = aborting, err
	i.priv = model.Key{}
	c.ns[i.ns].dirty = true
}

// AttachDone takes the control plane's answer to an attach.
func (c *Core) AttachDone(now time.Time, id model.InterfaceID, resp *api.AttachResponse, err error) {
	i, ok := c.ifaces[id]
	if !ok || i.phase != registering {
		return
	}
	if err != nil {
		var ae *api.Error
		if errors.As(err, &ae) && ae.Code != api.CodeUnavailable || !now.Before(i.deadline) {
			c.abort(i, err)
			return
		}
		// The control plane may be briefly away; the same identifier makes
		// a retry the same attach.
		c.emit(CallAttach{Request: c.attachRequest(i)})
		return
	}
	n := resp.State
	x, ok := n.Interface(id)
	if !ok {
		c.abort(i, errors.New("the control plane's answer lacks the interface"))
		return
	}
	i.network, i.service = n.Network, x.Service
	i.addr6, i.addr4 = x.Addr6, x.Addr4
	c.desired.Merge(n)
	i.phase, i.handoverBy = configuring, now.Add(c.cfg.AckWait)
	c.ns[i.ns].dirty = true
	// The answer carries the network at a newer revision, which other
	// namespaces on the host reconcile too, such as a co-located backend
	// that now peers with this interface.
	c.refresh()
}

func (c *Core) attachRequest(i *iface) api.AttachRequest {
	return api.AttachRequest{
		Interface: i.id, Network: i.netRef, Service: i.svcRef, Kind: i.kind,
		PublicKey: i.pub, ListenPort: i.port, Member: i.member, Replace: i.replace,
	}
}

// ReleaseDone takes the control plane's answer to a release.
func (c *Core) ReleaseDone(now time.Time, ids []model.InterfaceID, err error) {
	for _, id := range ids {
		i, ok := c.ifaces[id]
		if !ok {
			continue
		}
		i.releasing = false
		if err != nil {
			if c.nextRelease.IsZero() || c.nextRelease.Before(now) {
				c.nextRelease = now.Add(releaseRetry)
			}
			continue
		}
		i.released = true
		c.finish(i)
	}
}

// releaseRetry is how long a failed release waits before it is sent again.
const releaseRetry = time.Second

// retryReleases sends again every release the control plane has yet to
// take, in one call.
func (c *Core) retryReleases(now time.Time) {
	if c.nextRelease.IsZero() || now.Before(c.nextRelease) {
		return
	}
	c.nextRelease = time.Time{}
	var ids []model.InterfaceID
	for _, id := range slices.Sorted(maps.Keys(c.ifaces)) {
		i := c.ifaces[id]
		if (i.tornDown || i.phase == detaching) && i.attachSent && !i.released && !i.releasing {
			i.releasing = true
			ids = append(ids, id)
		}
	}
	if len(ids) > 0 {
		c.emit(CallRelease{Interfaces: ids})
	}
}

// finish forgets an interface once its kernel state is gone and the control
// plane knows.
func (c *Core) finish(i *iface) {
	if !i.tornDown || !i.released && i.attachSent {
		return
	}
	if i.phase == detaching {
		c.emit(DeleteJournal{Interface: i.id})
	}
	if st, ok := c.ns[i.ns]; ok {
		c.dropWaits(st)
	}
	delete(c.ifaces, i.id)
	delete(c.ns, i.ns)
}

// State merges a poll's answer and marks for reconciliation every namespace
// whose network changed.
func (c *Core) State(now time.Time, u api.StateUpdate) error {
	if err := c.desired.Apply(u); err != nil {
		return err
	}
	c.synced = true
	for _, nid := range c.desired.NetworkIDs() {
		for _, x := range c.desired.Networks[nid].Interfaces {
			if _, known := c.ifaces[x.ID]; !known && x.State == api.Live {
				// Issued to this host but never journaled: an attach that
				// crashed partway. Its kernel state is already gone.
				c.releaseLater(x.ID)
			}
		}
	}
	c.refresh()
	return nil
}

// refresh marks for reconciliation every namespace whose network desired
// state holds at another revision than the one it reconciled.
func (c *Core) refresh() {
	for _, name := range slices.Sorted(maps.Keys(c.ns)) {
		st := c.ns[name]
		i, ok := c.ifaces[st.iface]
		if !ok || i.phase != ready && i.phase != configuring {
			continue
		}
		n, ok := c.desired.Networks[i.network]
		if !ok || n.Revision != st.revision {
			st.dirty = true
		}
	}
}

// Live lists the interfaces whose leases the agent renews.
func (c *Core) Live() []model.InterfaceID {
	var out []model.InterfaceID
	for _, id := range slices.Sorted(maps.Keys(c.ifaces)) {
		if p := c.ifaces[id].phase; p == ready || p == configuring {
			out = append(out, id)
		}
	}
	return out
}

// Interfaces describes every interface the agent holds.
func (c *Core) Interfaces() []api.LocalInterface {
	var out []api.LocalInterface
	for _, id := range slices.Sorted(maps.Keys(c.ifaces)) {
		out = append(out, c.describe(c.ifaces[id]))
	}
	return out
}

func (c *Core) describe(i *iface) api.LocalInterface {
	li := api.LocalInterface{
		Interface: i.id, Name: i.name, Network: i.network, Service: i.service, Namespace: i.ns,
		PublicKey: i.pub, Ready: i.phase == ready, Addr6: i.addr6, Addr4: i.addr4,
	}
	if n, x, ok := c.desired.Interface(i.id); ok {
		li.Addr6, li.Addr4 = x.Addr6, x.Addr4
		li.Search = n.Domain()
		li.Resolver = dns.ListenAddr().Addr()
		if x.Name != "" {
			li.Member = x.Name + "." + n.Domain()
		}
	}
	return li
}
