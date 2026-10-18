//sdn:deterministic

package cp

import (
	"encoding/binary"
	"net/netip"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
	"sdn.sh/internal/store"
)

// alloc6 takes the network's next IPv6 address. A /64 holds more addresses
// than any network will ever use, so IPv6 addresses are never reused.
func alloc6(n *store.Network) netip.Addr {
	idx := max(n.Next6, first6)
	n.Next6 = idx + 1
	return addrAt(n.Prefix6, idx)
}

// alloc4 takes the network's next never-used IPv4 address, or, once the
// prefix is used up, the address that has sat longest in quarantine past its
// term.
func (p *Plane) alloc4(tx store.Tx, n *store.Network, now time.Time) (netip.Addr, error) {
	if !n.Prefix4.IsValid() {
		return netip.Addr{}, apiErr(api.CodeInvalid, "network %s has no IPv4 prefix", n.Name)
	}
	// The prefix's first and last addresses stay unused.
	size := uint64(1) << (32 - n.Prefix4.Bits())
	idx := max(n.Next4, first4)
	if idx <= size-2 {
		n.Next4 = idx + 1
		return addrAt(n.Prefix4, idx), nil
	}
	free, err := tx.Released4(n.ID, now.Add(-p.Config.Quarantine4), 1)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(free) == 0 {
		return netip.Addr{}, apiErr(api.CodeExhausted, "network %s has no IPv4 address out of quarantine", n.Name)
	}
	if err := tx.DeleteReleased4(n.ID, free[0].Addr); err != nil {
		return netip.Addr{}, err
	}
	return free[0].Addr, nil
}

// addrAt returns the address idx places past a prefix's base.
func addrAt(prefix netip.Prefix, idx uint64) netip.Addr {
	if prefix.Addr().Is4() {
		b := prefix.Masked().Addr().As4()
		binary.BigEndian.PutUint32(b[:], binary.BigEndian.Uint32(b[:])+uint32(idx))
		return netip.AddrFrom4(b)
	}
	b := prefix.Masked().Addr().As16()
	binary.BigEndian.PutUint64(b[8:], binary.BigEndian.Uint64(b[8:])+idx)
	return netip.AddrFrom16(b)
}

// allocPorts takes two ports on one of a relay's addresses for an edge.
func (p *Plane) allocPorts(tx store.Tx, r store.Relay, now time.Time) (store.EdgePorts, error) {
	for _, a := range r.Addresses {
		ab, ok, err := p.allocPort(tx, r, a.Local, now)
		if err != nil {
			return store.EdgePorts{}, err
		}
		if !ok {
			continue
		}
		ba, ok, err := p.allocPort(tx, r, a.Local, now)
		if err != nil {
			return store.EdgePorts{}, err
		}
		if !ok {
			// Hand the first port back, free at once: no sender ever
			// learned it.
			if err := tx.PutReleasedPort(store.ReleasedPort{Relay: r.ID, Addr: a.Local, Port: ab}); err != nil {
				return store.EdgePorts{}, err
			}
			continue
		}
		return store.EdgePorts{Relay: r.ID, Addr: a.Local, AB: ab, BA: ba}, nil
	}
	return store.EdgePorts{}, apiErr(api.CodeExhausted, "relay %s has no ports out of quarantine", r.Name)
}

func (p *Plane) allocPort(tx store.Tx, r store.Relay, addr netip.Addr, now time.Time) (uint16, bool, error) {
	next, err := tx.PortCursor(r.ID, addr)
	if err != nil {
		return 0, false, err
	}
	if next == 0 {
		next = r.PortLo
	}
	if next <= r.PortHi {
		if err := tx.SetPortCursor(r.ID, addr, next+1); err != nil {
			return 0, false, err
		}
		return next, true, nil
	}
	free, err := tx.ReleasedPorts(r.ID, addr, now.Add(-p.Config.PortQuarantine), 1)
	if err != nil || len(free) == 0 {
		return 0, false, err
	}
	if err := tx.DeleteReleasedPort(r.ID, addr, free[0].Port); err != nil {
		return 0, false, err
	}
	return free[0].Port, true, nil
}

// releasePorts quarantines an edge's ports.
func releasePorts(tx store.Tx, e store.Edge, now time.Time) error {
	for _, ports := range e.Ports {
		for _, port := range []uint16{ports.AB, ports.BA} {
			if err := tx.PutReleasedPort(store.ReleasedPort{Relay: ports.Relay, Addr: ports.Addr, Port: port, At: now}); err != nil {
				return err
			}
		}
	}
	return nil
}

// relayIDs lists the relays an edge holds ports on.
func relayIDs(e store.Edge) []model.RelayID {
	out := make([]model.RelayID, 0, len(e.Ports))
	for _, p := range e.Ports {
		out = append(out, p.Relay)
	}
	return out
}
