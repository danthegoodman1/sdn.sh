//wirenet:deterministic

package cp

import (
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// Census counts what the control plane's pools hold, for its metrics.
type Census struct {
	// Interfaces counts every network's interfaces by lease state.
	Interfaces map[api.LeaseState]int
	// IPv4Quarantined counts released IPv4 addresses still in quarantine.
	IPv4Quarantined int
	// Relays holds each relay's port pool, sorted by identifier.
	Relays []RelayCensus
}

// RelayCensus is one relay's port pool.
type RelayCensus struct {
	Relay model.RelayID
	Name  string
	// Capacity counts every port the relay's range offers on each of its
	// addresses.
	Capacity int
	// Live counts the ports edges hold, dormant edges among them.
	Live int
	// Quarantined counts released ports still in quarantine.
	Quarantined int
}

// TakeCensus counts interfaces, quarantined IPv4 addresses and relay ports.
// A released address or port stays on record past its quarantine until it
// is reused, so it counts as quarantined only while released within one
// quarantine of now, or later, by a replica whose clock runs ahead.
func (p *Plane) TakeCensus(tx store.ReadTx, now time.Time) (Census, error) {
	c := Census{Interfaces: map[api.LeaseState]int{}}
	nets, err := tx.Networks()
	if err != nil {
		return Census{}, err
	}
	free4 := now.Add(-p.Config.Quarantine4)
	for _, n := range nets {
		ifaces, err := tx.Interfaces(n.ID)
		if err != nil {
			return Census{}, err
		}
		for _, i := range ifaces {
			c.Interfaces[i.State]++
		}
		released, err := tx.Released4(n.ID, endOfTime(), 0)
		if err != nil {
			return Census{}, err
		}
		for _, r := range released {
			if !r.At.Before(free4) {
				c.IPv4Quarantined++
			}
		}
	}
	relays, err := tx.Relays()
	if err != nil {
		return Census{}, err
	}
	freePort := now.Add(-p.Config.PortQuarantine)
	for _, r := range relays {
		rc := RelayCensus{Relay: r.ID, Name: r.Name, Capacity: (int(r.PortHi) - int(r.PortLo) + 1) * len(r.Addresses)}
		edges, err := tx.RelayEdges(r.ID)
		if err != nil {
			return Census{}, err
		}
		for _, e := range edges {
			for _, ports := range e.Ports {
				if ports.Relay == r.ID {
					rc.Live += 2
				}
			}
		}
		for _, a := range r.Addresses {
			released, err := tx.ReleasedPorts(r.ID, a.Local, endOfTime(), 0)
			if err != nil {
				return Census{}, err
			}
			for _, rp := range released {
				if !rp.At.Before(freePort) {
					rc.Quarantined++
				}
			}
		}
		c.Relays = append(c.Relays, rc)
	}
	return c, nil
}

// endOfTime bounds a list that should hold every record, whenever it was
// stamped.
func endOfTime() time.Time { return time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC) }
