package cp

import (
	"maps"
	"net/netip"
	"testing"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

func (f *fixture) census(at time.Time) Census {
	f.t.Helper()
	var c Census
	if err := f.s.View(f.t.Context(), func(tx store.ReadTx) error {
		var err error
		c, err = f.p.TakeCensus(tx, at)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return c
}

// TestTheCensusCountsEachPool releases one client and revokes another, and
// counts the census at that instant, when their addresses and ports have
// just entered quarantine, and again once the quarantines have passed.
func TestTheCensusCountsEachPool(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r") // 100 ports on one address
		f.network(api.CreateNetwork{Name: "n", Prefix4: netip.MustParsePrefix("10.42.0.0/16"), Relays: []model.RelayID{relay}})
		f.service("n", "a", true)
		f.service("n", "b", true)
		f.rule("n", "a", "b", model.TCP, 80)
		b, _ := f.attach("hb", "n", "b")
		a1, _ := f.attach("h1", "n", "a")
		a2, _ := f.attach("h2", "n", "a")
		if c := f.census(f.now); len(c.Relays) != 1 || c.Relays[0] != (RelayCensus{Relay: relay, Name: "r", Capacity: 100, Live: 4}) {
			t.Fatalf("relays with two edges: %+v", c.Relays)
		}
		f.update(func(tx store.Tx) error { return f.p.Release(tx, f.now, f.host("h2"), []model.InterfaceID{a2.ID}) })
		f.now = f.now.Add(f.p.Config.DrainGrace + time.Second)
		f.update(func(tx store.Tx) error {
			if _, err := f.p.Renew(tx, f.now, f.host("hb"), []model.InterfaceID{b.ID}); err != nil {
				return err
			}
			if _, err := f.p.Renew(tx, f.now, f.host("h1"), []model.InterfaceID{a1.ID}); err != nil {
				return err
			}
			if _, err := f.p.Sweep(tx, f.now); err != nil {
				return err
			}
			return f.p.Revoke(tx, f.now, a1.ID)
		})

		c := f.census(f.now)
		want := map[api.LeaseState]int{api.Live: 1, api.Released: 1, api.Revoked: 1}
		if !maps.Equal(c.Interfaces, want) {
			t.Errorf("interfaces %v, want %v", c.Interfaces, want)
		}
		if c.IPv4Quarantined != 2 {
			t.Errorf("%d IPv4 addresses in quarantine, want 2", c.IPv4Quarantined)
		}
		if len(c.Relays) != 1 || c.Relays[0] != (RelayCensus{Relay: relay, Name: "r", Capacity: 100, Quarantined: 4}) {
			t.Errorf("relays once both edges ended: %+v", c.Relays)
		}

		c = f.census(f.now.Add(f.p.Config.PortQuarantine + time.Second))
		if c.IPv4Quarantined != 0 || len(c.Relays) != 1 || c.Relays[0].Quarantined != 0 {
			t.Errorf("past every quarantine: %d IPv4 addresses, relays %+v", c.IPv4Quarantined, c.Relays)
		}
	})
}
