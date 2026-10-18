package cp

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
	"sdn.sh/internal/store"
)

var edgeEndpoint = netip.MustParseAddrPort("203.0.113.7:0")

// gateway attaches a gateway interface on a host development machines can
// reach.
func (f *fixture) gateway(host, net, svc string) store.Interface {
	f.t.Helper()
	if _, ok := f.hosts[host]; !ok {
		f.update(func(tx store.Tx) error {
			h, _, err := f.p.CreateHost(tx, f.now, api.CreateHost{Name: host, Endpoint: edgeEndpoint})
			f.hosts[host] = h.ID
			return err
		})
	}
	priv, _ := model.NewPrivateKey(f.rng)
	id, _ := model.NewID(model.InterfacePrefix, f.rng)
	var i store.Interface
	f.update(func(tx store.Tx) error {
		var err error
		i, err = f.p.Attach(tx, f.now, f.hosts[host], api.AttachRequest{
			Interface: model.InterfaceID(id), Network: net, Service: svc, Kind: api.Gateway,
			PublicKey: priv.Public(), ListenPort: 51820,
		})
		return err
	})
	return i
}

// device registers a development machine's public key behind a gateway.
func (f *fixture) device(net, svc string, gw model.InterfaceID, ttl time.Duration) (store.Interface, error) {
	priv, _ := model.NewPrivateKey(f.rng)
	var d store.Interface
	err := f.tryUpdate(func(tx store.Tx) error {
		var err error
		d, err = f.p.CreateDevice(tx, f.now, net, api.CreateDevice{Service: svc, Gateway: gw, PublicKey: priv.Public(), TTL: ttl})
		return err
	})
	return d, err
}

func peerOf(u api.StateUpdate, iface, peer model.InterfaceID) (api.Peer, bool) {
	for _, n := range u.Networks {
		if i, ok := n.Interface(iface); ok {
			for _, p := range i.Peers {
				if p.Interface == peer {
					return p, true
				}
			}
		}
	}
	return api.Peer{}, false
}

// shopWithDevices builds a network where development machines reach db and
// nothing else, through one gateway.
func shopWithDevices(f *fixture) (gw, db, secret store.Interface) {
	relay := f.relay("r")
	f.network(api.CreateNetwork{Name: "shop", Prefix4: netip.MustParsePrefix("10.42.0.0/16"), Relays: []model.RelayID{relay}})
	f.service("shop", "edge", true)
	f.service("shop", "dev", true)
	f.service("shop", "db", true)
	f.service("shop", "secret", true)
	f.rule("shop", "dev", "db", model.TCP, 5432)
	gw = f.gateway("edge", "shop", "edge")
	db, _ = f.attach("h2", "shop", "db")
	secret, _ = f.attach("h2", "shop", "secret")
	return gw, db, secret
}

func TestADeviceReachesWhatPolicyGrantsThroughItsGateway(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, db, secret := shopWithDevices(f)
		laptop, err := f.device("shop", "dev", gw.ID, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		other, err := f.device("shop", "dev", gw.ID, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		edge, h2 := f.state("edge"), f.state("h2")

		// The gateway holds each machine as a dial-in peer allowed its own
		// addresses alone, so one machine cannot send as another.
		for _, d := range []store.Interface{laptop, other} {
			p, ok := peerOf(edge, gw.ID, d.ID)
			want := []netip.Prefix{netip.PrefixFrom(d.Addr6, 128), netip.PrefixFrom(d.Addr4, 32)}
			if !ok || !p.DialsIn || len(p.Relays) != 0 || !slices.Equal(p.Allowed, want) {
				t.Fatalf("gateway's peer for %s: %+v, want dial-in allowed %v", d.ID, p, want)
			}
		}
		// db's entry for the gateway carries both machines' addresses, so
		// db enforces policy against them; secret, which policy keeps from
		// the machines, has no peer for the gateway at all.
		p, ok := peerOf(h2, db.ID, gw.ID)
		if !ok || len(p.Fronts) != 2 {
			t.Fatalf("db's peer for the gateway: %+v", p)
		}
		for _, fr := range p.Fronts {
			if fr.Interface != laptop.ID && fr.Interface != other.ID {
				t.Fatalf("db's gateway entry fronts %s", fr.Interface)
			}
		}
		if p, ok := peerOf(h2, secret.ID, gw.ID); ok {
			t.Fatalf("secret peers with the gateway: %+v", p)
		}

		// The config points at the gateway's host and routes the network.
		var c api.DeviceConfig
		if err := f.s.View(t.Context(), func(tx store.ReadTx) error {
			c, err = DeviceConfig(tx, laptop.ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if c.GatewayAddress != netip.AddrPortFrom(edgeEndpoint.Addr(), gw.ListenPort) || c.GatewayKey != gw.PublicKey || c.DNS != gw.Addr6 || len(c.Routes) != 2 {
			t.Fatalf("config %+v", c)
		}
	})
}

func TestARevokedDeviceLeavesItsGatewayAndBackendsAtOnce(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, db, _ := shopWithDevices(f)
		laptop, err := f.device("shop", "dev", gw.ID, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		f.update(func(tx store.Tx) error { return f.p.Revoke(tx, f.now, laptop.ID) })
		if p, ok := peerOf(f.state("edge"), gw.ID, laptop.ID); ok {
			t.Fatalf("the gateway still holds the revoked machine: %+v", p)
		}
		if p, ok := peerOf(f.state("h2"), db.ID, gw.ID); ok && len(p.Fronts) != 0 {
			t.Fatalf("db's gateway entry still fronts %+v", p.Fronts)
		}
	})
}

func TestADeviceLeaseEndsWithItsTerm(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, _, _ := shopWithDevices(f)
		if _, err := f.device("shop", "dev", gw.ID, MaxDeviceTTL+time.Hour); err == nil {
			t.Fatal("a term past the maximum was accepted")
		}
		laptop, err := f.device("shop", "dev", gw.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		// The gateway's agent keeps renewing its own lease; nothing renews
		// the machine's.
		for range 3 {
			f.now = f.now.Add(25 * time.Minute)
			f.update(func(tx store.Tx) error {
				if _, err := f.p.Renew(tx, f.now, f.host("edge"), []model.InterfaceID{gw.ID, laptop.ID}); err != nil {
					return err
				}
				_, err := f.p.Sweep(tx, f.now)
				return err
			})
		}
		if p, ok := peerOf(f.state("edge"), gw.ID, laptop.ID); ok && !p.Draining {
			t.Fatalf("the gateway still holds the machine past its term: %+v", p)
		}
	})
}

func TestADeviceHasIPv4OnlyWhereItsGatewayDoes(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "shop", Prefix4: netip.MustParsePrefix("10.42.0.0/16"), Relays: []model.RelayID{relay}})
		f.service("shop", "edge", false)
		f.service("shop", "dev", true)
		gw := f.gateway("edge", "shop", "edge")
		laptop, err := f.device("shop", "dev", gw.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if laptop.Addr4.IsValid() {
			t.Fatalf("a machine behind an IPv6-only gateway drew %v", laptop.Addr4)
		}
	})
}
