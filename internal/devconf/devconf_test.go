package devconf

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/prng"
)

func TestTheConfigIsWhatWGQuickReads(t *testing.T) {
	priv, _ := model.NewPrivateKey(prng.New(1))
	gw, _ := model.NewPrivateKey(prng.New(2))
	c := api.DeviceConfig{
		Interface: "if-laptop", Addr6: netip.MustParseAddr("fd8a:2c41:7e09::51"), Addr4: netip.MustParseAddr("10.42.0.51"),
		DNS: netip.MustParseAddr("fd8a:2c41:7e09::3"), Domain: "shop.internal", MTU: 1380,
		GatewayKey: gw.Public(), GatewayAddress: netip.MustParseAddrPort("198.51.100.7:51820"),
		Routes:  []netip.Prefix{netip.MustParsePrefix("fd8a:2c41:7e09::/64"), netip.MustParsePrefix("10.42.0.0/16")},
		Expires: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	got := WGQuick(priv, c)
	for _, want := range []string{
		"[Interface]\nPrivateKey = " + priv.String() + "\n",
		"Address = fd8a:2c41:7e09::51/128, 10.42.0.51/32\n",
		"DNS = fd8a:2c41:7e09::3, shop.internal\n",
		"MTU = 1380\n",
		"[Peer]\nPublicKey = " + gw.Public().String() + "\n",
		"Endpoint = 198.51.100.7:51820\n",
		"AllowedIPs = fd8a:2c41:7e09::/64, 10.42.0.0/16\n",
		"PersistentKeepalive = 25\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("config lacks %q:\n%s", want, got)
		}
	}
}
