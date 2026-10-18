// Package devconf writes a development machine's WireGuard config in the
// wg-quick format every stock client imports, the macOS app among them.
package devconf

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
)

// Keepalive holds the machine's own NAT mapping to its gateway open; a
// stock client cannot send the relay's registration datagram.
const Keepalive = 25

// WGQuick renders the config. priv never left the machine that minted it.
func WGQuick(priv model.Key, c api.DeviceConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# sdn.sh development machine %s, valid until %s\n", c.Interface, c.Expires.UTC().Format(time.RFC3339))
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", priv)
	addrs := []string{netip.PrefixFrom(c.Addr6, 128).String()}
	if c.Addr4.IsValid() {
		addrs = append(addrs, netip.PrefixFrom(c.Addr4, 32).String())
	}
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(addrs, ", "))
	fmt.Fprintf(&b, "DNS = %s, %s\n", c.DNS, c.Domain)
	fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.GatewayKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", c.GatewayAddress)
	var routes []string
	for _, r := range c.Routes {
		routes = append(routes, r.String())
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(routes, ", "))
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", Keepalive)
	return b.String()
}
