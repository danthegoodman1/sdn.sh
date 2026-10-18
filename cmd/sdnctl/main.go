// Command sdnctl drives the control plane's operator API and a host
// agent's local API.
//
//	sdnctl network create NAME [--prefix6 P] [--prefix4 P] [--mtu N] [--relays R1,R2]
//	sdnctl network list | get NET | delete NET
//	sdnctl service create NET NAME [--ipv4] [--mode flip|cutover]
//	sdnctl service list NET | delete NET SVC
//	sdnctl rule create NET FROM TO [--proto tcp|udp|any] [--ports 80 | 8000-8100]
//	sdnctl rule list NET | delete NET RULE
//	sdnctl interface list NET | revoke IFACE
//	sdnctl host create NAME [--endpoint ADDR:PORT]
//	sdnctl relay create NAME --address LOCAL[=ADVERTISED] [--address ...] --ports LO-HI --probe-port N
//	sdnctl relay list
//	sdnctl attach NAME NET SVC      (local agent)
//	sdnctl detach IFACE             (local agent)
//	sdnctl interfaces | status      (local agent)
//
// The control plane is $SDN_CP, authenticated by $SDN_ADMIN_TOKEN; the
// agent's socket is $SDN_AGENT_SOCKET.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"sdn.sh/internal/agent/localapi"
	"sdn.sh/internal/api"
	"sdn.sh/internal/cpclient"
	"sdn.sh/internal/model"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sdnctl:", err)
		os.Exit(1)
	}
}

func usage() error {
	return errors.New("usage: sdnctl network|service|rule|interface|host|relay|attach|detach|interfaces|status ...; see the package documentation")
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	switch args[0] {
	case "attach", "detach", "interfaces", "status":
		return local(ctx, args)
	}
	if len(args) < 2 {
		return usage()
	}
	c, err := cpclient.New(env("SDN_CP", "http://127.0.0.1:8443"), os.Getenv("SDN_ADMIN_TOKEN"), cpclient.Options{CAFile: os.Getenv("SDN_CA_FILE")})
	if err != nil {
		return err
	}
	verb, rest := args[0]+" "+args[1], args[2:]
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	switch verb {
	case "network create":
		p6 := fs.String("prefix6", "", "IPv6 prefix, a random ULA /64 by default")
		p4 := fs.String("prefix4", "", "IPv4 prefix for services that opt in")
		mtu := fs.Int("mtu", 0, "overlay MTU")
		relays := fs.String("relays", "", "relay names or identifiers, in preference order")
		name, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		req := api.CreateNetwork{Name: name[0], MTU: *mtu}
		if req.Prefix6, err = optPrefix(*p6); err != nil {
			return err
		}
		if req.Prefix4, err = optPrefix(*p4); err != nil {
			return err
		}
		if *relays != "" {
			if req.Relays, err = relayIDs(ctx, c, strings.Split(*relays, ",")); err != nil {
				return err
			}
		}
		return show(c.CreateNetwork(ctx, req))
	case "network list":
		return show(c.Networks(ctx))
	case "network get":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.Network(ctx, a[0]))
	case "network delete":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return c.DeleteNetwork(ctx, a[0])
	case "service create":
		ipv4 := fs.Bool("ipv4", false, "give the service an IPv4 address too")
		mode := fs.String("mode", "", "flip (default) or cutover")
		a, err := parse(fs, rest, 2)
		if err != nil {
			return err
		}
		return show(c.CreateService(ctx, a[0], api.CreateService{Name: a[1], IPv4: *ipv4, Mode: api.Mode(*mode)}))
	case "service list":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.Services(ctx, a[0]))
	case "service delete":
		a, err := parse(fs, rest, 2)
		if err != nil {
			return err
		}
		return c.DeleteService(ctx, a[0], a[1])
	case "rule create":
		proto := fs.String("proto", "tcp", "tcp, udp or any")
		ports := fs.String("ports", "", "a port or a range, all ports when empty")
		a, err := parse(fs, rest, 3)
		if err != nil {
			return err
		}
		var pr model.PortRange
		if *ports != "" {
			if pr, err = model.ParsePortRange(*ports); err != nil {
				return err
			}
		}
		return show(c.CreateRule(ctx, a[0], api.CreateRule{From: a[1], To: a[2], Proto: model.Proto(*proto), Ports: pr}))
	case "rule list":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.Rules(ctx, a[0]))
	case "rule delete":
		a, err := parse(fs, rest, 2)
		if err != nil {
			return err
		}
		return c.DeleteRule(ctx, a[0], model.RuleID(a[1]))
	case "interface list":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.Interfaces(ctx, a[0]))
	case "interface revoke":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return c.Revoke(ctx, model.InterfaceID(a[0]))
	case "host create":
		endpoint := fs.String("endpoint", "", "where development machines reach a gateway on this host")
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		req := api.CreateHost{Name: a[0]}
		if *endpoint != "" {
			if req.Endpoint, err = netip.ParseAddrPort(*endpoint); err != nil {
				return err
			}
		}
		return show(c.CreateHost(ctx, req))
	case "relay create":
		var addrs addrList
		fs.Var(&addrs, "address", "LOCAL[=ADVERTISED], repeatable")
		ports := fs.String("ports", "", "the port range edges draw from, LO-HI")
		probe := fs.Uint("probe-port", 0, "the port agents probe on the first address")
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		pr, err := model.ParsePortRange(*ports)
		if err != nil {
			return fmt.Errorf("--ports: %w", err)
		}
		return show(c.CreateRelay(ctx, api.CreateRelay{Name: a[0], Addresses: addrs, PortLo: pr.Lo, PortHi: pr.Hi, ProbePort: uint16(*probe)}))
	case "relay list":
		return show(c.Relays(ctx))
	}
	return usage()
}

// local drives the agent on this host.
func local(ctx context.Context, args []string) error {
	c := localapi.NewClient(env("SDN_AGENT_SOCKET", "/run/sdn/agent.sock"))
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "attach":
		kind := fs.String("kind", "", "workload (default) or gateway")
		a, err := parse(fs, args[1:], 3)
		if err != nil {
			return err
		}
		return show(c.Attach(ctx, api.LocalAttach{Name: a[0], Network: a[1], Service: a[2], Kind: api.Kind(*kind)}))
	case "detach":
		a, err := parse(fs, args[1:], 1)
		if err != nil {
			return err
		}
		return show(c.Detach(ctx, model.InterfaceID(a[0])))
	case "interfaces":
		return show(c.Interfaces(ctx))
	case "status":
		return show(c.Status(ctx))
	}
	return usage()
}

func parse(fs *flag.FlagSet, args []string, n int) ([]string, error) {
	// Flags may follow the positional arguments.
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	if len(pos) != n {
		return nil, fmt.Errorf("%s: want %d arguments, got %d", fs.Name(), n, len(pos))
	}
	return pos, nil
}

func show[T any](v T, err error) error {
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func optPrefix(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, nil
	}
	return netip.ParsePrefix(s)
}

// relayIDs resolves relay names to identifiers, passing identifiers
// through.
func relayIDs(ctx context.Context, c *cpclient.Client, refs []string) ([]model.RelayID, error) {
	relays, err := c.Relays(ctx)
	if err != nil {
		return nil, err
	}
	var out []model.RelayID
	for _, ref := range refs {
		found := false
		for _, r := range relays {
			if string(r.ID) == ref || r.Name == ref {
				out = append(out, r.ID)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no relay %q", ref)
		}
	}
	return out, nil
}

type addrList []api.RelayAddress

func (a *addrList) String() string { return fmt.Sprint(*a) }

func (a *addrList) Set(s string) error {
	local, adv, ok := strings.Cut(s, "=")
	l, err := netip.ParseAddr(local)
	if err != nil {
		return err
	}
	ra := api.RelayAddress{Local: l, Advertised: l}
	if ok {
		if ra.Advertised, err = netip.ParseAddr(adv); err != nil {
			return err
		}
	}
	*a = append(*a, ra)
	return nil
}
