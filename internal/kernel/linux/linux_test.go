//go:build linux

package linux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/danthegoodman1/wirenet/internal/kernel"
	"github.com/danthegoodman1/wirenet/internal/kernel/kmodel"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/nft"
	"github.com/danthegoodman1/wirenet/internal/prng"
)

// newKernel returns a kernel for tests that need root in a namespace of
// their own: run them with
//
//	go test -exec 'sudo unshare --net' ./internal/kernel/linux/
//
// so devices' sockets land in a throwaway namespace, not the host's.
// began records that a test found the namespace fresh, so links found later
// are an earlier test's leftovers rather than the environment's.
var began bool

func newKernel(t *testing.T) *Kernel {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: go test -exec 'sudo unshare --net'")
	}
	// A namespace an earlier test deleted is torn down on a workqueue
	// (__put_net in net/core/net_namespace.c), and its egress link with it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		links, err := netlink.LinkList()
		if err != nil {
			t.Fatal(err)
		}
		var extra []string
		for _, l := range links {
			if l.Attrs().Name != "lo" {
				extra = append(extra, l.Attrs().Name)
			}
		}
		if len(extra) == 0 {
			break
		}
		if !began {
			t.Skipf("needs a fresh network namespace, found %v: go test -exec 'sudo unshare --net'", extra)
		}
		if time.Now().After(deadline) {
			t.Fatalf("an earlier test left %v", extra)
		}
		time.Sleep(20 * time.Millisecond)
	}
	began = true
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	k, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	return k
}

// prefix names this test run's namespaces, so a run never touches another's.
func prefix(t *testing.T) string {
	return fmt.Sprintf("wnt%d-", os.Getpid()%100000)
}

func run(t *testing.T, k *Kernel, ops ...kernel.Op) {
	t.Helper()
	for _, op := range ops {
		if _, err := k.Run(op); err != nil {
			t.Fatalf("%v: %v", op, err)
		}
	}
}

// namespace creates a namespace and removes it, devices first, at cleanup.
func namespace(t *testing.T, k *Kernel, name string) string {
	t.Helper()
	run(t, k, kernel.Op{Kind: kernel.CreateNamespace, Namespace: name})
	t.Cleanup(func() {
		k.Run(kernel.Op{Kind: kernel.DeleteDevice, Namespace: name, Device: "wirenet0"})
		k.Run(kernel.Op{Kind: kernel.DeleteNamespace, Namespace: name})
	})
	return name
}

type end struct {
	ns   string
	priv model.Key
	port uint16
	addr netip.Addr
	a4   netip.Addr
}

func (e end) pub() model.Key { return e.priv.Public() }

// pair builds two devices in two namespaces peered over the root
// namespace's loopback, keepalive on one side only.
func pair(t *testing.T, k *Kernel, r *prng.Rand) (end, end) {
	t.Helper()
	p := prefix(t)
	mk := func(name string, i byte, port uint16) end {
		priv, _ := model.NewPrivateKey(r)
		e := end{
			ns: namespace(t, k, p+name), priv: priv, port: port,
			addr: netip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i}),
			a4:   netip.AddrFrom4([4]byte{10, 99, 0, i}),
		}
		run(t, k,
			kernel.Op{Kind: kernel.CreateDevice, Namespace: e.ns, Device: "wirenet0",
				Create: &kernel.DeviceConfig{PrivateKey: priv, ListenPort: port, Alias: "wirenet:test:" + name}},
			kernel.Op{Kind: kernel.ConfigureLink, Namespace: e.ns, Device: "wirenet0", Link: &kernel.LinkConfig{
				Addrs:  []netip.Prefix{netip.PrefixFrom(e.addr, 128), netip.PrefixFrom(e.a4, 32)},
				Routes: []netip.Prefix{netip.MustParsePrefix("fd00::/64"), netip.MustParsePrefix("10.99.0.0/16")},
				MTU:    1380,
			}})
		return e
	}
	base := uint16(42000 + r.Below(1000))
	a, b := mk("a", 1, base), mk("b", 2, base+1)
	peer := func(from, to end, keepalive time.Duration) {
		run(t, k, kernel.Op{Kind: kernel.SetPeers, Namespace: from.ns, Device: "wirenet0", Peers: []kernel.PeerUpdate{{
			PublicKey: to.pub(),
			Allowed:   []netip.Prefix{netip.PrefixFrom(to.addr, 128), netip.PrefixFrom(to.a4, 32)},
			Endpoint:  netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), to.port),
			Keepalive: keepalive,
		}}})
	}
	// The side without keepalive learns its peer first, so the other's
	// first initiation finds it.
	peer(b, a, 0)
	peer(a, b, 25*time.Second)
	return a, b
}

// inNamespace runs fn with the calling goroutine's thread in a namespace;
// sockets it opens stay there.
func inNamespace(t *testing.T, name string, fn func()) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	root, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	h, err := netns.GetFromName(name)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := netns.Set(h); err != nil {
		t.Fatal(err)
	}
	defer netns.Set(root)
	fn()
}

// serve accepts TCP connections in a namespace and answers each with its
// name.
func serve(t *testing.T, ns string, addr netip.AddrPort, reply string) {
	t.Helper()
	var ln net.Listener
	inNamespace(t, ns, func() {
		var err error
		ln, err = net.Listen("tcp", addr.String())
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.WriteString(c, reply)
				io.Copy(io.Discard, c)
			}()
		}
	}()
}

// dial connects from a namespace and returns the connection, or the error.
func dial(t *testing.T, ns string, addr netip.AddrPort, timeout time.Duration) (net.Conn, error) {
	t.Helper()
	var c net.Conn
	var err error
	inNamespace(t, ns, func() {
		c, err = net.DialTimeout("tcp", addr.String(), timeout)
	})
	return c, err
}

// udpArrives sends datagrams from one namespace to a socket bound in
// another, and reports whether any arrived within a second.
func udpArrives(t *testing.T, from, to string, addr netip.AddrPort) bool {
	t.Helper()
	var pc net.PacketConn
	inNamespace(t, to, func() {
		var err error
		if pc, err = net.ListenPacket("udp", addr.String()); err != nil {
			t.Fatal(err)
		}
	})
	defer pc.Close()
	inNamespace(t, from, func() {
		c, err := net.Dial("udp", addr.String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for range 3 {
			c.Write([]byte("probe"))
		}
	})
	pc.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err := pc.ReadFrom(make([]byte, 16))
	return err == nil
}

func readReply(t *testing.T, c net.Conn) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 64)
	n, err := c.Read(b)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b[:n])
}

// TestADeviceCreatedIntoANamespaceKeepsItsSocketInTheRoot checks placement
// by traffic: the two namespaces share no path but the root's loopback, so
// a connection between them proves both sockets live in the root.
func TestADeviceCreatedIntoANamespaceKeepsItsSocketInTheRoot(t *testing.T) {
	k := newKernel(t)
	a, b := pair(t, k, prng.New(1))
	if _, err := netlink.LinkByName("wirenet0"); err == nil {
		t.Fatal("the device shows in the root namespace")
	}
	serve(t, b.ns, netip.AddrPortFrom(b.addr, 8080), "b over v6")
	c, err := dial(t, a.ns, netip.AddrPortFrom(b.addr, 8080), 5*time.Second)
	if err != nil {
		t.Fatalf("a cannot reach b: %v", err)
	}
	defer c.Close()
	if got := readReply(t, c); got != "b over v6" {
		t.Fatalf("got %q", got)
	}
	// Neither workload namespace holds an underlay interface.
	inNamespace(t, a.ns, func() {
		links, _ := netlink.LinkList()
		for _, l := range links {
			if l.Attrs().Name != "lo" && l.Attrs().Name != "wirenet0" {
				t.Errorf("workload namespace holds %s", l.Attrs().Name)
			}
		}
	})
}

func TestAPortInUseFailsTheCreateAndLeavesNoDevice(t *testing.T) {
	k := newKernel(t)
	r := prng.New(2)
	a, _ := pair(t, k, r)
	other := namespace(t, k, prefix(t)+"c")
	priv, _ := model.NewPrivateKey(r)
	_, err := k.Run(kernel.Op{Kind: kernel.CreateDevice, Namespace: other, Device: "wirenet0",
		Create: &kernel.DeviceConfig{PrivateKey: priv, ListenPort: a.port, Alias: "wirenet:test:c"}})
	if !errors.Is(err, kernel.ErrPortInUse) {
		t.Fatalf("create on a used port: %v", err)
	}
	ns, err := k.Namespace(other, "")
	if err != nil || len(ns.Devices) != 0 {
		t.Fatalf("left %+v (%v)", ns.Devices, err)
	}
}

// TestTheModelAgreesWithLinux drives the kernel model and Linux through the
// same random peer changes, including allowed IPs that move between peers,
// and compares what each reports.
func TestTheModelAgreesWithLinux(t *testing.T) {
	k := newKernel(t)
	m := kmodel.New()
	r := prng.New(3)
	name := namespace(t, k, prefix(t)+"m")
	priv, _ := model.NewPrivateKey(r)
	both := func(op kernel.Op) {
		t.Helper()
		_, lerr := k.Run(op)
		_, merr := m.Run(op)
		if (lerr == nil) != (merr == nil) {
			t.Fatalf("%v: linux %v, model %v", op, lerr, merr)
		}
	}
	both(kernel.Op{Kind: kernel.CreateNamespace, Namespace: name})
	both(kernel.Op{Kind: kernel.CreateDevice, Namespace: name, Device: "wirenet0",
		Create: &kernel.DeviceConfig{PrivateKey: priv, ListenPort: uint16(43000 + r.Below(1000)), Alias: "wirenet:test:m"}})
	var keys []model.Key
	for range 6 {
		p, _ := model.NewPrivateKey(r)
		keys = append(keys, p.Public())
	}
	addr := func(i uint64) netip.Prefix {
		return netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 1, 15: byte(i)}), 128)
	}
	for round := range 200 {
		var ups []kernel.PeerUpdate
		for range 1 + r.Below(4) {
			u := kernel.PeerUpdate{PublicKey: keys[r.Index(len(keys))]}
			if r.Percent(25) {
				u.Remove = true
			} else {
				for range 1 + r.Below(2) {
					u.Allowed = append(u.Allowed, addr(r.Below(8)))
				}
				u.Allowed = kernel.SortPrefixes(u.Allowed)
				u.Allowed = slices.Compact(u.Allowed)
				if r.Percent(50) {
					u.Endpoint = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(1000+r.Below(100)))
				}
				if r.Percent(30) {
					u.Keepalive = 25 * time.Second
				}
			}
			ups = append(ups, u)
		}
		both(kernel.Op{Kind: kernel.SetPeers, Namespace: name, Device: "wirenet0", Peers: ups})
		lns, err := k.Namespace(name, "")
		if err != nil {
			t.Fatal(err)
		}
		mns, _ := m.Namespace(name, "")
		lp, mp := describe(lns), describe(mns)
		if lp != mp {
			t.Fatalf("round %d after %+v:\nlinux:\n%s\nmodel:\n%s", round, ups, lp, mp)
		}
	}
}

func describe(ns kernel.Namespace) string {
	var b strings.Builder
	for _, d := range ns.Devices {
		fmt.Fprintf(&b, "%s port=%d key=%v\n", d.Name, d.ListenPort, d.HasKey)
		for _, p := range d.Peers {
			fmt.Fprintf(&b, "  %s allowed=%v endpoint=%v keepalive=%v\n", p.PublicKey.String()[:8], p.Allowed, p.Endpoint, p.Keepalive)
		}
	}
	return b.String()
}

// serviceRules is a ruleset translating one service address in each family
// to backends through full slot maps, rejecting what finds no translation,
// and accepting a source set on one port.
func serviceRules(svc6, svc4 netip.Addr, backends6, backends4 []netip.Addr, port uint16, sources6 []netip.Addr) *nft.Ruleset {
	rs := &nft.Ruleset{}
	slot := func(bs []netip.Addr) []netip.Addr {
		out := make([]netip.Addr, nft.Slots)
		for i := range out {
			out[i] = bs[i%len(bs)]
		}
		return out
	}
	ports := model.PortRange{Lo: port, Hi: port}
	if len(backends6) > 0 {
		rs.Maps = append(rs.Maps, nft.Map{Name: "s_svc_6", Family: nft.IPv6, Slots: slot(backends6)})
		rs.Rules.Translate = append(rs.Rules.Translate, nft.Translate{Addr: svc6, Proto: model.TCP, Ports: ports, Map: "s_svc_6"})
	}
	if len(backends4) > 0 {
		rs.Maps = append(rs.Maps, nft.Map{Name: "s_svc_4", Family: nft.IPv4, Slots: slot(backends4)})
		rs.Rules.Translate = append(rs.Rules.Translate, nft.Translate{Addr: svc4, Proto: model.TCP, Ports: ports, Map: "s_svc_4"})
	}
	rs.Rules.Reject = []netip.Addr{svc6, svc4}
	if sources6 != nil {
		rs.Sets = append(rs.Sets, nft.Set{Name: "f_cli_6", Family: nft.IPv6, Addrs: sources6})
		rs.Rules.Accept = append(rs.Rules.Accept, nft.Accept{Set: "f_cli_6", Family: nft.IPv6, Proto: model.TCP, Ports: ports})
	}
	rs.Normalize()
	return rs
}

// TestServicesTranslateInBothFamilies verifies by traffic the nftables
// forms the slot table rests on: a typeof-numgen map keyed by slot, dnat
// through it in IPv6 and IPv4, a reject for a service with no translation,
// and the input chain's default drop.
func TestServicesTranslateInBothFamilies(t *testing.T) {
	k := newKernel(t)
	a, b := pair(t, k, prng.New(4))
	svc6, svc4 := netip.MustParseAddr("fd00::7"), netip.MustParseAddr("10.99.0.7")
	serve(t, b.ns, netip.AddrPortFrom(b.addr, 5432), "db")
	serve(t, b.ns, netip.AddrPortFrom(b.a4, 5432), "db")
	// The client namespace translates; the server namespace admits a's
	// address on 5432 alone.
	clientRules := serviceRules(svc6, svc4, []netip.Addr{b.addr}, []netip.Addr{b.a4}, 5432, nil)
	run(t, k, kernel.Op{Kind: kernel.ApplyRules, Namespace: a.ns, Rules: &nft.Transaction{Replace: clientRules}})
	serverRules := &nft.Ruleset{
		Sets: []nft.Set{{Name: "f_cli_6", Family: nft.IPv6, Addrs: []netip.Addr{a.addr}}, {Name: "f_cli_4", Family: nft.IPv4, Addrs: []netip.Addr{a.a4}}},
		Rules: nft.Rules{Accept: []nft.Accept{
			{Set: "f_cli_6", Family: nft.IPv6, Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}},
			{Set: "f_cli_4", Family: nft.IPv4, Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}},
		}},
	}
	serverRules.Normalize()
	run(t, k, kernel.Op{Kind: kernel.ApplyRules, Namespace: b.ns, Rules: &nft.Transaction{Replace: serverRules}})
	for _, svc := range []netip.Addr{svc6, svc4} {
		c, err := dial(t, a.ns, netip.AddrPortFrom(svc, 5432), 5*time.Second)
		if err != nil {
			dump(t, a.ns, b.ns)
			t.Fatalf("dial %v: %v", svc, err)
		}
		if got := readReply(t, c); got != "db" {
			t.Fatalf("%v answered %q", svc, got)
		}
		c.Close()
	}
	// A port policy does not name finds no translation and is rejected at
	// once rather than hanging.
	start := time.Now()
	if _, err := dial(t, a.ns, netip.AddrPortFrom(svc6, 22), 5*time.Second); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("untranslated port: %v after %v", err, time.Since(start))
	}
	// The server's input chain drops a port it does not admit.
	for _, addr := range []netip.Addr{b.addr, b.a4} {
		serve(t, b.ns, netip.AddrPortFrom(addr, 9999), "secret")
		if c, err := dial(t, a.ns, netip.AddrPortFrom(addr, 9999), time.Second); err == nil {
			c.Close()
			t.Fatalf("reached %v on a port the receiver's policy does not admit", addr)
		}
	}
	// nft can print what the agent wrote.
	out, err := exec.Command("ip", "netns", "exec", a.ns, "nft", "list", "ruleset").CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("numgen random mod 1024")) {
		t.Fatalf("nft list: %v\n%s", err, out)
	}
}

// TestOtherProtocolsPassWhereTCPAndUDPStop admits a peer for every protocol
// but TCP and UDP, the grant a deny leaves when it takes TCP out of an
// allow for any protocol: ICMP reaches the receiver in each family, and TCP
// and UDP do not.
func TestOtherProtocolsPassWhereTCPAndUDPStop(t *testing.T) {
	k := newKernel(t)
	a, b := pair(t, k, prng.New(9))
	rules := &nft.Ruleset{
		Sets: []nft.Set{{Name: "f_cli_6", Family: nft.IPv6, Addrs: []netip.Addr{a.addr}}, {Name: "f_cli_4", Family: nft.IPv4, Addrs: []netip.Addr{a.a4}}},
		Rules: nft.Rules{Accept: []nft.Accept{
			{Set: "f_cli_6", Family: nft.IPv6, Proto: model.OtherProto},
			{Set: "f_cli_4", Family: nft.IPv4, Proto: model.OtherProto},
		}},
	}
	rules.Normalize()
	run(t, k, kernel.Op{Kind: kernel.ApplyRules, Namespace: b.ns, Rules: &nft.Transaction{Replace: rules}})
	for _, addr := range []netip.Addr{b.addr, b.a4} {
		if out, err := exec.Command("ip", "netns", "exec", a.ns, "ping", "-c", "1", "-W", "5", addr.String()).CombinedOutput(); err != nil {
			dump(t, a.ns, b.ns)
			t.Fatalf("ping %v through a grant for other protocols: %v\n%s", addr, err, out)
		}
		serve(t, b.ns, netip.AddrPortFrom(addr, 9999), "secret")
		if c, err := dial(t, a.ns, netip.AddrPortFrom(addr, 9999), time.Second); err == nil {
			c.Close()
			t.Fatalf("reached %v over TCP through a grant for other protocols", addr)
		}
		if udpArrives(t, a.ns, b.ns, netip.AddrPortFrom(addr, 9998)) {
			t.Fatalf("reached %v over UDP through a grant for other protocols", addr)
		}
	}
}

// TestARejectedServiceLeavesNoEntryToRefuseItsReturn dials a service from
// fixed source ports while policy keeps the namespace from it, then
// restores the service. Under a reject the dial is refused at once and
// leaves conntrack nothing, so the restored service's first connection
// from the same port reaches it. Under no rule at all, as a namespace
// once had for a service it could not reach, the dial leaves an entry
// with no translation, and the same port stays refused once the service
// translates, since NAT runs once per entry.
func TestARejectedServiceLeavesNoEntryToRefuseItsReturn(t *testing.T) {
	k := newKernel(t)
	a, b := pair(t, k, prng.New(4))
	svc6, svc4 := netip.MustParseAddr("fd00::7"), netip.MustParseAddr("10.99.0.7")
	serve(t, b.ns, netip.AddrPortFrom(b.addr, 5432), "db")
	target := netip.AddrPortFrom(svc6, 5432)
	from := func(port int) (net.Conn, error) {
		var c net.Conn
		var err error
		inNamespace(t, a.ns, func() {
			d := net.Dialer{Timeout: 300 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: a.addr.AsSlice(), Port: port}}
			c, err = d.Dial("tcp", target.String())
		})
		return c, err
	}
	entries := func(port int) string {
		out, err := exec.Command("ip", "netns", "exec", a.ns, "conntrack", "-L", "-p", "tcp", "--sport", strconv.Itoa(port)).Output()
		if err != nil {
			t.Fatalf("conntrack: %v", err)
		}
		return string(bytes.TrimSpace(out))
	}
	reach := serviceRules(svc6, svc4, []netip.Addr{b.addr}, nil, 5432, nil)
	rejected := &nft.Ruleset{Rules: nft.Rules{Reject: []netip.Addr{svc6, svc4}}}
	rejected.Normalize()
	none := &nft.Ruleset{}
	none.Normalize()
	for _, c := range []struct {
		name   string
		denied *nft.Ruleset
		port   int
		reach  bool
	}{{"rejected", rejected, 40711, true}, {"without a rule", none, 40712, false}} {
		run(t, k, kernel.Op{Kind: kernel.ApplyRules, Namespace: a.ns, Rules: &nft.Transaction{Replace: c.denied}})
		conn, err := from(c.port)
		if err == nil {
			conn.Close()
			t.Fatalf("%s: reached a service policy keeps the namespace from", c.name)
		}
		if refused := errors.Is(err, unix.ECONNREFUSED); refused != c.reach {
			t.Fatalf("%s: dial failed with %v", c.name, err)
		}
		if left := entries(c.port); (left == "") != c.reach {
			t.Fatalf("%s: conntrack holds %q", c.name, left)
		}
		tx := nft.Diff(c.denied, reach)
		run(t, k, kernel.Op{Kind: kernel.ApplyRules, Namespace: a.ns, Rules: &tx})
		conn, err = from(c.port)
		if (err == nil) != c.reach {
			t.Fatalf("%s: the restored service's first connection from port %d: %v", c.name, c.port, err)
		}
		if err == nil {
			if got := readReply(t, conn); got != "db" {
				t.Fatalf("%s: reached %q", c.name, got)
			}
			conn.Close()
		}
	}
}

// TestASessionShowsOnceAHandshakeCompletes reads b's sessions after a's
// keepalive handshake, which lists a, then gives b a fresh peer for a,
// which lists nothing until traffic shakes hands again.
func TestASessionShowsOnceAHandshakeCompletes(t *testing.T) {
	k := newKernel(t)
	a, b := pair(t, k, prng.New(12))
	read := func() []model.Key {
		t.Helper()
		r, err := k.Run(kernel.Op{Kind: kernel.ReadSessions, Namespace: b.ns, Device: "wirenet0"})
		if err != nil {
			t.Fatal(err)
		}
		return r.Sessions
	}
	deadline := time.Now().Add(3 * time.Second)
	for !slices.Equal(read(), []model.Key{a.pub()}) {
		if time.Now().After(deadline) {
			t.Fatalf("b reads sessions %v after a's keepalive, want a's key", read())
		}
		time.Sleep(10 * time.Millisecond)
	}
	update := kernel.PeerUpdate{PublicKey: a.pub(), Allowed: []netip.Prefix{netip.PrefixFrom(a.addr, 128), netip.PrefixFrom(a.a4, 32)},
		Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), a.port)}
	remove := update
	remove.Remove = true
	run(t, k, kernel.Op{Kind: kernel.SetPeers, Namespace: b.ns, Device: "wirenet0", Peers: []kernel.PeerUpdate{remove}})
	run(t, k, kernel.Op{Kind: kernel.SetPeers, Namespace: b.ns, Device: "wirenet0", Peers: []kernel.PeerUpdate{update}})
	if got := read(); len(got) != 0 {
		t.Fatalf("a fresh peer reads sessions %v before any handshake", got)
	}
}

// TestASideThatWaitsForItsSessionConnectsAtOnce re-forms a loopback pair
// twenty times, arming a's keepalive while b, the side without it, waits
// for its device to read a session with a before dialing. Dialing as a
// arms instead crossed the two initiations and waited out WireGuard's
// 5-second retry in 29 of 40 rounds.
func TestASideThatWaitsForItsSessionConnectsAtOnce(t *testing.T) {
	k := newKernel(t)
	a, b := pair(t, k, prng.New(11))
	serve(t, a.ns, netip.AddrPortFrom(a.addr, 5432), "a")
	set := func(from, to end, keepalive time.Duration, remove bool) kernel.Op {
		u := kernel.PeerUpdate{PublicKey: to.pub(), Remove: remove}
		if !remove {
			u.Allowed = []netip.Prefix{netip.PrefixFrom(to.addr, 128), netip.PrefixFrom(to.a4, 32)}
			u.Endpoint = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), to.port)
			u.Keepalive = keepalive
		}
		return kernel.Op{Kind: kernel.SetPeers, Namespace: from.ns, Device: "wirenet0", Peers: []kernel.PeerUpdate{u}}
	}
	for round := range 20 {
		run(t, k, set(a, b, 0, true), set(b, a, 0, true), set(a, b, 0, false), set(b, a, 0, false))
		armed := make(chan error, 1)
		go func() { _, err := k.Run(set(a, b, 25*time.Second, false)); armed <- err }()
		for end := time.Now().Add(time.Second); time.Now().Before(end); time.Sleep(200 * time.Microsecond) {
			r, err := k.Run(kernel.Op{Kind: kernel.ReadSessions, Namespace: b.ns, Device: "wirenet0"})
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(r.Sessions, a.pub()) {
				break
			}
		}
		start := time.Now()
		c, err := dial(t, b.ns, netip.AddrPortFrom(a.addr, 5432), 7*time.Second)
		if err := <-armed; err != nil {
			t.Fatal(err)
		}
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		c.Close()
		if took := time.Since(start); took > time.Second {
			t.Fatalf("round %d: the first connection took %v", round, took)
		}
	}
}

// TestAnElementUpdateMovesNewConnectionsOnly replaces a service's backend
// through element updates: a connection open before stays where it was.
func TestAnElementUpdateMovesNewConnectionsOnly(t *testing.T) {
	k := newKernel(t)
	r := prng.New(5)
	a, b := pair(t, k, r)
	// A second server address on b stands in for a second backend.
	b2 := netip.MustParseAddr("fd00::22")
	run(t, k, kernel.Op{Kind: kernel.ConfigureLink, Namespace: b.ns, Device: "wirenet0", Link: &kernel.LinkConfig{
		Addrs:  []netip.Prefix{netip.PrefixFrom(b.addr, 128), netip.PrefixFrom(b.a4, 32), netip.PrefixFrom(b2, 128)},
		Routes: []netip.Prefix{netip.MustParsePrefix("fd00::/64"), netip.MustParsePrefix("10.99.0.0/16")},
		MTU:    1380,
	}})
	run(t, k, kernel.Op{Kind: kernel.SetPeers, Namespace: a.ns, Device: "wirenet0", Peers: []kernel.PeerUpdate{{
		PublicKey: b.pub(),
		Allowed:   []netip.Prefix{netip.PrefixFrom(b.addr, 128), netip.PrefixFrom(b.a4, 32), netip.PrefixFrom(b2, 128)},
		Endpoint:  netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), b.port),
		Keepalive: 25 * time.Second,
	}}})
	serve(t, b.ns, netip.AddrPortFrom(b.addr, 5432), "old")
	serve(t, b.ns, netip.AddrPortFrom(b2, 5432), "new")
	svc6 := netip.MustParseAddr("fd00::7")
	before := serviceRules(svc6, netip.MustParseAddr("10.99.0.7"), []netip.Addr{b.addr}, nil, 5432, nil)
	run(t, k, kernel.Op{Kind: kernel.ApplyRules, Namespace: a.ns, Rules: &nft.Transaction{Replace: before}})
	held, err := dial(t, a.ns, netip.AddrPortFrom(svc6, 5432), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if got := readReply(t, held); got != "old" {
		t.Fatalf("first connection reached %q", got)
	}
	after := serviceRules(svc6, netip.MustParseAddr("10.99.0.7"), []netip.Addr{b2}, nil, 5432, nil)
	tx := nft.Diff(before, after)
	if tx.Replace != nil || tx.Rules != nil || len(tx.Slots) != nft.Slots {
		t.Fatalf("a backend swap should be %d element updates and no rule change: %+v", nft.Slots, tx)
	}
	run(t, k, kernel.Op{Kind: kernel.ApplyRules, Namespace: a.ns, Rules: &tx})
	c, err := dial(t, a.ns, netip.AddrPortFrom(svc6, 5432), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := readReply(t, c); got != "new" {
		t.Fatalf("a new connection reached %q", got)
	}
	c.Close()
	if _, err := held.Write([]byte("still here")); err != nil {
		t.Fatalf("the held connection broke: %v", err)
	}
	// A connection addressed to the old backend directly.
	direct, err := dial(t, a.ns, netip.AddrPortFrom(b.addr, 5432), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	readReply(t, direct)
	// Flushing the old backend's address removes both connections'
	// conntrack entries and destroys both sockets: the one addressed to it,
	// and the one addressed to the service whose entry it carried.
	res, err := k.Run(kernel.Op{Kind: kernel.Flush, Namespace: a.ns, Addrs: []netip.Addr{b.addr}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Conntrack != 2 || res.Sockets != 2 {
		t.Fatalf("flush removed %d entries and %d sockets, want 2 and 2", res.Conntrack, res.Sockets)
	}
	for name, c := range map[string]net.Conn{"addressed to the flushed backend": direct, "through the service": held} {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("the socket %s lives on: %v", name, err)
		}
	}
}

// TestASweepKeepsConnectionsThroughALiveService sweeps a namespace as an
// agent does after a restart: a connection through a service address whose
// backend is still a peer survives, though the sweep keeps no service
// address, and once that backend is no longer kept, the connection goes.
func TestASweepKeepsConnectionsThroughALiveService(t *testing.T) {
	k := newKernel(t)
	a, b := pair(t, k, prng.New(9))
	svc6, svc4 := netip.MustParseAddr("fd00::7"), netip.MustParseAddr("10.99.0.7")
	serve(t, b.ns, netip.AddrPortFrom(b.addr, 5432), "db")
	rules := serviceRules(svc6, svc4, []netip.Addr{b.addr}, nil, 5432, nil)
	run(t, k, kernel.Op{Kind: kernel.ApplyRules, Namespace: a.ns, Rules: &nft.Transaction{Replace: rules}})
	held, err := dial(t, a.ns, netip.AddrPortFrom(svc6, 5432), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	readReply(t, held)
	prefixes := []netip.Prefix{netip.MustParsePrefix("fd00::/64"), netip.MustParsePrefix("10.99.0.0/16")}
	keep := []netip.Addr{a.addr, a.a4, b.addr, b.a4}
	res, err := k.Run(kernel.Op{Kind: kernel.Sweep, Namespace: a.ns, Addrs: keep, Prefixes: prefixes})
	if err != nil {
		t.Fatal(err)
	}
	if res.Conntrack != 0 || res.Sockets != 0 {
		t.Fatalf("a sweep keeping every live address removed %d entries and %d sockets", res.Conntrack, res.Sockets)
	}
	if _, err := held.Write([]byte("still here")); err != nil {
		t.Fatalf("the connection broke: %v", err)
	}
	res, err = k.Run(kernel.Op{Kind: kernel.Sweep, Namespace: a.ns, Addrs: []netip.Addr{a.addr, a.a4}, Prefixes: prefixes})
	if err != nil {
		t.Fatal(err)
	}
	if res.Conntrack != 1 || res.Sockets != 1 {
		t.Fatalf("a sweep without the backend removed %d entries and %d sockets, want 1 and 1", res.Conntrack, res.Sockets)
	}
}

// dump logs what each namespace's table and devices hold.
func dump(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		for _, cmd := range [][]string{{"nft", "list", "ruleset"}, {"wg", "show"}, {"conntrack", "-L"}, {"ss", "-tanp"}} {
			out, _ := exec.Command("ip", append([]string{"netns", "exec", n}, cmd...)...).CombinedOutput()
			t.Logf("%s: %v\n%s", n, cmd, out)
		}
	}
}

func TestTheKernelCanDestroySockets(t *testing.T) {
	k := newKernel(t)
	if err := k.CheckDestroy(); err != nil {
		t.Fatal(err)
	}
}

// TestADeletedNamespaceAProcessHoldsIsFoundAndReaped holds a namespace open
// with a process, deletes its name, and checks the device is still found,
// reaped, and its listen port freed.
func TestADeletedNamespaceAProcessHoldsIsFoundAndReaped(t *testing.T) {
	k := newKernel(t)
	r := prng.New(6)
	a, _ := pair(t, k, r)
	holder := exec.Command("ip", "netns", "exec", a.ns, "sleep", "60")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer holder.Process.Kill()
	time.Sleep(200 * time.Millisecond)
	run(t, k, kernel.Op{Kind: kernel.DeleteNamespace, Namespace: a.ns})
	snap, err := k.Snapshot(prefix(t), "wirenet:test:")
	if err != nil {
		t.Fatal(err)
	}
	var ref string
	for _, ns := range snap.Namespaces {
		if ns.Name == "" {
			ref = ns.Ref
		}
	}
	if ref == "" {
		t.Fatalf("the held namespace is missing: %+v", snap)
	}
	run(t, k, kernel.Op{Kind: kernel.Reap, Ref: ref, AliasPrefix: "wirenet:test:"})
	// The port is free: a new device binds it.
	other := namespace(t, k, prefix(t)+"d")
	priv, _ := model.NewPrivateKey(r)
	run(t, k, kernel.Op{Kind: kernel.CreateDevice, Namespace: other, Device: "wirenet0",
		Create: &kernel.DeviceConfig{PrivateKey: priv, ListenPort: a.port, Alias: "wirenet:test:d"}})
}

// internet builds a namespace standing for the internet behind the root
// namespace: 198.51.100.0/24 links them, and 203.0.113.7 and 2001:db8::7
// answer inside it. So does every address in reachable, which the root
// routes there, so a dial that fails shows a filter dropped it.
var reachable = []string{
	"10.0.0.1", "168.63.129.16", "169.254.169.254", "192.0.2.1", "fd00:ec2::254",
	"64:ff9b::cb00:7107", "64:ff9b::c000:201", "64:ff9b::a00:1",
}

func internet(t *testing.T, k *Kernel) string {
	t.Helper()
	name := namespace(t, k, prefix(t)+"inet")
	for _, args := range [][]string{
		{"ip", "link", "add", "up0", "type", "veth", "peer", "name", "eth0", "netns", name},
		{"ip", "addr", "add", "198.51.100.1/24", "dev", "up0"},
		{"ip", "addr", "add", "2001:db8:1::1/64", "dev", "up0", "nodad"},
		{"ip", "link", "set", "up0", "up"},
		{"ip", "-n", name, "addr", "add", "198.51.100.2/24", "dev", "eth0"},
		{"ip", "-n", name, "addr", "add", "2001:db8:1::2/64", "dev", "eth0", "nodad"},
		{"ip", "-n", name, "link", "set", "eth0", "up"},
		{"ip", "-n", name, "addr", "add", "203.0.113.7/32", "dev", "lo"},
		{"ip", "-n", name, "addr", "add", "2001:db8::7/128", "dev", "lo"},
		{"ip", "-n", name, "route", "add", "default", "via", "198.51.100.1"},
		{"ip", "-n", name, "-6", "route", "add", "default", "via", "2001:db8:1::1"},
		{"ip", "route", "add", "203.0.113.0/24", "via", "198.51.100.2"},
		{"ip", "-6", "route", "add", "2001:db8::/64", "via", "2001:db8:1::2"},
		{"sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	for _, a := range reachable {
		addr := netip.MustParseAddr(a)
		family, via := "-4", "198.51.100.2"
		if addr.Is6() {
			family, via = "-6", "2001:db8:1::2"
		}
		host := netip.PrefixFrom(addr, addr.BitLen()).String()
		for _, args := range [][]string{
			{"ip", "-n", name, "addr", "add", host, "dev", "lo"},
			{"ip", family, "route", "add", host, "via", via},
		} {
			if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
				t.Fatalf("%v: %v %s", args, err, out)
			}
		}
	}
	t.Cleanup(func() { exec.Command("ip", "link", "del", "up0").Run() })
	return name
}

func TestAnEgressGrantReachesWhatItNamesAndNothingElse(t *testing.T) {
	k := newKernel(t)
	inet := internet(t, k)
	ipv6, err := EnableForwarding()
	if err != nil || !ipv6 {
		t.Fatalf("forwarding: %v %v", ipv6, err)
	}
	k.SetEgressIPv6(true)
	// The root's own link to the internet counts as the host's underlay
	// prefix; the internet namespace's far side stays reachable through it.
	if err := k.EnsureEgress([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}); err != nil {
		t.Fatal(err)
	}
	blocked, err := k.EgressBlocked()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"192.0.2.0/24", "64:ff9b::c000:200/120", "10.0.0.0/8"} {
		if !slices.Contains(blocked, netip.MustParsePrefix(want)) {
			t.Errorf("the filter records %v, which lacks %s", blocked, want)
		}
	}
	r := prng.New(7)
	a, _ := pair(t, k, r)
	for _, addr := range []string{"203.0.113.7", "2001:db8::7"} {
		serve(t, inet, netip.AddrPortFrom(netip.MustParseAddr(addr), 443), "web")
		serve(t, inet, netip.AddrPortFrom(netip.MustParseAddr(addr), 22), "ssh")
	}
	for _, addr := range reachable {
		ap := netip.AddrPortFrom(netip.MustParseAddr(addr), 443)
		serve(t, inet, ap, "web")
		// The host reaches each one, which no filter guards.
		c, err := net.DialTimeout("tcp", ap.String(), 3*time.Second)
		if err != nil {
			t.Fatalf("the host cannot reach %v: %v", ap, err)
		}
		c.Close()
	}
	// No grant, no path.
	if c, err := dial(t, a.ns, netip.MustParseAddrPort("203.0.113.7:443"), time.Second); err == nil {
		c.Close()
		t.Fatal("reached the internet with no grant")
	}
	grant := &kernel.EgressConfig{Index: a.port, Rules: []kernel.EgressRule{{Proto: model.TCP, Ports: model.PortRange{Lo: 443, Hi: 443}}}}
	run(t, k, kernel.Op{Kind: kernel.SetEgress, Namespace: a.ns, Egress: grant})
	ns, err := k.Namespace(a.ns, "")
	if err != nil || !ns.Egress.Equal(grant) {
		t.Fatalf("observed egress %+v (%v), want %+v", ns.Egress, err, grant)
	}
	// The NAT64 form of an address no prefix blocks passes too.
	for _, addr := range []string{"203.0.113.7", "[2001:db8::7]", "[64:ff9b::cb00:7107]"} {
		c, err := dial(t, a.ns, netip.MustParseAddrPort(addr+":443"), 3*time.Second)
		if err != nil {
			t.Fatalf("granted %s:443: %v", addr, err)
		}
		if got := readReply(t, c); got != "web" {
			t.Fatalf("got %q", got)
		}
		c.Close()
		if addr == "[64:ff9b::cb00:7107]" {
			continue
		}
		if c, err := dial(t, a.ns, netip.MustParseAddrPort(addr+":22"), time.Second); err == nil {
			c.Close()
			t.Fatalf("reached %s:22, which the grant does not name", addr)
		}
	}
	// The host itself, private and metadata ranges, a blocked prefix, and
	// the NAT64 forms of blocked IPv4 addresses are out of reach, though
	// each answers.
	for _, a := range []string{"198.51.100.1:443", "[2001:db8:1::1]:443"} {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
	}
	for _, addr := range []string{"198.51.100.1:443", "[2001:db8:1::1]:443", "10.0.0.1:443", "192.0.2.1:443", "168.63.129.16:443",
		"169.254.169.254:443", "[fd00:ec2::254]:443", "[64:ff9b::c000:201]:443", "[64:ff9b::a00:1]:443"} {
		if c, err := dial(t, a.ns, netip.MustParseAddrPort(addr), 700*time.Millisecond); err == nil {
			c.Close()
			t.Errorf("an egress link reached %s", addr)
		}
	}
	// Removing the grant removes the link and its filter.
	run(t, k, kernel.Op{Kind: kernel.SetEgress, Namespace: a.ns})
	if ns, _ := k.Namespace(a.ns, ""); ns.Egress != nil {
		t.Fatalf("egress after removal: %+v", ns.Egress)
	}
	if _, err := netlink.LinkByName(egressLink(a.port)); err == nil {
		t.Fatal("the host side outlived the grant")
	}
	if c, err := dial(t, a.ns, netip.MustParseAddrPort("203.0.113.7:443"), time.Second); err == nil {
		c.Close()
		t.Fatal("reached the internet after the grant went")
	}
}

// TestTheModelAgreesWithLinuxOnEgress plays random grants, changes and
// removals through both and compares what each observes.
func TestTheModelAgreesWithLinuxOnEgress(t *testing.T) {
	k := newKernel(t)
	if err := k.EnsureEgress(nil); err != nil {
		t.Fatal(err)
	}
	m := kmodel.New()
	r := prng.New(8)
	name := namespace(t, k, prefix(t)+"x")
	m.Run(kernel.Op{Kind: kernel.CreateNamespace, Namespace: name})
	rules := []kernel.EgressRule{
		{Proto: model.TCP, Ports: model.PortRange{Lo: 443, Hi: 443}},
		{Proto: model.UDP, Ports: model.PortRange{Lo: 53, Hi: 53}},
		{Proto: model.AnyProto},
	}
	for round := range 30 {
		var cfg *kernel.EgressConfig
		if !r.Percent(25) {
			cfg = &kernel.EgressConfig{Index: uint16(41000 + r.Below(2))}
			for _, rule := range rules {
				if r.Percent(50) {
					cfg.Rules = append(cfg.Rules, rule)
				}
			}
		}
		op := kernel.Op{Kind: kernel.SetEgress, Namespace: name, Egress: cfg}
		if _, err := k.Run(op); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		m.Run(op)
		lns, err := k.Namespace(name, "")
		if err != nil {
			t.Fatal(err)
		}
		mns, _ := m.Namespace(name, "")
		if !lns.Egress.Equal(mns.Egress) {
			t.Fatalf("round %d after %+v: linux %+v, model %+v", round, cfg, lns.Egress, mns.Egress)
		}
	}
}

// TestAGrantSplitByManyDeniesReadsBack installs a grant of 44 flows, the
// shape forty single-port denies leave of an allow for any protocol, and
// observes all of it back.
func TestAGrantSplitByManyDeniesReadsBack(t *testing.T) {
	k := newKernel(t)
	if err := k.EnsureEgress(nil); err != nil {
		t.Fatal(err)
	}
	name := namespace(t, k, prefix(t)+"x")
	cfg := &kernel.EgressConfig{Index: 41000}
	lo := uint16(1)
	for p := uint16(25); p < 4025; p += 100 {
		cfg.Rules = append(cfg.Rules, kernel.EgressRule{Proto: model.TCP, Ports: model.PortRange{Lo: lo, Hi: p - 1}})
		lo = p + 1
	}
	cfg.Rules = append(cfg.Rules, kernel.EgressRule{Proto: model.TCP, Ports: model.PortRange{Lo: lo, Hi: 65535}},
		kernel.EgressRule{Proto: model.UDP}, kernel.EgressRule{Proto: model.OtherProto})
	run(t, k, kernel.Op{Kind: kernel.SetEgress, Namespace: name, Egress: cfg})
	ns, err := k.Namespace(name, "")
	if err != nil || !ns.Egress.Equal(cfg) {
		t.Fatalf("observed %+v (%v), want %d flows", ns.Egress, err, len(cfg.Rules))
	}
}

// TestAGrantChainThatRecordsNothingIsRewritten writes a link's chain as an
// agent that kept grants in the link's alias did, with rules that record
// no flow, and a blocked prefix tagged in bare text. The namespace still
// reads, its grant as empty, and the rewrite reads back whole; the blocked
// prefix reads too, and nft shows what the agent records as comments.
func TestAGrantChainThatRecordsNothingIsRewritten(t *testing.T) {
	k := newKernel(t)
	if err := k.EnsureEgress(nil); err != nil {
		t.Fatal(err)
	}
	name := namespace(t, k, prefix(t)+"x")
	cfg := &kernel.EgressConfig{Index: 41001, Rules: []kernel.EgressRule{{Proto: model.TCP, Ports: model.PortRange{Lo: 443, Hi: 443}}}}
	run(t, k, kernel.Op{Kind: kernel.SetEgress, Namespace: name, Egress: cfg})
	c, err := nftables.New(nftables.WithNetNSFd(int(k.root)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseLasting()
	tb := &nftables.Table{Name: egressTable, Family: nftables.TableFamilyINet}
	ch := &nftables.Chain{Name: egressLink(cfg.Index), Table: tb}
	c.FlushChain(ch)
	c.AddRule(&nftables.Rule{Table: tb, Chain: ch, Exprs: append(protoMatch(model.TCP, cfg.Rules[0].Ports), accept())})
	bare := netip.MustParsePrefix("198.18.0.0/15")
	c.AddRule(&nftables.Rule{Table: tb, Chain: &nftables.Chain{Name: "forward", Table: tb},
		Exprs:    concat(ifnamePrefix(expr.MetaKeyIIFNAME, egressPrefix), prefixMatch(bare), []expr.Any{drop()}),
		UserData: []byte(blockedTag + bare.String())})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	ns, err := k.Namespace(name, "")
	if err != nil || ns.Egress == nil || ns.Egress.Index != cfg.Index || len(ns.Egress.Rules) != 0 {
		t.Fatalf("an unrecorded chain observed as %+v (%v), want link %d with an empty grant", ns.Egress, err, cfg.Index)
	}
	if blocked, err := k.EgressBlocked(); err != nil || !slices.Contains(blocked, bare) {
		t.Fatalf("blocked %v (%v), want %v among them", blocked, err, bare)
	}
	run(t, k, kernel.Op{Kind: kernel.SetEgress, Namespace: name, Egress: cfg})
	if ns, err = k.Namespace(name, ""); err != nil || !ns.Egress.Equal(cfg) {
		t.Fatalf("after the rewrite observed %+v (%v), want %+v", ns.Egress, err, cfg)
	}
	out, err := exec.Command("nft", "list", "table", "inet", egressTable).CombinedOutput()
	if err != nil {
		t.Fatalf("nft: %v: %s", err, out)
	}
	for _, want := range []string{`comment "grant tcp/443-443"`, `comment "blocked 10.0.0.0/8"`} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("nft shows no %s:\n%s", want, out)
		}
	}
}

// TestAFilterRefreshedFromWhatItHoldsStaysTheSame refreshes the egress
// filter from the set it reads back, as each agent start does, and checks
// the filter keeps one rule per prefix.
func TestAFilterRefreshedFromWhatItHoldsStaysTheSame(t *testing.T) {
	k := newKernel(t)
	if err := k.EnsureEgress([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}); err != nil {
		t.Fatal(err)
	}
	first, err := k.EgressBlocked()
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		kept, err := k.EgressBlocked()
		if err != nil {
			t.Fatal(err)
		}
		if err := k.EnsureEgress(kept); err != nil {
			t.Fatal(err)
		}
	}
	again, err := k.EgressBlocked()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(again, first) {
		t.Fatalf("after three refreshes the filter blocks %d prefixes, first %d: %v", len(again), len(first), again)
	}
}

// TestADeletedNamespaceADescriptorHoldsIsFoundAndReaped holds a namespace
// open with a descriptor alone, deletes its name, and checks the device is
// still found, reaped, and its listen port freed.
func TestADeletedNamespaceADescriptorHoldsIsFoundAndReaped(t *testing.T) {
	k := newKernel(t)
	r := prng.New(8)
	a, _ := pair(t, k, r)
	f, err := os.Open(filepath.Join(netnsDir, a.ns))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	run(t, k, kernel.Op{Kind: kernel.DeleteNamespace, Namespace: a.ns})
	snap, err := k.Snapshot(prefix(t), "wirenet:test:")
	if err != nil {
		t.Fatal(err)
	}
	var ref string
	for _, ns := range snap.Namespaces {
		if ns.Name == "" && len(ns.Devices) == 1 && ns.Devices[0].Alias == "wirenet:test:a" {
			ref = ns.Ref
		}
	}
	if ref == "" {
		t.Fatalf("the namespace a descriptor holds is missing: %+v", snap)
	}
	run(t, k, kernel.Op{Kind: kernel.Reap, Ref: ref, AliasPrefix: "wirenet:test:"})
	other := namespace(t, k, prefix(t)+"e")
	priv, _ := model.NewPrivateKey(r)
	run(t, k, kernel.Op{Kind: kernel.CreateDevice, Namespace: other, Device: "wirenet0",
		Create: &kernel.DeviceConfig{PrivateKey: priv, ListenPort: a.port, Alias: "wirenet:test:e"}})
}

// TestANameAnOperatorDeletesStopsReachingTheAgentsSockets deletes a
// namespace's name as `ip netns del` does, behind the agent, and checks that
// the agent learns it, that the device keeps its port while the agent's
// sockets hold the namespace, and that the port frees once the agent deletes
// it.
func TestANameAnOperatorDeletesStopsReachingTheAgentsSockets(t *testing.T) {
	k := newKernel(t)
	r := prng.New(9)
	a, _ := pair(t, k, r)
	if out, err := exec.Command("ip", "netns", "del", a.ns).CombinedOutput(); err != nil {
		t.Fatalf("ip netns del: %v: %s", err, out)
	}
	if _, err := k.Namespace(a.ns, "wirenet:test:"); !errors.Is(err, kernel.ErrNoNamespace) {
		t.Fatalf("observing a deleted name: %v", err)
	}
	if _, err := k.Run(kernel.Op{Kind: kernel.SetPeers, Namespace: a.ns, Device: "wirenet0"}); !errors.Is(err, kernel.ErrNoNamespace) {
		t.Fatalf("configuring through a deleted name: %v", err)
	}
	other := namespace(t, k, prefix(t)+"f")
	priv, _ := model.NewPrivateKey(r)
	create := kernel.Op{Kind: kernel.CreateDevice, Namespace: other, Device: "wirenet0",
		Create: &kernel.DeviceConfig{PrivateKey: priv, ListenPort: a.port, Alias: "wirenet:test:f"}}
	if _, err := k.Run(create); !errors.Is(err, kernel.ErrPortInUse) {
		t.Fatalf("binding the port the agent's sockets hold: %v", err)
	}
	run(t, k, kernel.Op{Kind: kernel.DeleteNamespace, Namespace: a.ns})
	// A namespace is torn down on a workqueue once its last reference goes
	// (__put_net in net/core/net_namespace.c), so the port frees soon after.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := k.Run(create)
		if err == nil {
			break
		}
		if !errors.Is(err, kernel.ErrPortInUse) || time.Now().After(deadline) {
			t.Fatalf("binding the port once the agent deleted the namespace: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestANameACrashLeftUnmountedIsReplaced leaves a namespace's name as the
// plain file a crash between creating and mounting it leaves, and checks
// that creating the namespace mounts a real one and deleting it removes
// the file.
func TestANameACrashLeftUnmountedIsReplaced(t *testing.T) {
	k := newKernel(t)
	name := prefix(t) + "wedged"
	path := filepath.Join(netnsDir, name)
	if err := os.MkdirAll(netnsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o444); err != nil {
		t.Fatal(err)
	}
	namespace(t, k, name)
	if mounted, err := isNamespace(path); err != nil || !mounted {
		t.Fatalf("after creating over a plain file: namespace %v, %v", mounted, err)
	}
	if _, err := k.Namespace(name, "wirenet:test:"); err != nil {
		t.Fatalf("observing the replaced namespace: %v", err)
	}
	run(t, k, kernel.Op{Kind: kernel.DeleteNamespace, Namespace: name})
	if err := os.WriteFile(path, nil, 0o444); err != nil {
		t.Fatal(err)
	}
	run(t, k, kernel.Op{Kind: kernel.DeleteNamespace, Namespace: name})
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleting a plain-file name left %s: %v", path, err)
	}
}
