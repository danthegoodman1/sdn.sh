// hostbench measures the kernel costs an agent pays per attach and detach, and
// tests what the agent's design rests on:
//
//  1. A device created straight into the workload namespace keeps its UDP
//     socket in the creating namespace, so no move is needed.
//  2. Whether namespace moves overlap under concurrency the way destroys do.
//  3. How fast peers install and remove, alone and with concurrent writers.
//     wg_set_device holds RTNL for the whole call, so concurrency only sizes a
//     host-wide ceiling.
//
// Every namespace and device it creates is named with harnessPrefix, and it
// sweeps that prefix's leftovers before starting. Every netlink call is checked and every step asserts its post-condition. An
// earlier version discarded errors and published the cost of three failures as
// if they were measurements.
package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var origin netns.NsHandle
var okCount atomic.Uint64

// procCPU returns this process's user+system CPU seconds, so a global lock is
// distinguishable from simply running out of cores: under a lock, adding
// writers adds neither throughput nor CPU.
func procCPU() float64 {
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(raw))
	if len(f) < 15 {
		return 0
	}
	u, _ := strconv.ParseFloat(f[13], 64)
	sy, _ := strconv.ParseFloat(f[14], 64)
	return (u + sy) / 100
}

func must(err error, what string) {
	if err != nil {
		fmt.Printf("FATAL %s: %v\n", what, err)
		os.Exit(1)
	}
}

func check(cond bool, what string) {
	if !cond {
		fmt.Printf("ASSERT FAILED: %s\n", what)
		os.Exit(1)
	}
}

func inNS(ns netns.NsHandle, f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := netns.Set(ns); err != nil {
		return err
	}
	defer netns.Set(origin)
	return f()
}

// udpPortOpen reports whether /proc/net/udp in the caller's namespace lists the
// port. /proc/net is per-namespace, so this says where a socket lives.
func udpPortOpen(port int) bool {
	raw, err := os.ReadFile("/proc/thread-self/net/udp")
	if err != nil {
		return false
	}
	want := fmt.Sprintf(":%04X", port)
	for _, line := range strings.Split(string(raw), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) > 1 && strings.HasSuffix(f[1], want) {
			return true
		}
	}
	return false
}

func addInto(name string, ns netns.NsHandle) error {
	la := netlink.NewLinkAttrs()
	la.Name = name
	if ns != 0 {
		la.Namespace = netlink.NsFd(int(ns))
	}
	return netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la})
}

func report(label string, d time.Duration, n int) {
	fmt.Printf("  %-44s %9v  %8.2fms/op  %7.0f/s\n", label, d.Round(time.Millisecond),
		float64(d.Microseconds())/float64(n)/1000, float64(n)/d.Seconds())
}

// harnessPrefix starts the name of every namespace and device hostbench
// creates, so the sweep removes exactly what an aborted run left behind and
// never an operator's own interfaces, such as a wg0 carrying their SSH session.
const harnessPrefix = "hb-"

// sweepLeftovers removes the namespaces and devices an aborted earlier run left
// behind, so the harness can run unattended. It touches only names that start
// with harnessPrefix.
func sweepLeftovers() {
	removed := 0
	entries, _ := os.ReadDir("/run/netns")
	for _, ent := range entries {
		n := ent.Name()
		if !strings.HasPrefix(n, harnessPrefix) {
			continue
		}
		// Delete the devices inside first. A WireGuard device left in a stale
		// namespace keeps its UDP socket bound in the host namespace, so
		// dropping only the namespace name leaves the listen port taken.
		if h, err := netns.GetFromName(n); err == nil {
			_ = inNS(h, func() error {
				links, err := netlink.LinkList()
				if err != nil {
					return nil
				}
				for _, l := range links {
					if l.Type() == "wireguard" && netlink.LinkDel(l) == nil {
						removed++
					}
				}
				return nil
			})
			h.Close()
		}
		if netns.DeleteNamed(n) == nil {
			removed++
		}
	}
	if links, err := netlink.LinkList(); err == nil {
		for _, l := range links {
			if l.Type() == "wireguard" && strings.HasPrefix(l.Attrs().Name, harnessPrefix) && netlink.LinkDel(l) == nil {
				removed++
			}
		}
	}
	if removed > 0 {
		fmt.Printf("swept %d leftover namespaces and devices from an earlier run\n\n", removed)
	}
}

func newNS(name string) netns.NsHandle {
	runtime.LockOSThread()
	h, err := netns.NewNamed(name)
	netns.Set(origin)
	runtime.UnlockOSThread()
	must(err, "netns.NewNamed "+name)
	return h
}

func main() {
	runtime.LockOSThread()
	o, err := netns.Get()
	must(err, "netns.Get")
	origin = o
	runtime.UnlockOSThread()
	fmt.Printf("cpus=%d\n\n", runtime.NumCPU())
	sweepLeftovers()

	ns := newNS(harnessPrefix + "w0")
	defer netns.DeleteNamed(harnessPrefix + "w0")
	var cli *wgctrl.Client
	must(inNS(ns, func() error { var e error; cli, e = wgctrl.New(); return e }), "wgctrl in w0")
	hostCli, err := wgctrl.New()
	must(err, "wgctrl in host ns")

	// ---------------------------------------------------------------- H1
	fmt.Println("== H1: does a device created straight into the workload namespace keep its socket on the host?")
	// Two devices created directly into two workload namespaces, peered through
	// the HOST's loopback. Neither workload namespace has a path to the other,
	// so traffic can only cross if both sockets live in the host namespace.
	nsB := newNS(harnessPrefix + "w1")
	defer netns.DeleteNamed(harnessPrefix + "w1")
	var cliB *wgctrl.Client
	must(inNS(nsB, func() error { var e error; cliB, e = wgctrl.New(); return e }), "wgctrl in w1")
	// Randomized so a socket lingering from an aborted run cannot block this one.
	pA := 41000 + int(time.Now().UnixNano()/1e6)%2000
	pB := pA + 1
	must(addInto(harnessPrefix+"h1a", ns), "LinkAdd h1a with Namespace=w0")
	must(addInto(harnessPrefix+"h1b", nsB), "LinkAdd h1b with Namespace=w1")
	_, err = netlink.LinkByName(harnessPrefix + "h1a")
	check(err != nil, "h1a must NOT be visible in the host namespace")
	must(inNS(ns, func() error { _, e := netlink.LinkByName(harnessPrefix + "h1a"); return e }), "h1a must be visible in w0")

	ka, _ := wgtypes.GeneratePrivateKey()
	kb, _ := wgtypes.GeneratePrivateKey()
	lo := net.IPv4(127, 0, 0, 1)
	m32 := net.CIDRMask(32, 32)
	must(cli.ConfigureDevice(harnessPrefix+"h1a", wgtypes.Config{
		PrivateKey: &ka, ListenPort: intp(pA),
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  kb.PublicKey(),
			Endpoint:   &net.UDPAddr{IP: lo, Port: pB},
			AllowedIPs: []net.IPNet{{IP: net.IPv4(10, 99, 0, 2), Mask: m32}},
		}},
	}), "configure h1a")
	must(cliB.ConfigureDevice(harnessPrefix+"h1b", wgtypes.Config{
		PrivateKey: &kb, ListenPort: intp(pB),
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  ka.PublicKey(),
			Endpoint:   &net.UDPAddr{IP: lo, Port: pA},
			AllowedIPs: []net.IPNet{{IP: net.IPv4(10, 99, 0, 1), Mask: m32}},
		}},
	}), "configure h1b")
	setup := func(h netns.NsHandle, dev, addr string) error {
		return inNS(h, func() error {
			l, e := netlink.LinkByName(dev)
			if e != nil {
				return e
			}
			a, e := netlink.ParseAddr(addr)
			if e != nil {
				return e
			}
			if e := netlink.AddrAdd(l, a); e != nil {
				return e
			}
			if e := netlink.LinkSetUp(l); e != nil {
				return e
			}
			_, dst, e := net.ParseCIDR("10.99.0.0/24")
			if e != nil {
				return e
			}
			return netlink.RouteAdd(&netlink.Route{LinkIndex: l.Attrs().Index, Dst: dst})
		})
	}
	must(setup(ns, harnessPrefix+"h1a", "10.99.0.1/32"), "address and up h1a")
	must(setup(nsB, harnessPrefix+"h1b", "10.99.0.2/32"), "address and up h1b")
	// Both sockets exist now, so arming keepalive produces an initiation that
	// has somewhere to land. Only h1a arms it. Two peers on one host that both
	// initiate at once collide, each answering the other and invalidating its
	// own handshake, and their retries stay in lockstep: the 5s retry plus up to
	// 333ms of jitter lands in a timer-wheel level that rounds to 512ms at
	// HZ=1000, so both usually fire on the same tick again.
	ka5 := 5 * time.Second
	must(cli.ConfigureDevice(harnessPrefix+"h1a", wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey: kb.PublicKey(), UpdateOnly: true, PersistentKeepaliveInterval: &ka5,
	}}}), "keepalive h1a")

	hostHasA, hostHasB := udpPortOpen(pA), udpPortOpen(pB)
	nsHasA := false
	must(inNS(ns, func() error { nsHasA = udpPortOpen(pA); return nil }), "read udp table in w0")
	fmt.Printf("   sockets in the host namespace: %v and %v   in the workload namespace: %v\n",
		hostHasA, hostHasB, nsHasA)
	// w0 holds no interface but h1a, so a completed handshake proves the
	// encrypted side went out through the host.
	// Push a packet so WireGuard has a reason to initiate.
	must(inNS(ns, func() error {
		c, e := net.Dial("udp", "10.99.0.2:9")
		if e != nil {
			return e
		}
		defer c.Close()
		_, e = c.Write([]byte("x"))
		return e
	}), "send through h1a")
	ok := false
	for i := 0; i < 300; i++ {
		d, e := cli.Device(harnessPrefix + "h1a")
		must(e, "read h1a")
		if len(d.Peers) == 1 && !d.Peers[0].LastHandshakeTime.IsZero() {
			ok = true
			fmt.Printf("   handshake completed through the host loopback after %dms, rx %d B tx %d B\n",
				i*50, d.Peers[0].ReceiveBytes, d.Peers[0].TransmitBytes)
			_ = ok
			break
		}
		if i == 299 {
			fmt.Printf("   no handshake: peers=%d tx=%d\n", len(d.Peers), d.Peers[0].TransmitBytes)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ok && hostHasA && !nsHasA {
		fmt.Println("   H1 HOLDS: create straight into the namespace; no move is needed")
	} else {
		fmt.Printf("   H1 FAILS (traffic=%v hostsocket=%v nssocket=%v): the move stays required\n", ok, hostHasA, nsHasA)
	}
	check(ok && hostHasA && !nsHasA, "H1: socket must stay in the creating namespace and traffic must cross")
	for _, x := range []struct {
		h netns.NsHandle
		d string
	}{{ns, harnessPrefix + "h1a"}, {nsB, harnessPrefix + "h1b"}} {
		must(inNS(x.h, func() error {
			l, e := netlink.LinkByName(x.d)
			if e != nil {
				return e
			}
			return netlink.LinkDel(l)
		}), "del "+x.d)
	}

	// ---------------------------------------------------------------- per-op
	const n = 200
	names := make([]string, n)
	devKeys := make([]wgtypes.Key, n)
	// Peers' public keys are derived here, outside every timer. An agent receives
	// them from the control plane and never pays the scalar multiplication that
	// PublicKey() performs.
	peerPubs := make([]wgtypes.Key, n)
	for i := range names {
		names[i] = harnessPrefix + "p" + strconv.Itoa(i)
		devKeys[i], _ = wgtypes.GeneratePrivateKey()
		k, _ := wgtypes.GeneratePrivateKey()
		peerPubs[i] = k.PublicKey()
	}
	ip := net.IPNet{IP: net.IPv4(10, 42, 0, 9), Mask: net.CIDRMask(32, 32)}

	fmt.Println("\n== each step on its own, every call checked")
	t := time.Now()
	for _, nm := range names {
		must(addInto(nm, 0), "LinkAdd "+nm)
	}
	report("LinkAdd into the host namespace", time.Since(t), n)

	t = time.Now()
	for i := range names {
		must(hostCli.ConfigureDevice(names[i], wgtypes.Config{
			PrivateKey: &devKeys[i], ListenPort: intp(42000 + i),
		}), "key "+names[i])
	}
	report("set private key + listen port", time.Since(t), n)

	t = time.Now()
	for i := range names {
		must(hostCli.ConfigureDevice(names[i], wgtypes.Config{Peers: []wgtypes.PeerConfig{{
			PublicKey: peerPubs[i], AllowedIPs: []net.IPNet{ip},
		}}}), "peer "+names[i])
	}
	report("add 1 peer (keyed device, distinct peer key)", time.Since(t), n)

	dv, err := hostCli.Device(names[0])
	must(err, "read p0")
	check(len(dv.Peers) == 1, "the peer must actually be present")
	check(dv.Peers[0].PublicKey == peerPubs[0], "the peer must be the one we added")

	t = time.Now()
	for i := range names {
		must(hostCli.ConfigureDevice(names[i], wgtypes.Config{ReplacePeers: true}), "flush "+names[i])
	}
	report("flush peers", time.Since(t), n)

	links := make([]netlink.Link, n)
	for i, nm := range names {
		links[i], err = netlink.LinkByName(nm)
		must(err, "LinkByName "+nm)
	}
	t = time.Now()
	for i := range links {
		must(netlink.LinkSetNsFd(links[i], int(ns)), "move in "+names[i])
	}
	report("LinkSetNsFd host -> workload, serial", time.Since(t), n)

	t = time.Now()
	for _, nm := range names {
		must(inNS(ns, func() error {
			l, e := netlink.LinkByName(nm)
			if e != nil {
				return e
			}
			return netlink.LinkSetNsFd(l, int(origin))
		}), "move out "+nm)
	}
	report("LinkSetNsFd workload -> host, serial", time.Since(t), n)

	t = time.Now()
	for _, nm := range names {
		l, e := netlink.LinkByName(nm)
		must(e, "LinkByName "+nm)
		must(netlink.LinkDel(l), "del "+nm)
	}
	report("LinkDel, serial", time.Since(t), n)

	// ---------------------------------------------------------------- H2
	fmt.Println("\n== H2: do namespace moves overlap under concurrency the way destroys do?")
	for _, c := range []int{1, 4, 16, 64} {
		for i := 0; i < n; i++ {
			must(addInto(names[i], 0), "LinkAdd")
		}
		idx := make(chan int, n)
		for i := 0; i < n; i++ {
			idx <- i
		}
		close(idx)
		okCount.Store(0)
		var wg sync.WaitGroup
		t = time.Now()
		for g := 0; g < c; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range idx {
					l, e := netlink.LinkByName(names[i])
					if e != nil {
						continue
					}
					if netlink.LinkSetNsFd(l, int(ns)) == nil {
						okCount.Add(1)
					}
				}
			}()
		}
		wg.Wait()
		check(int(okCount.Load()) == n, fmt.Sprintf("all %d moves must succeed, %d did", n, okCount.Load()))
		report(fmt.Sprintf("move into a namespace, %d goroutines", c), time.Since(t), n)
		must(inNS(ns, func() error {
			for _, nm := range names {
				if l, e := netlink.LinkByName(nm); e == nil {
					if e := netlink.LinkDel(l); e != nil {
						return e
					}
				}
			}
			return nil
		}), "cleanup moves")
	}

	fmt.Println("\n== for comparison: destroy under the same concurrency")
	for _, c := range []int{1, 4, 16, 64} {
		for i := 0; i < n; i++ {
			must(addInto(names[i], 0), "LinkAdd")
		}
		idx := make(chan string, n)
		for i := 0; i < n; i++ {
			idx <- names[i]
		}
		close(idx)
		okCount.Store(0)
		var wg sync.WaitGroup
		t = time.Now()
		for g := 0; g < c; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for nm := range idx {
					if l, e := netlink.LinkByName(nm); e == nil {
						if netlink.LinkDel(l) == nil {
							okCount.Add(1)
						}
					}
				}
			}()
		}
		wg.Wait()
		check(int(okCount.Load()) == n, fmt.Sprintf("all %d destroys must succeed, %d did", n, okCount.Load()))
		report(fmt.Sprintf("destroy, %d goroutines", c), time.Since(t), n)
	}

	// ---------------------------------------------------------------- attach shapes
	fmt.Println("\n== whole attach, two shapes, 64-way concurrent")
	for _, shape := range []string{"create-into-ns", "create-then-move"} {
		idx := make(chan int, n)
		for i := 0; i < n; i++ {
			idx <- i
		}
		close(idx)
		okCount.Store(0)
		var wg sync.WaitGroup
		t = time.Now()
		for g := 0; g < 64; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range idx {
					nm := harnessPrefix + "a" + strconv.Itoa(i)
					if shape == "create-into-ns" {
						if addInto(nm, ns) != nil {
							continue
						}
					} else {
						if addInto(nm, 0) != nil {
							continue
						}
						l, e := netlink.LinkByName(nm)
						if e != nil {
							continue
						}
						if netlink.LinkSetNsFd(l, int(ns)) != nil {
							continue
						}
					}
					k, _ := wgtypes.GeneratePrivateKey()
					if cli.ConfigureDevice(nm, wgtypes.Config{
						PrivateKey: &k, ListenPort: intp(43000 + i),
						Peers: []wgtypes.PeerConfig{{
							PublicKey: peerPubs[i], AllowedIPs: []net.IPNet{ip},
						}},
					}) == nil {
						okCount.Add(1)
					}
				}
			}()
		}
		wg.Wait()
		check(int(okCount.Load()) == n, fmt.Sprintf("all %d attaches must succeed, %d did", n, okCount.Load()))
		report(shape, time.Since(t), n)
		must(inNS(ns, func() error {
			for i := 0; i < n; i++ {
				if l, e := netlink.LinkByName(harnessPrefix + "a" + strconv.Itoa(i)); e == nil {
					if e := netlink.LinkDel(l); e != nil {
						return e
					}
				}
			}
			return nil
		}), "cleanup attach")
	}

	// ---------------------------------------------------------------- peer scaling
	fmt.Println("\n== K peers in one netlink call, on a keyed device")
	big := make([]wgtypes.Key, 2000)
	for i := range big {
		big[i], _ = wgtypes.GeneratePrivateKey()
	}
	// A fresh device per row: ReplacePeers inside the timer would also charge
	// the row for removing the previous row's peers.
	for ki, k := range []int{1, 10, 100, 1000, 2000} {
		dev := harnessPrefix + "kdev" + strconv.Itoa(ki)
		must(addInto(dev, 0), "LinkAdd "+dev)
		dk, _ := wgtypes.GeneratePrivateKey()
		must(hostCli.ConfigureDevice(dev, wgtypes.Config{PrivateKey: &dk, ListenPort: intp(44000 + ki)}), "key "+dev)
		peers := make([]wgtypes.PeerConfig, k)
		for i := range peers {
			peers[i] = wgtypes.PeerConfig{
				PublicKey:  big[i].PublicKey(),
				AllowedIPs: []net.IPNet{{IP: net.IPv4(10, 43, byte(i>>8), byte(i)), Mask: net.CIDRMask(32, 32)}},
			}
		}
		t = time.Now()
		must(hostCli.ConfigureDevice(dev, wgtypes.Config{Peers: peers}), "K peers")
		d := time.Since(t)
		got, e := hostCli.Device(dev)
		must(e, "read "+dev)
		check(len(got.Peers) == k, fmt.Sprintf("device must hold %d peers, holds %d", k, len(got.Peers)))
		fmt.Printf("  K=%-5d %9v  %8.1fus/peer\n", k, d.Round(time.Millisecond), float64(d.Microseconds())/float64(k))
		l, e := netlink.LinkByName(dev)
		must(e, "find "+dev)
		must(netlink.LinkDel(l), "del "+dev)
	}

	// ---------------------------------------------------------------- convergence batch
	fmt.Println("\n== convergence batch: one peer into each of H namespaces on this host")
	maxH := 400
	type slot struct {
		dev string
		ns  netns.NsHandle
		cli *wgctrl.Client
	}
	slots := make([]*slot, 0, maxH)
	for i := 0; i < maxH; i++ {
		nsName := harnessPrefix + "s" + strconv.Itoa(i)
		dev := harnessPrefix + "w" + strconv.Itoa(i)
		h := newNS(nsName)
		must(addInto(dev, h), "LinkAdd into "+nsName)
		var c *wgctrl.Client
		must(inNS(h, func() error { var e error; c, e = wgctrl.New(); return e }), "wgctrl in "+nsName)
		dk, _ := wgtypes.GeneratePrivateKey()
		must(c.ConfigureDevice(dev, wgtypes.Config{PrivateKey: &dk, ListenPort: intp(45000 + i)}), "key "+dev)
		slots = append(slots, &slot{dev: dev, ns: h, cli: c})
	}
	fmt.Printf("   %d namespaces ready\n", len(slots))
	for _, h := range []int{40, 100, 400} {
		if h > len(slots) {
			continue
		}
		// Fresh keys every round: re-adding a peer that already exists skips the
		// static-static precompute and reads as a cheaper operation than an add.
		round := make([]wgtypes.Key, h)
		for i := range round {
			k, _ := wgtypes.GeneratePrivateKey()
			round[i] = k.PublicKey()
		}
		t = time.Now()
		for i, s := range slots[:h] {
			must(s.cli.ConfigureDevice(s.dev, wgtypes.Config{Peers: []wgtypes.PeerConfig{{
				PublicKey:         round[i],
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{ip},
			}}}), "batch peer")
		}
		d := time.Since(t)
		fmt.Printf("  H=%-5d %9v  %8.1fus/op\n", h, d.Round(time.Millisecond), float64(d.Microseconds())/float64(h))
	}
	for i, s := range slots {
		s.cli.Close()
		s.ns.Close()
		must(netns.DeleteNamed(harnessPrefix+"s"+strconv.Itoa(i)), "delete ns")
	}
	// ------------------------------------------------------------ peer concurrency
	fmt.Println("\n== do peer operations scale with cores, or share one host-wide lane?")
	{
		const perG = 500
		for _, c := range []int{1, 2, 4, 8} {
			devs := make([]string, c)
			clis := make([]*wgctrl.Client, c)
			for i := 0; i < c; i++ {
				devs[i] = harnessPrefix + "pc" + strconv.Itoa(i)
				must(addInto(devs[i], 0), "LinkAdd "+devs[i])
				dk, _ := wgtypes.GeneratePrivateKey()
				cl, e := wgctrl.New()
				must(e, "wgctrl")
				clis[i] = cl
				must(cl.ConfigureDevice(devs[i], wgtypes.Config{PrivateKey: &dk, ListenPort: intp(46000 + i)}), "key")
			}
			// Public keys precomputed outside the timer. PublicKey() is the
			// Curve25519 scalar multiplication, which parallelizes; leaving it
			// inside the loop reads as netlink scaling. GeneratePrivateKey only
			// reads random bytes.
			pre := make([][]wgtypes.Key, c)
			for g := range pre {
				pre[g] = make([]wgtypes.Key, perG)
				for j := range pre[g] {
					k, _ := wgtypes.GeneratePrivateKey()
					pre[g][j] = k.PublicKey()
				}
			}
			okCount.Store(0)
			cpu0 := procCPU()
			var wg sync.WaitGroup
			t = time.Now()
			for g := 0; g < c; g++ {
				wg.Add(1)
				go func(g int) {
					defer wg.Done()
					for j := 0; j < perG; j++ {
						if clis[g].ConfigureDevice(devs[g], wgtypes.Config{Peers: []wgtypes.PeerConfig{{
							PublicKey: pre[g][j],
							AllowedIPs: []net.IPNet{{
								IP: net.IPv4(10, 50, byte(g), byte(j>>8)), Mask: net.CIDRMask(24, 32)},
							},
						}}}) == nil {
							okCount.Add(1)
						}
					}
				}(g)
			}
			wg.Wait()
			d := time.Since(t)
			cpu := procCPU() - cpu0
			total := c * perG
			check(int(okCount.Load()) == total, fmt.Sprintf("all %d peer adds must succeed, %d did", total, okCount.Load()))
			fmt.Printf("  %2d writer(s): %8v  %7.0f peer-ops/s  %6.1fus/op  cpu %5.2fs  (%.2f cores busy)\n",
				c, d.Round(time.Millisecond), float64(total)/d.Seconds(),
				float64(d.Microseconds())/float64(total), cpu, cpu/d.Seconds())
			for i := 0; i < c; i++ {
				clis[i].Close()
				l, e := netlink.LinkByName(devs[i])
				must(e, "find")
				must(netlink.LinkDel(l), "del")
			}
		}
	}

	// wgctrl splits any config over 32 peers into separate netlink messages
	// (peerBatchChunk = 32), so a "2000-peer call" releases the lock 60-odd
	// times and a waiter only ever queues behind one chunk. Saturating with
	// single-peer adds from several writers keeps the lock hot instead.
	fmt.Println("\n== does a device create stall while writers saturate peer adds? (the RTNL question)")
	{
		const writers = 8
		devs := make([]string, writers)
		clis := make([]*wgctrl.Client, writers)
		pre := make([][]wgtypes.Key, writers)
		for i := 0; i < writers; i++ {
			devs[i] = harnessPrefix + "sat" + strconv.Itoa(i)
			must(addInto(devs[i], 0), "LinkAdd "+devs[i])
			dk, _ := wgtypes.GeneratePrivateKey()
			cl, e := wgctrl.New()
			must(e, "wgctrl")
			clis[i] = cl
			must(cl.ConfigureDevice(devs[i], wgtypes.Config{PrivateKey: &dk, ListenPort: intp(48100 + i)}), "key")
			pre[i] = make([]wgtypes.Key, 4000)
			for j := range pre[i] {
				k, _ := wgtypes.GeneratePrivateKey()
				pre[i][j] = k.PublicKey()
			}
		}
		timeCreate := func(nm string) time.Duration {
			t := time.Now()
			must(addInto(nm, 0), "add "+nm)
			d := time.Since(t)
			l, e := netlink.LinkByName(nm)
			must(e, "find "+nm)
			must(netlink.LinkDel(l), "del "+nm)
			return d
		}
		var base []time.Duration
		for i := 0; i < 20; i++ {
			base = append(base, timeCreate(harnessPrefix+"cb"+strconv.Itoa(i)))
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var satOps atomic.Uint64
		for g := 0; g < writers; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for j := 0; ; j++ {
					select {
					case <-stop:
						return
					default:
					}
					if clis[g].ConfigureDevice(devs[g], wgtypes.Config{Peers: []wgtypes.PeerConfig{{
						PublicKey:  pre[g][j%len(pre[g])],
						AllowedIPs: []net.IPNet{{IP: net.IPv4(10, 52, byte(g), byte(j)), Mask: net.CIDRMask(32, 32)}},
					}}}) == nil {
						satOps.Add(1)
					}
				}
			}(g)
		}
		time.Sleep(300 * time.Millisecond)
		var during []time.Duration
		for i := 0; i < 20; i++ {
			during = append(during, timeCreate(harnessPrefix+"cd"+strconv.Itoa(i)))
		}
		close(stop)
		wg.Wait()
		fmt.Printf("  saturating writers managed %d peer adds meanwhile\n", satOps.Load())
		stat := func(v []time.Duration) (time.Duration, time.Duration) {
			var sum, max time.Duration
			for _, x := range v {
				sum += x
				if x > max {
					max = x
				}
			}
			return sum / time.Duration(len(v)), max
		}
		ba, bm := stat(base)
		da, dm := stat(during)
		fmt.Printf("  device create, idle host:            mean %8v  max %8v\n", ba.Round(time.Microsecond), bm.Round(time.Microsecond))
		fmt.Printf("  device create, 8 writers saturating: mean %8v  max %8v  (%.1fx slower)\n",
			da.Round(time.Microsecond), dm.Round(time.Microsecond), float64(da)/float64(ba))
		fmt.Println("  (wg_set_device holds rtnl_lock for the whole call: netlink.c, rtnl_lock() then device_update_lock)")
		for i := 0; i < writers; i++ {
			clis[i].Close()
			l, e := netlink.LinkByName(devs[i])
			must(e, "find")
			must(netlink.LinkDel(l), "del")
		}
	}

	// ------------------------------------------------------------ detach cost
	fmt.Println("\n== peer removal: wg_peer_remove waits an RCU grace period per peer (peer.c)")
	{
		const np = 100
		mk := func(dev string, port int) (*wgctrl.Client, []wgtypes.Key) {
			must(addInto(dev, 0), "LinkAdd "+dev)
			dk, _ := wgtypes.GeneratePrivateKey()
			cl, e := wgctrl.New()
			must(e, "wgctrl")
			must(cl.ConfigureDevice(dev, wgtypes.Config{PrivateKey: &dk, ListenPort: intp(49000 + port)}), "key")
			ks := make([]wgtypes.Key, np)
			peers := make([]wgtypes.PeerConfig, np)
			for i := range ks {
				k, _ := wgtypes.GeneratePrivateKey()
				ks[i] = k.PublicKey()
				peers[i] = wgtypes.PeerConfig{
					PublicKey:  ks[i],
					AllowedIPs: []net.IPNet{{IP: net.IPv4(10, 53, byte(port), byte(i)), Mask: net.CIDRMask(32, 32)}},
				}
			}
			must(cl.ConfigureDevice(dev, wgtypes.Config{Peers: peers}), "fill")
			return cl, ks
		}
		c1, ks := mk(harnessPrefix+"rm1", 1)
		t = time.Now()
		for _, k := range ks {
			must(c1.ConfigureDevice(harnessPrefix+"rm1", wgtypes.Config{Peers: []wgtypes.PeerConfig{{
				PublicKey: k, Remove: true,
			}}}), "remove one")
		}
		one := time.Since(t)
		report(fmt.Sprintf("remove %d peers, one call each", np), one, np)

		c2, _ := mk(harnessPrefix+"rm2", 2)
		t = time.Now()
		must(c2.ConfigureDevice(harnessPrefix+"rm2", wgtypes.Config{ReplacePeers: true}), "remove all")
		all := time.Since(t)
		fmt.Printf("  %-44s %9v  %8.2fms total  %.0fx cheaper\n", "remove all "+strconv.Itoa(np)+" in one call",
			all.Round(time.Millisecond), float64(all.Microseconds())/1000, float64(one)/float64(all))
		for _, d := range []struct {
			c *wgctrl.Client
			n string
		}{{c1, harnessPrefix + "rm1"}, {c2, harnessPrefix + "rm2"}} {
			d.c.Close()
			l, e := netlink.LinkByName(d.n)
			must(e, "find")
			must(netlink.LinkDel(l), "del")
		}
	}

	fmt.Println("\n== peer rate while netdev churns (weak direction, kept for comparison)")
	{
		const reps = 120
		must(addInto(harnessPrefix+"lane", 0), "LinkAdd lane")
		lk, _ := wgtypes.GeneratePrivateKey()
		must(hostCli.ConfigureDevice(harnessPrefix+"lane", wgtypes.Config{PrivateKey: &lk, ListenPort: intp(47000)}), "key lane")
		peerOnly := func() time.Duration {
			pubs := make([]wgtypes.Key, reps)
			for j := range pubs {
				k, _ := wgtypes.GeneratePrivateKey()
				pubs[j] = k.PublicKey()
			}
			t := time.Now()
			for j := 0; j < reps; j++ {
				must(hostCli.ConfigureDevice(harnessPrefix+"lane", wgtypes.Config{Peers: []wgtypes.PeerConfig{{
					PublicKey:  pubs[j],
					AllowedIPs: []net.IPNet{{IP: net.IPv4(10, 51, 0, byte(j)), Mask: net.CIDRMask(32, 32)}},
				}}}), "peer")
			}
			return time.Since(t)
		}
		netdevOnly := func() time.Duration {
			t := time.Now()
			for j := 0; j < reps; j++ {
				nm := harnessPrefix + "ln" + strconv.Itoa(j)
				must(addInto(nm, 0), "add")
				l, e := netlink.LinkByName(nm)
				must(e, "find")
				must(netlink.LinkDel(l), "del")
			}
			return time.Since(t)
		}
		alone := peerOnly()
		ndAlone := netdevOnly()
		var wg sync.WaitGroup
		var together time.Duration
		wg.Add(2)
		t = time.Now()
		go func() { defer wg.Done(); together = peerOnly() }()
		go func() { defer wg.Done(); netdevOnly() }()
		wg.Wait()
		both := time.Since(t)
		fmt.Printf("  peer ops alone:            %8v  %6.0f/s\n", alone.Round(time.Millisecond), float64(reps)/alone.Seconds())
		fmt.Printf("  netdev create+del alone:   %8v  %6.0f/s\n", ndAlone.Round(time.Millisecond), float64(reps)/ndAlone.Seconds())
		fmt.Printf("  peer ops while netdev runs:%8v  %6.0f/s  (wall for both: %v)\n",
			together.Round(time.Millisecond), float64(reps)/together.Seconds(), both.Round(time.Millisecond))
		l, e := netlink.LinkByName(harnessPrefix + "lane")
		must(e, "find lane")
		must(netlink.LinkDel(l), "del lane")
	}

	fmt.Println("\nall assertions passed")
}

func intp(i int) *int { return &i }
