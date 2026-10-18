//go:build linux

// Package lab builds a whole deployment inside one Linux kernel: an
// underlay namespace holding a bridge, a namespace per host and per relay
// attached to it, and the real sdn-cp, sdn-relay and sdn-agent processes,
// one per role. The end-to-end tests run on it, and so do the benchmark
// plans when no cloud is at hand.
//
// The control plane runs in the caller's namespace, reached over a veth
// from the underlay, so it can use a database on the caller's loopback.
// The underlay forwards between its own interfaces, so the caller's
// firewall sees only the control plane's traffic, on input.
package lab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netns"

	"sdn.sh/internal/agent/localapi"
	"sdn.sh/internal/api"
	"sdn.sh/internal/cpclient"
	"sdn.sh/internal/model"
)

// Options configure a lab.
type Options struct {
	// Name prefixes every namespace, link and file; at most 6 characters.
	Name string
	// Dir holds binaries' logs, credentials, journals and state.
	Dir string
	// Bin holds sdn-cp, sdn-agent and sdn-relay.
	Bin string
	// Store is sdn-cp's --store.
	Store string
	// CPArgs are extra sdn-cp flags, such as short lease clocks.
	CPArgs []string
	// Log receives a line per step.
	Log io.Writer
}

// Lab is one deployment.
type Lab struct {
	opts   Options
	Admin  *cpclient.Client
	CPURL  string
	Token  string
	net    string // the underlay namespace
	cp     *Proc
	hosts  []*Host
	relays []*Relay
	nextIP byte
	mu     sync.Mutex
	procs  []*Proc
}

// Underlay addressing.
var (
	underlay6  = netip.MustParsePrefix("fd13:213::/64")
	cpLink     = netip.MustParsePrefix("10.213.255.0/30")
	cpRoot     = netip.MustParseAddr("10.213.255.1")
	cpUnderlay = netip.MustParseAddr("10.213.255.2")
	bridgeAddr = netip.MustParseAddr("10.213.0.1")
)

const adminToken = "lab-admin-token-0123456789abcdef"

// Build checks for binaries in dir, building them from the module when
// missing, and returns dir.
func Build(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	root, err := moduleRoot()
	if err != nil {
		return "", err
	}
	cmd := exec.Command("go", "build", "-o", dir+"/", "./cmd/sdn-cp", "./cmd/sdn-agent", "./cmd/sdn-relay", "./cmd/sdnctl")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build: %v\n%s", err, out)
	}
	return dir, nil
}

func moduleRoot() (string, error) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		dir = filepath.Dir(dir)
	}
	return "", errors.New("no go.mod above the lab package")
}

// New builds the underlay and starts the control plane.
func New(opts Options) (*Lab, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("the lab needs root")
	}
	if len(opts.Name) == 0 || len(opts.Name) > 6 {
		return nil, errors.New("lab name must be 1 to 6 characters")
	}
	if opts.Log == nil {
		opts.Log = io.Discard
	}
	if opts.Store == "" {
		opts.Store = "memory"
	}
	l := &Lab{opts: opts, net: opts.Name + "net", nextIP: 10, Token: adminToken}
	l.Purge()
	if err := l.underlay(); err != nil {
		l.Close()
		return nil, err
	}
	if err := l.startCP(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (l *Lab) logf(format string, args ...any) {
	fmt.Fprintf(l.opts.Log, "lab: "+format+"\n", args...)
}

// sh runs a command and returns its error with its output.
func sh(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func nsh(ns string, args ...string) error {
	return sh(append([]string{"ip", "netns", "exec", ns}, args...)...)
}

func (l *Lab) underlay() error {
	cpLinkRoot, cpLinkNS := l.opts.Name+"cp", l.opts.Name+"cpu"
	steps := [][]string{
		{"ip", "netns", "add", l.net},
		{"ip", "-n", l.net, "link", "set", "lo", "up"},
		{"ip", "-n", l.net, "link", "add", "br0", "type", "bridge"},
		{"ip", "-n", l.net, "addr", "add", bridgeAddr.String() + "/24", "dev", "br0"},
		{"ip", "-n", l.net, "addr", "add", "fd13:213::1/64", "dev", "br0", "nodad"},
		{"ip", "-n", l.net, "link", "set", "br0", "up"},
		{"ip", "netns", "exec", l.net, "sysctl", "-qw", "net.ipv4.ip_forward=1"},
		{"ip", "netns", "exec", l.net, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"},
		{"ip", "link", "add", cpLinkRoot, "type", "veth", "peer", "name", cpLinkNS},
		{"ip", "link", "set", cpLinkNS, "netns", l.net},
		{"ip", "addr", "add", cpRoot.String() + "/30", "dev", cpLinkRoot},
		{"ip", "link", "set", cpLinkRoot, "up"},
		{"ip", "-n", l.net, "addr", "add", cpUnderlay.String() + "/30", "dev", cpLinkNS},
		{"ip", "-n", l.net, "link", "set", cpLinkNS, "up"},
		{"ip", "route", "add", "10.213.0.0/24", "via", cpUnderlay.String(), "dev", cpLinkRoot},
	}
	for _, s := range steps {
		if err := sh(s...); err != nil {
			return err
		}
	}
	l.logf("underlay %s up", l.net)
	return nil
}

// Proc is one daemon.
type Proc struct {
	Name string
	Log  string
	cmd  *exec.Cmd
	done chan struct{} // closed once the process is reaped
}

func (l *Lab) spawn(name, ns string, args ...string) (*Proc, error) {
	logPath := filepath.Join(l.opts.Dir, name+".log")
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	if ns != "" {
		// nsenter switches the network namespace alone. ip netns exec
		// would also give the daemon a mount namespace of its own, hiding
		// the namespaces an agent bind-mounts under /run/netns.
		args = append([]string{"nsenter", "--net=/run/netns/" + ns, "--"}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = f, f
	cmd.Env = append(os.Environ(), "SDN_ADMIN_TOKEN="+adminToken)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		f.Close()
		return nil, err
	}
	p := &Proc{Name: name, Log: logPath, cmd: cmd, done: make(chan struct{})}
	go func() { cmd.Wait(); f.Close(); close(p.done) }()
	l.mu.Lock()
	l.procs = append(l.procs, p)
	l.mu.Unlock()
	l.logf("started %s (pid %d)", name, cmd.Process.Pid)
	return p, nil
}

// Stop sends SIGTERM and waits, then kills.
func (p *Proc) Stop() {
	if p.Exited() {
		return
	}
	syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
	}
}

// Kill kills at once, as a crash does.
func (p *Proc) Kill() {
	if p.Exited() {
		return
	}
	syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	<-p.done
}

// Exited reports whether the process has ended.
func (p *Proc) Exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// Tail returns the last lines of the process's log.
func (p *Proc) Tail(n int) string {
	b, _ := os.ReadFile(p.Log)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (l *Lab) bin(name string) string { return filepath.Join(l.opts.Bin, name) }

func (l *Lab) startCP() error {
	addr := netip.AddrPortFrom(cpRoot, 18443)
	args := append([]string{l.bin("sdn-cp"), "--listen", addr.String(), "--telemetry", netip.AddrPortFrom(cpRoot, 19090).String(),
		"--store", l.opts.Store, "--log-format", "json", "--log-level", "debug"}, l.opts.CPArgs...)
	p, err := l.spawn("cp", "", args...)
	if err != nil {
		return err
	}
	l.cp = p
	l.CPURL = "http://" + addr.String()
	l.Admin, err = cpclient.New(l.CPURL, adminToken, cpclient.Options{})
	if err != nil {
		return err
	}
	return waitHTTP("http://"+netip.AddrPortFrom(cpRoot, 19090).String()+"/healthz", 10*time.Second, p)
}

// RestartCP stops the control plane and starts it again on the same store.
func (l *Lab) RestartCP() error {
	l.cp.Stop()
	return l.startCP()
}

// CP returns the control plane's process.
func (l *Lab) CP() *Proc { return l.cp }

func waitHTTP(url string, d time.Duration, p *Proc) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if p != nil && p.Exited() {
			return fmt.Errorf("%s exited:\n%s", p.Name, p.Tail(20))
		}
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("%s did not answer %s", p.Name, url)
}

// node is a namespace on the underlay.
type node struct {
	NS    string
	Addr  netip.Addr
	Addr6 netip.Addr
}

func (l *Lab) addNode(name string) (node, error) {
	l.mu.Lock()
	l.nextIP++
	ip := l.nextIP
	l.mu.Unlock()
	n := node{
		NS:    l.opts.Name + name,
		Addr:  netip.AddrFrom4([4]byte{10, 213, 0, ip}),
		Addr6: netip.AddrFrom16([16]byte{0xfd, 0x13, 0x02, 0x13, 15: ip}),
	}
	link := l.opts.Name + name
	steps := [][]string{
		{"ip", "netns", "add", n.NS},
		{"ip", "-n", n.NS, "link", "set", "lo", "up"},
		{"ip", "-n", l.net, "link", "add", link, "type", "veth", "peer", "name", "eth0", "netns", n.NS},
		{"ip", "-n", l.net, "link", "set", link, "master", "br0", "up"},
		{"ip", "-n", n.NS, "addr", "add", n.Addr.String() + "/24", "dev", "eth0"},
		{"ip", "-n", n.NS, "addr", "add", n.Addr6.String() + "/64", "dev", "eth0", "nodad"},
		{"ip", "-n", n.NS, "link", "set", "eth0", "up"},
		{"ip", "-n", n.NS, "route", "add", "default", "via", bridgeAddr.String()},
	}
	for _, s := range steps {
		if err := sh(s...); err != nil {
			return n, err
		}
	}
	return n, nil
}

// Relay is one relay node.
type Relay struct {
	node
	Name      string
	ID        model.RelayID
	Probe     netip.AddrPort
	Telemetry string
	Proc      *Proc
	creds     string
	state     string
	lab       *Lab
}

// AddRelay registers a relay with the control plane and starts it.
func (l *Lab) AddRelay(ctx context.Context, name string) (*Relay, error) {
	n, err := l.addNode(name)
	if err != nil {
		return nil, err
	}
	r := &Relay{node: n, Name: name, Probe: netip.AddrPortFrom(n.Addr, 7000), lab: l}
	creds, err := l.Admin.CreateRelay(ctx, api.CreateRelay{
		Name: name, Addresses: []api.RelayAddress{{Local: n.Addr, Advertised: n.Addr}},
		PortLo: 20000, PortHi: 29999, ProbePort: 7000,
	})
	if err != nil {
		return nil, err
	}
	r.ID = model.RelayID(creds.ID)
	r.creds = filepath.Join(l.opts.Dir, name+".json")
	r.state = filepath.Join(l.opts.Dir, name+"-state")
	if err := writeJSON(r.creds, creds); err != nil {
		return nil, err
	}
	l.relays = append(l.relays, r)
	return r, r.Start()
}

// Kill kills the relay, as a crash does.
func (r *Relay) Kill() { r.Proc.Kill() }

// Start starts the relay's process.
func (r *Relay) Start() error {
	r.Telemetry = "http://" + netip.AddrPortFrom(r.Addr, 9092).String()
	p, err := r.lab.spawn(r.Name, r.NS, r.lab.bin("sdn-relay"), "--cp", r.lab.CPURL, "--credentials", r.creds,
		"--state", r.state, "--probe", r.Probe.String(), "--telemetry", netip.AddrPortFrom(r.Addr, 9092).String(),
		"--log-format", "json", "--log-level", "debug", "--socket-buffer", "0")
	if err != nil {
		return err
	}
	r.Proc = p
	return waitHTTP(r.Telemetry+"/readyz", 10*time.Second, p)
}

// Host is one agent host.
type Host struct {
	node
	Name      string
	ID        model.HostID
	Socket    string
	Prefix    string
	Telemetry string
	Agent     *Proc
	Local     *localapi.Client
	// NATNS and Public are the NAT in front of a host behind one, and the
	// address it translates to.
	NATNS   string
	Public  netip.Addr
	creds   string
	journal string
	lab     *Lab
	args    []string
}

// AddHost registers a host and starts its agent. args are extra sdn-agent
// flags.
func (l *Lab) AddHost(ctx context.Context, name string, args ...string) (*Host, error) {
	n, err := l.addNode(name)
	if err != nil {
		return nil, err
	}
	h := &Host{node: n, Name: name, Prefix: l.opts.Name + name + "w", lab: l, args: args}
	return h, l.register(ctx, h)
}

func (l *Lab) register(ctx context.Context, h *Host) error {
	creds, err := l.Admin.CreateHost(ctx, api.CreateHost{Name: h.Name})
	if err != nil {
		return err
	}
	h.ID = model.HostID(creds.ID)
	h.creds = filepath.Join(l.opts.Dir, h.Name+".json")
	h.journal = filepath.Join(l.opts.Dir, h.Name+"-journal")
	h.Socket = filepath.Join(l.opts.Dir, h.Name+".sock")
	if err := writeJSON(h.creds, creds); err != nil {
		return err
	}
	h.Local = localapi.NewClient(h.Socket)
	l.hosts = append(l.hosts, h)
	return h.Start()
}

// Start starts the host's agent.
func (h *Host) Start() error {
	h.Telemetry = "http://" + netip.AddrPortFrom(h.Addr, 9091).String()
	args := append([]string{h.lab.bin("sdn-agent"), "--cp", h.lab.CPURL, "--credentials", h.creds,
		"--journal", h.journal, "--socket", h.Socket, "--telemetry", netip.AddrPortFrom(h.Addr, 9091).String(),
		"--prefix", h.Prefix, "--log-format", "json", "--log-level", "debug"}, h.args...)
	p, err := h.lab.spawn(h.Name, h.NS, args...)
	if err != nil {
		return err
	}
	h.Agent = p
	return waitHTTP(h.Telemetry+"/readyz", 15*time.Second, p)
}

// NAT shapes the address translation in front of a host.
type NAT struct {
	// UDPTimeout is how long a UDP mapping outlives its last packet, in
	// both conntrack states.
	UDPTimeout time.Duration
	// Random gives every new mapping a random public port, as a NAT that
	// reassigns ports does.
	Random bool
}

// AddHostBehindNAT registers a host whose underlay traffic leaves through
// a NAT namespace, and starts its agent.
func (l *Lab) AddHostBehindNAT(ctx context.Context, name string, nat NAT, args ...string) (*Host, error) {
	gw, err := l.addNode(name + "n")
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.nextIP++
	k := l.nextIP
	l.mu.Unlock()
	inner := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, k, 0}), 24)
	gwIn := netip.AddrFrom4([4]byte{192, 168, k, 1})
	host := netip.AddrFrom4([4]byte{192, 168, k, 2})
	ns := l.opts.Name + name
	masq := "masquerade"
	if nat.Random {
		masq = "masquerade random"
	}
	timeout := strconv.Itoa(max(int(nat.UDPTimeout/time.Second), 1))
	steps := [][]string{
		{"ip", "netns", "add", ns},
		{"ip", "-n", ns, "link", "set", "lo", "up"},
		{"ip", "-n", gw.NS, "link", "add", "in0", "type", "veth", "peer", "name", "eth0", "netns", ns},
		{"ip", "-n", gw.NS, "addr", "add", gwIn.String() + "/24", "dev", "in0"},
		{"ip", "-n", gw.NS, "link", "set", "in0", "up"},
		{"ip", "-n", ns, "addr", "add", host.String() + "/24", "dev", "eth0"},
		{"ip", "-n", ns, "link", "set", "eth0", "up"},
		{"ip", "-n", ns, "route", "add", "default", "via", gwIn.String()},
		{"ip", "netns", "exec", gw.NS, "sysctl", "-qw", "net.ipv4.ip_forward=1"},
		{"ip", "netns", "exec", gw.NS, "nft", "add table ip nat; add chain ip nat post { type nat hook postrouting priority srcnat; }; " +
			"add rule ip nat post ip saddr " + inner.String() + " oif eth0 " + masq},
		// Conntrack's UDP clocks are per namespace once a rule loads it.
		{"ip", "netns", "exec", gw.NS, "sysctl", "-qw", "net.netfilter.nf_conntrack_udp_timeout=" + timeout},
		{"ip", "netns", "exec", gw.NS, "sysctl", "-qw", "net.netfilter.nf_conntrack_udp_timeout_stream=" + timeout},
		// The caller reaches the agent's telemetry through the underlay;
		// connections it opens are never translated.
		{"ip", "-n", l.net, "route", "add", inner.String(), "via", gw.Addr.String()},
		{"ip", "route", "add", inner.String(), "via", cpUnderlay.String(), "dev", l.opts.Name + "cp"},
	}
	for _, st := range steps {
		if err := sh(st...); err != nil {
			return nil, err
		}
	}
	h := &Host{node: node{NS: ns, Addr: host}, Name: name, Prefix: l.opts.Name + name + "w", lab: l, args: args, NATNS: gw.NS, Public: gw.Addr}
	return h, l.register(ctx, h)
}

// FlushNAT drops every mapping the host's NAT holds, as a NAT that reboots
// or rebinds does.
func (h *Host) FlushNAT() error {
	return nsh(h.NATNS, "conntrack", "-F")
}

// Restart kills the agent, as a crash does, and starts it again.
func (h *Host) Restart() error {
	h.Agent.Kill()
	return h.Start()
}

// Detach asks the host's agent to tear an interface down.
func (h *Host) Detach(ctx context.Context, id model.InterfaceID) (api.LocalInterface, error) {
	return h.Local.Detach(ctx, id)
}

// Namespaces lists the workload namespaces the host's agent has named.
func (h *Host) Namespaces() []string {
	names, _ := filepath.Glob("/run/netns/" + h.Prefix + "*")
	for i, n := range names {
		names[i] = filepath.Base(n)
	}
	return names
}

// DevicePorts lists the UDP ports kernel sockets hold in the host's
// namespace: every WireGuard device's, and nothing a process opened.
func (h *Host) DevicePorts() ([]uint16, error) {
	out, err := exec.Command("ip", "netns", "exec", h.NS, "ss", "-Hulnp").Output()
	if err != nil {
		return nil, err
	}
	var ports []uint16
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || strings.Contains(line, "users:") {
			continue
		}
		if i := strings.LastIndex(f[3], ":"); i >= 0 {
			if p, err := strconv.ParseUint(f[3][i+1:], 10, 16); err == nil {
				ports = append(ports, uint16(p))
			}
		}
	}
	return ports, nil
}

// Attach asks the host's agent for an interface.
func (h *Host) Attach(ctx context.Context, name, network, service string) (api.LocalInterface, error) {
	return h.Local.Attach(ctx, api.LocalAttach{Name: name, Network: network, Service: service})
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Close stops every process and removes everything the lab made.
func (l *Lab) Close() {
	l.mu.Lock()
	procs := l.procs
	l.mu.Unlock()
	for i := len(procs) - 1; i >= 0; i-- {
		procs[i].Stop()
	}
	l.Purge()
}

// Purge removes every namespace and link named for the lab, including
// those a crashed run left behind, and kills processes still inside them.
func (l *Lab) Purge() {
	names, _ := filepath.Glob("/run/netns/" + l.opts.Name + "*")
	for _, path := range names {
		ns := filepath.Base(path)
		out, _ := exec.Command("ip", "netns", "pids", ns).Output()
		for _, pid := range strings.Fields(string(out)) {
			exec.Command("kill", "-9", pid).Run()
		}
	}
	for _, path := range names {
		exec.Command("ip", "netns", "del", filepath.Base(path)).Run()
	}
	exec.Command("ip", "link", "del", l.opts.Name+"cp").Run()
	exec.Command("ip", "route", "del", "10.213.0.0/24").Run()
}

// InNS runs fn on a thread inside a namespace. Sockets fn opens stay in it.
func InNS(name string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	root, err := netns.Get()
	if err != nil {
		return err
	}
	defer root.Close()
	h, err := netns.GetFromName(name)
	if err != nil {
		return err
	}
	defer h.Close()
	if err := netns.Set(h); err != nil {
		return err
	}
	ferr := fn()
	if err := netns.Set(root); err != nil {
		// The thread stays locked and dies with the goroutine, rather than
		// carrying the wrong namespace back to the scheduler.
		runtime.LockOSThread()
		return errors.Join(ferr, err)
	}
	return ferr
}

// Serve accepts TCP connections in a namespace and answers each with reply.
func Serve(ns string, addr netip.AddrPort, reply string) (net.Listener, error) {
	var ln net.Listener
	err := InNS(ns, func() error {
		var err error
		ln, err = net.Listen("tcp", addr.String())
		return err
	})
	if err != nil {
		return nil, err
	}
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
	return ln, nil
}

// Dial connects from a namespace and reads the server's first answer.
func Dial(ns string, addr netip.AddrPort, timeout time.Duration) (string, error) {
	var c net.Conn
	err := InNS(ns, func() error {
		var err error
		c, err = net.DialTimeout("tcp", addr.String(), timeout)
		return err
	})
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(timeout))
	b := make([]byte, 256)
	n, err := c.Read(b)
	return string(b[:n]), err
}

// DialUntil retries Dial until it answers or d passes.
func DialUntil(ns string, addr netip.AddrPort, d time.Duration) (string, error) {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		got, err := Dial(ns, addr, time.Second)
		if err == nil {
			return got, nil
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("no answer from %v within %v: %w", addr, d, last)
}

// Metrics fetches a daemon's metrics text.
func Metrics(url string) (string, error) {
	resp, err := http.Get(url + "/metrics")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// Logs returns every process's log tail, for a failing test.
func (l *Lab) Logs(n int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	for _, p := range l.procs {
		fmt.Fprintf(&b, "==== %s\n%s\n", p.Name, p.Tail(n))
	}
	return b.String()
}
