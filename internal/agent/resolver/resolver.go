//go:build linux

// Package resolver serves each workload namespace's stub resolver: a UDP
// and a TCP socket on 127.0.0.53:53 inside the namespace, answered from the
// zone the agent last computed for it.
//
// The sockets outlive the agent. Under systemd each one goes into the
// service's descriptor store as it opens, and comes back through
// LISTEN_FDS when the agent restarts, so queries sent during a restart wait
// in the socket's buffer and are answered once the agent reloads.
package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/vishvananda/netns"

	"sdn.sh/internal/dns"
)

// Resolver serves every namespace's resolver.
type Resolver struct {
	upstream netip.AddrPort
	store    *fdStore
	log      zerolog.Logger
	queries  *prometheus.CounterVec

	mu     sync.Mutex
	served map[string]*served // by namespace
	zones  map[string]*dns.Zone
	// adopted holds descriptors systemd handed back, until a namespace
	// claims them.
	adopted map[string]*os.File
}

type served struct {
	udp *net.UDPConn
	tcp *net.TCPListener
}

// New returns a resolver forwarding names outside a network's domain to
// upstream, and adopts descriptors systemd handed over.
func New(upstream netip.AddrPort, log zerolog.Logger, reg prometheus.Registerer) *Resolver {
	r := &Resolver{
		upstream: upstream,
		store:    openFDStore(),
		log:      log,
		served:   map[string]*served{},
		zones:    map[string]*dns.Zone{},
		adopted:  listenFDs(),
		queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_agent_resolver_queries_total", Help: "Stub resolver queries by answer.",
		}, []string{"answer"}),
	}
	reg.MustRegister(r.queries)
	if len(r.adopted) > 0 {
		log.Info().Int("descriptors", len(r.adopted)).Msg("resolver adopted sockets from the descriptor store")
	}
	return r
}

// Upstream reads the first nameserver of a resolv.conf, the host's own
// resolver for names outside every network.
func Upstream(path string) (netip.AddrPort, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			a, err := netip.ParseAddr(f[1])
			if err == nil {
				return netip.AddrPortFrom(a, 53), nil
			}
		}
	}
	return netip.AddrPort{}, fmt.Errorf("%s names no nameserver", path)
}

// Sync serves exactly the namespaces zones names, each with its zone. Until
// the agent holds desired state, settled is false and descriptors handed
// over at start wait for their namespaces' zones, their queries queued.
func (r *Resolver) Sync(zones map[string]dns.Zone, settled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := make(map[string]*dns.Zone, len(zones))
	for ns, z := range zones {
		next[ns] = &z
	}
	r.zones = next
	for ns, s := range r.served {
		if _, ok := zones[ns]; !ok {
			s.udp.Close()
			s.tcp.Close()
			delete(r.served, ns)
			r.store.remove(ns + ".udp")
			r.store.remove(ns + ".tcp")
		}
	}
	for ns := range zones {
		if _, ok := r.served[ns]; ok {
			continue
		}
		s, err := r.open(ns)
		if err != nil {
			r.log.Warn().Err(err).Str("namespace", ns).Msg("resolver socket")
			continue
		}
		r.served[ns] = s
		go r.serveUDP(ns, s.udp)
		go r.serveTCP(ns, s.tcp)
	}
	if !settled {
		return
	}
	// Descriptors no namespace claimed belong to namespaces gone while the
	// agent was down.
	for name, f := range r.adopted {
		f.Close()
		r.store.remove(name)
		delete(r.adopted, name)
	}
}

// Close stops serving; the sockets stay in the descriptor store.
func (r *Resolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ns, s := range r.served {
		s.udp.Close()
		s.tcp.Close()
		delete(r.served, ns)
	}
}

func (r *Resolver) zone(ns string) *dns.Zone {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.zones[ns]
}

// open adopts a namespace's sockets from the descriptor store, or binds
// new ones inside it and stores them.
func (r *Resolver) open(ns string) (*served, error) {
	if u, t := r.adopted[ns+".udp"], r.adopted[ns+".tcp"]; u != nil && t != nil {
		delete(r.adopted, ns+".udp")
		delete(r.adopted, ns+".tcp")
		pc, err := net.FilePacketConn(u)
		u.Close()
		if err != nil {
			t.Close()
			return nil, err
		}
		ln, err := net.FileListener(t)
		t.Close()
		if err != nil {
			pc.Close()
			return nil, err
		}
		return &served{udp: pc.(*net.UDPConn), tcp: ln.(*net.TCPListener)}, nil
	}
	var s served
	addr := dns.ListenAddr()
	err := inNamespace(ns, func() error {
		var err error
		if s.udp, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr)); err != nil {
			return err
		}
		if s.tcp, err = net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(addr)); err != nil {
			s.udp.Close()
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for kind, f := range map[string]interface{ File() (*os.File, error) }{"udp": s.udp, "tcp": s.tcp} {
		file, err := f.File()
		if err != nil {
			continue
		}
		if err := r.store.add(ns+"."+kind, file); err != nil {
			r.log.Debug().Err(err).Str("namespace", ns).Msg("descriptor store")
		}
		file.Close()
	}
	return &s, nil
}

func (r *Resolver) serveUDP(ns string, c *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		if resp := r.answer(ns, q, false); resp != nil {
			c.WriteToUDPAddrPort(resp, from)
		}
	}
}

func (r *Resolver) serveTCP(ns string, ln *net.TCPListener) {
	for {
		c, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			for {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp := r.answer(ns, q, true)
				if resp == nil {
					return
				}
				out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
				if _, err := c.Write(append(out, resp...)); err != nil {
					return
				}
			}
		}()
	}
}

// answer returns the response to a query, or nil to send nothing.
func (r *Resolver) answer(ns string, q []byte, tcp bool) []byte {
	z := r.zone(ns)
	if z == nil {
		r.queries.WithLabelValues("no_zone").Inc()
		return nil
	}
	v, resp := z.Answer(q)
	switch v {
	case dns.Reply:
		r.queries.WithLabelValues("local").Inc()
		return resp
	case dns.Forward:
		resp, err := r.forward(q, tcp)
		if err != nil {
			r.queries.WithLabelValues("upstream_failed").Inc()
			return nil
		}
		r.queries.WithLabelValues("upstream").Inc()
		return resp
	}
	r.queries.WithLabelValues("ignored").Inc()
	return nil
}

// forward asks the host's upstream resolver, from the host's namespace.
func (r *Resolver) forward(q []byte, tcp bool) ([]byte, error) {
	if !r.upstream.IsValid() {
		return nil, errors.New("no upstream resolver")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	network := "udp"
	if tcp {
		network = "tcp"
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, network, r.upstream.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	if tcp {
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(l[:]))
		_, err := io.ReadFull(c, resp)
		return resp, err
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	return buf[:n], err
}

// inNamespace runs fn on a thread inside a named namespace; sockets fn
// opens stay there.
func inNamespace(name string, fn func() error) error {
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
		// Leave the thread locked so it dies rather than carry the wrong
		// namespace back to the scheduler.
		runtime.LockOSThread()
		return errors.Join(ferr, err)
	}
	return ferr
}
