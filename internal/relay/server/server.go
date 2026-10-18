// Package server runs a relay: one UDP socket per direction's port, read
// and written in batches, decisions from the deterministic core, a durable
// registration log, and a long poll for the control plane's port table.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"sdn.sh/internal/api"
	relaycore "sdn.sh/internal/relay/core"
)

// ControlPlane is the relay's side of the control plane's API.
type ControlPlane interface {
	RelayState(ctx context.Context, since uint64, wait time.Duration) (api.RelayState, error)
}

// Config holds a relay's settings.
type Config struct {
	Core relaycore.Config
	// Probe is where agents' probes arrive.
	Probe netip.AddrPort
	// Batch is how many datagrams one read or write moves.
	Batch int
	// SocketBuffer sizes each socket's receive and send buffers.
	SocketBuffer int
	// PollWait bounds one long poll; it exceeds the server's poll timeout.
	PollWait time.Duration
	// SnapshotEvery is how often the state file is rewritten and the log
	// emptied.
	SnapshotEvery time.Duration
}

// DefaultConfig returns production settings.
func DefaultConfig() Config {
	return Config{
		Core:          relaycore.DefaultConfig(),
		Batch:         64,
		SocketBuffer:  8 << 20,
		PollWait:      40 * time.Second,
		SnapshotEvery: 10 * time.Second,
	}
}

// Server is one relay.
type Server struct {
	cfg  Config
	cp   ControlPlane
	disk *Disk
	log  zerolog.Logger
	m    *Metrics

	mu    sync.Mutex // guards table
	table *relaycore.Table

	smu   sync.RWMutex // guards socks
	socks map[netip.AddrPort]*sock

	regs     chan relaycore.Registration
	snapshot chan struct{}
	ready    chan struct{}
}

type sock struct {
	local netip.AddrPort
	conn  *net.UDPConn
	pc    batchConn
}

// batchConn is satisfied by *ipv4.PacketConn and *ipv6.PacketConn, whose
// Message types are aliases of one struct.
type batchConn interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

// New opens the relay's disk and restores its table.
func New(cfg Config, cp ControlPlane, dir string, m *Metrics, log zerolog.Logger) (*Server, error) {
	disk, st, regs, err := OpenDisk(dir)
	if err != nil {
		return nil, fmt.Errorf("relay state: %w", err)
	}
	t := relaycore.New(cfg.Core)
	t.Restore(st, regs)
	s := &Server{
		cfg: cfg, cp: cp, disk: disk, log: log, m: m, table: t,
		socks:    map[netip.AddrPort]*sock{},
		regs:     make(chan relaycore.Registration, 4096),
		snapshot: make(chan struct{}, 1),
		ready:    make(chan struct{}),
	}
	m.attach(s)
	log.Info().Uint64("generation", st.Generation).Int("ports", len(st.Ports)).Int("logged", len(regs)).Msg("relay state restored")
	return s, nil
}

// Ready closes once the restored table's ports are bound.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// Run binds the table's ports, answers probes, polls the control plane and
// commits registrations until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	defer s.disk.Close()
	s.mu.Lock()
	dirs := s.table.Dirs()
	s.mu.Unlock()
	if err := s.sync(dirs); err != nil {
		return err
	}
	if s.cfg.Probe.IsValid() {
		probe, err := s.listen(s.cfg.Probe)
		if err != nil {
			return fmt.Errorf("probe port: %w", err)
		}
		go s.answerProbes(probe)
		defer probe.conn.Close()
	}
	// The restored table is the state file from here on.
	s.requestSnapshot()
	close(s.ready)
	errs := make(chan error, 1)
	go func() { errs <- s.committer(ctx) }()
	go s.poll(ctx)
	defer s.closeAll()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		return err
	}
}

// poll long-polls the control plane for the port table.
func (s *Server) poll(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		s.mu.Lock()
		since := s.table.Generation()
		s.mu.Unlock()
		asked := time.Now()
		st, err := s.cp.RelayState(ctx, since, s.cfg.PollWait)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Warn().Err(err).Dur("retry", backoff).Msg("port-table poll failed; serving the table held")
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 15*time.Second)
			continue
		}
		backoff = time.Second
		if st.Generation <= since {
			// Nothing newer. A control plane answering that at once,
			// rather than at its poll timeout, gets a pause, not a spin.
			if time.Since(asked) < time.Second {
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
				}
			}
			continue
		}
		s.mu.Lock()
		held := s.table.Load(time.Now(), st)
		dirs := s.table.Dirs()
		s.mu.Unlock()
		for _, r := range held {
			s.enqueue(r)
		}
		if err := s.sync(dirs); err != nil {
			s.log.Error().Err(err).Msg("binding the port table")
		}
		s.requestSnapshot()
		s.m.generation.Set(float64(st.Generation))
		s.log.Info().Uint64("generation", st.Generation).Int("ports", len(st.Ports)).Int("held_registrations", len(held)).Msg("port table loaded")
	}
}

// sync opens a socket for every direction's port and closes the rest.
func (s *Server) sync(dirs []*relaycore.Dir) error {
	want := map[netip.AddrPort]bool{}
	for _, d := range dirs {
		want[d.Local] = true
	}
	s.smu.Lock()
	var gone []*sock
	for local, k := range s.socks {
		if !want[local] {
			gone = append(gone, k)
			delete(s.socks, local)
		}
	}
	var errs []error
	var opened []*sock
	for local := range want {
		if _, ok := s.socks[local]; ok {
			continue
		}
		k, err := s.listen(local)
		if err != nil {
			errs = append(errs, fmt.Errorf("bind %v: %w", local, err))
			continue
		}
		s.socks[local] = k
		opened = append(opened, k)
	}
	s.smu.Unlock()
	for _, k := range gone {
		k.conn.Close()
	}
	for _, k := range opened {
		go s.serve(k)
	}
	s.m.ports.Set(float64(len(want)))
	return errors.Join(errs...)
}

func (s *Server) listen(local netip.AddrPort) (*sock, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var err error
		if e := c.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}); e != nil {
			return e
		}
		return err
	}}
	network := "udp4"
	if local.Addr().Is6() {
		network = "udp6"
	}
	c, err := lc.ListenPacket(context.Background(), network, local.String())
	if err != nil {
		return nil, err
	}
	u := c.(*net.UDPConn)
	if s.cfg.SocketBuffer > 0 {
		u.SetReadBuffer(s.cfg.SocketBuffer)
		u.SetWriteBuffer(s.cfg.SocketBuffer)
	}
	var pc batchConn = ipv4.NewPacketConn(u)
	if network == "udp6" {
		pc = ipv6.NewPacketConn(u)
	}
	return &sock{local: local, conn: u, pc: pc}, nil
}

func (s *Server) sockFor(local netip.AddrPort) *sock {
	s.smu.RLock()
	defer s.smu.RUnlock()
	return s.socks[local]
}

func (s *Server) closeAll() {
	s.smu.Lock()
	defer s.smu.Unlock()
	for local, k := range s.socks {
		k.conn.Close()
		delete(s.socks, local)
	}
}

// serve reads one port in batches until its socket closes, and writes each
// forward through the socket of the port the core names.
func (s *Server) serve(k *sock) {
	batch := max(s.cfg.Batch, 1)
	rms := make([]ipv4.Message, batch)
	for i := range rms {
		rms[i].Buffers = [][]byte{make([]byte, 2048)}
	}
	type out struct {
		from netip.AddrPort
		msgs []ipv4.Message
	}
	var outs []out
	decisions := make([]relaycore.Decision, batch)
	for {
		n, err := k.pc.ReadBatch(rms, 0)
		if err != nil {
			return
		}
		s.m.readBatch.Observe(float64(n))
		now := time.Now()
		s.mu.Lock()
		for i := range n {
			src := addrPort(rms[i].Addr)
			decisions[i] = s.table.Packet(now, k.local, src, rms[i].Buffers[0][:rms[i].N])
		}
		s.mu.Unlock()
		outs = outs[:0]
		for i := range n {
			d := decisions[i]
			switch d.Verdict {
			case relaycore.Forward:
				j := len(outs) - 1
				if j < 0 || outs[j].from != d.From {
					outs = append(outs, out{from: d.From})
					j++
				}
				outs[j].msgs = append(outs[j].msgs, ipv4.Message{
					Buffers: [][]byte{rms[i].Buffers[0][:rms[i].N]},
					Addr:    net.UDPAddrFromAddrPort(d.To),
				})
			case relaycore.Register:
				s.enqueue(d.Registration)
			case relaycore.Held:
				s.m.registrations.WithLabelValues("held").Inc()
			default:
				s.m.dropped.WithLabelValues(string(d.Reason)).Inc()
				if d.Reason == relaycore.BadMAC || d.Reason == relaycore.Replay {
					s.m.registrations.WithLabelValues(string(d.Reason)).Inc()
				}
			}
		}
		for _, o := range outs {
			s.write(o.from, o.msgs)
		}
	}
}

func (s *Server) write(from netip.AddrPort, msgs []ipv4.Message) {
	k := s.sockFor(from)
	if k == nil {
		s.m.writeFailed.Add(float64(len(msgs)))
		return
	}
	var bytes int
	for _, m := range msgs {
		bytes += len(m.Buffers[0])
	}
	sent := 0
	for sent < len(msgs) {
		n, err := k.pc.WriteBatch(msgs[sent:], 0)
		if err != nil || n <= 0 {
			break
		}
		sent += n
	}
	s.m.forwarded.Add(float64(sent))
	s.m.forwardedBytes.Add(float64(bytes))
	if sent < len(msgs) {
		s.m.writeFailed.Add(float64(len(msgs) - sent))
	}
}

func addrPort(a net.Addr) netip.AddrPort {
	u, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ap := u.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// enqueue hands a verified registration to the committer. A full queue
// drops it; the agent sends again within its period.
func (s *Server) enqueue(r relaycore.Registration) {
	select {
	case s.regs <- r:
	default:
		s.m.registrations.WithLabelValues("queue_full").Inc()
	}
}

func (s *Server) requestSnapshot() {
	select {
	case s.snapshot <- struct{}{}:
	default:
	}
}

// committer makes registrations durable, then commits them, sharing one
// fsync among every registration waiting. It also writes snapshots, so no
// append lands between a snapshot's read of the table and its emptying of
// the log.
func (s *Server) committer(ctx context.Context) error {
	t := time.NewTicker(s.cfg.SnapshotEvery)
	defer t.Stop()
	dirty := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case r := <-s.regs:
			batch := []relaycore.Registration{r}
		drain:
			for len(batch) < 1024 {
				select {
				case r := <-s.regs:
					batch = append(batch, r)
				default:
					break drain
				}
			}
			start := time.Now()
			if err := s.disk.Append(batch); err != nil {
				return fmt.Errorf("registration log: %w", err)
			}
			s.m.fsync.Observe(time.Since(start).Seconds())
			s.mu.Lock()
			for _, r := range batch {
				if s.table.Commit(r) {
					s.m.registrations.WithLabelValues("accepted").Inc()
					s.log.Debug().Stringer("port", r.Local).Stringer("endpoint", r.Endpoint).Uint64("counter", r.Counter).Msg("registration")
				} else {
					s.m.registrations.WithLabelValues("superseded").Inc()
				}
			}
			s.mu.Unlock()
			dirty = true
		case <-s.snapshot:
			if err := s.writeSnapshot(); err != nil {
				return err
			}
			dirty = false
		case <-t.C:
			if dirty {
				if err := s.writeSnapshot(); err != nil {
					return err
				}
				dirty = false
			}
		}
	}
}

func (s *Server) writeSnapshot() error {
	s.mu.Lock()
	st := s.table.Persisted()
	s.mu.Unlock()
	if err := s.disk.Snapshot(st); err != nil {
		return fmt.Errorf("relay state: %w", err)
	}
	return nil
}

// answerProbes echoes probes on the probe port.
func (s *Server) answerProbes(k *sock) {
	buf := make([]byte, 64)
	for {
		n, from, err := k.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if b, ok := relaycore.ProbeReply(buf[:n]); ok {
			k.conn.WriteToUDPAddrPort(b, from)
			s.m.probes.Inc()
		}
	}
}

// Dirs returns a copy of every direction, for metrics and status.
func (s *Server) Dirs() []relaycore.Dir {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []relaycore.Dir
	for _, d := range s.table.Dirs() {
		out = append(out, *d)
	}
	return out
}
