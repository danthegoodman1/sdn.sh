// A dumb UDP relay. One port per *directed* policy edge: a packet's destination
// port names its sender, so the relay never guesses who sent it from the source
// address. It holds no key and never sees plaintext, so encryption stays at the
// edges.
//
// Each direction learns one endpoint, from the packets that arrive on its own
// port. A packet read on A's port is forwarded to B's learned endpoint and sent
// from B's port, which is exactly where B addresses A, so WireGuard's roaming
// keeps both sides pointing at the relay without any configuration.
//
// Two things this build cannot do. It does not yet authenticate an endpoint
// change: the design is the agent's registration datagram, MACed with a key
// derived per relay from the direction's secret, carrying a counter both ends
// persist, which is Phase 3 work. Until then an active direction merely holds
// its endpoint for a few seconds, which is weak — a dormant direction is
// claimable by anyone who knows the port. And it cannot serve the stated edge
// capacity, since it opens a socket per directed port; sk_lookup would fix only
// the receive side, because sending from the peer direction's port needs a
// socket bound there or a raw socket, so the whole path wants XDP or TC.
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// holdFor is how long an active direction keeps its endpoint against a
// different source. It bounds hijacking of a live direction and leaves a
// dormant one claimable; the authenticated registration datagram in SPEC.md
// replaces it in Phase 3.
const holdFor = 3 * time.Second

// family selects the underlay address family. A relay process serves one, since
// a directed edge's two ports live on one relay address; run one process per
// family for a dual-stack fleet.
var family = 4

type dir struct {
	port int
	peer *dir

	mu      sync.Mutex
	learned *net.UDPAddr
	seen    time.Time

	socks []batchConn

	fwd      atomic.Uint64
	bytes    atomic.Uint64
	noPeer   atomic.Uint64
	rejected atomic.Uint64
	werr     atomic.Uint64
}

// observe records the endpoint this direction's sender is currently using, and
// reports whether the packet may be forwarded. A source that loses the race for
// an active direction is dropped rather than forwarded: forwarding it would
// make the relay a reflector for anyone who knows the port, even though the
// receiver would discard what it cannot authenticate.
func (d *dir) observe(src *net.UDPAddr) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if d.learned == nil {
		d.learned = src
		d.seen = now
		fmt.Printf("port %d: sender registered %s\n", d.port, src)
		return true
	}
	if d.learned.Port == src.Port && d.learned.IP.Equal(src.IP) {
		d.seen = now
		return true
	}
	if now.Sub(d.seen) < holdFor {
		d.rejected.Add(1)
		return false
	}
	fmt.Printf("port %d: sender moved %s -> %s\n", d.port, d.learned, src)
	d.learned = src
	d.seen = now
	return true
}

func (d *dir) target() *net.UDPAddr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.learned
}

// batchConn is satisfied by both *ipv4.PacketConn and *ipv6.PacketConn, whose
// Message types are aliases of the same struct.
type batchConn interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

func listen(port int) (batchConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var err error
		if e := c.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}); e != nil {
			return e
		}
		return err
	}}
	network, addr := "udp4", fmt.Sprintf("0.0.0.0:%d", port)
	if family == 6 {
		network, addr = "udp6", fmt.Sprintf("[::]:%d", port)
	}
	c, err := lc.ListenPacket(nil, network, addr)
	if err != nil {
		return nil, err
	}
	u := c.(*net.UDPConn)
	_ = u.SetReadBuffer(64 << 20)
	_ = u.SetWriteBuffer(64 << 20)
	if family == 6 {
		return ipv6.NewPacketConn(u), nil
	}
	return ipv4.NewPacketConn(u), nil
}

// worker reads on this direction's port and writes through the peer
// direction's socket, so the receiver sees the packet arrive from the port it
// sends to.
func (d *dir) worker(idx, batch int) {
	in := d.socks[idx]
	out := d.peer.socks[idx]
	rms := make([]ipv4.Message, batch)
	for i := range rms {
		rms[i].Buffers = [][]byte{make([]byte, 2048)}
	}
	wms := make([]ipv4.Message, 0, batch)
	for {
		n, err := in.ReadBatch(rms, 0)
		if err != nil {
			return
		}
		wms = wms[:0]
		var nb uint64
		for i := 0; i < n; i++ {
			src, ok := rms[i].Addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			if !d.observe(src) {
				continue
			}
			dst := d.peer.target()
			if dst == nil {
				d.noPeer.Add(1)
				continue
			}
			wms = append(wms, ipv4.Message{
				Buffers: [][]byte{rms[i].Buffers[0][:rms[i].N]},
				Addr:    dst,
			})
			nb += uint64(rms[i].N)
		}
		for off := 0; off < len(wms); {
			k, err := out.WriteBatch(wms[off:], 0)
			if err != nil || k <= 0 {
				d.werr.Add(uint64(len(wms) - off))
				break
			}
			off += k
		}
		d.fwd.Add(uint64(len(wms)))
		d.bytes.Add(nb)
	}
}

func main() {
	workers, batch := 1, 128
	if v := os.Getenv("WORKERS"); v != "" {
		workers, _ = strconv.Atoi(v)
	}
	if v := os.Getenv("BATCH"); v != "" {
		batch, _ = strconv.Atoi(v)
	}
	if v := os.Getenv("FAMILY"); v != "" {
		f, err := strconv.Atoi(v)
		if err != nil || (f != 4 && f != 6) {
			fmt.Println("FAMILY must be 4 or 6")
			os.Exit(1)
		}
		family = f
	}
	if len(os.Args) < 2 {
		fmt.Println("usage: relay A:B [A:B ...]   # one port per direction of an edge")
		os.Exit(1)
	}
	var all []*dir
	for _, arg := range os.Args[1:] {
		f := strings.SplitN(arg, ":", 2)
		if len(f) != 2 {
			fmt.Printf("bad edge %q, want A:B\n", arg)
			os.Exit(1)
		}
		pa, ea := strconv.Atoi(f[0])
		pb, eb := strconv.Atoi(f[1])
		if ea != nil || eb != nil || pa == pb {
			fmt.Printf("bad edge %q\n", arg)
			os.Exit(1)
		}
		a, b := &dir{port: pa}, &dir{port: pb}
		a.peer, b.peer = b, a
		for _, d := range []*dir{a, b} {
			for w := 0; w < workers; w++ {
				c, err := listen(d.port)
				if err != nil {
					fmt.Printf("port %d: %v\n", d.port, err)
					os.Exit(1)
				}
				d.socks = append(d.socks, c)
			}
		}
		for w := 0; w < workers; w++ {
			go a.worker(w, batch)
			go b.worker(w, batch)
		}
		all = append(all, a, b)
		fmt.Printf("edge %d<->%d: IPv%d, %d socket(s) per direction, batch %d\n", pa, pb, family, workers, batch)
	}
	prev := make([]uint64, len(all))
	prevB := make([]uint64, len(all))
	for {
		time.Sleep(2 * time.Second)
		for i, d := range all {
			f, b := d.fwd.Load(), d.bytes.Load()
			dp, dB := f-prev[i], b-prevB[i]
			prev[i], prevB[i] = f, b
			if dp > 200 {
				fmt.Printf("port %d -> %d: %8d pps  %6.2f Gbit/s  (no-peer %d, rejected %d, werr %d)\n",
					d.port, d.peer.port, dp/2, float64(dB)*8/2/1e9,
					d.noPeer.Load(), d.rejected.Load(), d.werr.Load())
			}
		}
	}
}
