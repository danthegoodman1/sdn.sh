//go:build linux

// Package underlay sends the agent's datagrams on the host's network: the
// registration datagrams, from a WireGuard device's own listen port, and
// relay probes.
package underlay

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// RawSender sends UDP datagrams from a chosen source port through raw
// sockets, so a datagram leaves from the port a kernel WireGuard socket
// holds and a NAT maps it as WireGuard's own traffic.
type RawSender struct {
	fd4, fd6 int

	mu   sync.Mutex
	srcs map[netip.Addr]source // destination -> the source address routing picks
}

type source struct {
	addr netip.Addr
	at   time.Time
}

// NewRawSender opens raw UDP sockets in both families. It needs
// CAP_NET_RAW.
func NewRawSender() (*RawSender, error) {
	fd4, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("raw IPv4 socket: %w", err)
	}
	fd6, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		unix.Close(fd4)
		return nil, fmt.Errorf("raw IPv6 socket: %w", err)
	}
	// The kernel fills in the IPv6 UDP checksum at offset 6.
	if err := unix.SetsockoptInt(fd6, unix.IPPROTO_IPV6, unix.IPV6_CHECKSUM, 6); err != nil {
		unix.Close(fd4)
		unix.Close(fd6)
		return nil, fmt.Errorf("IPV6_CHECKSUM: %w", err)
	}
	// A raw socket receives a copy of every UDP datagram the host gets; a
	// filter that accepts nothing drops them before they queue.
	dropAll := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: 0}}
	prog := &unix.SockFprog{Len: 1, Filter: &dropAll[0]}
	for _, fd := range []int{fd4, fd6} {
		if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog); err != nil {
			unix.Close(fd4)
			unix.Close(fd6)
			return nil, fmt.Errorf("SO_ATTACH_FILTER: %w", err)
		}
	}
	return &RawSender{fd4: fd4, fd6: fd6, srcs: map[netip.Addr]source{}}, nil
}

// Close closes both sockets.
func (s *RawSender) Close() error {
	unix.Close(s.fd4)
	return unix.Close(s.fd6)
}

// Send sends payload from fromPort to to.
func (s *RawSender) Send(fromPort uint16, to netip.AddrPort, payload []byte) error {
	dst := to.Addr().Unmap()
	pkt := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], fromPort)
	binary.BigEndian.PutUint16(pkt[2:4], to.Port())
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)))
	copy(pkt[8:], payload)
	if dst.Is4() {
		src, err := s.source(dst)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(pkt[6:8], checksum4(src, dst, pkt))
		return unix.Sendto(s.fd4, pkt, 0, &unix.SockaddrInet4{Addr: dst.As4()})
	}
	return unix.Sendto(s.fd6, pkt, 0, &unix.SockaddrInet6{Addr: dst.As16()})
}

// source returns the address routing picks for a destination, by
// connecting a UDP socket, which sends nothing. Answers are kept briefly,
// since an underlay change moves them.
func (s *RawSender) source(dst netip.Addr) (netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if src, ok := s.srcs[dst]; ok && time.Since(src.at) < 10*time.Second {
		return src.addr, nil
	}
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 9)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("route to %v: %w", dst, err)
	}
	addr := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	c.Close()
	if len(s.srcs) > 4096 {
		clear(s.srcs)
	}
	s.srcs[dst] = source{addr: addr, at: time.Now()}
	return addr, nil
}

// checksum4 is the UDP checksum over the IPv4 pseudo-header and the
// datagram.
func checksum4(src, dst netip.Addr, udp []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for len(b) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		if len(b) == 1 {
			sum += uint32(b[0]) << 8
		}
	}
	s4, d4 := src.As4(), dst.As4()
	add(s4[:])
	add(d4[:])
	sum += unix.IPPROTO_UDP + uint32(len(udp))
	add(udp)
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	c := ^uint16(sum)
	if c == 0 {
		return 0xffff
	}
	return c
}

// Prober sends relay probes from one UDP socket and reports the nonces
// that come back.
type Prober struct {
	conn *net.UDPConn
}

// NewProber binds a UDP socket on addr, port 0 for any.
func NewProber(addr string) (*Prober, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		return nil, err
	}
	return &Prober{conn: c}, nil
}

// Send sends one probe.
func (p *Prober) Send(to netip.AddrPort, b []byte) error {
	_, err := p.conn.WriteToUDPAddrPort(b, to)
	return err
}

// Receive calls fn with every datagram until the socket closes.
func (p *Prober) Receive(fn func(from netip.AddrPort, b []byte)) error {
	buf := make([]byte, 64)
	for {
		n, from, err := p.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		fn(netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), buf[:n])
	}
}

// Close closes the socket, ending Receive.
func (p *Prober) Close() error { return p.conn.Close() }
