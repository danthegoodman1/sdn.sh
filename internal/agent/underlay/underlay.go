//go:build linux

// Package underlay carries the agent's datagrams on the host's network: the
// registration datagrams, sent from a WireGuard device's own listen port,
// the relays' acknowledgments of them, and relay probes.
package underlay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// RawSender sends UDP datagrams from a chosen source port through raw
// sockets, so a datagram leaves from the port a kernel WireGuard socket
// holds and a NAT maps it as WireGuard's own traffic, and receives the
// relays' acknowledgments, which arrive at that port.
//
// The kernel builds the IP header and picks the source address by routing,
// as it does for WireGuard's socket. An IPv6 datagram's checksum is the
// kernel's too (IPV6_CHECKSUM). An IPv4 datagram carries none: a zero UDP
// checksum means none was computed (RFC 768), which IPv4 receivers accept,
// so the checksum never depends on a source address the sender would have
// to predict, and an address change cannot corrupt the next registration.
type RawSender struct {
	c4, c6 *net.IPConn
}

// ackMagic opens every acknowledgment's payload: 0xff 'S' 'D' 'A'.
const ackMagic = 0xff534441

// A raw socket receives a copy of every UDP datagram the host gets, so each
// carries a filter that passes acknowledgments alone, judged by the first
// word of the UDP payload. An IPv4 raw socket's filter sees the IP header
// first, whose length it reads; an IPv6 one's sees the UDP header first.
var (
	acks4 = []unix.SockFilter{
		{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_IND, K: 8},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: ackMagic},
		{Code: unix.BPF_RET | unix.BPF_K, K: 256},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
	acks6 = []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 8},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: ackMagic},
		{Code: unix.BPF_RET | unix.BPF_K, K: 256},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
)

// NewRawSender opens raw UDP sockets in both families. It needs
// CAP_NET_RAW.
func NewRawSender() (*RawSender, error) {
	c4, err := net.ListenIP("ip4:17", nil)
	if err != nil {
		return nil, fmt.Errorf("raw IPv4 socket: %w", err)
	}
	c6, err := net.ListenIP("ip6:17", nil)
	if err != nil {
		c4.Close()
		return nil, fmt.Errorf("raw IPv6 socket: %w", err)
	}
	s := &RawSender{c4: c4, c6: c6}
	err = errors.Join(
		control(c4, func(fd int) error { return filter(fd, acks4) }),
		control(c6, func(fd int) error { return filter(fd, acks6) }),
		// The kernel fills in the IPv6 UDP checksum at offset 6.
		control(c6, func(fd int) error { return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_CHECKSUM, 6) }),
	)
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func control(c *net.IPConn, fn func(fd int) error) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := raw.Control(func(fd uintptr) { ferr = fn(int(fd)) }); err != nil {
		return err
	}
	return ferr
}

func filter(fd int, prog []unix.SockFilter) error {
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		return fmt.Errorf("SO_ATTACH_FILTER: %w", err)
	}
	return nil
}

// Close closes both sockets, ending Receive.
func (s *RawSender) Close() error {
	return errors.Join(s.c4.Close(), s.c6.Close())
}

// Send sends payload from fromPort to to.
func (s *RawSender) Send(fromPort uint16, to netip.AddrPort, payload []byte) error {
	dst := to.Addr().Unmap()
	pkt := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], fromPort)
	binary.BigEndian.PutUint16(pkt[2:4], to.Port())
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)))
	copy(pkt[8:], payload)
	c := s.c6
	if dst.Is4() {
		c = s.c4
	}
	_, err := c.WriteToIP(pkt, &net.IPAddr{IP: dst.AsSlice()})
	return err
}

// Receive calls fn with each acknowledgment the host receives: the address
// and port it came from, the listen port it reached and its payload. fn
// runs on one goroutine per family. Receive returns once the sockets close.
func (s *RawSender) Receive(fn func(from netip.AddrPort, port uint16, payload []byte)) error {
	errs := make(chan error, 2)
	for _, c := range []*net.IPConn{s.c4, s.c6} {
		go func() {
			buf := make([]byte, 512)
			for {
				// An IPv4 raw socket's read comes back without its IP
				// header, so both families start at the UDP header.
				n, addr, err := c.ReadFromIP(buf)
				if err != nil {
					errs <- err
					return
				}
				ip, ok := netip.AddrFromSlice(addr.IP)
				if !ok || n < 8 {
					continue
				}
				src, dst := binary.BigEndian.Uint16(buf[0:2]), binary.BigEndian.Uint16(buf[2:4])
				fn(netip.AddrPortFrom(ip.Unmap(), src), dst, buf[8:n])
			}
		}()
	}
	err := <-errs
	<-errs
	return err
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
