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

	"golang.org/x/sys/unix"
)

// RawSender sends UDP datagrams from a chosen source port through raw
// sockets, so a datagram leaves from the port a kernel WireGuard socket
// holds and a NAT maps it as WireGuard's own traffic.
//
// The kernel builds the IP header and picks the source address by routing,
// as it does for WireGuard's socket. An IPv6 datagram's checksum is the
// kernel's too (IPV6_CHECKSUM). An IPv4 datagram carries none: a zero UDP
// checksum means none was computed (RFC 768), which IPv4 receivers accept,
// so the checksum never depends on a source address the sender would have
// to predict, and an address change cannot corrupt the next registration.
type RawSender struct {
	fd4, fd6 int
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
	return &RawSender{fd4: fd4, fd6: fd6}, nil
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
		return unix.Sendto(s.fd4, pkt, 0, &unix.SockaddrInet4{Addr: dst.As4()})
	}
	return unix.Sendto(s.fd6, pkt, 0, &unix.SockaddrInet6{Addr: dst.As16()})
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
