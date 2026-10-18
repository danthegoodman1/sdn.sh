//go:build linux

package linux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// sockDiag speaks NETLINK_SOCK_DIAG on a socket opened inside one
// namespace, which it keeps addressing from any thread.
type sockDiag struct {
	fd  int
	seq atomic.Uint32
}

// sock is one TCP or UDP socket as sock_diag reports it.
type sock struct {
	family, proto uint8
	id            [48]byte // struct inet_diag_sockid, verbatim
	local, remote netip.AddrPort
}

const (
	sockDestroy      = 21 // SOCK_DESTROY
	sockDiagByFamily = 20 // SOCK_DIAG_BY_FAMILY
	inetDiagReqLen   = 56 // struct inet_diag_req_v2
	inetDiagMsgLen   = 72 // struct inet_diag_msg
)

// openSockDiag opens the socket in the calling thread's namespace.
func openSockDiag() (*sockDiag, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("sock_diag socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("sock_diag bind: %w", err)
	}
	return &sockDiag{fd: fd}, nil
}

func (d *sockDiag) close() error { return unix.Close(d.fd) }

// request builds a netlink message carrying an inet_diag_req_v2.
func (d *sockDiag) request(typ uint16, flags uint16, family, proto uint8, states uint32, id []byte) ([]byte, uint32) {
	seq := d.seq.Add(1)
	b := make([]byte, unix.NLMSG_HDRLEN+inetDiagReqLen)
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:6], typ)
	binary.NativeEndian.PutUint16(b[6:8], flags)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	r := b[unix.NLMSG_HDRLEN:]
	r[0], r[1] = family, proto
	binary.NativeEndian.PutUint32(r[4:8], states)
	copy(r[8:56], id)
	return b, seq
}

// list dumps every socket of one family and protocol.
func (d *sockDiag) list(family, proto uint8) ([]sock, error) {
	msg, seq := d.request(sockDiagByFamily, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, family, proto, ^uint32(0), nil)
	if err := unix.Sendto(d.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sock_diag dump: %w", err)
	}
	var out []sock
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(d.fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("sock_diag dump: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				return nil, netlinkError(m.Data)
			}
			if len(m.Data) < inetDiagMsgLen {
				continue
			}
			s := sock{family: m.Data[0], proto: proto}
			copy(s.id[:], m.Data[4:52])
			s.local, s.remote = sockAddrs(s.family, s.id[:])
			out = append(out, s)
		}
	}
}

// sockAddrs decodes an inet_diag_sockid's ports and addresses.
func sockAddrs(family uint8, id []byte) (local, remote netip.AddrPort) {
	sport := binary.BigEndian.Uint16(id[0:2])
	dport := binary.BigEndian.Uint16(id[2:4])
	var src, dst netip.Addr
	if family == unix.AF_INET {
		src = netip.AddrFrom4([4]byte(id[4:8]))
		dst = netip.AddrFrom4([4]byte(id[20:24]))
	} else {
		src = netip.AddrFrom16([16]byte(id[4:20])).Unmap()
		dst = netip.AddrFrom16([16]byte(id[20:36])).Unmap()
	}
	return netip.AddrPortFrom(src, sport), netip.AddrPortFrom(dst, dport)
}

// destroy kills one socket, as ss -K does.
func (d *sockDiag) destroy(s sock) error {
	msg, seq := d.request(sockDestroy, unix.NLM_F_REQUEST|unix.NLM_F_ACK, s.family, s.proto, ^uint32(0), s.id[:])
	if err := unix.Sendto(d.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("sock_diag destroy: %w", err)
	}
	buf := make([]byte, 4096)
	for {
		n, _, err := unix.Recvfrom(d.fd, buf, 0)
		if err != nil {
			return fmt.Errorf("sock_diag destroy: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Seq == seq && m.Header.Type == unix.NLMSG_ERROR {
				return netlinkError(m.Data)
			}
		}
	}
}

// netlinkError decodes an NLMSG_ERROR payload; a zero code is an ack.
func netlinkError(b []byte) error {
	if len(b) < 4 {
		return errors.New("short netlink error")
	}
	code := int32(binary.NativeEndian.Uint32(b[0:4]))
	if code == 0 {
		return nil
	}
	return unix.Errno(-code)
}

// destroyMatching destroys every connected TCP and UDP socket, in both
// families, that match accepts, and returns how many went. A socket with a
// loopback peer is the workload's own and never matches.
func (d *sockDiag) destroyMatching(match func(sock) bool) (int, error) {
	n := 0
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			socks, err := d.list(family, proto)
			if err != nil {
				return n, err
			}
			for _, s := range socks {
				if !s.remote.Addr().IsValid() || s.remote.Addr().IsUnspecified() || s.remote.Addr().IsLoopback() || !match(s) {
					continue
				}
				// A socket that closed between the dump and now is fine.
				if err := d.destroy(s); err != nil && !errors.Is(err, unix.ENOENT) {
					return n, fmt.Errorf("destroy %v->%v: %w", s.local, s.remote, err)
				}
				n++
			}
		}
	}
	return n, nil
}
