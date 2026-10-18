//go:build linux

package underlay

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/danthegoodman1/wirenet/internal/regproto"
)

// fresh skips unless the test runs as root in a namespace of its own, and
// brings loopback up.
func fresh(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: go test -exec 'sudo unshare --net'")
	}
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		if l.Attrs().Name != "lo" {
			t.Skipf("needs a fresh network namespace, found %s: go test -exec 'sudo unshare --net'", l.Attrs().Name)
		}
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
}

type got struct {
	from    netip.AddrPort
	port    uint16
	payload []byte
}

func TestAcknowledgmentsArriveAndNothingElseDoes(t *testing.T) {
	fresh(t)
	s, err := NewRawSender()
	if err != nil {
		t.Fatal(err)
	}
	arrived := make(chan got, 16)
	done := make(chan error, 1)
	go func() {
		done <- s.Receive(func(from netip.AddrPort, port uint16, payload []byte) {
			arrived <- got{from, port, bytes.Clone(payload)}
		})
	}()
	ack := regproto.Ack(42)
	for _, family := range []string{"127.0.0.1", "::1"} {
		relay, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(family), 0)))
		if err != nil {
			t.Fatal(err)
		}
		defer relay.Close()
		from := relay.LocalAddr().(*net.UDPAddr).AddrPort()
		to := netip.AddrPortFrom(from.Addr(), 40001)
		// Ordinary traffic to the port is filtered out; the ack is not.
		for _, b := range [][]byte{[]byte{4, 0, 0, 0, 1, 2, 3, 4}, ack[:]} {
			if _, err := relay.WriteToUDPAddrPort(b, to); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case g := <-arrived:
			if g.from != from || g.port != 40001 || !bytes.Equal(g.payload, ack[:]) {
				t.Fatalf("over %s: %v to port %d carrying %x; want the ack from %v to 40001", family, g.from, g.port, g.payload, from)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("over %s: no acknowledgment arrived", family)
		}
		select {
		case g := <-arrived:
			t.Fatalf("over %s: the filter passed %x", family, g.payload)
		case <-time.After(100 * time.Millisecond):
		}
		// A send leaves from the port it names, with a checksum the
		// receiving socket accepts.
		if err := s.Send(40002, from, []byte("registration")); err != nil {
			t.Fatal(err)
		}
		relay.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, src, err := relay.ReadFromUDPAddrPort(buf)
		if err != nil || src.Port() != 40002 || string(buf[:n]) != "registration" {
			t.Fatalf("over %s: received %q from %v, %v; want the datagram from port 40002", family, buf[:n], src, err)
		}
	}
	s.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Receive outlived Close")
	}
}
