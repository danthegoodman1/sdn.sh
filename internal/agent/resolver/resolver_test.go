//go:build linux

package resolver

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/danthegoodman1/wirenet/internal/dns"
)

func query(t *testing.T, id uint16, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// slowUpstream answers every query with an empty response after delay.
func slowUpstream(t *testing.T, delay time.Duration) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			go func() {
				time.Sleep(delay)
				q[2] |= 0x80 // QR: a response
				c.WriteToUDPAddrPort(q, from)
			}()
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// withZone is a resolver answering db.n.wirenet. for namespace ns and forwarding
// everything else to upstream.
func withZone(t *testing.T, upstream netip.AddrPort) *Resolver {
	t.Helper()
	r := New(upstream, zerolog.Nop(), prometheus.NewRegistry())
	r.zones["ns"] = &dns.Zone{Domain: "n.wirenet.", Forward: true,
		Names: []dns.Name{{FQDN: "db.n.wirenet.", AAAA: netip.MustParseAddr("fd00::5")}}}
	return r
}

func TestASlowUpstreamDelaysNoLocalAnswer(t *testing.T) {
	r := withZone(t, slowUpstream(t, time.Second))
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go r.serveUDP("ns", c)
	client, err := net.DialUDP("udp", nil, c.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	start := time.Now()
	for _, q := range [][]byte{query(t, 1, "example.com.", dnsmessage.TypeA), query(t, 2, "db.n.wirenet.", dnsmessage.TypeAAAA)} {
		if _, err := client.Write(q); err != nil {
			t.Fatal(err)
		}
	}
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	var order []uint16
	buf := make([]byte, 1500)
	for range 2 {
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("after %v: %v", time.Since(start), err)
		}
		order = append(order, binary.BigEndian.Uint16(buf[:n]))
		if len(order) == 1 && time.Since(start) > 500*time.Millisecond {
			t.Fatalf("the first answer took %v behind a forwarded query", time.Since(start))
		}
	}
	if order[0] != 2 || order[1] != 1 {
		t.Fatalf("answers came in order %v, want the local one (2) first", order)
	}
}

func TestATCPConnectionPastTheCapIsClosed(t *testing.T) {
	r := withZone(t, netip.AddrPort{})
	ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go r.serveTCP("ns", ln)
	addr := ln.Addr().String()
	ask := func(c net.Conn) error {
		q := query(t, 7, "db.n.wirenet.", dnsmessage.TypeAAAA)
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
			return err
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		_, err := io.ReadFull(c, make([]byte, binary.BigEndian.Uint16(l[:])))
		return err
	}
	var held []net.Conn
	for range tcpConns {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := ask(c); err != nil {
			t.Fatalf("a connection within the cap: %v", err)
		}
		held = append(held, c)
	}
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if err := ask(extra); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !isReset(err) {
		t.Fatalf("a connection past the cap was answered or hung: %v", err)
	}
	held[0].Close()
	time.Sleep(50 * time.Millisecond)
	again, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := ask(again); err != nil {
		t.Fatalf("a connection after one closed: %v", err)
	}
}

func isReset(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && !op.Timeout()
}
