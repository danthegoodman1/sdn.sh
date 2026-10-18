//go:build linux

package resolver

import (
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestAStoredSocketStaysNonBlockingAndCloses stores a socket a reader is
// blocked on, as the resolver does for each namespace it serves, and checks
// that the descriptor store received it, that the socket is still
// non-blocking, and that closing it ends the read at once.
func TestAStoredSocketStaysNonBlockingAndCloses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	notify, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer notify.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	store := openFDStore()
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFromUDPAddrPort(make([]byte, 64))
		read <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := store.add("ns.udp", c); err != nil {
		t.Fatal(err)
	}
	buf, oob := make([]byte, 256), make([]byte, unix.CmsgSpace(4))
	notify.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, oobn, _, _, err := notify.ReadMsgUnix(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	if msg := string(buf[:n]); !strings.Contains(msg, "FDSTORE=1") || !strings.Contains(msg, "FDNAME=ns.udp") {
		t.Fatalf("the store received %q", msg)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		t.Fatalf("control messages %v, %v; want one carrying the descriptor", msgs, err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		t.Fatalf("descriptors %v, %v; want one", fds, err)
	}
	unix.Close(fds[0])
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	rc.Control(func(fd uintptr) { flags, err = unix.FcntlInt(fd, unix.F_GETFL, 0) })
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("after storing, the socket's flags are %#x, %v; want O_NONBLOCK", flags, err)
	}
	closed := make(chan struct{})
	go func() {
		c.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the stored socket waits on a read blocked in the kernel")
	}
	select {
	case <-read:
	case <-time.After(2 * time.Second):
		t.Fatal("the read outlived Close")
	}
}
