//go:build linux

package resolver

import (
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// fdStore speaks systemd's notify protocol to keep descriptors in the
// service's descriptor store. Without NOTIFY_SOCKET it does nothing.
type fdStore struct {
	addr *unix.SockaddrUnix
	fd   int
}

func openFDStore() *fdStore {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return &fdStore{fd: -1}
	}
	if path[0] == '@' {
		path = "\x00" + path[1:]
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return &fdStore{fd: -1}
	}
	return &fdStore{addr: &unix.SockaddrUnix{Name: path}, fd: fd}
}

// add stores a socket's descriptor under a name, replacing one stored
// before. It sends the socket's own descriptor from inside RawConn.Control,
// since asking a copy from File for its number (os.File.Fd) puts the open
// file description the two share into blocking mode, and a read the kernel
// then blocks never returns to the Close that waits for it.
func (s *fdStore) add(name string, c syscall.Conn) error {
	if s.fd < 0 {
		return nil
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	msg := "FDSTORE=1\nFDNAME=" + name + "\nFDPOLL=0"
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = unix.Sendmsg(s.fd, []byte(msg), unix.UnixRights(int(fd)), s.addr, 0)
	}); err != nil {
		return err
	}
	return serr
}

// remove drops a stored descriptor.
func (s *fdStore) remove(name string) {
	if s.fd < 0 {
		return
	}
	unix.Sendmsg(s.fd, []byte("FDSTOREREMOVE=1\nFDNAME="+name), nil, s.addr, 0)
}

// listenFDs returns the descriptors systemd passed this process, by name,
// and clears the variables so no child inherits them.
func listenFDs() map[string]*os.File {
	defer func() {
		os.Unsetenv("LISTEN_PID")
		os.Unsetenv("LISTEN_FDS")
		os.Unsetenv("LISTEN_FDNAMES")
	}()
	out := map[string]*os.File{}
	if pid, err := strconv.Atoi(os.Getenv("LISTEN_PID")); err != nil || pid != os.Getpid() {
		return out
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n <= 0 {
		return out
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	for i := range n {
		fd := 3 + i
		unix.CloseOnExec(fd)
		name := "unknown"
		if i < len(names) {
			name = names[i]
		}
		out[name] = os.NewFile(uintptr(fd), name)
	}
	return out
}
