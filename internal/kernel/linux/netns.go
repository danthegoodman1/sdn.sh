//go:build linux

package linux

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// netnsDir is where named namespaces are bind-mounted, as ip-netns(8) does.
const netnsDir = "/run/netns"

// inNS runs fn on a thread inside ns. If the thread cannot return to the
// root namespace it stays locked, so Go retires it rather than reusing a
// thread in the wrong namespace.
func (k *Kernel) inNS(ns netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	if err := netns.Set(ns); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("setns: %w", err)
	}
	ferr := fn()
	if err := netns.Set(k.root); err != nil {
		return errors.Join(ferr, fmt.Errorf("returning to the root namespace: %w", err))
	}
	runtime.UnlockOSThread()
	return ferr
}

// createNamed makes a namespace and bind-mounts it under its name. A name
// a crash left between creating its file and mounting the namespace on it
// is a plain file, which is replaced.
func (k *Kernel) createNamed(name string) error {
	switch mounted, err := isNamespace(filepath.Join(netnsDir, name)); {
	case err == nil && mounted:
		return nil
	case err == nil:
		if err := os.Remove(filepath.Join(netnsDir, name)); err != nil {
			return fmt.Errorf("namespace %s: removing an unmounted name: %w", name, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("namespace %s: %w", name, err)
	}
	runtime.LockOSThread()
	h, err := netns.NewNamed(name)
	if err != nil {
		if restore := netns.Set(k.root); restore != nil {
			return errors.Join(err, restore)
		}
		runtime.UnlockOSThread()
		return fmt.Errorf("create namespace %s: %w", name, err)
	}
	h.Close()
	// A workload's own traffic to its addresses, and the rejects its
	// rules send, loop back through lo.
	upErr := loopbackUp()
	if err := netns.Set(k.root); err != nil {
		return fmt.Errorf("returning to the root namespace: %w", err)
	}
	runtime.UnlockOSThread()
	if upErr != nil {
		return fmt.Errorf("namespace %s: %w", name, upErr)
	}
	return nil
}

// loopbackUp brings up lo in the calling thread's namespace.
func loopbackUp() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("lo: %w", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("lo up: %w", err)
	}
	return nil
}

// isNamespace reports whether path is a mounted namespace rather than a
// plain file.
func isNamespace(path string) (bool, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, os.ErrNotExist
		}
		return false, err
	}
	return fs.Type == unix.NSFS_MAGIC, nil
}

// deleteNamed unmounts and removes a namespace's name. A process still
// inside keeps the namespace alive without it. A name nothing is mounted on
// is removed as a plain file.
func deleteNamed(name string) error {
	path := filepath.Join(netnsDir, name)
	err := netns.DeleteNamed(name)
	if errors.Is(err, unix.EINVAL) {
		if mounted, serr := isNamespace(path); serr == nil && !mounted {
			err = os.Remove(path)
		}
	}
	if err == nil || errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) {
		if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
	}
	return err
}

// namedWithPrefix lists the names under netnsDir that start with prefix.
func namedWithPrefix(prefix string) ([]string, error) {
	entries, err := os.ReadDir(netnsDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}

// nsInode identifies a namespace by its nsfs inode.
func nsInode(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// heldNamespaces finds namespaces something holds, keyed by inode, each
// with one path that opens it: a thread inside one, a descriptor open on
// one, or a mount of one outside netnsDir. It skips the root namespace and
// every named one.
func (k *Kernel) heldNamespaces() (map[uint64]string, error) {
	skip := map[uint64]bool{}
	if ino, err := nsInode("/proc/thread-self/ns/net"); err == nil {
		skip[ino] = true
	}
	if entries, err := os.ReadDir(netnsDir); err == nil {
		for _, e := range entries {
			if ino, err := nsInode(filepath.Join(netnsDir, e.Name())); err == nil {
				skip[ino] = true
			}
		}
	}
	paths, err := nsPaths()
	if err != nil {
		return nil, err
	}
	out := map[uint64]string{}
	for _, path := range paths {
		ino, err := nsInode(path)
		if err != nil || skip[ino] {
			continue
		}
		if _, seen := out[ino]; !seen {
			out[ino] = path
		}
	}
	return out, nil
}

// nsPaths lists every path that opens a network namespace: each thread's
// ns/net, each descriptor open on a network namespace, and each nsfs mount
// of one. A descriptor opened through a name reads back as that name's
// path, so descriptors are matched by the namespace filesystem's device and
// then by type.
func nsPaths() ([]string, error) {
	var self unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &self); err != nil {
		return nil, err
	}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		dir := filepath.Join("/proc", p.Name())
		out = append(out, filepath.Join(dir, "ns", "net"))
		if tasks, err := os.ReadDir(filepath.Join(dir, "task")); err == nil {
			for _, t := range tasks {
				if t.Name() != p.Name() {
					out = append(out, filepath.Join(dir, "task", t.Name(), "ns", "net"))
				}
			}
		}
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			path := filepath.Join(dir, "fd", fd.Name())
			if onNSFS(path, self.Dev) && isNetNS(path) {
				out = append(out, path)
			}
		}
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(mounts), "\n") {
		// mountinfo(5): ID parent major:minor root mount-point options...
		// - fstype source super-options.
		fields := strings.Fields(line)
		sep := slices.Index(fields, "-")
		if sep < 5 || sep+1 >= len(fields) || fields[sep+1] != "nsfs" || !strings.HasPrefix(fields[3], "net:[") {
			continue
		}
		out = append(out, unescapeMount(fields[4]))
	}
	return out, nil
}

// onNSFS reports whether the file a descriptor's path opens lives on the
// namespace filesystem, device dev. A descriptor may open a file on a
// network filesystem whose server hangs, so the look takes what the kernel
// has cached rather than asking it (AT_STATX_DONT_SYNC, statx(2)).
func onNSFS(path string, dev uint64) bool {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_STATX_DONT_SYNC, unix.STATX_TYPE, &st); err != nil {
		return false
	}
	return unix.Mkdev(st.Dev_major, st.Dev_minor) == dev
}

// isNetNS reports whether path opens a network namespace.
func isNetNS(path string) bool {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	typ, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	return err == nil && typ == unix.CLONE_NEWNET
}

// unescapeMount undoes mountinfo's octal escapes of space, tab, newline and
// backslash.
func unescapeMount(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

// refFor names a held namespace by inode, which outlives any one process.
func refFor(ino uint64) string { return "ino:" + strconv.FormatUint(ino, 10) }

// openRef opens a held namespace by its ref, finding a process inside it.
func (k *Kernel) openRef(ref string) (netns.NsHandle, error) {
	ino, err := strconv.ParseUint(strings.TrimPrefix(ref, "ino:"), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad namespace ref %q", ref)
	}
	held, err := k.heldNamespaces()
	if err != nil {
		return 0, err
	}
	path, ok := held[ino]
	if !ok {
		return 0, os.ErrNotExist
	}
	h, err := netns.GetFromPath(path)
	if err != nil {
		return 0, err
	}
	// The process or descriptor the scan found may have gone since, and its
	// path been reused for another namespace.
	var st unix.Stat_t
	if err := unix.Fstat(int(h), &st); err != nil || st.Ino != ino {
		h.Close()
		return 0, os.ErrNotExist
	}
	return h, nil
}
