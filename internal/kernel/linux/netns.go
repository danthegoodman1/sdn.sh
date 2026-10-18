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

// createNamed makes a namespace and bind-mounts it under its name.
func (k *Kernel) createNamed(name string) error {
	if _, err := os.Stat(filepath.Join(netnsDir, name)); err == nil {
		return nil
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

// deleteNamed unmounts and removes a namespace's name. A process still
// inside keeps the namespace alive without it.
func deleteNamed(name string) error {
	err := netns.DeleteNamed(name)
	if err == nil || errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) {
		if _, statErr := os.Stat(filepath.Join(netnsDir, name)); errors.Is(statErr, os.ErrNotExist) {
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

// heldNamespaces finds namespaces processes hold, keyed by inode, each with
// one path that opens it. It skips the root namespace and every named one.
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
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := map[uint64]string{}
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		path := filepath.Join("/proc", p.Name(), "ns", "net")
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
	return netns.GetFromPath(path)
}
