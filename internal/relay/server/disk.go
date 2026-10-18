package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	relaycore "sdn.sh/internal/relay/core"
)

// Disk is what survives a relay restart: a state file holding the pushed
// table and every direction's registration, and a log of registrations
// made since the state file was written.
type Disk struct {
	dir string
	log *os.File
}

const (
	stateFile = "state.json"
	logFile   = "registrations.log"
)

// OpenDisk reads what the directory holds and opens the log for appends. A
// torn last line, from a crash mid-append, never reached fsync and so never
// committed; it is cut from the log, so the next append starts a line of its
// own rather than joining one a later restart could not read.
func OpenDisk(dir string) (*Disk, relaycore.State, []relaycore.Registration, error) {
	var st relaycore.State
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, st, nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, st, nil, err
	default:
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, st, nil, err
		}
	}
	b, err = os.ReadFile(filepath.Join(dir, logFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, st, nil, err
	}
	regs, n := readLog(b)
	f, err := os.OpenFile(filepath.Join(dir, logFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, st, nil, err
	}
	if n < len(b) {
		if err := f.Truncate(int64(n)); err != nil {
			f.Close()
			return nil, st, nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, st, nil, err
		}
	}
	return &Disk{dir: dir, log: f}, st, regs, nil
}

// readLog returns the registrations a log holds and the length of the
// lines that hold them: every line before the first that lacks its newline
// or fails to parse.
func readLog(b []byte) ([]relaycore.Registration, int) {
	var regs []relaycore.Registration
	n := 0
	for {
		i := bytes.IndexByte(b[n:], '\n')
		if i < 0 {
			return regs, n
		}
		var r relaycore.Registration
		if json.Unmarshal(b[n:n+i], &r) != nil {
			return regs, n
		}
		regs = append(regs, r)
		n += i + 1
	}
}

// Append writes registrations to the log and returns once they are on
// disk. Registrations that arrive together share one fsync.
func (d *Disk) Append(regs []relaycore.Registration) error {
	var buf bytes.Buffer
	for _, r := range regs {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if _, err := d.log.Write(buf.Bytes()); err != nil {
		return err
	}
	return d.log.Sync()
}

// Snapshot replaces the state file and empties the log, which the new
// state covers. The caller makes no Append in between.
func (d *Disk) Snapshot(st relaycore.State) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	path := filepath.Join(d.dir, stateFile)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(d.dir)
	if err != nil {
		return err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return err
	}
	if err := d.log.Truncate(0); err != nil {
		return err
	}
	return d.log.Sync()
}

// Close closes the log.
func (d *Disk) Close() error { return d.log.Close() }
