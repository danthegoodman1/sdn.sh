package server

import (
	"bufio"
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
// committed; it is dropped.
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
	var regs []relaycore.Registration
	b, err = os.ReadFile(filepath.Join(dir, logFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, st, nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		var r relaycore.Registration
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			break
		}
		regs = append(regs, r)
	}
	f, err := os.OpenFile(filepath.Join(dir, logFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, st, nil, err
	}
	return &Disk{dir: dir, log: f}, st, regs, nil
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
