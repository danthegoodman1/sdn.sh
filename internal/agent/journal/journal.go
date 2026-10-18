// Package journal persists the agent's journal entries, one file per
// interface, each replaced atomically and durably.
package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	agentcore "sdn.sh/internal/agent/core"
	"sdn.sh/internal/model"
)

// Journal is a directory of entries.
type Journal struct {
	dir string
}

// Open creates the directory if needed and removes temporary files a crash
// left behind.
func Open(dir string) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range names {
		if strings.HasSuffix(e.Name(), ".tmp") {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return &Journal{dir: dir}, nil
}

func (j *Journal) path(id model.InterfaceID) (string, error) {
	name := string(id)
	if name == "" || strings.ContainsAny(name, "/\\.") {
		return "", fmt.Errorf("journal: bad interface identifier %q", id)
	}
	return filepath.Join(j.dir, name+".json"), nil
}

// Load returns every entry, ordered by interface.
func (j *Journal) Load() ([]agentcore.JournalEntry, error) {
	files, err := filepath.Glob(filepath.Join(j.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	var out []agentcore.JournalEntry
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var e agentcore.JournalEntry
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("journal %s: %w", f, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// Write replaces an entry: the new file is complete on disk before it takes
// the old one's name, and the rename is on disk before Write returns.
func (j *Journal) Write(e agentcore.JournalEntry) error {
	path, err := j.path(e.Interface)
	if err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
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
	return j.syncDir()
}

// Delete removes an entry durably. Deleting one that is absent succeeds.
func (j *Journal) Delete(id model.InterfaceID) error {
	path, err := j.path(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return j.syncDir()
}

func (j *Journal) syncDir() error {
	d, err := os.Open(j.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
