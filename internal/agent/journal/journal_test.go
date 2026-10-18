package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentcore "sdn.sh/internal/agent/core"
	"sdn.sh/internal/model"
	"sdn.sh/internal/prng"
)

func TestEntriesSurviveReopeningAndCarryNoPrivateKey(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := model.NewPrivateKey(prng.New(1))
	a := agentcore.JournalEntry{Interface: "if-a", Name: "w1", Namespace: "sdn-a", ListenPort: 40000, PublicKey: priv.Public()}
	b := agentcore.JournalEntry{Interface: "if-b", Name: "w2", Namespace: "sdn-b", ListenPort: 40001}
	for _, e := range []agentcore.JournalEntry{b, a} {
		if err := j.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	a.Detaching = true
	if err := j.Write(a); err != nil {
		t.Fatal(err)
	}
	if err := j.Delete("if-b"); err != nil {
		t.Fatal(err)
	}
	if err := j.Delete("if-b"); err != nil {
		t.Fatalf("deleting an absent entry: %v", err)
	}
	// A crash mid-write leaves a temporary file, which reopening removes.
	os.WriteFile(filepath.Join(dir, "if-c.json.tmp"), []byte("{"), 0o600)
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := j.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != a {
		t.Fatalf("loaded %+v", got)
	}
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(dir, f.Name()))
		if strings.Contains(string(b), priv.String()) {
			t.Fatalf("%s holds the private key", f.Name())
		}
		if strings.HasSuffix(f.Name(), ".tmp") {
			t.Fatalf("%s survived reopening", f.Name())
		}
	}
}

func TestAnIdentifierCannotEscapeTheDirectory(t *testing.T) {
	j, _ := Open(t.TempDir())
	for _, id := range []model.InterfaceID{"", "../x", "a/b", "if-.."} {
		if err := j.Write(agentcore.JournalEntry{Interface: id}); err == nil {
			t.Errorf("wrote %q", id)
		}
	}
}
