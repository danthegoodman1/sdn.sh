package detcheck

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestModuleIsDeterministic checks every deterministic package in the module.
func TestModuleIsDeterministic(t *testing.T) {
	touchSources(t, "../..")
	pkgs, err := Load("../..", "github.com/danthegoodman1/wirenet/...")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, p := range pkgs {
		if IsDeterministic(p) {
			found = append(found, p.PkgPath)
		}
	}
	for _, want := range deterministic {
		if !slices.Contains(found, want) {
			t.Errorf("%s lacks %s", want, Directive)
		}
	}
	for _, f := range Check(pkgs) {
		t.Error(f)
	}
}

// touchSources opens every Go file in the module. The packages load through
// a go list subprocess, whose reads the test cache cannot see; reading them
// here makes an edit invalidate a cached pass.
func touchSources(t *testing.T, root string) {
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") {
			_, err = os.ReadFile(path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// deterministic lists the packages that must carry the directive, so
// removing it from one fails here rather than exempting the package.
var deterministic = []string{
	"github.com/danthegoodman1/wirenet/internal/agent/core",
	"github.com/danthegoodman1/wirenet/internal/api",
	"github.com/danthegoodman1/wirenet/internal/compile",
	"github.com/danthegoodman1/wirenet/internal/cp",
	"github.com/danthegoodman1/wirenet/internal/kernel",
	"github.com/danthegoodman1/wirenet/internal/kernel/kmodel",
	"github.com/danthegoodman1/wirenet/internal/model",
	"github.com/danthegoodman1/wirenet/internal/nft",
	"github.com/danthegoodman1/wirenet/internal/prng",
	"github.com/danthegoodman1/wirenet/internal/regproto",
	"github.com/danthegoodman1/wirenet/internal/relay/core",
	"github.com/danthegoodman1/wirenet/internal/sim",
	"github.com/danthegoodman1/wirenet/internal/slots",
	"github.com/danthegoodman1/wirenet/internal/store",
	"github.com/danthegoodman1/wirenet/internal/store/mem",
}

func TestFixtureViolatesEveryRule(t *testing.T) {
	pkgs, err := Load(".", "./testdata/bad")
	if err != nil {
		t.Fatal(err)
	}
	var rules []string
	for _, f := range Check(pkgs) {
		rules = append(rules, f.Rule)
	}
	want := []string{
		"imports os",
		"declares package variable counter",
		"calls time.Now",
		"starts a goroutine",
		"uses a channel type",
		"selects on channels",
		"sends on a channel",
		"receives from a channel",
		"ranges over a map",
		"iterates maps.Keys outside slices.Sorted",
	}
	for _, w := range want {
		if !slices.Contains(rules, w) {
			t.Errorf("missing finding %q in:\n%s", w, strings.Join(rules, "\n"))
		}
	}
	if n := strings.Count(strings.Join(rules, "\n"), "maps.Keys"); n != 1 {
		t.Errorf("maps.Keys flagged %d times; the sorted call must pass", n)
	}
	if len(rules) != len(want) {
		t.Errorf("got %d findings, want %d:\n%s", len(rules), len(want), strings.Join(rules, "\n"))
	}
}
