package detcheck

import (
	"slices"
	"strings"
	"testing"
)

// TestModuleIsDeterministic checks every deterministic package in the module.
func TestModuleIsDeterministic(t *testing.T) {
	pkgs, err := Load("../..", "sdn.sh/...")
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

// deterministic lists the packages that must carry the directive, so
// removing it from one fails here rather than exempting the package.
var deterministic = []string{
	"sdn.sh/internal/prng",
	"sdn.sh/internal/sim",
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
