// Command mutants plants known bugs, one at a time, in a scratch copy of the
// repository and reports which test layer catches each.
//
//	go run ./scripts/mutants [-only ID,...] [-root] [-jobs N] [-all-layers] [-v]
//	go run ./scripts/mutants -check | -list
//	go run ./scripts/mutants -only ID -plant DIR
//
// A mutant is a list of edits, each replacing an exact string that must occur
// exactly once in its file, and the layers that catch it, cheapest first.
// For each mutant the harness copies the working tree (tracked and untracked
// files, less what git ignores) to a scratch directory, applies the edits,
// builds everything including tests, and runs the layers in order until one
// fails. A layer that fails catches the mutant; a layer that runs past its
// timeout catches it too, as a hang. The unmutated tree first runs every
// layer the selected mutants name, since a layer that fails without a mutant
// would claim to catch them all. Each mutant copies the tree when it starts,
// so leave the tree alone while the harness runs.
//
// Layers that need root run only with -root, or when the harness runs as
// root; without them a mutant only they would catch is reported as skipped.
// The harness exits non-zero if the baseline fails, an edit does not apply,
// a mutant does not build, or any mutant is missed.
//
// -plant writes one mutant's copy to a directory and stops, for a longer
// sweep or a trace of the seed that catches it.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"
)

// Mutant is one planted bug.
type Mutant struct {
	ID string
	// Breaks says what behavior the bug breaks.
	Breaks string
	Edits  []Edit
	// Catch names the layers that catch it, cheapest first.
	Catch []string
}

// Edit replaces Old, which must occur exactly once in File, with New.
type Edit struct {
	File, Old, New string
}

// Layer is a test layer: commands run from the copy's root unless a step
// names a directory.
type Layer struct {
	Name  string
	Root  bool
	Steps []Step
}

// Step is one command of a layer. Root runs it under sudo unless the
// harness is root already.
type Step struct {
	Dir  string
	Args []string
	Root bool
}

func (l Layer) String() string {
	var b []string
	for _, s := range l.Steps {
		cmd := strings.Join(s.Args, " ")
		if s.Root {
			cmd = "sudo " + cmd
		}
		if s.Dir != "" {
			cmd = "(cd " + s.Dir + " && " + cmd + ")"
		}
		b = append(b, cmd)
	}
	return strings.Join(b, " && ")
}

// Outcome is what happened to one mutant.
type Outcome struct {
	Mutant  Mutant
	Status  string // caught, missed, skipped, unbuilt
	Layer   string
	Detail  string
	Took    time.Duration
	Results []LayerResult
}

// LayerResult is one layer's run against one mutant.
type LayerResult struct {
	Layer  string
	Failed bool
	Hung   bool
	Took   time.Duration
	Detail string
	Output string
}

type options struct {
	root      bool
	allLayers bool
	verbose   bool
	keep      bool
	timeout   time.Duration
}

func main() {
	only := flag.String("only", "", "comma-separated mutant IDs to run; all when empty")
	check := flag.Bool("check", false, "only check that every edit applies exactly once")
	list := flag.Bool("list", false, "list the mutants and layers, then exit")
	jobs := flag.Int("jobs", 4, "mutants to run at once")
	noBaseline := flag.Bool("no-baseline", false, "skip running the layers against the unmutated tree")
	plant := flag.String("plant", "", "write a copy of the tree with the one -only mutant applied to this directory, then exit")
	var o options
	flag.BoolVar(&o.root, "root", os.Geteuid() == 0, "run layers that need root, through sudo")
	flag.BoolVar(&o.allLayers, "all-layers", false, "run every layer a mutant names, not only until the first catch")
	flag.BoolVar(&o.verbose, "v", false, "print the tail of every failing layer's output")
	flag.BoolVar(&o.keep, "keep", false, "keep each scratch copy")
	flag.DurationVar(&o.timeout, "timeout", 15*time.Minute, "longest one layer may run before it counts as hung")
	flag.Parse()

	root, err := repoRoot()
	if err != nil {
		fatal(err)
	}
	layers := Layers(o)
	selected, err := selectMutants(*only)
	if err != nil {
		fatal(err)
	}
	if err := validate(selected, layers); err != nil {
		fatal(err)
	}
	if *list {
		printList(selected, layers)
		return
	}
	if err := checkEdits(root, selected); err != nil {
		fatal(err)
	}
	if *check {
		fmt.Printf("%d mutants apply\n", len(selected))
		return
	}
	files, err := trackedFiles(root)
	if err != nil {
		fatal(err)
	}
	if *plant != "" {
		if len(selected) != 1 {
			fatal(errors.New("-plant takes exactly one mutant through -only"))
		}
		if err := plantInto(root, files, selected[0], *plant); err != nil {
			fatal(err)
		}
		return
	}
	if !*noBaseline {
		if err := baseline(root, files, selected, layers, o); err != nil {
			fatal(err)
		}
	}
	outcomes := make([]Outcome, len(selected))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(*jobs, 1))
	var mu sync.Mutex
	for i, m := range selected {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			out := runMutant(root, files, m, layers, o)
			outcomes[i] = out
			mu.Lock()
			defer mu.Unlock()
			report(os.Stdout, out, o.verbose)
		})
	}
	wg.Wait()
	if !summarize(os.Stdout, outcomes) {
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mutants:", err)
	os.Exit(1)
}

// Layers returns the test layers by name.
func Layers(o options) map[string]Layer {
	goTest := func(name string, pkgs ...string) Layer {
		args := append([]string{"go", "test", "-count=1", "-timeout", o.timeout.String()}, pkgs...)
		return Layer{Name: name, Steps: []Step{{Args: args}}}
	}
	ls := []Layer{
		goTest("nft", "./internal/nft"),
		goTest("regproto", "./internal/regproto"),
		goTest("relay-core", "./internal/relay/core"),
		goTest("relay-server", "./internal/relay/server"),
		goTest("cp", "./internal/cp"),
		goTest("cpserver", "./internal/cpserver"),
		goTest("agent-core", "./internal/agent/core"),
		goTest("sim", "./internal/sim"),
		{Name: "kernel", Root: true, Steps: []Step{
			{Args: []string{"mkdir", "-p", ".mutants"}},
			{Args: []string{"go", "test", "-c", "-o", ".mutants/linux.test", "./internal/kernel/linux"}},
			{Dir: "internal/kernel/linux", Root: true, Args: []string{"unshare", "--net", "../../../.mutants/linux.test", "-test.timeout", o.timeout.String()}},
		}},
		{Name: "e2e", Root: true, Steps: []Step{{Args: []string{"scripts/e2e"}}}},
	}
	out := map[string]Layer{}
	for _, l := range ls {
		out[l.Name] = l
	}
	return out
}

func selectMutants(only string) ([]Mutant, error) {
	if only == "" {
		return Mutants, nil
	}
	var out []Mutant
	for _, id := range strings.Split(only, ",") {
		i := slices.IndexFunc(Mutants, func(m Mutant) bool { return m.ID == id })
		if i < 0 {
			return nil, fmt.Errorf("no mutant %q", id)
		}
		out = append(out, Mutants[i])
	}
	return out, nil
}

// validate checks the list itself: unique IDs, edits, and known layers.
func validate(ms []Mutant, layers map[string]Layer) error {
	seen := map[string]bool{}
	for _, m := range ms {
		if m.ID == "" || seen[m.ID] {
			return fmt.Errorf("mutant ID %q is empty or repeated", m.ID)
		}
		seen[m.ID] = true
		if len(m.Edits) == 0 || len(m.Catch) == 0 || m.Breaks == "" {
			return fmt.Errorf("mutant %s needs edits, a description and layers", m.ID)
		}
		for _, l := range m.Catch {
			if _, ok := layers[l]; !ok {
				return fmt.Errorf("mutant %s names unknown layer %q", m.ID, l)
			}
		}
	}
	return nil
}

// checkEdits applies every mutant's edits in memory, failing on an old string
// that does not occur exactly once.
func checkEdits(root string, ms []Mutant) error {
	var errs []error
	for _, m := range ms {
		if _, err := mutate(root, m); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// mutate returns each edited file's new content.
func mutate(root string, m Mutant) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, e := range m.Edits {
		b, ok := out[e.File]
		if !ok {
			var err error
			if b, err = os.ReadFile(filepath.Join(root, e.File)); err != nil {
				return nil, fmt.Errorf("mutant %s: %w", m.ID, err)
			}
		}
		if n := bytes.Count(b, []byte(e.Old)); n != 1 {
			return nil, fmt.Errorf("mutant %s: %s holds its old string %d times, want once:\n%s", m.ID, e.File, n, e.Old)
		}
		out[e.File] = bytes.Replace(b, []byte(e.Old), []byte(e.New), 1)
	}
	return out, nil
}

func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("finding the repository: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// trackedFiles lists the working tree's files that git tracks or would
// track, so build outputs it ignores stay out of the copy.
func trackedFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("listing files: %w", err)
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		// git lists a nested repository, such as a worktree, as a
		// directory; it is not part of this tree.
		if f == "" || strings.HasSuffix(f, "/") {
			continue
		}
		// A file deleted from the working tree but still in the index.
		if _, err := os.Lstat(filepath.Join(root, f)); err == nil {
			files = append(files, f)
		}
	}
	return files, nil
}

// copyTree copies files from root into a fresh scratch directory.
func copyTree(root string, files []string, tag string) (string, error) {
	dir, err := os.MkdirTemp("", "sdn-mutant-"+tag+"-")
	if err != nil {
		return "", err
	}
	return dir, copyFiles(root, files, dir)
}

// plantInto writes a mutated copy of the tree to dir.
func plantInto(root string, files []string, m Mutant, dir string) error {
	if err := copyFiles(root, files, dir); err != nil {
		return err
	}
	return apply(dir, m)
}

// apply writes a mutant's edits into a copy.
func apply(dir string, m Mutant) error {
	edited, err := mutate(dir, m)
	if err != nil {
		return err
	}
	for f, b := range edited {
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func copyFiles(root string, files []string, dir string) error {
	for _, f := range files {
		src, dst := filepath.Join(root, f), filepath.Join(dir, f)
		info, err := os.Lstat(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(src)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, dst); err != nil {
				return err
			}
			continue
		}
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

// enabled reports whether a layer can run under these options.
func enabled(l Layer, o options) bool { return !l.Root || o.root }

// baseline runs every layer the mutants name against the unmutated tree.
func baseline(root string, files []string, ms []Mutant, layers map[string]Layer, o options) error {
	var names []string
	for _, m := range ms {
		for _, l := range m.Catch {
			if !slices.Contains(names, l) && enabled(layers[l], o) {
				names = append(names, l)
			}
		}
	}
	dir, err := copyTree(root, files, "baseline")
	if !o.keep {
		defer os.RemoveAll(dir)
	}
	if err != nil {
		return err
	}
	fmt.Printf("== baseline: %s\n", strings.Join(names, ", "))
	if r := build(dir, o); r.Failed {
		return fmt.Errorf("the unmutated tree does not build:\n%s", tail(r.Output, 40))
	}
	for _, name := range names {
		r := runLayer(dir, layers[name], o)
		fmt.Printf("   %-12s %s\n", name, r.Took.Round(100*time.Millisecond))
		if r.Failed {
			return fmt.Errorf("the unmutated tree fails layer %s: %s\n%s", name, r.Detail, tail(r.Output, 60))
		}
	}
	return nil
}

func runMutant(root string, files []string, m Mutant, layers map[string]Layer, o options) (out Outcome) {
	start := time.Now()
	out.Mutant = m
	defer func() { out.Took = time.Since(start) }()
	dir, err := copyTree(root, files, m.ID)
	if !o.keep {
		defer os.RemoveAll(dir)
	}
	if err != nil {
		out.Status, out.Detail = "unbuilt", err.Error()
		return out
	}
	if err := apply(dir, m); err != nil {
		out.Status, out.Detail = "unbuilt", err.Error()
		return out
	}
	if r := build(dir, o); r.Failed {
		out.Status, out.Detail = "unbuilt", tail(r.Output, 20)
		return out
	}
	skipped := false
	for _, name := range m.Catch {
		l := layers[name]
		if !enabled(l, o) {
			skipped = true
			continue
		}
		r := runLayer(dir, l, o)
		out.Results = append(out.Results, r)
		if r.Failed && out.Status == "" {
			out.Status, out.Layer, out.Detail = "caught", name, r.Detail
			if !o.allLayers {
				break
			}
		}
	}
	switch {
	case out.Status != "":
	case skipped:
		out.Status = "skipped"
		out.Detail = "only layers that need root remain; rerun with -root"
	default:
		out.Status = "missed"
	}
	return out
}

// build compiles every package and every test binary.
func build(dir string, o options) LayerResult {
	return runLayer(dir, Layer{Name: "build", Steps: []Step{
		{Args: []string{"go", "build", "./..."}},
		{Args: []string{"go", "test", "-run", "^$", "./..."}},
	}}, o)
}

// runLayer runs a layer's steps in order, stopping at the first that fails.
func runLayer(dir string, l Layer, o options) LayerResult {
	start := time.Now()
	r := LayerResult{Layer: l.Name}
	var output bytes.Buffer
	for _, s := range l.Steps {
		err := runStep(dir, s, l.Root, o, &output)
		if err == nil {
			continue
		}
		r.Failed = true
		r.Hung = errors.Is(err, context.DeadlineExceeded)
		break
	}
	r.Took = time.Since(start)
	r.Output = output.String()
	if r.Failed {
		r.Detail = explain(r.Output)
		if r.Hung {
			r.Detail = "hung past " + o.timeout.String()
		}
	}
	return r
}

// runStep runs one command in its own process group, which it kills however
// the command ends, so a hung test binary never outlives its step.
func runStep(dir string, s Step, root bool, o options, out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	args := s.Args
	if s.Root && os.Geteuid() != 0 {
		args = append([]string{"sudo", "--preserve-env=SDN_TEST_POSTGRES"}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = filepath.Join(dir, s.Dir)
	// -trimpath keeps the build cache's keys free of the scratch path, so
	// each copy rebuilds only what its mutant touched. The copy has no
	// repository to stamp a version from.
	cmd.Env = append(os.Environ(), "GOFLAGS=-trimpath -buildvcs=false "+os.Getenv("GOFLAGS"))
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		kill(cmd.Process.Pid, root)
		return err
	case <-ctx.Done():
		kill(cmd.Process.Pid, root)
		select {
		case <-done:
		case <-time.After(time.Minute):
		}
		return ctx.Err()
	}
}

// kill ends a step's process group. Signalling what a root layer started
// takes sudo.
func kill(pgid int, root bool) {
	syscall.Kill(-pgid, syscall.SIGKILL)
	if root && os.Geteuid() != 0 {
		exec.Command("sudo", "-n", "kill", "-KILL", "--", fmt.Sprint(-pgid)).Run()
	}
}

// explain says why a layer failed: the first failure message, then the
// failing tests, or the simulator's failed-seed summary, else the last line.
func explain(output string) string {
	var tests []string
	var first string
	for line := range strings.Lines(output) {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "--- FAIL:"):
			name := strings.Fields(strings.TrimPrefix(t, "--- FAIL:"))
			if len(name) > 0 && !strings.Contains(name[0], "/") && !slices.Contains(tests, name[0]) {
				tests = append(tests, name[0])
			}
		case strings.Contains(t, " seeds from ") && strings.Contains(t, " failed"):
			return t
		case first == "" && strings.Contains(t, "_test.go:"):
			first = t
		}
	}
	if len(first) > 200 {
		first = first[:200] + "…"
	}
	msg := first
	if len(tests) > 0 {
		names := tests[0]
		if len(tests) > 1 {
			names += fmt.Sprintf(" and %d more", len(tests)-1)
		}
		msg = strings.TrimSpace(msg + " [" + names + "]")
	}
	if msg == "" {
		msg = strings.TrimSpace(tail(output, 1))
	}
	return msg
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func report(w io.Writer, o Outcome, verbose bool) {
	fmt.Fprintf(w, "== %s: %s", o.Mutant.ID, o.Status)
	if o.Layer != "" {
		fmt.Fprintf(w, " by %s", o.Layer)
	}
	fmt.Fprintf(w, " (%s)\n", o.Took.Round(100*time.Millisecond))
	for _, r := range o.Results {
		verdict := "passed"
		if r.Failed {
			verdict = "failed: " + r.Detail
		}
		fmt.Fprintf(w, "   %-12s %7s  %s\n", r.Layer, r.Took.Round(100*time.Millisecond), verdict)
		if verbose && r.Failed {
			fmt.Fprintln(w, indent(tail(r.Output, 30)))
		}
	}
	if o.Status == "unbuilt" || o.Status == "skipped" {
		fmt.Fprintln(w, indent(o.Detail))
	}
}

func indent(s string) string {
	return "      " + strings.ReplaceAll(s, "\n", "\n      ")
}

// summarize prints the table and reports whether every mutant was caught or
// only skipped.
func summarize(w io.Writer, outcomes []Outcome) bool {
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "MUTANT\tRESULT\tLAYER\tTIME\tWHY")
	ok := true
	counts := map[string]int{}
	for _, o := range outcomes {
		counts[o.Status]++
		if o.Status == "missed" || o.Status == "unbuilt" {
			ok = false
		}
		why := o.Detail
		if o.Status == "missed" {
			why = o.Mutant.Breaks
		}
		if i := strings.IndexByte(why, '\n'); i >= 0 {
			why = why[:i]
		}
		if len(why) > 120 {
			why = why[:120] + "…"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", o.Mutant.ID, o.Status, o.Layer, o.Took.Round(time.Second), why)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n%d caught, %d missed, %d skipped, %d unbuilt of %d\n",
		counts["caught"], counts["missed"], counts["skipped"], counts["unbuilt"], len(outcomes))
	return ok
}

func printList(ms []Mutant, layers map[string]Layer) {
	names := make([]string, 0, len(layers))
	for n := range layers {
		names = append(names, n)
	}
	slices.Sort(names)
	fmt.Println("Layers:")
	for _, n := range names {
		root := ""
		if layers[n].Root {
			root = " (root)"
		}
		fmt.Printf("  %-12s %s%s\n", n, layers[n], root)
	}
	fmt.Println("\nMutants:")
	for _, m := range ms {
		var files []string
		for _, e := range m.Edits {
			if !slices.Contains(files, e.File) {
				files = append(files, e.File)
			}
		}
		fmt.Printf("  %s\n      %s\n      in %s; caught by %s\n", m.ID, m.Breaks, strings.Join(files, ", "), strings.Join(m.Catch, ", "))
	}
}
