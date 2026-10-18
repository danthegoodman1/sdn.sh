package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Report is one plan's run: what produced the numbers, the numbers, and
// any assertion that failed. It renders as markdown for SPEC.md and as
// JSON with every raw result.
type Report struct {
	Plan      string            `json:"plan"`
	Env       string            `json:"env"`
	Started   time.Time         `json:"started"`
	Seconds   float64           `json:"seconds"`
	Substrate Substrate         `json:"substrate"`
	Ceiling   *Ceiling          `json:"ceiling,omitempty"`
	Params    map[string]string `json:"params"`
	Tables    []Table           `json:"tables"`
	Notes     []string          `json:"notes,omitempty"`
	Raw       []Raw             `json:"raw,omitempty"`
	Failures  []string          `json:"failures,omitempty"`
	Data      map[string]any    `json:"data"`
}

// Ceiling is the plain-TCP underlay throughput between two hosts, measured
// in the same run.
type Ceiling struct {
	From          string  `json:"from"`
	To            string  `json:"to"`
	Streams       int     `json:"streams"`
	BitsPerSecond float64 `json:"bits_per_second"`
	Retransmits   uint64  `json:"retransmits"`
}

// Table is a markdown table with a caption under it.
type Table struct {
	Title   string     `json:"title"`
	Columns []string   `json:"columns"`
	Rows    [][]string `json:"rows"`
	Caption string     `json:"caption,omitempty"`
}

// Raw is a tool's verbatim output.
type Raw struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

func (r *Report) table(t Table) { r.Tables = append(r.Tables, t) }

func (r *Report) note(format string, a ...any) { r.Notes = append(r.Notes, fmt.Sprintf(format, a...)) }

// Markdown renders the report.
func (r *Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s on %s, %s\n\n", r.Plan, r.Env, r.Started.UTC().Format("2006-01-02 15:04 UTC"))
	if len(r.Failures) > 0 {
		fmt.Fprintf(&b, "**FAILED:** %d assertion(s); see the end of this report.\n\n", len(r.Failures))
	}
	b.WriteString("| Substrate | |\n|---|---|\n")
	region := r.Substrate.Region
	fmt.Fprintf(&b, "| Environment | %s, region %s |\n", r.Substrate.Env, region)
	var types []string
	for _, role := range sortedKeys(r.Substrate.InstanceTypes) {
		types = append(types, fmt.Sprintf("%s %s", role, r.Substrate.InstanceTypes[role]))
	}
	fmt.Fprintf(&b, "| Instance types | %s |\n", strings.Join(types, ", "))
	fmt.Fprintf(&b, "| Control-plane store | %s |\n", r.Substrate.Store)
	for _, m := range r.Substrate.Nodes {
		fmt.Fprintf(&b, "| %s | kernel %s, %s, %s CPUs, rmem_max %s |\n", strings.Join(m.Nodes, ", "), m.Kernel, m.CPU, m.CPUs, m.RmemMax)
	}
	if c := r.Ceiling; c != nil {
		fmt.Fprintf(&b, "| Underlay ceiling | %s plain TCP, %s to %s, %d stream(s), %d retransmits |\n",
			mbit(c.BitsPerSecond), c.From, c.To, c.Streams, c.Retransmits)
	}
	var params []string
	for _, k := range sortedKeys(r.Params) {
		params = append(params, k+" "+r.Params[k])
	}
	fmt.Fprintf(&b, "| Parameters | %s |\n", strings.Join(params, ", "))
	fmt.Fprintf(&b, "| Run time | %.0fs |\n", r.Seconds)
	for _, t := range r.Tables {
		fmt.Fprintf(&b, "\n## %s\n\n", t.Title)
		b.WriteString("| " + strings.Join(t.Columns, " | ") + " |\n")
		b.WriteString("|---|" + strings.Repeat("--:|", len(t.Columns)-1) + "\n")
		for _, row := range t.Rows {
			b.WriteString("| " + strings.Join(row, " | ") + " |\n")
		}
		if t.Caption != "" {
			fmt.Fprintf(&b, "\n%s\n", t.Caption)
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("\n## Notes\n\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
	}
	for _, raw := range r.Raw {
		fmt.Fprintf(&b, "\n## %s\n\n```text\n%s\n```\n", raw.Title, strings.TrimRight(raw.Text, "\n"))
	}
	if len(r.Failures) > 0 {
		b.WriteString("\n## Failed assertions\n\n")
		for _, f := range r.Failures {
			fmt.Fprintf(&b, "- %s\n", f)
		}
	}
	return b.String()
}

// Write saves the report as markdown and JSON under dir and returns the
// markdown's path. Under sudo the files belong to the invoking user.
func (r *Report) Write(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	base := filepath.Join(dir, fmt.Sprintf("%s-%s-%s", r.Started.UTC().Format("20060102-150405"), r.Plan, r.Env))
	js, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	files := map[string][]byte{base + ".md": []byte(r.Markdown()), base + ".json": append(js, '\n')}
	for _, name := range sortedKeys(files) {
		if err := os.WriteFile(name, files[name], 0o644); err != nil {
			return "", err
		}
		chownToInvoker(name)
	}
	chownToInvoker(dir)
	return base + ".md", nil
}

// chownToInvoker gives a file to the user who ran sudo, if anyone did.
func chownToInvoker(name string) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 == nil && err2 == nil {
		os.Chown(name, uid, gid)
	}
}

// Formatting for tables.

func mbit(bps float64) string { return fmt.Sprintf("%.0f Mbit/s", bps/1e6) }

func msec(v float64) string {
	switch {
	case v == 0:
		return "0"
	case v < 1:
		return fmt.Sprintf("%.3fms", v)
	case v < 100:
		return fmt.Sprintf("%.1fms", v)
	}
	return fmt.Sprintf("%.0fms", v)
}

func num(v float64, prec int) string { return strconv.FormatFloat(v, 'f', prec, 64) }

func itoa(v int) string { return strconv.Itoa(v) }
