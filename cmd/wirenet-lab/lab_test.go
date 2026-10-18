package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fleetOutput is `terraform output -json` for a fleet of three agent hosts
// and two relays, as deploy/aws/terraform writes it.
const fleetOutput = `{
  "fleet": {
    "sensitive": false,
    "type": ["object", {}],
    "value": {
      "region": "us-east-1",
      "ssh_user": "ubuntu",
      "instance_types": {"cp": "c6i.xlarge", "agent": "c6i.xlarge", "relay": "c6i.xlarge", "middle": "c6i.xlarge"},
      "cp": {"name": "cp", "public_ip": "198.51.100.10", "private_ip": "10.60.1.10"},
      "middle": {"name": "mid", "public_ip": "198.51.100.11", "private_ip": "10.60.1.11"},
      "agents": [
        {"name": "h1", "public_ip": "198.51.100.21", "private_ip": "10.60.1.21"},
        {"name": "h2", "public_ip": "198.51.100.22", "private_ip": "10.60.1.22"},
        {"name": "h3", "public_ip": "198.51.100.23", "private_ip": "10.60.1.23"}
      ],
      "relays": [
        {"name": "r1", "public_ip": "198.51.100.31", "private_ip": "10.60.1.31"},
        {"name": "r2", "public_ip": "198.51.100.32", "private_ip": "10.60.1.32"}
      ]
    }
  }
}`

func dryAWS(t *testing.T) (*awsEnv, *bytes.Buffer) {
	t.Helper()
	tf := filepath.Join(t.TempDir(), "fleet.json")
	if err := os.WriteFile(tf, []byte(fleetOutput), 0o644); err != nil {
		t.Fatal(err)
	}
	fleet, err := readFleet(tf)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	e, err := newAWSEnv(fleet, "/keys/fleet.pem", t.TempDir(), true, &out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, &out
}

var dryOptions = Options{Duration: 10 * time.Second, Streams: 8, RRSize: 1, Degree: 20, ChurnDegree: 4, Rounds: 10, Clients: 30, Concurrency: 4, MaxIfaces: 1000, Edges: 12}

func TestEveryPlanRunsDryAgainstAWS(t *testing.T) {
	e, out := dryAWS(t)
	reports := t.TempDir()
	for _, p := range plans {
		out.Reset()
		var log bytes.Buffer
		if err := runPlan(context.Background(), e, p, dryOptions, reports, &log); err != nil {
			t.Fatalf("%s: %v\n%s", p.name, err, log.String())
		}
		printed := out.String()
		// Every machine is purged before and after.
		for _, m := range e.machines() {
			if strings.Count(printed, "["+m.Name+" "+e.public[m.Name]+"] sudo /usr/local/lib/wirenet/purge.sh") < 2 {
				t.Errorf("%s: %s is not purged before and after:\n%s", p.name, m.Name, printed)
			}
		}
		if p.fleet && !strings.Contains(printed, "systemctl restart wirenet-agent") {
			t.Errorf("%s: no agent started:\n%s", p.name, printed)
		}
		if !strings.Contains(log.String(), "dry run complete") {
			t.Errorf("%s: %s", p.name, log.String())
		}
	}
	if entries, _ := os.ReadDir(reports); len(entries) > 0 {
		t.Errorf("a dry run wrote %d report files", len(entries))
	}
}

func TestPathsDryRunComparesThreePathsOnTheMiddleBox(t *testing.T) {
	e, out := dryAWS(t)
	var log bytes.Buffer
	var paths plan
	for _, p := range plans {
		if p.name == "paths" {
			paths = p
		}
	}
	if err := runPlan(context.Background(), e, paths, dryOptions, t.TempDir(), &log); err != nil {
		t.Fatal(err)
	}
	printed := out.String()
	ceiling := strings.Index(printed, "stream --target 10.60.1.22:5300")
	relay := strings.Index(printed, "network create paths --relays mid")
	gateway := strings.Index(printed, "ip link add wnbgw0 type wireguard")
	if ceiling < 0 || relay < 0 || gateway < 0 || !(ceiling < relay && relay < gateway) {
		t.Fatalf("want the plain-TCP ceiling, then the relay, then the gateway; got offsets %d, %d, %d:\n%s", ceiling, relay, gateway, printed)
	}
	if !strings.Contains(printed, "[mid 198.51.100.11] sudo /usr/local/bin/wirenet-bench cpu --duration 10s") {
		t.Errorf("no CPU sampling on the middle box:\n%s", printed)
	}
	// The private key never leaves the machine that minted it.
	if strings.Contains(printed, "wg genkey") && strings.Contains(printed, "private-key /etc/wireguard/wnbgw-h1.key") {
		return
	}
	t.Errorf("gateway keys are not minted and used in place:\n%s", printed)
}

func TestDeployDryRunInstallsEachRole(t *testing.T) {
	e, out := dryAWS(t)
	if err := e.Deploy(context.Background()); err != nil {
		t.Fatal(err)
	}
	printed := out.String()
	for _, want := range []string{
		"[cp 198.51.100.10] scp " + filepath.Join(e.bin, "wirenet-cp"),
		"[h1 198.51.100.21] scp " + filepath.Join(e.bin, "wirenet-agent"),
		"[r1 198.51.100.31] scp " + filepath.Join(e.bin, "wirenet-relay"),
		"sudo /usr/local/lib/wirenet/hostprep.sh agent",
		"sudo /usr/local/lib/wirenet/hostprep.sh middle",
		"sudo systemctl restart prometheus",
		`"10.60.1.21:9091"`,
	} {
		if !strings.Contains(printed, want) {
			t.Errorf("deploy never printed %q:\n%s", want, printed)
		}
	}
}

func TestFleetOutputNeedsTwoHostsAndRelays(t *testing.T) {
	var v map[string]map[string]any
	if err := json.Unmarshal([]byte(fleetOutput), &v); err != nil {
		t.Fatal(err)
	}
	v["fleet"]["value"].(map[string]any)["relays"] = []any{}
	b, _ := json.Marshal(v)
	tf := filepath.Join(t.TempDir(), "fleet.json")
	os.WriteFile(tf, b, 0o644)
	if _, err := readFleet(tf); err == nil {
		t.Fatal("a fleet without relays was accepted")
	}
}

func TestSumMetricMatchesWholeNamesAndLabels(t *testing.T) {
	text := `# HELP x
wirenet_relay_forwarded_bytes_total 100
wirenet_relay_forwarded_bytes_total_extra 7
wirenet_agent_core_events_total{event="failovers"} 2
wirenet_agent_core_events_total{event="failures"} 5
wirenet_agent_kernel_op_seconds_count{kind="apply_rules"} 3
wirenet_agent_kernel_op_seconds_count{kind="apply_rules_x"} 9
`
	for sel, want := range map[string]float64{
		"wirenet_relay_forwarded_bytes_total":                              100,
		`wirenet_agent_core_events_total{event="failovers"}`:               2,
		"wirenet_agent_core_events_total":                                  7,
		`wirenet_agent_kernel_op_seconds_count{kind="apply_rules"}`:        3,
		`wirenet_agent_kernel_op_seconds_count{kind="missing"}`:            0,
		`wirenet_agent_kernel_op_seconds_count{kind="apply_rules_x"}`:      9,
		`wirenet_agent_kernel_op_seconds_count{kind="apply_rules"} broken`: 0,
	} {
		if got := sumMetric(text, sel); got != want {
			t.Errorf("%s = %v, want %v", sel, got, want)
		}
	}
}

func TestShellQuoteSurvivesTheShell(t *testing.T) {
	args := []string{"plain", "with space", "it's", "[fd00::1]:5300", "", "$(reboot)", "a*b", "--netns="}
	out, err := exec.Command("sh", "-c", "printf '%s\\n' "+shellJoin(args)).Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n"); strings.Join(got, "|") != strings.Join(args, "|") {
		t.Fatalf("got %q, want %q", got, args)
	}
}

func TestReportMarkdownCarriesTheSubstrateAndCeiling(t *testing.T) {
	r := &Report{
		Plan: "paths", Env: "aws", Started: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		Substrate: Substrate{Env: "aws", Region: "us-east-1", InstanceTypes: map[Role]string{RoleAgent: "c6i.xlarge"},
			Nodes: []Machine{{Nodes: []string{"h1", "h2"}, Kernel: "7.0.0-1001-aws", CPU: "Intel Xeon", CPUs: "4", RmemMax: "268435456"}}},
		Ceiling: &Ceiling{From: "h1", To: "h2", Streams: 8, BitsPerSecond: 1.621e9, Retransmits: 3},
		Params:  map[string]string{"duration": "10s"},
	}
	r.table(Table{Title: "T", Columns: []string{"Path", "x"}, Rows: [][]string{{"relay", "1"}}})
	md := r.Markdown()
	for _, want := range []string{"region us-east-1", "agent c6i.xlarge", "kernel 7.0.0-1001-aws", "1621 Mbit/s plain TCP, h1 to h2, 8 stream(s)", "| Path | x |\n|---|--:|\n| relay | 1 |"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
}
