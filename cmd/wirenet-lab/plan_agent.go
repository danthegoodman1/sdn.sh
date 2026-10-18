package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/bench"
)

// spreadAttach attaches count workloads of a service round-robin over
// hosts, each serving its own name on wirenet-bench's port.
func (r *run) spreadAttach(hosts []Node, prefix, network, service string, count int, serve bool) ([]api.LocalInterface, error) {
	out := make([]api.LocalInterface, count)
	byHost := map[int][]int{}
	for i := range count {
		byHost[i%len(hosts)] = append(byHost[i%len(hosts)], i)
	}
	var fns []func() error
	for h, idxs := range byHost {
		fns = append(fns, func() error {
			for _, i := range idxs {
				name := fmt.Sprintf("%s-%d", prefix, i)
				li, err := r.attach(hosts[h], name, network, service)
				if err != nil {
					return err
				}
				out[i] = li
				if serve {
					if _, err := r.serve(hosts[h], li.Namespace, port(li.Addr6), name); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
	return out, together(fns...)
}

func planAttach(r *run) error {
	if err := r.quickCeiling(); err != nil {
		return err
	}
	hs := r.env.Hosts()
	a, others := hs[0], hs[1:]
	svcs, err := r.network("attach", r.env.Relays()[:1], []string{"peer", "new"}, [2]string{"new", "peer"})
	if err != nil {
		return err
	}
	// The policy degree: every new interface peers with each of these,
	// all on other hosts, so a first connection crosses the relay.
	if _, err := r.spreadAttach(others, "peer", "attach", "peer", r.o.Degree, true); err != nil {
		return err
	}
	var peers []api.InterfaceInfo
	if err := r.ctl(r.env.CP(), &peers, "interface", "list", "attach"); err != nil {
		return err
	}
	r.check(len(peers) == r.o.Degree, "the network holds %d interfaces, want the %d peers", len(peers), r.o.Degree)
	to := port(svcs["peer"].Addr6)
	agentArgs := func(name string, rounds int) []string {
		return []string{"agent", "attach", "--socket", r.env.AgentSocket(a), "--network", "attach", "--service", "new",
			"--name", name, "--rounds", itoa(rounds), "--dial", to.String(), "--until", "30s", "--detach"}
	}
	// One round to warm the path, outside the figures.
	var warm bench.Attach
	if err := r.bench(a, &warm, agentArgs("warm", 1)...); err != nil {
		return err
	}
	r.check(warm.Reached == 1, "the warm-up attach never reached a peer: %+v", warm.Rounds)
	relay := r.env.Relays()[0]
	before, err := r.relayReadings(relay)
	if err != nil {
		return err
	}
	r.logf("attach: %d rounds at degree %d", r.o.Rounds, r.o.Degree)
	var res bench.Attach
	if err := r.bench(a, &res, agentArgs("new", r.o.Rounds)...); err != nil {
		return err
	}
	after, err := r.relayReadings(relay)
	if err != nil {
		return err
	}
	r.data("attach", res)
	defer r.relayTable(relay, "The relay during the rounds", before, after)
	r.check(res.Failures == 0 && res.Reached == r.o.Rounds, "%d of %d rounds reached a peer, %d failed", res.Reached, r.o.Rounds, res.Failures)
	t := Table{
		Title:   fmt.Sprintf("Attach to first connection, policy degree %d", r.o.Degree),
		Columns: []string{"Stage", "Rounds", "p50", "p90", "max"},
		Rows: [][]string{
			{"Local API attach returns", itoa(res.Attach.Count), msec(res.Attach.P50), msec(res.Attach.P90), msec(res.Attach.Max)},
			{"First connection to a remote peer", itoa(res.FirstConn.Count), msec(res.FirstConn.P50), msec(res.FirstConn.P90), msec(res.FirstConn.Max)},
		},
		Caption: fmt.Sprintf("Both stages are timed from the attach request on %s. The first connection dials the peer service's address, "+
			"so it lands on a random peer on another host and needs that host to have installed the new interface. Each round detaches its "+
			"interface afterwards, outside the timer.", a.Name),
	}
	r.rep.table(t)
	var rows []string
	for _, rd := range res.Rounds {
		rows = append(rows, fmt.Sprintf("%s/%s", msec(rd.AttachMS), msec(rd.FirstConn)))
	}
	r.rep.note("Per round, attach/first connection: %s.", strings.Join(rows, ", "))
	return nil
}

func planChurn(r *run) error {
	if err := r.quickCeiling(); err != nil {
		return err
	}
	hs := r.env.Hosts()
	relays := r.env.Relays()[:1]
	if _, err := r.network("churn", relays, []string{"anchor", "churn"}, [2]string{"churn", "anchor"}); err != nil {
		return err
	}
	// Each churned interface peers with every anchor, spread over the
	// hosts, so an attach also costs neighbour work elsewhere.
	if _, err := r.spreadAttach(hs, "anchor", "churn", "anchor", r.o.ChurnDegree, false); err != nil {
		return err
	}
	baseline := map[string]int{}
	for _, h := range hs {
		n, err := r.agentInterfaces(h)
		if err != nil {
			return err
		}
		baseline[h.Name] = n
	}
	relay := relays[0]
	relayBefore, err := r.relayReadings(relay)
	if err != nil {
		return err
	}
	results := make([]bench.Churn, len(hs))
	var fns []func() error
	for i, h := range hs {
		fns = append(fns, func() error {
			return r.bench(h, &results[i], "agent", "churn", "--socket", r.env.AgentSocket(h), "--network", "churn", "--service", "churn",
				"--name", "churn-"+h.Name, "--duration", r.o.Duration.String(), "--concurrency", itoa(r.o.Concurrency))
		})
	}
	r.logf("churn: %v on %d hosts, %d workers each", r.o.Duration, len(hs), r.o.Concurrency)
	if err := together(fns...); err != nil {
		return err
	}
	relayAfter, err := r.relayReadings(relay)
	if err != nil {
		return err
	}
	defer r.relayTable(relay, "The relay during the churn", relayBefore, relayAfter)
	r.data("churn", results)
	if r.env.Name() == "local" {
		r.rep.note("The local environment's hosts share one kernel, so they share one RTNL lock too, and their rates are not independent.")
	}
	t := Table{
		Title:   fmt.Sprintf("Attach and detach, %d workers per host, policy degree %d", r.o.Concurrency, r.o.ChurnDegree),
		Columns: []string{"Host", "Pairs", "Pairs per second", "Attach p50", "Attach p99", "Detach p50", "Detach p99", "Failures"},
	}
	var total bench.Churn
	for i, h := range hs {
		c := results[i]
		// Every attempt finished: each attach succeeded and was detached.
		r.check(c.Failures == 0 && c.Attempts == c.Attached && c.Attached == c.Detached,
			"%s: %d attempts, %d attached, %d detached, %d failures: %v", h.Name, c.Attempts, c.Attached, c.Detached, c.Failures, c.Errors)
		r.check(c.Attempts > 0 || r.env.DryRun(), "%s: no attempt ran", h.Name)
		left, err := r.agentInterfaces(h)
		if err != nil {
			return err
		}
		r.check(left == baseline[h.Name], "%s: the agent holds %d interfaces after churn, %d before", h.Name, left, baseline[h.Name])
		nss, err := r.namespaces(h)
		if err != nil {
			return err
		}
		r.check(nss == baseline[h.Name], "%s: %d agent namespaces after churn, %d interfaces", h.Name, nss, baseline[h.Name])
		t.Rows = append(t.Rows, []string{h.Name, itoa(c.Detached), num(c.PerSecond, 1), msec(c.Attach.P50), msec(c.Attach.P99),
			msec(c.Detach.P50), msec(c.Detach.P99), itoa(c.Failures)})
		total.Detached += c.Detached
		total.PerSecond += c.PerSecond
		total.Failures += c.Failures
	}
	t.Rows = append(t.Rows, []string{"all hosts", itoa(total.Detached), num(total.PerSecond, 1), "", "", "", "", itoa(total.Failures)})
	t.Caption = fmt.Sprintf("A pair is one attach and its detach. Every churned interface peers with %d anchors spread over the hosts, so each attach "+
		"also adds a peer on their devices. Each host ends with the interfaces it began with, checked through its agent and its namespaces.", r.o.ChurnDegree)
	r.rep.table(t)
	ports := total.Detached * r.o.ChurnDegree * 2 * len(relays)
	r.rep.note("The run took %d relay ports (%d attaches × degree %d × 2 directions × %d relay), each quarantined for the control plane's port quarantine after its edge ends.",
		ports, total.Detached, r.o.ChurnDegree, len(relays))
	return nil
}

// agentInterfaces counts the interfaces n's agent holds.
func (r *run) agentInterfaces(n Node) (int, error) {
	var ifs []api.LocalInterface
	if err := r.ctl(n, &ifs, "interfaces"); err != nil {
		return 0, err
	}
	return len(ifs), nil
}

// namespaces counts n's agent namespaces under /run/netns.
func (r *run) namespaces(n Node) (int, error) {
	out, err := r.env.Exec(r.ctx, n, "ls", "/run/netns")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, name := range strings.Fields(string(out)) {
		if strings.HasPrefix(name, r.env.NamespacePrefix(n)) {
			count++
		}
	}
	return count, nil
}

func planDensity(r *run) error {
	if err := r.quickCeiling(); err != nil {
		return err
	}
	hs := r.env.Hosts()
	a, b := hs[0], hs[1]
	svcs, err := r.network("density", r.env.Relays()[:1], []string{"anchor", "dense"}, [2]string{"dense", "anchor"})
	if err != nil {
		return err
	}
	anchor, err := r.attach(b, "anchor", "density", "anchor")
	if err != nil {
		return err
	}
	if _, err := r.serve(b, anchor.Namespace, port(anchor.Addr6), "anchor"); err != nil {
		return err
	}
	before, err := r.agentInterfaces(a)
	if err != nil {
		return err
	}
	r.logf("density: up to %d interfaces on %s", r.o.MaxIfaces, a.Name)
	var d bench.Density
	if err := r.bench(a, &d, "agent", "density", "--socket", r.env.AgentSocket(a), "--network", "density", "--service", "dense",
		"--name", "dense", "--max", itoa(r.o.MaxIfaces), "--dial", port(svcs["anchor"].Addr6).String(), "--verify", "10"); err != nil {
		return err
	}
	r.data("density", d)
	r.check(d.Stopped != "failed", "an attach failed at %d interfaces: %s", d.Interfaces, d.Error)
	r.check(d.Reached == d.Verified, "%d of %d sampled interfaces reached the anchor", d.Reached, d.Verified)
	r.check(d.Detached == d.Interfaces && d.DetachFailures == 0, "detached %d of %d interfaces, %d failed", d.Detached, d.Interfaces, d.DetachFailures)
	after, err := r.agentInterfaces(a)
	if err != nil {
		return err
	}
	r.check(after == before, "%s holds %d interfaces after detaching, %d before", a.Name, after, before)

	t := Table{
		Title:   fmt.Sprintf("Interfaces on one host, policy degree 1, cap %d", r.o.MaxIfaces),
		Columns: []string{"Interfaces held", "Attach p50", "Attach p99", "Attach max"},
	}
	samples := d.AttachMS
	step := max(len(samples)/10, 1)
	for lo := 0; lo < len(samples); lo += step {
		hi := min(lo+step, len(samples))
		var w []time.Duration
		for _, v := range samples[lo:hi] {
			w = append(w, bench.Millis(v))
		}
		l := bench.Summarize(w)
		t.Rows = append(t.Rows, []string{fmt.Sprintf("%d–%d", lo+1, hi), msec(l.P50), msec(l.P99), msec(l.Max)})
	}
	t.Caption = fmt.Sprintf("Attaches run one after another on %s. Each interface peers with one anchor on %s, whose device ends up holding every one of them.", a.Name, b.Name)
	r.rep.table(t)
	stopped := map[string]string{"max": "the cap", "failed": "a failed attach", "degraded": "degraded attach latency"}[d.Stopped]
	perIface := "—"
	if d.Interfaces > 0 && d.MemBefore > d.MemPeak {
		perIface = fmt.Sprintf("%.0f KiB", float64(d.MemBefore-d.MemPeak)/float64(d.Interfaces))
	}
	r.rep.table(Table{
		Title:   "Summary",
		Columns: []string{"Interfaces", "Stopped at", "Sampled that reached the anchor", "Memory per interface", "Detach all", "Detach p50", "Detach p99"},
		Rows: [][]string{{itoa(d.Interfaces), stopped, fmt.Sprintf("%d of %d", d.Reached, d.Verified), perIface,
			num(d.DetachSeconds, 1) + "s", msec(d.Detach.P50), msec(d.Detach.P99)}},
		Caption: "Memory per interface is the fall in the host's MemAvailable from before the first attach to the last, divided by the interfaces held. " +
			"The run stops early when a window's median attach exceeds the first window's tenfold.",
	})
	if r.env.Name() == "local" {
		r.rep.note("MemAvailable is the whole machine's in the local environment, so other work on it moves the memory figure.")
	}
	return nil
}
