package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/bench"
)

// opStats is an agent's nftables work so far: apply_rules operations and
// their seconds, and transactions and the objects they wrote.
type opStats struct{ count, seconds, nftCount, nftSize float64 }

func (r *run) applyRules(n Node) (opStats, error) {
	text, err := r.env.Metrics(r.ctx, n)
	if err != nil {
		return opStats{}, err
	}
	return opStats{
		count:    sumMetric(text, `wirenet_agent_kernel_op_seconds_count{kind="apply_rules"}`),
		seconds:  sumMetric(text, `wirenet_agent_kernel_op_seconds_sum{kind="apply_rules"}`),
		nftCount: sumMetric(text, `wirenet_agent_nft_transaction_size_count`),
		nftSize:  sumMetric(text, `wirenet_agent_nft_transaction_size_sum`),
	}, nil
}

// convergeSetup is the network a converge run changes.
type convergeSetup struct {
	hosts  []Node
	db     Node       // the backends' host
	byHost [][]string // client namespaces on each host
	to     string     // the db service's address
}

// change is one measured service change.
type change struct {
	Name     string        `json:"name"`
	Detach   bench.Detach  `json:"detach"`
	Dials    []bench.Dials `json:"dials"`
	Churn    []bench.Churn `json:"churn"`
	Settled  bench.Latency `json:"settled"`
	Departed bench.Latency `json:"last_departing_answer"`
	rules    []opStats
	relay    [2]map[string]float64
}

// dialAll runs a dial loop in every client, one wirenet-bench per host.
func (r *run) dialAll(s convergeSetup, want string, streak int, interval time.Duration, out []bench.Dials) []func() error {
	var fns []func() error
	for i, h := range s.hosts {
		if len(s.byHost[i]) == 0 {
			continue
		}
		fns = append(fns, func() error {
			return r.bench(h, &out[i], "dial", "--target", s.to, "--netns", strings.Join(s.byHost[i], ","), "--want", want,
				"--streak", itoa(streak), "--interval", interval.String(), "--timeout", "300ms", "--until", "60s")
		})
	}
	return fns
}

// reachAll waits until every client has reached want at least once.
func (r *run) reachAll(s convergeSetup, want string) error {
	out := make([]bench.Dials, len(s.hosts))
	if err := together(r.dialAll(s, want, 1, 20*time.Millisecond, out)...); err != nil {
		return err
	}
	for _, d := range out {
		for _, res := range d.Results {
			if !r.check(res.Reached, "client %s never reached %s: %s", res.Namespace, want, res.Error) {
				return fmt.Errorf("the clients did not all reach %s", want)
			}
		}
	}
	return nil
}

// measureChange detaches leaving while every host churns and every client
// dials until its new connections reach only want. When next is set, it
// first attaches next on the db host and serves it.
func (r *run) measureChange(s convergeSetup, name, next string, leaving api.LocalInterface, want string) (change, error) {
	c := change{Name: name, Dials: make([]bench.Dials, len(s.hosts)), Churn: make([]bench.Churn, len(s.hosts)), rules: make([]opStats, len(s.hosts))}
	relay := r.env.Relays()[0]
	var err error
	if c.relay[0], err = r.relayReadings(relay); err != nil {
		return c, err
	}
	before := make([]opStats, len(s.hosts))
	for i, h := range s.hosts {
		if before[i], err = r.applyRules(h); err != nil {
			return c, err
		}
	}
	churnFor := max(r.o.Duration, 5*time.Second)
	var fns []func() error
	for i, h := range s.hosts {
		fns = append(fns, func() error {
			return r.bench(h, &c.Churn[i], "agent", "churn", "--socket", r.env.AgentSocket(h), "--network", "converge", "--service", "noise",
				"--name", fmt.Sprintf("noise-%s-%s", strings.Fields(name)[0], h.Name), "--duration", churnFor.String(), "--concurrency", itoa(r.o.Concurrency))
		})
	}
	fns = append(fns, r.dialAll(s, want, 20, 10*time.Millisecond, c.Dials)...)
	fns = append(fns, func() error {
		r.sleep(time.Second)
		if next != "" {
			li, err := r.attach(s.db, next, "converge", "db")
			if err != nil {
				return err
			}
			if _, err := r.serve(s.db, li.Namespace, port(li.Addr6), next); err != nil {
				return err
			}
		}
		return r.bench(s.db, &c.Detach, "agent", "detach", "--socket", r.env.AgentSocket(s.db), "--interface", string(leaving.Interface))
	})
	r.logf("converge: %s under churn", name)
	if err := together(fns...); err != nil {
		return c, err
	}
	if c.relay[1], err = r.relayReadings(relay); err != nil {
		return c, err
	}
	for i, h := range s.hosts {
		after, err := r.applyRules(h)
		if err != nil {
			return c, err
		}
		c.rules[i] = opStats{after.count - before[i].count, after.seconds - before[i].seconds, after.nftCount - before[i].nftCount, after.nftSize - before[i].nftSize}
		ch := c.Churn[i]
		r.check(ch.Failures == 0 && ch.Attempts == ch.Attached && ch.Attached == ch.Detached,
			"%s, %s: churn %d attempts, %d attached, %d detached, %d failures: %v", name, h.Name, ch.Attempts, ch.Attached, ch.Detached, ch.Failures, ch.Errors)
	}
	var settled, departed []time.Duration
	for _, d := range c.Dials {
		for _, res := range d.Results {
			if !r.check(res.Reached, "%s: client %s never settled on %s: %d attempts, answers %v, %s", name, res.Namespace, want, res.Attempts, res.Answers, res.Error) {
				continue
			}
			settled = append(settled, time.Duration(res.Converged-c.Detach.Start))
			if res.Other > c.Detach.Start {
				departed = append(departed, time.Duration(res.Other-c.Detach.Start))
			}
		}
	}
	r.check(len(settled) == r.o.Clients, "%s: %d of %d clients settled on %s", name, len(settled), r.o.Clients, want)
	c.Settled, c.Departed = bench.Summarize(settled), bench.Summarize(departed)
	return c, nil
}

func planConverge(r *run) error {
	if err := r.quickCeiling(); err != nil {
		return err
	}
	hs := r.env.Hosts()
	s := convergeSetup{hosts: hs, db: hs[len(hs)-1], byHost: make([][]string, len(hs))}
	svcs, err := r.network("converge", r.env.Relays()[:1], []string{"web", "db", "noise"}, [2]string{"web", "db"}, [2]string{"noise", "db"})
	if err != nil {
		return err
	}
	s.to = port(svcs["db"].Addr6).String()
	first, err := r.attach(s.db, "db-1", "converge", "db")
	if err != nil {
		return err
	}
	if _, err := r.serve(s.db, first.Namespace, port(first.Addr6), "db-1"); err != nil {
		return err
	}
	r.logf("converge: %d clients over %d hosts", r.o.Clients, len(hs))
	clients, err := r.spreadAttach(hs, "web", "converge", "web", r.o.Clients, false)
	if err != nil {
		return err
	}
	for i, c := range clients {
		s.byHost[i%len(hs)] = append(s.byHost[i%len(hs)], c.Namespace)
	}
	if err := r.reachAll(s, "db-1"); err != nil {
		return err
	}
	var changes []change
	defer func() { r.convergeTables(s, changes) }()

	// A cold replacement: a new backend attaches and the old one leaves at
	// once, so clients meet the new backend before any has a session.
	cold, err := r.measureChange(s, "cold replacement", "db-2", first, "db-2")
	changes = append(changes, cold)
	if err != nil {
		return err
	}

	// A warm removal: a third backend attaches and every client reaches
	// it before db-2 leaves, so the change is the push and the slot-map
	// rewrite alone.
	third, err := r.attach(s.db, "db-3", "converge", "db")
	if err != nil {
		return err
	}
	if _, err := r.serve(s.db, third.Namespace, port(third.Addr6), "db-3"); err != nil {
		return err
	}
	if err := r.reachAll(s, "db-3"); err != nil {
		return err
	}
	var second api.LocalInterface
	var ifs []api.LocalInterface
	if err := r.ctl(s.db, &ifs, "interfaces"); err != nil {
		return err
	}
	for _, li := range ifs {
		if li.Name == "db-2" {
			second = li
		}
	}
	if second.Interface == "" && !r.env.DryRun() {
		return fmt.Errorf("%s's agent does not list db-2", s.db.Name)
	}
	warm, err := r.measureChange(s, "warm removal", "", second, "db-3")
	changes = append(changes, warm)
	return err
}

func (r *run) convergeTables(s convergeSetup, changes []change) {
	if len(changes) == 0 {
		return
	}
	r.data("changes", changes)
	t := Table{
		Title:   fmt.Sprintf("Service change to settled, %d clients", r.o.Clients),
		Columns: []string{"Change", "Clients settled", "p50", "p90", "p99", "max", "Last answer from the departing backend, max"},
	}
	for _, c := range changes {
		t.Rows = append(t.Rows, []string{c.Name, itoa(c.Settled.Count), msec(c.Settled.P50), msec(c.Settled.P90), msec(c.Settled.P99),
			msec(c.Settled.Max), msec(c.Departed.Max)})
	}
	t.Caption = fmt.Sprintf("Times run from the departing backend's detach on %s. Each client launches a connection every 10ms and settles at the first "+
		"of 20 in a row that reach the backend that stays, so each figure is good to 10ms. A cold replacement attaches the new backend a second "+
		"before the old one leaves; a warm removal leaves two backends that every client has reached, then removes one, which rewrites half "+
		"the service's slot map in every client namespace.", s.db.Name)
	if r.env.Name() != "local" {
		t.Caption += " Client and backend times come from different machines' clocks, so the figures carry their synchronization error."
	}
	r.rep.table(t)

	ct := Table{
		Title:   "Under churn, during each change",
		Columns: []string{"Change", "Host", "Pairs", "Pairs per second", "Failures", "Rule transactions", "Mean transaction", "Mean objects per transaction"},
	}
	for _, c := range changes {
		for i, h := range s.hosts {
			ch, ru := c.Churn[i], c.rules[i]
			mean, size := "—", "—"
			if ru.count > 0 {
				mean = msec(ru.seconds / ru.count * 1000)
			}
			if ru.nftCount > 0 {
				size = num(ru.nftSize/ru.nftCount, 0)
			}
			ct.Rows = append(ct.Rows, []string{c.Name, h.Name, itoa(ch.Detached), num(ch.PerSecond, 1), itoa(ch.Failures), num(ru.count, 0), mean, size})
		}
	}
	ct.Caption = fmt.Sprintf("Each host attaches and detaches clients of the same backends with %d workers through each change, so each attach and detach "+
		"also changes the backends' host. Rule transactions are each agent's nftables transactions over the change, churn included, from its metrics.", r.o.Concurrency)
	r.rep.table(ct)
	for _, c := range changes {
		if c.relay[0] != nil && c.relay[1] != nil {
			r.relayTable(r.env.Relays()[0], "The relay during the "+c.Name, c.relay[0], c.relay[1])
		}
	}
}
