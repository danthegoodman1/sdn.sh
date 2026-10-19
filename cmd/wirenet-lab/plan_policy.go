package main

import (
	"fmt"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/bench"
)

// policyDial is how often each sandbox launches a connection while a rule
// change settles, which bounds each figure's resolution.
const policyDial = 2 * time.Millisecond

// policyChange is one measured rule change.
type policyChange struct {
	Name    string        `json:"name"`
	Commit  time.Time     `json:"commit"`
	Dials   []bench.Dials `json:"dials"`
	Settled bench.Latency `json:"settled"`
}

// planPolicy opens db to every service with a wildcard, attaches sandbox
// clients across the hosts, then denies the sandboxes db and removes the
// deny, timing each from its commit until every sandbox's new connections
// fail, or reach db again.
func planPolicy(r *run) error {
	if err := r.quickCeiling(); err != nil {
		return err
	}
	hs := r.env.Hosts()
	s := convergeSetup{hosts: hs, db: hs[len(hs)-1], byHost: make([][]string, len(hs))}
	svcs, err := r.network("policy", r.env.Relays()[:1], []string{"db", "box"}, [2]string{api.Wildcard, "db"})
	if err != nil {
		return err
	}
	s.to = port(svcs["db"].Addr6).String()
	db, err := r.attach(s.db, "db-1", "policy", "db")
	if err != nil {
		return err
	}
	if _, err := r.serve(s.db, db.Namespace, port(db.Addr6), "db-1"); err != nil {
		return err
	}
	r.logf("policy: %d sandboxes over %d hosts", r.o.Clients, len(hs))
	clients, err := r.spreadAttach(hs, "box", "policy", "box", r.o.Clients, false)
	if err != nil {
		return err
	}
	for i, c := range clients {
		s.byHost[i%len(hs)] = append(s.byHost[i%len(hs)], c.Namespace)
	}
	if err := r.reachAll(s, "db-1"); err != nil {
		return err
	}
	var changes []policyChange
	defer func() { r.policyTable(s, changes) }()

	var deny api.Rule
	closed, err := r.measureRule(s, "deny", "", true, func() error {
		return r.ctl(r.env.CP(), &deny, "rule", "create", "policy", "box", "db", "--deny", "--proto", "any")
	})
	changes = append(changes, closed)
	if err != nil {
		return err
	}
	opened, err := r.measureRule(s, "deny removed", "db-1", false, func() error {
		return r.ctl(r.env.CP(), nil, "rule", "delete", "policy", string(deny.ID))
	})
	changes = append(changes, opened)
	return err
}

// measureRule makes a rule change a second into every client's dial loop,
// then times each client from the change's commit to the first of 20
// connections in a row that reach want, or with refused that fail. The
// network's revision must advance by exactly one across the change, so its
// commit time is the change's own.
func (r *run) measureRule(s convergeSetup, name, want string, refused bool, apply func() error) (policyChange, error) {
	c := policyChange{Name: name, Dials: make([]bench.Dials, len(s.hosts))}
	var extra []string
	if refused {
		extra = []string{"--refused"}
	}
	fns := r.dialAll(s, want, 20, policyDial, c.Dials, extra...)
	fns = append(fns, func() error {
		r.sleep(time.Second)
		var before, after api.Network
		if err := r.ctl(r.env.CP(), &before, "network", "get", "policy"); err != nil {
			return err
		}
		if err := apply(); err != nil {
			return err
		}
		if err := r.ctl(r.env.CP(), &after, "network", "get", "policy"); err != nil {
			return err
		}
		if after.Revision != before.Revision+1 && !r.env.DryRun() {
			return fmt.Errorf("%s: the network moved from revision %d to %d across one change", name, before.Revision, after.Revision)
		}
		c.Commit = after.Changed
		return nil
	})
	r.logf("policy: %s", name)
	if err := together(fns...); err != nil {
		return c, err
	}
	var settled []time.Duration
	for _, d := range c.Dials {
		for _, res := range d.Results {
			if !r.check(res.Reached, "%s: sandbox %s never settled: %d attempts, %d failures, answers %v, %s", name, res.Namespace, res.Attempts, res.Failures, res.Answers, res.Error) {
				continue
			}
			// A connection in flight at the commit can fail because of the
			// change, since removing a peer destroys its flows' sockets; it
			// counts as settling at the commit. One begun longer before
			// had timed out by then.
			took := time.Duration(res.Converged - c.Commit.UnixNano())
			if r.check(took > -dialTimeout, "%s: sandbox %s settled %v before the commit", name, res.Namespace, -took) {
				settled = append(settled, max(took, 0))
			}
		}
	}
	r.check(len(settled) == r.o.Clients, "%s: %d of %d sandboxes settled", name, len(settled), r.o.Clients)
	c.Settled = bench.Summarize(settled)
	return c, nil
}

func (r *run) policyTable(s convergeSetup, changes []policyChange) {
	if len(changes) == 0 {
		return
	}
	r.data("changes", changes)
	t := Table{
		Title:   fmt.Sprintf("Rule change to settled, %d sandboxes", r.o.Clients),
		Columns: []string{"Change", "Sandboxes settled", "p50", "p90", "p99", "max"},
	}
	for _, c := range changes {
		t.Rows = append(t.Rows, []string{c.Name, itoa(c.Settled.Count), msec(c.Settled.P50), msec(c.Settled.P90), msec(c.Settled.P99), msec(c.Settled.Max)})
	}
	t.Caption = fmt.Sprintf("db, on %s, takes TCP from every other service through `* -> db`, and the sandboxes are clients spread over every host. "+
		"The deny is `box -> db` for any protocol. Times run from the control plane's commit of each change; each sandbox launches a connection "+
		"every %v and settles at the first of 20 in a row that fail after the deny, or reach db once it is gone, so each figure is good to %v.", s.db.Name, policyDial, policyDial)
	if r.env.Name() != "local" {
		t.Caption += " Sandbox and control-plane times come from different machines' clocks, so the figures carry their synchronization error."
	}
	r.rep.table(t)
}
