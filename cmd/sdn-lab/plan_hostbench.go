package main

import (
	"strings"
	"sync"
)

// planHostbench runs cmd/hostbench on each agent host at once. The local
// environment's hosts share one kernel, so it runs there once.
func planHostbench(r *run) error {
	if err := r.quickCeiling(); err != nil {
		return err
	}
	hosts := r.env.Hosts()
	if r.env.Name() == "local" {
		hosts = hosts[:1]
		r.rep.note("The local environment's hosts share one kernel, so hostbench ran once, in %s's namespace.", hosts[0].Name)
	}
	outs := make([]string, len(hosts))
	var mu sync.Mutex
	err := forEach(hosts, func(n Node) error {
		r.logf("hostbench: running on %s", n.Name)
		out, err := r.env.Exec(r.ctx, n, r.env.Bin("hostbench"))
		mu.Lock()
		defer mu.Unlock()
		for i, h := range hosts {
			if h.Name == n.Name {
				outs[i] = string(out)
			}
		}
		return err
	})
	for i, h := range hosts {
		r.rep.Raw = append(r.rep.Raw, Raw{Title: "hostbench on " + h.Name, Text: outs[i]})
		r.check(strings.Contains(outs[i], "all assertions passed"), "hostbench on %s did not pass its assertions", h.Name)
	}
	r.data("hostbench", outs)
	return err
}
