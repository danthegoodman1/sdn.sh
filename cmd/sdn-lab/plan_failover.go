package main

import (
	"fmt"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/bench"
)

// failoverRound is one relay kill.
type failoverRound struct {
	Killed  string   `json:"killed"`
	After   string   `json:"moved_to"`
	Flow    bench.RR `json:"established_flow"`
	NewConn float64  `json:"new_connection_ms"`
	Dial    bench.Dial
	// Failovers counts the agents' relay failovers during the round.
	Failovers float64 `json:"failovers"`
}

// edgeRelay names the relay n's agent sends its one edge through, as its
// count of peers on each relay shows.
func (r *run) edgeRelay(n Node) (string, error) {
	var relays []api.RelayInfo
	if err := r.ctl(r.env.CP(), &relays, "relay", "list"); err != nil {
		return "", err
	}
	var st struct {
		Peers map[string]int `json:"relay_peers"`
	}
	if err := r.ctl(n, &st, "status"); err != nil {
		return "", err
	}
	var carrying []string
	for _, rl := range relays {
		if st.Peers[string(rl.ID)] > 0 {
			carrying = append(carrying, rl.Name)
		}
	}
	if r.env.DryRun() {
		return r.env.Relays()[0].Name, nil
	}
	if len(carrying) != 1 {
		return "", fmt.Errorf("%s's peers send through %v; want one relay carrying its one edge", n.Name, st.Peers)
	}
	return carrying[0], nil
}

func planFailover(r *run) error {
	if err := r.quickCeiling(); err != nil {
		return err
	}
	hs := r.env.Hosts()
	a, b := hs[0], hs[1]
	relays := r.env.Relays()
	if len(relays) < 2 {
		return fmt.Errorf("failover needs 2 relays, the environment has %d", len(relays))
	}
	svcs, err := r.network("failover", relays[:2], []string{"web", "db"}, [2]string{"web", "db"})
	if err != nil {
		return err
	}
	db, err := r.attach(b, "db", "failover", "db")
	if err != nil {
		return err
	}
	if _, err := r.serve(b, db.Namespace, port(db.Addr6), "db"); err != nil {
		return err
	}
	web, err := r.attach(a, "web", "failover", "web")
	if err != nil {
		return err
	}
	to := port(svcs["db"].Addr6)
	if _, err := r.reach(a, web.Namespace, to, 30*time.Second); err != nil {
		return err
	}
	byName := map[string]Node{}
	for _, n := range relays {
		byName[n.Name] = n
	}
	failovers := func() (float64, error) {
		var sum float64
		for _, h := range []Node{a, b} {
			v, err := r.metric(h, `sdn_agent_core_events_total{event="failovers"}`)
			if err != nil {
				return 0, err
			}
			sum += v
		}
		return sum, nil
	}
	rounds := min(r.o.Rounds, 3)
	var results []failoverRound
	defer func() { r.data("failover", results) }()
	for i := range rounds {
		carrying, err := r.edgeRelay(a)
		if err != nil {
			return err
		}
		victim, ok := byName[carrying]
		if !ok {
			return fmt.Errorf("%s's edge sends through %q, which is not in the set", a.Name, carrying)
		}
		f0, err := failovers()
		if err != nil {
			return err
		}
		round := failoverRound{Killed: victim.Name}
		r.logf("failover: round %d, killing %s", i+1, victim.Name)
		// The established flow runs round trips every 5ms from before the
		// kill until well after it; its worst round trip is the stall.
		if err := together(
			func() error {
				return r.bench(a, &round.Flow, "rr", "--target", to.String(), "--netns="+web.Namespace, "--duration", "12s", "--interval", "5ms")
			},
			func() error {
				r.sleep(3 * time.Second)
				if err := r.env.StopRelay(r.ctx, victim); err != nil {
					return err
				}
				// A new connection, from the moment the kill returned.
				d, err := r.reach(a, web.Namespace, to, 15*time.Second)
				round.Dial = d
				round.NewConn = float64(d.FirstDone-d.Start) / 1e6
				return err
			},
		); err != nil {
			return err
		}
		f1, err := failovers()
		if err != nil {
			return err
		}
		round.Failovers = f1 - f0
		if round.After, err = r.edgeRelay(a); err != nil {
			return err
		}
		r.check(round.Flow.Error == "", "round %d: the established flow broke: %s", i+1, round.Flow.Error)
		r.check(round.After != victim.Name, "round %d: %s still sends to the dead relay %s", i+1, a.Name, victim.Name)
		r.check(round.Failovers >= 1, "round %d: the agents counted no failover", i+1)
		results = append(results, round)
		if err := r.env.StartRelay(r.ctx, victim); err != nil {
			return err
		}
		// Let probes see the relay again, which brings the edge back to it.
		r.sleep(2 * time.Second)
	}
	t := Table{
		Title:   "Relay loss to resumed traffic",
		Columns: []string{"Round", "Killed", "Moved to", "Established flow's stall", "New connection after the kill", "Round trips p99"},
	}
	for i, rd := range results {
		t.Rows = append(t.Rows, []string{itoa(i + 1), rd.Killed, rd.After, msec(rd.Flow.Latency.Max), msec(rd.NewConn), msec(rd.Flow.Latency.P99)})
	}
	t.Caption = "The established flow sends a round trip every 5ms across the kill; its stall is its slowest round trip, which includes TCP's " +
		"retransmission backoff. The new connection's wait runs from the moment the kill command returned to its first successful connection, " +
		"launching one every 20ms. The killed relay restarts between rounds."
	r.rep.table(t)
	return nil
}
