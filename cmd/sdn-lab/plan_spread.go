package main

import (
	"fmt"
	"strings"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/bench"
	"sdn.sh/internal/model"
)

// spreadRound is one relay set's run: every edge streaming at once.
type spreadRound struct {
	Relays []string `json:"relays"`
	// Edges counts the edges each relay carries by the edges' weights, with
	// every relay up.
	Edges         map[string]int       `json:"edges_per_relay"`
	Streams       []bench.Stream       `json:"streams"`
	BitsPerSecond float64              `json:"bits_per_second"`
	Forwarded     map[string]float64   `json:"forwarded_bytes"`
	CPU           map[string]bench.CPU `json:"relay_cpu"`
}

// spreadEdge is one client streaming to its own server.
type spreadEdge struct {
	from, to Node
	cli, srv api.LocalInterface
}

// planSpread streams over many edges at once through one relay, then two,
// then three, so a network's throughput can be read against its relay count.
// Clients run on the first half of the hosts and servers on the rest, each
// client streaming to its own server's address, so each stream is one edge.
func planSpread(r *run) error {
	if err := r.quickCeiling(); err != nil {
		return err
	}
	hs, relays := r.env.Hosts(), r.env.Relays()
	if len(relays) < 2 {
		return fmt.Errorf("spread needs 2 relays, the environment has %d", len(relays))
	}
	split := (len(hs) + 1) / 2
	senders, receivers := hs[:split], hs[split:]
	var infos []api.RelayInfo
	if err := r.ctl(r.env.CP(), &infos, "relay", "list"); err != nil {
		return err
	}
	ids := map[string]model.RelayID{}
	for _, info := range infos {
		ids[info.Name] = info.ID
	}
	var rounds []spreadRound
	defer func() {
		r.data("spread", rounds)
		r.spreadTable(rounds)
	}()
	for k := 1; k <= min(3, len(relays)); k++ {
		set := relays[:k]
		name := fmt.Sprintf("spread%d", k)
		r.logf("spread: %d relay(s), %d edges", k, r.o.Edges)
		if _, err := r.network(name, set, []string{"client", "server"}, [2]string{"client", "server"}); err != nil {
			return err
		}
		var edges []spreadEdge
		for i := range r.o.Edges {
			e := spreadEdge{from: senders[i%len(senders)], to: receivers[i%len(receivers)]}
			var err error
			if e.srv, err = r.attach(e.to, fmt.Sprintf("%s-s%d", name, i), name, "server"); err != nil {
				return err
			}
			if _, err := r.serve(e.to, e.srv.Namespace, port(e.srv.Addr6), e.srv.Name); err != nil {
				return err
			}
			if e.cli, err = r.attach(e.from, fmt.Sprintf("%s-c%d", name, i), name, "client"); err != nil {
				return err
			}
			edges = append(edges, e)
		}
		for _, e := range edges {
			if _, err := r.reach(e.from, e.cli.Namespace, port(e.srv.Addr6), 30*time.Second); err != nil {
				return err
			}
		}
		round := spreadRound{Edges: map[string]int{}, Forwarded: map[string]float64{}, CPU: map[string]bench.CPU{}}
		carrier := make([]string, len(edges))
		for i, e := range edges {
			var w uint64
			for _, n := range set {
				if x := model.RelayWeight(e.cli.Interface, e.srv.Interface, ids[n.Name]); carrier[i] == "" || x > w {
					carrier[i], w = n.Name, x
				}
			}
			round.Edges[carrier[i]]++
		}
		before := map[string]float64{}
		for _, n := range set {
			round.Relays = append(round.Relays, n.Name)
			v, err := r.metric(n, "sdn_relay_forwarded_bytes_total")
			if err != nil {
				return err
			}
			before[n.Name] = v
		}
		round.Streams = make([]bench.Stream, len(edges))
		cpus := make([]bench.CPU, len(set))
		var fns []func() error
		for i, e := range edges {
			fns = append(fns, func() error {
				return r.bench(e.from, &round.Streams[i], "stream", "--target", port(e.srv.Addr6).String(), "--netns="+e.cli.Namespace,
					"--duration", r.o.Duration.String(), "--parallel", "1")
			})
		}
		for i, n := range set {
			fns = append(fns, func() error { return r.bench(n, &cpus[i], "cpu", "--duration", r.o.Duration.String()) })
		}
		if err := together(fns...); err != nil {
			return err
		}
		carried := map[string]int64{}
		for i, s := range round.Streams {
			round.BitsPerSecond += s.BitsPerSecond
			carried[carrier[i]] += s.Bytes
		}
		for i, n := range set {
			round.CPU[n.Name] = cpus[i]
			v, err := r.metric(n, "sdn_relay_forwarded_bytes_total")
			if err != nil {
				return err
			}
			round.Forwarded[n.Name] = v - before[n.Name]
			// Verified by traffic: each relay forwarded at least what the
			// edges its weight wins carried.
			r.check(round.Forwarded[n.Name] >= float64(carried[n.Name]), "%d relays: %s forwarded %.0f bytes, fewer than the %d its %d edges carried",
				k, n.Name, round.Forwarded[n.Name], carried[n.Name], round.Edges[n.Name])
		}
		rounds = append(rounds, round)
	}
	return nil
}

func (r *run) spreadTable(rounds []spreadRound) {
	if len(rounds) == 0 {
		return
	}
	t := Table{
		Title:   fmt.Sprintf("Throughput by relay count, %d edges", r.o.Edges),
		Columns: []string{"Relays", "Edges per relay", "Aggregate", "Gbit per relay CPU-second", "Relay CPU busy"},
	}
	for _, rd := range rounds {
		var edges, cpu []string
		var busy float64
		for _, name := range rd.Relays {
			edges = append(edges, fmt.Sprintf("%s %d", name, rd.Edges[name]))
			c := rd.CPU[name]
			busy += c.Busy
			cpu = append(cpu, fmt.Sprintf("%s %ss", name, num(c.Busy, 1)))
		}
		var bytes float64
		for _, name := range rd.Relays {
			bytes += rd.Forwarded[name]
		}
		perCPU := "—"
		if busy > 0 {
			perCPU = num(bytes*8/1e9/busy, 2)
		}
		t.Rows = append(t.Rows, []string{itoa(len(rd.Relays)), strings.Join(edges, ", "), mbit(rd.BitsPerSecond), perCPU, strings.Join(cpu, ", ")})
	}
	t.Caption = fmt.Sprintf("Every edge streams one TCP connection for %v at once, clients on the first half of the hosts and servers on the rest. "+
		"Aggregate is the sum of what every server received. Edges per relay come from the edges' weights with every relay up; "+
		"relay CPU is busy time from /proc/stat over the same window, and bits per relay CPU-second divide what the relays forwarded by it.", r.o.Duration)
	r.rep.table(t)
	if r.env.Name() == "local" {
		r.rep.note("Every role shares one kernel in the local environment, so the relays compete with the endpoints' encryption for the same cores, and the aggregate cannot grow with relays.")
	}
}
