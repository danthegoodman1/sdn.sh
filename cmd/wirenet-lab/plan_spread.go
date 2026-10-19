package main

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/bench"
	"github.com/danthegoodman1/wirenet/internal/model"
)

// spreadRound is one relay set's run: every edge streaming at once. The
// plain round streams the same pairs over the hosts' own addresses.
type spreadRound struct {
	Plain  bool     `json:"plain,omitempty"`
	Relays []string `json:"relays"`
	// Edges counts the edges each relay carries by the edges' weights, with
	// every relay up.
	Edges         map[string]int       `json:"edges_per_relay"`
	Streams       []bench.Stream       `json:"streams"`
	BitsPerSecond float64              `json:"bits_per_second"`
	Forwarded     map[string]float64   `json:"forwarded_bytes"`
	CPU           map[string]bench.CPU `json:"relay_cpu"`
	// HostCPU is every endpoint host's, to show when the endpoints'
	// encryption rather than the relays bounds the aggregate.
	HostCPU map[string]bench.CPU `json:"host_cpu"`
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
// The same streams first run as plain TCP between the hosts, which gives
// the hosts' CPU per bit without the overlay.
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
	plain, err := r.plainSpread(senders, receivers)
	if err != nil {
		return err
	}
	rounds = append(rounds, plain)
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
		round := spreadRound{Edges: map[string]int{}, Forwarded: map[string]float64{}, CPU: map[string]bench.CPU{}, HostCPU: map[string]bench.CPU{}}
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
			v, err := r.metric(n, "wirenet_relay_forwarded_bytes_total")
			if err != nil {
				return err
			}
			before[n.Name] = v
		}
		round.Streams = make([]bench.Stream, len(edges))
		cpus := make([]bench.CPU, len(set))
		at := startAt()
		var fns []func() error
		for i, e := range edges {
			fns = append(fns, func() error {
				return r.bench(e.from, &round.Streams[i], "stream", "--target", port(e.srv.Addr6).String(), "--netns="+e.cli.Namespace,
					"--duration", r.o.Duration.String(), "--parallel", "1", "--at", at)
			})
		}
		for i, n := range set {
			fns = append(fns, func() error { return r.bench(n, &cpus[i], "cpu", "--duration", r.o.Duration.String(), "--at", at) })
		}
		hcpus := make([]bench.CPU, len(hs))
		for i, n := range hs {
			fns = append(fns, func() error { return r.bench(n, &hcpus[i], "cpu", "--duration", r.o.Duration.String(), "--at", at) })
		}
		if err := together(fns...); err != nil {
			return err
		}
		carried := map[string]int64{}
		for i, s := range round.Streams {
			round.BitsPerSecond += s.BitsPerSecond
			carried[carrier[i]] += s.Bytes
		}
		for i, n := range hs {
			round.HostCPU[n.Name] = hcpus[i]
		}
		for i, n := range set {
			round.CPU[n.Name] = cpus[i]
			v, err := r.metric(n, "wirenet_relay_forwarded_bytes_total")
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

// plainSpread streams the plan's edges as plain TCP between the hosts' own
// addresses, each sender to the receiver the overlay rounds pair it with,
// and reads every host's CPU over the same window.
func (r *run) plainSpread(senders, receivers []Node) (spreadRound, error) {
	round := spreadRound{Plain: true, Edges: map[string]int{}, Forwarded: map[string]float64{}, CPU: map[string]bench.CPU{}, HostCPU: map[string]bench.CPU{}}
	r.logf("spread: plain TCP, %d streams", r.o.Edges)
	for _, b := range receivers {
		srv, err := r.serve(b, "", netip.AddrPortFrom(b.Addr, bench.Port), b.Name)
		if err != nil {
			return round, err
		}
		defer srv.Stop(r.ctx)
		for _, a := range senders {
			if _, err := r.reach(a, "", netip.AddrPortFrom(b.Addr, bench.Port), 10*time.Second); err != nil {
				return round, err
			}
		}
	}
	hs := r.env.Hosts()
	round.Streams = make([]bench.Stream, r.o.Edges)
	hcpus := make([]bench.CPU, len(hs))
	at := startAt()
	var fns []func() error
	for i := range r.o.Edges {
		from, to := senders[i%len(senders)], receivers[i%len(receivers)]
		fns = append(fns, func() error {
			return r.bench(from, &round.Streams[i], "stream", "--target", netip.AddrPortFrom(to.Addr, bench.Port).String(), "--netns=",
				"--duration", r.o.Duration.String(), "--parallel", "1", "--at", at)
		})
	}
	for i, n := range hs {
		fns = append(fns, func() error { return r.bench(n, &hcpus[i], "cpu", "--duration", r.o.Duration.String(), "--at", at) })
	}
	if err := together(fns...); err != nil {
		return round, err
	}
	for _, s := range round.Streams {
		round.BitsPerSecond += s.BitsPerSecond
	}
	for i, n := range hs {
		round.HostCPU[n.Name] = hcpus[i]
	}
	return round, nil
}

func (r *run) spreadTable(rounds []spreadRound) {
	if len(rounds) == 0 {
		return
	}
	t := Table{
		Title:   fmt.Sprintf("Throughput by relay count, %d edges", r.o.Edges),
		Columns: []string{"Relays", "Edges per relay", "Aggregate", "Gbit per relay CPU-second", "Relay CPU busy", "Host CPU busy"},
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
		var hosts []string
		for _, name := range slices.Sorted(maps.Keys(rd.HostCPU)) {
			hosts = append(hosts, fmt.Sprintf("%s %ss", name, num(rd.HostCPU[name].Busy, 1)))
		}
		relays, perRelay, relayCPU := itoa(len(rd.Relays)), strings.Join(edges, ", "), strings.Join(cpu, ", ")
		if rd.Plain {
			relays, perRelay, relayCPU = "none, plain TCP", "—", "—"
		}
		t.Rows = append(t.Rows, []string{relays, perRelay, mbit(rd.BitsPerSecond), perCPU, relayCPU, strings.Join(hosts, ", ")})
	}
	t.Caption = fmt.Sprintf("Every edge streams one TCP connection for %v, every stream and CPU sample starting at one wall-clock time, clients on the first half of the hosts and servers on the rest; "+
		"the plain-TCP row runs the same pairs between the hosts' own addresses, with no overlay. "+
		"Aggregate is the sum of what every server received. Edges per relay come from the edges' weights with every relay up; "+
		"relay and host CPU is busy time from /proc/stat over the same window, so a machine with every CPU busy reads its CPU count times the window, and bits per relay CPU-second divide what the relays forwarded by the relays' busy time.", r.o.Duration)
	r.rep.table(t)
	if r.env.Name() == "local" {
		r.rep.note("Every role shares one kernel in the local environment, so the relays compete with the endpoints' encryption for the same cores, and the aggregate cannot grow with relays.")
	}
}
