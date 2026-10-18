//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sdn.sh/internal/bench"
)

// agentClient speaks the agent's local API (internal/agent/localapi) over
// its unix socket. It declares only the fields it uses.
type agentClient struct{ http *http.Client }

type localInterface struct {
	Interface string `json:"interface"`
	Namespace string `json:"namespace"`
	Addr6     string `json:"addr6"`
}

func newAgentClient(socket string) *agentClient {
	return &agentClient{http: &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
			MaxIdleConnsPerHost: 64,
		},
	}}
}

func (a *agentClient) call(path string, in any) (localInterface, error) {
	var out localInterface
	body, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	resp, err := a.http.Post("http://agent"+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct{ Code, Message string }
		if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
			return out, fmt.Errorf("%s: %s", path, resp.Status)
		}
		return out, fmt.Errorf("%s: %s: %s", path, e.Code, e.Message)
	}
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

func (a *agentClient) attach(name, network, service string) (localInterface, error) {
	return a.call("/v1/attach", map[string]string{"name": name, "network": network, "service": service})
}

func (a *agentClient) detach(id string) error {
	_, err := a.call("/v1/detach", map[string]string{"interface": id})
	return err
}

func agent(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sdn-bench agent attach|detach|churn|density ...")
	}
	cmds := map[string]func([]string) error{
		"attach": agentAttach, "detach": agentDetach, "churn": agentChurn, "density": agentDensity,
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		return fmt.Errorf("unknown agent subcommand %q", args[0])
	}
	return cmd(args[1:])
}

func socketFlag(fs *flag.FlagSet) *string {
	return fs.String("socket", "/run/sdn/agent.sock", "the agent's local API socket")
}

func agentAttach(args []string) error {
	fs := flag.NewFlagSet("agent attach", flag.ContinueOnError)
	socket := socketFlag(fs)
	network := fs.String("network", "", "network")
	service := fs.String("service", "", "service")
	name := fs.String("name", "", "workload name; rounds add -1, -2, ...")
	rounds := fs.Int("rounds", 1, "attaches to run one after another")
	target := fs.String("dial", "", "address:port to reach from each new namespace")
	until := fs.Duration("until", 20*time.Second, "how long to try the first connection")
	interval := fs.Duration("interval", 5*time.Millisecond, "pause between connection attempts")
	detach := fs.Bool("detach", false, "detach each interface after its round, outside the timer")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *network == "" || *service == "" || *name == "" || *rounds < 1 {
		return errors.New("agent attach: --network, --service, --name and a positive --rounds are required")
	}
	a := newAgentClient(*socket)
	var res bench.Attach
	var attachT, connT []time.Duration
	for i := 1; i <= *rounds; i++ {
		wname := *name
		if *rounds > 1 {
			wname += "-" + strconv.Itoa(i)
		}
		start := time.Now()
		li, err := a.attach(wname, *network, *service)
		round := bench.AttachRound{Interface: li.Interface, Namespace: li.Namespace, Addr6: li.Addr6, AttachMS: ms(time.Since(start))}
		if err != nil {
			round.Error = err.Error()
			res.Failures++
			res.Rounds = append(res.Rounds, round)
			continue
		}
		attachT = append(attachT, time.Since(start))
		if *target != "" {
			d := dialLoop(li.Namespace, *target, "", 1, *until, *interval, 500*time.Millisecond)
			took := time.Duration(d.FirstDone - start.UnixNano())
			round.Reached = d.Reached
			if d.Reached {
				round.FirstConn = ms(took)
				connT = append(connT, took)
				res.Reached++
			} else {
				round.Error = d.Error
				res.Failures++
			}
		}
		res.Rounds = append(res.Rounds, round)
		if *detach {
			if err := a.detach(li.Interface); err != nil {
				return fmt.Errorf("detaching %s: %w", li.Interface, err)
			}
		}
	}
	res.Attach, res.FirstConn = bench.Summarize(attachT), bench.Summarize(connT)
	return emit(res)
}

func agentDetach(args []string) error {
	fs := flag.NewFlagSet("agent detach", flag.ContinueOnError)
	socket := socketFlag(fs)
	id := fs.String("interface", "", "interface identifier")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("agent detach: --interface is required")
	}
	start := time.Now()
	if err := newAgentClient(*socket).detach(*id); err != nil {
		return err
	}
	done := time.Now()
	return emit(bench.Detach{Interface: *id, Start: start.UnixNano(), Done: done.UnixNano(), MS: ms(done.Sub(start))})
}

func agentChurn(args []string) error {
	fs := flag.NewFlagSet("agent churn", flag.ContinueOnError)
	socket := socketFlag(fs)
	network := fs.String("network", "", "network")
	service := fs.String("service", "", "service")
	name := fs.String("name", "churn", "workload name prefix")
	duration := fs.Duration("duration", 10*time.Second, "how long to churn")
	concurrency := fs.Int("concurrency", 4, "workers, each attaching then detaching")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *network == "" || *service == "" || *concurrency < 1 {
		return errors.New("agent churn: --network, --service and a positive --concurrency are required")
	}
	a := newAgentClient(*socket)
	res := bench.Churn{Concurrency: *concurrency}
	var mu sync.Mutex
	var attachT, detachT []time.Duration
	note := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		res.Failures++
		if len(res.Errors) < 5 {
			res.Errors = append(res.Errors, err.Error())
		}
	}
	start := time.Now()
	deadline := start.Add(*duration)
	var wg sync.WaitGroup
	for w := range *concurrency {
		wg.Go(func() {
			for i := 0; time.Now().Before(deadline); i++ {
				mu.Lock()
				res.Attempts++
				mu.Unlock()
				t0 := time.Now()
				li, err := a.attach(fmt.Sprintf("%s-%d-%d", *name, w, i), *network, *service)
				if err != nil {
					note(err)
					continue
				}
				t1 := time.Now()
				if err := a.detach(li.Interface); err != nil {
					note(fmt.Errorf("detach %s: %w", li.Interface, err))
					mu.Lock()
					res.Attached++
					attachT = append(attachT, t1.Sub(t0))
					mu.Unlock()
					continue
				}
				mu.Lock()
				res.Attached++
				res.Detached++
				attachT = append(attachT, t1.Sub(t0))
				detachT = append(detachT, time.Since(t1))
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	res.Seconds = time.Since(start).Seconds()
	res.PerSecond = float64(res.Detached) / res.Seconds
	res.Attach, res.Detach = bench.Summarize(attachT), bench.Summarize(detachT)
	return emit(res)
}

func agentDensity(args []string) error {
	fs := flag.NewFlagSet("agent density", flag.ContinueOnError)
	socket := socketFlag(fs)
	network := fs.String("network", "", "network")
	service := fs.String("service", "", "service")
	name := fs.String("name", "dense", "workload name prefix")
	maxN := fs.Int("max", 1000, "interfaces to stop at")
	window := fs.Int("window", 20, "attaches per latency window")
	degrade := fs.Float64("degrade", 10, "stop once a window's median attach exceeds the first window's by this factor")
	target := fs.String("dial", "", "address:port each verified namespace must reach")
	verify := fs.Int("verify", 10, "namespaces, spread from first to last, that must reach --dial")
	until := fs.Duration("until", 20*time.Second, "how long a verified namespace tries")
	detachers := fs.Int("detach-concurrency", 8, "detaches at once")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *network == "" || *service == "" || *maxN < 1 || *window < 1 || *detachers < 1 {
		return errors.New("agent density: --network, --service and positive --max, --window and --detach-concurrency are required")
	}
	a := newAgentClient(*socket)
	res := bench.Density{Max: *maxN, Stopped: "max"}
	var err error
	if res.MemBefore, err = memAvailable(); err != nil {
		return err
	}
	var held []localInterface
	var samples []time.Duration
	for i := range *maxN {
		t0 := time.Now()
		li, err := a.attach(fmt.Sprintf("%s-%d", *name, i), *network, *service)
		if err != nil {
			res.Stopped, res.Error = "failed", err.Error()
			break
		}
		took := time.Since(t0)
		held = append(held, li)
		samples = append(samples, took)
		res.AttachMS = append(res.AttachMS, ms(took))
		if n := len(samples); n >= 2**window && n%*window == 0 {
			first := bench.Summarize(slices.Clone(samples[:*window]))
			last := bench.Summarize(slices.Clone(samples[n-*window:]))
			if last.P50 > *degrade*first.P50 {
				res.Stopped = "degraded"
				break
			}
		}
	}
	res.Interfaces = len(held)
	if res.MemPeak, err = memAvailable(); err != nil {
		return err
	}
	if len(samples) > 0 {
		w := min(*window, len(samples))
		res.First = bench.Summarize(slices.Clone(samples[:w]))
		res.Last = bench.Summarize(slices.Clone(samples[len(samples)-w:]))
	}
	if *target != "" && len(held) > 0 {
		picks := spread(len(held), *verify)
		res.Verified = len(picks)
		var reached atomic.Int64
		var wg sync.WaitGroup
		for _, i := range picks {
			wg.Go(func() {
				if dialLoop(held[i].Namespace, *target, "", 1, *until, 20*time.Millisecond, 500*time.Millisecond).Reached {
					reached.Add(1)
				}
			})
		}
		wg.Wait()
		res.Reached = int(reached.Load())
	}
	// Detach everything, counting each success.
	var mu sync.Mutex
	var detachT []time.Duration
	work := make(chan localInterface)
	start := time.Now()
	var wg sync.WaitGroup
	for range *detachers {
		wg.Go(func() {
			for li := range work {
				t0 := time.Now()
				err := a.detach(li.Interface)
				mu.Lock()
				if err != nil {
					res.DetachFailures++
				} else {
					res.Detached++
					detachT = append(detachT, time.Since(t0))
				}
				mu.Unlock()
			}
		})
	}
	for _, li := range held {
		work <- li
	}
	close(work)
	wg.Wait()
	res.DetachSeconds = time.Since(start).Seconds()
	res.Detach = bench.Summarize(detachT)
	return emit(res)
}

// memAvailable reads MemAvailable from /proc/meminfo, in kibibytes.
func memAvailable() (int64, error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "MemAvailable:" {
			return strconv.ParseInt(f[1], 10, 64)
		}
	}
	return 0, errors.New("/proc/meminfo has no MemAvailable")
}

// spread picks up to k indexes from 0 to n-1, evenly, first and last
// included.
func spread(n, k int) []int {
	if k >= n {
		k = n
	}
	if k <= 1 {
		return []int{n - 1}[:min(k, 1)]
	}
	out := make([]int, 0, k)
	for i := range k {
		idx := i * (n - 1) / (k - 1)
		if len(out) == 0 || out[len(out)-1] != idx {
			out = append(out, idx)
		}
	}
	return out
}
