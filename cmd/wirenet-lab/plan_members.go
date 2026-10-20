package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/bench"
)

// The members plan's network, etcd's ports, and how many keys the cluster
// holds when a member moves.
const (
	membersNet  = "members"
	etcdClient  = 2379
	etcdPeer    = 2380
	membersKeys = 200
	// etcdDirs holds each member's data directory on its host.
	etcdDirs = "/tmp/wirenet-lab-etcd"
)

// etcdMember is one member of the cluster: the workload holding its name,
// on a host, and its etcd process.
type etcdMember struct {
	name string
	host Node
	li   api.LocalInterface
	proc Stopper
}

func (m *etcdMember) dir() string { return etcdDirs + "/" + m.li.Name }

// memberMove is one measured move of a member to another host. Attach is
// the replacing attach and the new member's first connection to etcd-1,
// made at once from one process on its host, as a workload starting after
// its attach would, and timed there from the attach request. Commit is the
// control plane's commit of the attach, and Started when etcd and a
// wirenet-bench server started in the new namespace, by its host's clock.
// Every peer began asking for the member's name, and dialing it (Inbound),
// before the replacement attached, and Healthy and Synced are when the
// first health check the new member passed, and the first read that found
// every key on it, finished, by the client's clock. Republished is whether
// etcd's log has the new member's first attempt to publish itself to the
// cluster timing out.
type memberMove struct {
	Member      string            `json:"member"`
	From        string            `json:"from"`
	To          string            `json:"to"`
	Attach      bench.AttachRound `json:"attach"`
	Commit      time.Time         `json:"commit"`
	Started     int64             `json:"started_unix_ns"`
	Lookups     []bench.Lookup    `json:"lookups"`
	Inbound     []bench.Dial      `json:"inbound"`
	Healthy     int64             `json:"healthy_unix_ns"`
	Synced      int64             `json:"synced_unix_ns"`
	Republished bool              `json:"republished"`
	Fenced      bool              `json:"fenced"`
}

// memberURL is the URL a member is known by at one of its ports.
func memberURL(member string, port int) string {
	return fmt.Sprintf("http://%s.etcd.%s.internal:%d", member, membersNet, port)
}

// etcdNames are the cluster's members, one per host.
var etcdNames = []string{"etcd-1", "etcd-2", "etcd-3"}

func etcdCluster() string {
	var parts []string
	for _, m := range etcdNames {
		parts = append(parts, m+"="+memberURL(m, etcdPeer))
	}
	return strings.Join(parts, ",")
}

// planMembers runs a three-member etcd cluster in one service, each member
// holding its name, and then moves etcd-2 to another host round after
// round, as an orchestrator would after losing its host: the process stops,
// the cluster swaps the member for a new one at the same peer URL, and a
// workload on another host attaches holding etcd-2 and replacing its
// holder. No member's configuration changes. Each round times the names,
// the new member's health and its catching up, and checks that the
// replaced holder reaches none of its peers.
func planMembers(r *run) error {
	hs := r.env.Hosts()
	if len(hs) < 3 {
		return errors.New("members: needs three agent hosts")
	}
	for _, h := range hs {
		if _, err := r.env.Exec(r.ctx, h, "test", "-x", r.env.Bin("etcd"), "-a", "-x", r.env.Bin("etcdctl")); err != nil {
			return fmt.Errorf("members: %s has no etcd and etcdctl in %s; put them in --bin (deploy/README.md): %w", h.Name, path.Dir(r.env.Bin("etcd")), err)
		}
	}
	if err := r.quickCeiling(); err != nil {
		return err
	}
	if _, err := r.network(membersNet, r.env.Relays()[:1], []string{"etcd", "app"}); err != nil {
		return err
	}
	for _, rule := range [][3]string{{"etcd", "etcd", "2379-2380"}, {"etcd", "etcd", itoa(bench.Port)}, {"app", "etcd", itoa(etcdClient)}} {
		if err := r.ctl(r.env.CP(), nil, "rule", "create", membersNet, rule[0], rule[1], "--proto", "tcp", "--ports", rule[2]); err != nil {
			return err
		}
	}
	var namespaces []nsOn
	members := make([]*etcdMember, len(etcdNames))
	defer func() {
		for _, m := range members {
			if m != nil && m.proc != nil {
				m.proc.Stop(r.ctx)
			}
		}
		for _, ns := range namespaces {
			r.env.Exec(r.ctx, ns.host, "rm", "-rf", "/etc/netns/"+ns.name, etcdDirs)
		}
	}()
	attach := func(h Node, workload, member string, replace bool) (api.LocalInterface, error) {
		args := []string{"attach", workload, membersNet, "etcd", "--member", member}
		if replace {
			args = append(args, "--replace")
		}
		var li api.LocalInterface
		if err := r.ctl(h, &li, args...); err != nil {
			return li, err
		}
		r.check(li.Member == member+".etcd."+membersNet+".internal", "%s's attach names it %q", workload, li.Member)
		namespaces = append(namespaces, nsOn{h, li.Namespace})
		return li, r.resolvConf(h, li)
	}

	for i, name := range etcdNames {
		li, err := attach(hs[i], name+"-r0", name, false)
		if err != nil {
			return err
		}
		members[i] = &etcdMember{name: name, host: hs[i], li: li}
	}
	app, err := r.attach(hs[0], "app-1", membersNet, "app")
	if err != nil {
		return err
	}
	namespaces = append(namespaces, nsOn{hs[0], app.Namespace})
	if err := r.resolvConf(hs[0], app); err != nil {
		return err
	}
	client := nsOn{hs[0], app.Namespace}
	for _, m := range members {
		if err := r.startEtcd(m, "new"); err != nil {
			return err
		}
	}
	formed := time.Now()
	var all []string
	for _, m := range etcdNames {
		all = append(all, memberURL(m, etcdClient))
	}
	if _, err := r.untilOK(client, 30*time.Second, r.etcdctlArgv("--endpoints", strings.Join(all, ","), "endpoint", "health")...); err != nil {
		return fmt.Errorf("members: the cluster never formed: %w", err)
	}
	r.logf("members: the cluster formed in %v", time.Since(formed).Round(time.Millisecond))
	put := fmt.Sprintf("for i in $(seq 1 %d); do %s put key-$i value-$i >/dev/null || exit 1; done", membersKeys,
		shellJoin(r.etcdctlArgv("--endpoints", "http://etcd."+membersNet+".internal:"+itoa(etcdClient))))
	if _, err := r.env.Exec(r.ctx, client.host, "ip", "netns", "exec", client.name, "sh", "-c", put); err != nil {
		return fmt.Errorf("members: writing keys through the service: %w", err)
	}

	// etcd-1's namespace answers wirenet-bench, so the replaced holder's
	// reach can be put to the test.
	if _, err := r.serve(members[0].host, members[0].li.Namespace, port(members[0].li.Addr6), members[0].name); err != nil {
		return err
	}
	var moves []memberMove
	defer func() { r.membersTable(moves) }()
	moving := members[1]
	for round := 1; round <= r.o.Rounds; round++ {
		to := hs[len(hs)-1]
		if moving.host.Name == to.Name {
			to = hs[1]
		}
		mv, err := r.moveMember(moving, members, to, round, client, attach)
		moves = append(moves, mv)
		if err != nil {
			return err
		}
	}
	// Every member answers, and the cluster still knows etcd-2 by name.
	if _, err := r.untilOK(client, 30*time.Second, r.etcdctlArgv("--endpoints", strings.Join(all, ","), "endpoint", "health")...); err != nil {
		return fmt.Errorf("members: the cluster is unhealthy after the moves: %w", err)
	}
	list, err := r.memberList(client)
	if err != nil {
		return err
	}
	for _, m := range list.Members {
		r.check(slices.Equal(m.PeerURLs, []string{memberURL(m.Name, etcdPeer)}), "member %s's peer URLs are %v", m.Name, m.PeerURLs)
	}
	r.check(len(list.Members) == len(etcdNames) || r.env.DryRun(), "the cluster holds %d members", len(list.Members))
	return nil
}

// nsOn is a namespace on a host.
type nsOn struct {
	host Node
	name string
}

// moveMember stops m as a lost host would, swaps it for a new member at the
// same peer URL, and attaches its replacement on to with replace. Every
// measurement on the peers' side starts first, so each figure comes from
// the hosts' clocks.
func (r *run) moveMember(m *etcdMember, members []*etcdMember, to Node, round int, client nsOn,
	attach func(Node, string, string, bool) (api.LocalInterface, error)) (memberMove, error) {
	mv := memberMove{Member: m.name, From: m.host.Name, To: to.Name}
	old, oldHost := m.li, m.host
	r.logf("members: round %d moves %s from %s to %s", round, m.name, oldHost.Name, to.Name)
	if err := m.proc.Stop(r.ctx); err != nil {
		return mv, err
	}
	list, err := r.memberList(client)
	if err != nil {
		return mv, err
	}
	id := uint64(0)
	for _, e := range list.Members {
		if e.Name == m.name {
			id = e.ID
		}
	}
	if id == 0 && !r.env.DryRun() {
		return mv, fmt.Errorf("members: the cluster lists no %s: %+v", m.name, list.Members)
	}
	endpoint := r.etcdctlArgv("--endpoints", memberURL(members[0].name, etcdClient))
	if _, err := r.inNS(client, append(slices.Clone(endpoint), "member", "remove", strconv.FormatUint(id, 16))...); err != nil {
		return mv, err
	}
	// etcd refuses a member until its leader has seen the rest a while,
	// so the add repeats; one that took effect before its answer was lost
	// leaves the peer URL taken.
	add := shellJoin(append(slices.Clone(endpoint), "member", "add", m.name, "--peer-urls="+memberURL(m.name, etcdPeer)))
	if _, err := r.untilOK(client, 30*time.Second, "sh", "-c", fmt.Sprintf(`out=$(%s 2>&1) || echo "$out" | grep -q "already exists"`, add)); err != nil {
		return mv, fmt.Errorf("members: round %d: the cluster never took a new %s: %w", round, m.name, err)
	}

	name := m.name + ".etcd." + membersNet + ".internal."
	workload := fmt.Sprintf("%s-r%d", m.name, round)
	var peers []*etcdMember
	for _, p := range members {
		if p != m {
			peers = append(peers, p)
		}
	}
	mv.Lookups = make([]bench.Lookup, len(peers))
	mv.Inbound = make([]bench.Dial, len(peers))
	var fns []func() error
	for i, p := range peers {
		fns = append(fns, func() error {
			return r.bench(p.host, &mv.Lookups[i], "lookup", "--netns="+p.li.Namespace, "--name", name, "--unlike", old.Addr6.String(), "--until", "20s")
		}, func() error {
			var d bench.Dials
			if err := r.bench(p.host, &d, "dial", "--target", name+":"+itoa(bench.Port), "--netns="+p.li.Namespace, "--want", workload, "--until", "40s"); err != nil {
				return err
			}
			if len(d.Results) == 1 {
				mv.Inbound[i] = d.Results[0]
			}
			return nil
		})
	}
	// Each check is a fresh curl, which fails at once on a refused
	// connection, so none waits out a client library's reconnect backoff:
	// etcdctl's first check, begun before etcd listens, retried only a
	// second later.
	base := memberURL(m.name, etcdClient)
	curl := func(args ...string) string {
		return shellJoin(append([]string{"curl", "-sf", "--connect-timeout", "0.2", "--max-time", "2"}, args...))
	}
	health := curl(base + "/health")
	// A serializable count of the keys from key- up to key., over etcd's
	// gRPC gateway.
	count := curl("-X", "POST", base+"/v3/kv/range", "-d", `{"key":"a2V5LQ==","range_end":"a2V5Lg==","count_only":true,"serializable":true}`)
	fns = append(fns, func() error {
		var err error
		if mv.Healthy, err = r.untilOK(client, 60*time.Second, "sh", "-c", health+` | grep -q '"health":"true"'`); err != nil {
			return fmt.Errorf("members: round %d: the new %s never answered: %w", round, m.name, err)
		}
		return nil
	}, func() error {
		var err error
		if mv.Synced, err = r.untilOK(client, 60*time.Second, "sh", "-c", fmt.Sprintf(`%s | grep -q '"count":"%d"'`, count, membersKeys)); err != nil {
			return fmt.Errorf("members: round %d: the new %s never held every key: %w", round, m.name, err)
		}
		return nil
	})
	var li api.LocalInterface
	fns = append(fns, func() error {
		r.sleep(time.Second)
		var a bench.Attach
		if err := r.bench(to, &a, "agent", "attach", "--socket", r.env.AgentSocket(to), "--network", membersNet, "--service", "etcd",
			"--name", workload, "--member", m.name, "--replace", "--dial", port(members[0].li.Addr6).String(), "--until", "20s"); err != nil {
			return err
		}
		if len(a.Rounds) == 1 {
			mv.Attach = a.Rounds[0]
		}
		// Attaching the workload again answers with its interface.
		var err error
		if li, err = attach(to, workload, m.name, true); err != nil {
			return err
		}
		var after api.Network
		if err := r.ctl(r.env.CP(), &after, "network", "get", membersNet); err != nil {
			return err
		}
		mv.Commit = after.Changed
		m.host, m.li = to, li
		return r.startEtcd(m, "existing",
			shellJoin([]string{r.env.Bin("wirenet-bench"), "serve", "--listen", port(li.Addr6).String(), "--netns=" + li.Namespace, "--name", li.Name}))
	})
	if err := together(fns...); err != nil {
		return mv, err
	}
	for _, l := range mv.Lookups {
		r.check(l.Found && slices.Contains(l.Got, li.Addr6.String()), "round %d: %s's lookup of %s found %v, want %v: %s", round, l.Namespace, name, l.Got, li.Addr6, l.Error)
	}
	for _, d := range mv.Inbound {
		r.check(d.Reached, "round %d: %s never reached the new %s: %+v", round, d.Namespace, m.name, d)
	}
	r.check(mv.Attach.Reached, "round %d: the new %s never reached %s: %+v", round, m.name, members[0].name, mv.Attach)
	started, err := r.env.Exec(r.ctx, to, "cat", m.dir()+".started")
	if err != nil {
		return mv, err
	}
	if !r.env.DryRun() {
		if mv.Started, err = strconv.ParseInt(strings.TrimSpace(string(started)), 10, 64); err != nil {
			return mv, fmt.Errorf("members: the new %s's start: %w", m.name, err)
		}
		log := shellQuote(m.dir() + ".log")
		out, err := r.env.Exec(r.ctx, to, "sh", "-c", fmt.Sprintf("test -f %[1]s && { grep -q 'failed to publish local member' %[1]s && echo yes || echo no; }", log))
		if err != nil {
			return mv, fmt.Errorf("members: the new %s's log: %w", m.name, err)
		}
		mv.Republished = strings.TrimSpace(string(out)) == "yes"
	}

	// The replaced holder is revoked: it reaches no peer.
	var d bench.Dials
	if err := r.bench(oldHost, &d, "dial", "--target", port(members[0].li.Addr6).String(), "--netns="+old.Namespace, "--until", "2s"); err != nil {
		return mv, err
	}
	mv.Fenced = r.env.DryRun() || len(d.Results) == 1 && !d.Results[0].Reached
	r.check(mv.Fenced, "round %d: the replaced holder %s still reaches %s", round, old.Interface, members[0].name)
	var ifaces []api.InterfaceInfo
	if err := r.ctl(r.env.CP(), &ifaces, "interface", "list", membersNet); err != nil {
		return mv, err
	}
	for _, i := range ifaces {
		if i.ID == old.Interface {
			r.check(i.State == api.Revoked, "round %d: the replaced holder is %s", round, i.State)
		}
	}
	return mv, r.ctl(oldHost, nil, "detach", string(old.Interface))
}

// resolvConf points a namespace at the agent's resolver, as a runtime does
// from the attach answer, so `ip netns exec` gives etcd the network's names.
func (r *run) resolvConf(n Node, li api.LocalInterface) error {
	dir := "/etc/netns/" + li.Namespace
	_, err := r.env.Exec(r.ctx, n, "sh", "-c", fmt.Sprintf("mkdir -p %s && printf 'nameserver %s\\nsearch %s\\n' > %s/resolv.conf",
		shellQuote(dir), li.Resolver, li.Search, shellQuote(dir)))
	return err
}

// startEtcd starts m's etcd in its namespace on a fresh data directory,
// joining a new cluster or an existing one. It runs in one process with
// the shell commands alongside, each in the background, so they start
// together and end with it; the process writes when it started, and etcd
// its log, beside the data directory.
func (r *run) startEtcd(m *etcdMember, state string, alongside ...string) error {
	etcd := []string{"ip", "netns", "exec", m.li.Namespace, r.env.Bin("etcd"),
		"--name", m.name, "--data-dir", m.dir(),
		"--listen-peer-urls", fmt.Sprintf("http://[::]:%d", etcdPeer),
		"--listen-client-urls", fmt.Sprintf("http://[::]:%d", etcdClient),
		"--initial-advertise-peer-urls", memberURL(m.name, etcdPeer),
		"--advertise-client-urls", memberURL(m.name, etcdClient),
		"--initial-cluster", etcdCluster(), "--initial-cluster-token", "wirenet-lab",
		"--initial-cluster-state", state, "--log-level", "warn", "--log-outputs", "stderr," + m.dir() + ".log"}
	script := fmt.Sprintf("rm -rf %[1]s %[3]s && mkdir -p %[1]s && date +%%s%%N > %[2]s", shellQuote(m.dir()), shellQuote(m.dir()+".started"), shellQuote(m.dir()+".log"))
	for _, c := range alongside {
		script += " && { " + c + " & }"
	}
	p, err := r.spawn(m.host, "sh", "-c", script+" && exec "+shellJoin(etcd))
	m.proc = p
	return err
}

// etcdctlArgv is etcdctl with args and short timeouts.
func (r *run) etcdctlArgv(args ...string) []string {
	return append([]string{r.env.Bin("etcdctl"), "--dial-timeout", "2s", "--command-timeout", "5s"}, args...)
}

// inNS runs argv in a namespace on its host.
func (r *run) inNS(ns nsOn, argv ...string) ([]byte, error) {
	return r.env.Exec(r.ctx, ns.host, append([]string{"ip", "netns", "exec", ns.name}, argv...)...)
}

// untilOK runs argv in a namespace every 20ms until it succeeds or limit
// passes, and returns when the success finished, by its host's clock.
func (r *run) untilOK(ns nsOn, limit time.Duration, argv ...string) (int64, error) {
	script := fmt.Sprintf(`end=$(( $(date +%%s%%N) + %d )); while [ "$(date +%%s%%N)" -lt "$end" ]; do `+
		`if %s >/dev/null 2>&1; then date +%%s%%N; exit 0; fi; sleep 0.02; done; echo "no success within %v" >&2; exit 1`,
		limit.Nanoseconds(), shellJoin(argv), limit)
	out, err := r.inNS(ns, "sh", "-c", script)
	if err != nil || r.env.DryRun() {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
}

// etcdMembers is `etcdctl member list -w json`.
type etcdMembers struct {
	Members []struct {
		ID       uint64   `json:"ID"`
		Name     string   `json:"name"`
		PeerURLs []string `json:"peerURLs"`
	} `json:"members"`
}

func (r *run) memberList(client nsOn) (etcdMembers, error) {
	var list etcdMembers
	out, err := r.inNS(client, r.etcdctlArgv("--endpoints", memberURL(etcdNames[0], etcdClient), "member", "list", "-w", "json")...)
	if err != nil {
		return list, err
	}
	if r.env.DryRun() {
		return list, nil
	}
	return list, json.Unmarshal(out, &list)
}

func (r *run) membersTable(moves []memberMove) {
	if len(moves) == 0 {
		return
	}
	r.data("moves", moves)
	var attach, first, names, inbound []time.Duration
	// healthy and synced split on whether the first publish timed out.
	healthy, synced := map[bool][]time.Duration{}, map[bool][]time.Duration{}
	fenced := 0
	for _, mv := range moves {
		if mv.Attach.Reached {
			attach = append(attach, time.Duration(mv.Attach.AttachMS*float64(time.Millisecond)))
			first = append(first, time.Duration(mv.Attach.FirstConn*float64(time.Millisecond)))
		}
		fromCommit := func(ns int64) time.Duration { return max(time.Duration(ns-mv.Commit.UnixNano()), 0) }
		fromStart := func(ns int64) time.Duration { return time.Duration(ns - mv.Started) }
		for _, l := range mv.Lookups {
			if l.Found {
				names = append(names, fromCommit(l.First))
			}
		}
		if mv.Started == 0 {
			continue
		}
		for _, d := range mv.Inbound {
			if d.Reached {
				inbound = append(inbound, fromStart(d.FirstDone))
			}
		}
		healthy[mv.Republished] = append(healthy[mv.Republished], fromStart(mv.Healthy))
		synced[mv.Republished] = append(synced[mv.Republished], fromStart(mv.Synced))
		if mv.Fenced {
			fenced++
		}
	}
	t := Table{
		Title:   fmt.Sprintf("etcd-2 moves hosts, %d rounds", len(moves)),
		Columns: []string{"Step", "Measured", "p50", "max"},
	}
	row := func(step, from string, d []time.Duration) {
		l := bench.Summarize(d)
		t.Rows = append(t.Rows, []string{step, from, msec(l.P50), msec(l.Max)})
	}
	row("The replacing attach answers", "from its request", attach)
	row("The new member's first connection reaches etcd-1", "from the attach request", first)
	row("A peer's namespace resolves etcd-2 to its new address", "from the commit", names)
	row("A peer's connection by name reaches the new etcd-2", "from its start", inbound)
	for _, lost := range []bool{false, true} {
		if len(healthy[lost]) == 0 {
			continue
		}
		which := fmt.Sprintf("its first publish through, %d rounds", len(healthy[lost]))
		if lost {
			which = fmt.Sprintf("its first publish timed out, %d rounds", len(healthy[lost]))
		}
		row("The new etcd-2 answers a health check at its name, "+which, "from its start", healthy[lost])
		row("The new etcd-2 serves every key, "+which, "from its start", synced[lost])
	}
	t.Caption = fmt.Sprintf("etcd v3.6 with three members in service `etcd`, each attached with `--member` and known to the others only as "+
		"`http://etcd-N.etcd.members.internal:2380`; %d keys, written through the service address. Each round stops etcd-2's process "+
		"as a lost host would, removes it from the cluster and adds a member at the same peer URL, then attaches a workload on another host "+
		"with `--member etcd-2 --replace` and starts etcd there on an empty data directory; no other member's configuration changes. "+
		"Before the attach, each peer starts asking for etcd-2's name every 5ms and dialing it by name every 20ms, and a client starts "+
		"checking the new member's `/health` and counting its keys with curl every 20ms. One process on the new member's host attaches and dials etcd-1 the "+
		"moment the attach answers, as a starting workload does; etcd then starts there beside a server for the peers' dials. "+
		"Times from the commit run from the control plane's commit of the replacing attach to the first lookup with the new address; "+
		"times from its start run from etcd's start to the end of the first connection or check that succeeded. A new member applies "+
		"the leader's snapshot by stopping and redialing every peer connection (`applySnapshot` in etcd's `server/etcdserver/server.go`), "+
		"and its first attempt to publish itself to the cluster, begun before, can time out after 7 seconds, which etcd logs as a lost "+
		"connection; the last rows split on that attempt. In %d of %d rounds the replaced holder's namespace reached no peer.", membersKeys, fenced, len(moves))
	if r.env.Name() != "local" {
		t.Caption += " Past the first two rows, each figure compares two machines' clocks, so it carries their synchronization error."
	}
	r.rep.table(t)
}
