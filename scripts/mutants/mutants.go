package main

// Files the mutants edit.
const (
	agentCore    = "internal/agent/core/core.go"
	agentLife    = "internal/agent/core/lifecycle.go"
	agentPlan    = "internal/agent/core/plan.go"
	agentTarget  = "internal/agent/core/target.go"
	agentRelays  = "internal/agent/core/relays.go"
	agentDaemon  = "internal/agent/daemon/daemon.go"
	agentResolv  = "internal/agent/resolver/resolver.go"
	agentMain    = "cmd/sdn-agent/main.go"
	agentUnder   = "internal/agent/underlay/underlay.go"
	linuxEgress  = "internal/kernel/linux/egress.go"
	linuxNetns   = "internal/kernel/linux/netns.go"
	nftTx        = "internal/nft/tx.go"
	compileGo    = "internal/compile/compile.go"
	cpAlloc      = "internal/cp/alloc.go"
	cpEdges      = "internal/cp/edges.go"
	cpPlane      = "internal/cp/plane.go"
	cpCensus     = "internal/cp/census.go"
	cpServer     = "internal/cpserver/server.go"
	apiState     = "internal/api/state.go"
	pgTx         = "internal/store/pgstore/tx.go"
	cpHub        = "internal/cpserver/hub.go"
	linuxKernel  = "internal/kernel/linux/linux.go"
	linuxNFT     = "internal/kernel/linux/nftables.go"
	nftGo        = "internal/nft/nft.go"
	regprotoGo   = "internal/regproto/regproto.go"
	relayCore    = "internal/relay/core/core.go"
	relayServer  = "internal/relay/server/server.go"
	relayDisk    = "internal/relay/server/disk.go"
	simCP        = "internal/sim/cpnode.go"
	kmodelGo     = "internal/kernel/kmodel/kmodel.go"
	modelWeight  = "internal/model/relayweight.go"
	agentFDStore = "internal/agent/resolver/fdstore.go"
)

// Code that more than one edit moves or matches.
const (
	// relayDataOld is the relay's check that a data packet comes from its
	// direction's registered endpoint.
	relayDataOld = "if !d.Endpoint.IsValid() || src != d.Endpoint {"
	// applyRules is the agent's nftables transaction within a batch.
	applyRules = "\tif tx := nft.Diff(st.rules, tgt.rules); !tx.Empty() {\n\t\tops = append(ops, kernel.Op{Kind: kernel.ApplyRules, Namespace: st.name, Rules: &tx})\n\t}\n"
	// removeUnwanted opens the agent's loop over installed peers the target
	// drops.
	removeUnwanted = "\tfor _, key := range slices.SortedFunc(maps.Keys(st.peers), compareKey) {\n\t\tif want[key] {\n"
	// destroyFlushed is the kernel's destruction of a flush's sockets.
	destroyFlushed = "n, err := h.diag.destroyMatching(func(s sock) bool {\n\t\treturn cm.carried[flowTuple{s.proto, s.local, s.remote}] || !sweep && match(s.remote.Addr())\n\t})"
	// appendLog is the relay committer's write of registrations to its log.
	appendLog = "\t\t\tif err := s.disk.Append(batch); err != nil {\n\t\t\t\treturn fmt.Errorf(\"registration log: %w\", err)\n\t\t\t}\n"
)

// Mutants are the planted bugs, one per behavior SPEC.md and CLAUDE.md name.
var Mutants = []Mutant{
	{
		ID:     "slot-map-partial",
		Breaks: "every slot of a service's map carries a backend; a missed lookup leaves the packet addressed to the service",
		Edits:  []Edit{{agentTarget, "for slot, i := range table {", "for slot, i := range table[:len(table)-1] {"}},
		Catch:  []string{"sim"},
	},
	{
		ID:     "slot-map-unchecked",
		Breaks: "a slot map shorter than the slot count validates, so nftables would accept a map a lookup can miss",
		Edits:  []Edit{{nftGo, "if len(m.Slots) != Slots {", "if len(m.Slots) > Slots {"}},
		Catch:  []string{"nft"},
	},
	{
		ID:     "numgen-inc",
		Breaks: "slots are drawn with numgen random; numgen inc starts every client namespace on slot 0",
		Edits:  []Edit{{linuxNFT, "Type: unix.NFT_NG_RANDOM", "Type: unix.NFT_NG_INCREMENTAL"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "keepalive-both-sides",
		Breaks: "exactly one side of a co-located pair arms persistent-keepalive",
		Edits:  []Edit{{compileGo, "p.Keepalive = x.ID < y.ID", "p.Keepalive = true"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "keepalive-armed-before-reverse",
		Breaks: "a co-located peer's keepalive is armed only once the other device holds the reverse peer, so its first initiation is never dropped",
		Edits:  []Edit{{agentTarget, "(tp.awaiting || p.Draining)", "p.Draining"}},
		Catch:  []string{"sim"},
	},
	{
		ID:     "slot-before-colocated-reverse",
		Breaks: "no slot names a co-located backend until its device holds the reverse peer, so a client's first initiation is never dropped",
		Edits:  []Edit{{agentTarget, "if !p.peer.Draining && !p.awaiting {", "if !p.peer.Draining {"}},
		Catch:  []string{"sim"},
	},
	{
		ID:     "keepalive-on-relay-peers",
		Breaks: "relay peers carry no persistent-keepalive; the registration datagram holds the NAT mapping",
		Edits:  []Edit{{compileGo, "p.Registration = e.SecretAB", "p.Registration, p.Keepalive = e.SecretAB, true"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "relay-forwards-race-loser",
		Breaks: "a packet from anywhere but the direction's registered endpoint, such as one that lost an endpoint race, is dropped",
		Edits:  []Edit{{relayCore, relayDataOld, "if !d.Endpoint.IsValid() {"}},
		Catch:  []string{"relay-core", "relay-server"},
	},
	{
		ID:     "relay-data-moves-endpoint",
		Breaks: "only a verified registration moves a relay endpoint; a data packet never does",
		Edits:  []Edit{{relayCore, relayDataOld, "if d.Endpoint.IsValid() {\n\t\td.Endpoint = src\n\t}\n\t" + relayDataOld}},
		Catch:  []string{"relay-core", "relay-server", "sim"},
	},
	{
		ID:     "relay-replay-accepted",
		Breaks: "a registration whose counter does not exceed the highest accepted is a replay and fails",
		Edits:  []Edit{{relayCore, "if counter <= d.Counter {", "if counter < d.Counter {"}},
		Catch:  []string{"relay-core", "sim"},
	},
	{
		ID:     "registration-mac-skips-address",
		Breaks: "a registration's MAC covers the relay's advertised address and port, so one captured at one port or relay fails at another",
		Edits: []Edit{{regprotoGo,
			"\ta16 := advertised.Addr().As16()\n\tm.Write(a16[:])\n\tvar port [2]byte\n\tbinary.BigEndian.PutUint16(port[:], advertised.Port())\n\tm.Write(port[:])\n",
			"\t_ = advertised\n"}},
		Catch: []string{"regproto", "relay-core"},
	},
	{
		ID:     "relay-commit-ignores-key",
		Breaks: "a registration commits only under the key it verified under, so one made durable before its port was reallocated commits to nothing",
		Edits:  []Edit{{relayCore, "if !ok || r.Key != d.Key || r.Counter <= d.Counter {", "if !ok || r.Counter <= d.Counter {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "relay-core-commits-on-verify",
		Breaks: "a verified registration moves no endpoint until the shell has made it durable and calls Commit",
		Edits:  []Edit{{relayCore, "return Decision{Verdict: Register, Registration: r}", "t.Commit(r)\n\t\treturn Decision{Verdict: Register, Registration: r}"}},
		Catch:  []string{"relay-core", "relay-server"},
	},
	{
		ID:     "relay-commits-before-durable",
		Breaks: "the relay commits a registration only once its log holds it, so a crash never forgets an endpoint it forwarded to",
		Edits: []Edit{
			{relayServer, appendLog, ""},
			{relayServer, "\t\t\tdirty = true\n", appendLog + "\t\t\tdirty = true\n"},
		},
		Catch: []string{"relay-server"},
	},
	{
		ID:     "agent-skips-flush",
		Breaks: "removing a peer flushes the conntrack entries and sockets addressed to it",
		Edits: []Edit{
			{agentPlan,
				"\t\tops = append(ops,\n\t\t\tkernel.Op{Kind: kernel.SetPeers, Namespace: st.name, Device: c.cfg.Device, Peers: removes},\n\t\t\tkernel.Op{Kind: kernel.Flush, Namespace: st.name, Addrs: flush})",
				"\t\tops = append(ops, kernel.Op{Kind: kernel.SetPeers, Namespace: st.name, Device: c.cfg.Device, Peers: removes})"},
			{agentPlan,
				"\t\t\t\tfor _, a := range st.peers[u.PublicKey].Allowed {\n\t\t\t\t\tif !slices.Contains(st.unflushed, a.Addr()) {\n\t\t\t\t\t\tst.unflushed = append(st.unflushed, a.Addr())\n\t\t\t\t\t}\n\t\t\t\t}\n",
				""},
		},
		Catch: []string{"sim"},
	},
	{
		ID:     "kernel-flush-skips-conntrack",
		Breaks: "a flush deletes the conntrack entries translated to a removed peer's address",
		Edits: []Edit{{linuxKernel,
			"n, err := h.nl.ConntrackDeleteFilters(netlink.ConntrackTable, family, cm)",
			"_ = family\n\t\tn, err := uint(0), error(nil)"}},
		Catch: []string{"kernel"},
	},
	{
		ID:     "kernel-flush-skips-socket-destroy",
		Breaks: "a flush destroys the sockets addressed to a removed peer (SOCK_DESTROY), since flushing conntrack leaves them",
		Edits:  []Edit{{linuxKernel, destroyFlushed, "n, err := 0, error(nil)"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "kernel-flush-spares-translated-sockets",
		Breaks: "a flush destroys the sockets its conntrack entries carried, since a translated client's socket stays addressed to the service it dialed",
		Edits:  []Edit{{linuxKernel, "return cm.carried[flowTuple{s.proto, s.local, s.remote}] || !sweep && match(s.remote.Addr())", "return !sweep && match(s.remote.Addr())"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "kernel-sweep-judges-dialed-address",
		Breaks: "a sweep judges a flow by the addresses its ends send from, so a connection through a live service survives it",
		Edits:  []Edit{{linuxKernel, "\tif !c.senders {\n", "\tif true {\n"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "device-created-inside-namespace",
		Breaks: "a device is created from the host into the workload namespace, so its encrypted socket stays on the host",
		Edits:  []Edit{{linuxKernel, "if err := k.rootNL.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {", "if err := h.nl.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "revocation-drains",
		Breaks: "a revocation removes the interface from every peer at once, with no drain grace period",
		Edits:  []Edit{{cpPlane, "i.State, i.Drained = api.Revoked, true", "i.State, i.Drained = api.Released, false"}},
		Catch:  []string{"cp", "cpserver"},
	},
	{
		ID:     "peer-removed-before-slots",
		Breaks: "a batch removes a backend's slots before its peer, so no slot ever names an address without a peer",
		Edits: []Edit{
			{agentPlan, applyRules + removeUnwanted, removeUnwanted},
			{agentPlan, "\tif st.sweep {\n", applyRules + "\tif st.sweep {\n"},
		},
		Catch: []string{"sim"},
	},
	{
		ID:     "allowed-ip-moves",
		Breaks: "a peer claiming an address another installed peer holds waits until the holder is removed, so no allowed IP moves between peers",
		Edits:  []Edit{{agentTarget, "if conflicted(owner, p) {", "if false && conflicted(owner, p) {"}},
		Catch:  []string{"agent-core", "sim"},
	},
	{
		ID:     "ipv4-quarantine-from-release",
		Breaks: "an IPv4 address waits out its quarantine from its holder's drain, so a late drain never frees an address peers still route",
		Edits: []Edit{
			{cpPlane, "\t\ti.State, i.Ended = api.Released, now\n\t\tif err := p.end(tx, now, i, false); err != nil {", "\t\ti.State, i.Ended = api.Released, now\n\t\tif err := p.end(tx, now, i, true); err != nil {"},
			{cpPlane, "\t\tif i.Addr4.IsValid() {\n\t\t\tif err := tx.PutReleased4(store.Released4{Network: i.Network, Addr: i.Addr4, At: now}); err != nil {\n\t\t\t\treturn 0, err\n\t\t\t}\n\t\t}\n", ""},
		},
		Catch: []string{"cp"},
	},
	{
		ID:     "ipv4-quarantine-zero",
		Breaks: "a released IPv4 address waits out its quarantine before reuse",
		Edits:  []Edit{{cpAlloc, "free, err := tx.Released4(n.ID, now.Add(-p.Config.Quarantine4), 1)", "free, err := tx.Released4(n.ID, now, 1)"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "ipv6-reuse",
		Breaks: "an IPv6 address is never reused",
		Edits: []Edit{{cpPlane,
			"\tn, err := tx.Network(i.Network)\n\tif err != nil {\n\t\treturn err\n\t}\n\tif i.Drained {",
			"\tn, err := tx.Network(i.Network)\n\tif err != nil {\n\t\treturn err\n\t}\n\tif n.Next6 > first6 && addrAt(n.Prefix6, n.Next6-1) == i.Addr6 {\n\t\tn.Next6--\n\t}\n\tif i.Drained {"}},
		Catch: []string{"cp", "sim"},
	},
	{
		ID:     "expiry-ignores-boot-hold",
		Breaks: "after control-plane downtime, lease expiry waits at least as long as the outage lasted",
		Edits:  []Edit{{cpPlane, "if !now.Before(resumes) {", "if _ = resumes; true {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "dormant-edge-deleted-at-once",
		Breaks: "an edge policy no longer connects stays dormant for the port quarantine before its ports free up",
		Edits:  []Edit{{cpEdges, "old, err := tx.DormantEdges(now.Add(-p.Config.PortQuarantine), limit)", "old, err := tx.DormantEdges(now, limit)"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "relay-port-reused-in-quarantine",
		Breaks: "a released relay port waits out its quarantine before it serves another edge",
		Edits:  []Edit{{cpAlloc, "free, err := tx.ReleasedPorts(r.ID, addr, now.Add(-p.Config.PortQuarantine), 1)", "free, err := tx.ReleasedPorts(r.ID, addr, now, 1)"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "agent-journals-private-key",
		Breaks: "the agent keeps a private key in the kernel device alone; no journal entry carries it",
		Edits: []Edit{
			{agentCore, "\tDetaching  bool              `json:\"detaching,omitempty\"`\n}", "\tDetaching  bool              `json:\"detaching,omitempty\"`\n\tPrivateKey model.Key `json:\"private_key\"`\n}"},
			{agentLife, "PublicKey: i.pub, Detaching: i.phase == detaching,", "PublicKey: i.pub, PrivateKey: i.priv, Detaching: i.phase == detaching,"},
			{agentPlan, "\t\ti.priv = model.Key{}\n\t\ti.phase, i.attachSent = registering, true", "\t\ti.phase, i.attachSent = registering, true"},
		},
		Catch: []string{"sim"},
	},
	{
		ID:     "hub-ignores-networks",
		Breaks: "a parked long poll wakes on a commit to any network its host holds, not only on one naming the host",
		Edits:  []Edit{{cpHub, "\tfor _, id := range c.Networks {\n\t\tfor w := range h.nets[id] {\n\t\t\twoken = append(woken, w)\n\t\t}\n\t}\n", ""}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "sim-wake-ignores-networks",
		Breaks: "the simulator's control plane wakes a parked poll on a commit to a network its host holds, as the server's hub does",
		Edits: []Edit{{simCP,
			"if !slices.Contains(ch.Hosts, id) && !slices.ContainsFunc(p.nets, func(n model.NetworkID) bool { return slices.Contains(ch.Networks, n) }) {",
			"if !slices.Contains(ch.Hosts, id) {"}},
		Catch: []string{"sim"},
	},
	{
		ID:     "sweep-forgets-live-peers",
		Breaks: "a sweep keeps every flow a peer the batch leaves installed accounts for",
		Edits:  []Edit{{agentPlan, "\tfor _, tp := range tgt.peers {\n\t\tfor _, a := range tp.peer.Allowed {\n\t\t\tkeep = append(keep, a.Addr())", "\tfor _, tp := range tgt.peers[:0] {\n\t\tfor _, a := range tp.peer.Allowed {\n\t\t\tkeep = append(keep, a.Addr())"}},
		Catch:  []string{"sim"},
	},
	{
		ID:     "shrunk-peer-not-flushed",
		Breaks: "the addresses a peer drops, such as a machine a gateway stops fronting, are flushed like a removed peer's",
		Edits:  []Edit{{agentPlan, "\t\t\t\tfor _, a := range dropped {\n\t\t\t\t\tflush = append(flush, a.Addr())\n\t\t\t\t}\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "vanished-namespace-stays-ready",
		Breaks: "an interface whose namespace vanishes behind the agent is torn down, since its key went with the device",
		Edits:  []Edit{{agentPlan, "\t\t\ti.phase = detaching\n\t\t\tc.emit(WriteJournal{Entry: c.entry(i)})\n\t\t\tc.scan()\n", "\t\t\tc.scan()\n"}},
		Catch:  []string{"agent-core", "sim"},
	},
	{
		ID:     "held-namespace-reaped-repeatedly",
		Breaks: "the agent reaps a namespace only a process holds once, then waits for the holder to let go",
		Edits:  []Edit{{agentPlan, "\t\tif st.reaped {\n\t\t\treturn nil\n\t\t}\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "moved-path-left-in-place",
		Breaks: "an edge whose relay leaves the set, or fails, moves its endpoint to the relay it now chooses",
		Edits:  []Edit{{agentPlan, "\t\tcase chosen != tp.endpoint:\n", "\t\tcase chosen != tp.endpoint && false:\n"}},
		Catch:  []string{"agent-core", "e2e"},
	},
	{
		ID:     "egress-filter-outlives-namespace",
		Breaks: "tearing down an interface whose namespace is gone still removes its host egress filter, by index",
		Edits:  []Edit{{agentPlan, "kernel.Op{Kind: kernel.SetEgress, Namespace: st.name, EgressIndex: egressIndex(st, i)}", "kernel.Op{Kind: kernel.SetEgress, Namespace: st.name}"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "gateway-end-spares-devices",
		Breaks: "releasing, revoking or expiring a gateway revokes its development machines at once",
		Edits:  []Edit{{cpPlane, "if i.Kind == api.Gateway {", "if false && i.Kind == api.Gateway {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "device-fronted-from-any-host",
		Breaks: "a development machine is fronted only by its live gateway on that gateway's host",
		Edits:  []Edit{{compileGo, "i.State == api.Live && host == i.Host {", "i.State == api.Live && host != \"\" {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "failed-update-changes-state",
		Breaks: "a host-state update that fails a check changes nothing",
		Edits:  []Edit{{apiState, "\tnext := make(map[model.NetworkID]*NetworkState, len(h.Networks))\n\tmaps.Copy(next, h.Networks)", "\tnext := h.Networks"}},
		Catch:  []string{"api"},
	},
	{
		ID:     "expiry-hold-needs-a-whole-term",
		Breaks: "a heartbeat more than a third of a lease term after the last holds off expiry for as long as the gap lasted",
		Edits:  []Edit{{cpPlane, "if gap <= p.Config.LeaseTTL/3 {", "if gap <= p.Config.LeaseTTL {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "second-boot-shortens-hold",
		Breaks: "a boot or heartbeat only lengthens the expiry hold another replica set",
		Edits:  []Edit{{cpPlane, "if err != nil || !until.After(resumes) {", "if err != nil || !until.After(resumes) && false {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "token-cached-forever",
		Breaks: "a cached host token expires after the token TTL, so a deleted host's token stops working on every replica",
		Edits:  []Edit{{cpServer, "ok && now.Before(c.(cachedToken).until) {", "ok {"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "host-deleted-with-live-interfaces",
		Breaks: "deleting a host revokes its interfaces",
		Edits:  []Edit{{cpPlane, "if err := p.Revoke(tx, now, i.ID); err != nil {\n\t\t\treturn store.Host{}, err", "if err := error(nil); err != nil && i.ID != \"\" {\n\t\t\treturn store.Host{}, err"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "store-error-answers-unauthorized",
		Breaks: "a token the store cannot check answers 503, which agents retry",
		Edits:  []Edit{{cpServer, "fmt.Errorf(\"token lookup: %w: %w\", errCannotAuthenticate, err)", "fmt.Errorf(\"token lookup: %w: %w\", errUnauthorized, err)"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "edge-toward-draining-interface",
		Breaks: "a draining interface keeps its edges but gains none",
		Edits:  []Edit{{cpEdges, "if have[key] || byID[key[0]].State != api.Live || byID[key[1]].State != api.Live {", "if have[key] {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "host-releases-device",
		Breaks: "a development machine ends by revocation, its term or its gateway; its gateway's host cannot release it",
		Edits:  []Edit{{cpPlane, "if i.Host != host || i.State != api.Live || i.Kind == api.Device {\n\t\t\tcontinue\n\t\t}\n\t\ti.State, i.Ended", "if i.Host != host || i.State != api.Live {\n\t\t\tcontinue\n\t\t}\n\t\ti.State, i.Ended"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "network-delete-leaves-hosts",
		Breaks: "deleting a network moves its hosts' generations on, so their agents drop it",
		Edits:  []Edit{{cpPlane, "if err := bumpHosts(tx, slices.Compact(hosts)); err != nil {", "if err := bumpHosts(tx, nil); err != nil {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "store-error-reads-as-not-found",
		Breaks: "a store error comes back as an error, never as a missing record",
		Edits:  []Edit{{cpPlane, "\t\treturn notFound(err, \"rule \"+string(id))", "\t\treturn notFound(store.ErrNotFound, \"rule \"+string(id))"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "port-quarantine-zero-accepted",
		Breaks: "the control plane refuses a zero port quarantine",
		Edits:  []Edit{{cpPlane, "case c.PortQuarantine <= 0:", "case c.PortQuarantine < 0:"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "census-misses-recent-ports",
		Breaks: "the census counts every relay port released within one quarantine",
		Edits:  []Edit{{cpCensus, "released, err := tx.ReleasedPorts(r.ID, a.Local, endOfTime(), 0)", "released, err := tx.ReleasedPorts(r.ID, a.Local, now, 0)"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "relay-wait-scans-every-port",
		Breaks: "each port counts its own waiting packets, so admitting one costs the same however many wait",
		Edits:  []Edit{{relayCore, "\tif t.held >= t.cfg.WaitTotal || len(d.waits) >= t.cfg.WaitMax {", "\tcount := 0\n\tfor w := t.oldest; w != nil; w = w.next {\n\t\tif w.local == d.Local {\n\t\t\tcount++\n\t\t}\n\t}\n\tif t.held >= t.cfg.WaitTotal || count >= t.cfg.WaitMax {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "relay-release-scans-every-port",
		Breaks: "a commit looks only at the ports it touches",
		Edits:  []Edit{{relayCore, "\tfor _, local := range t.touched {", "\tfor _, local := range slices.SortedFunc(maps.Keys(t.ports), netip.AddrPort.Compare) {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "relay-forwards-truncated",
		Breaks: "the relay drops a datagram the kernel truncated rather than forward a prefix",
		Edits:  []Edit{{relayServer, "if rms[i].Flags&unix.MSG_TRUNC != 0 {", "if false {"}},
		Catch:  []string{"relay-server"},
	},
	{
		ID:     "relay-bind-never-retried",
		Breaks: "a port that fails to bind is retried every few seconds while the other ports serve",
		Edits:  []Edit{{relayServer, "\t\tcase <-retry.C:\n\t\t\tif !failed {\n\t\t\t\tcontinue\n\t\t\t}\n", "\t\tcase <-retry.C:\n\t\t\tcontinue\n"}},
		Catch:  []string{"relay-server"},
	},
	{
		ID:     "relay-commits-under-unsaved-table",
		Breaks: "a registration verified under a table the state file lacks writes that table first",
		Edits:  []Edit{{relayServer, "if s.generation() != s.durable {", "if false {"}},
		Catch:  []string{"relay-server"},
	},
	{
		ID:     "relay-log-keeps-torn-tail",
		Breaks: "opening the registration log cuts a torn last line, so the next append starts a fresh one",
		Edits:  []Edit{{relayDisk, "\tif n < len(b) {", "\tif false {"}},
		Catch:  []string{"relay-server"},
	},
	{
		ID:     "relay-junk-spends-owner-budget",
		Breaks: "only a verified registration spends a port's budget, so junk cannot lock its owner out",
		Edits:  []Edit{{relayCore, "\tr, reason := t.verify(d, src, b)\n", "\td.regs.spend()\n\tr, reason := t.verify(d, src, b)\n"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "relay-holds-unknown-ports",
		Breaks: "a packet for a port the table lacks drops",
		Edits:  []Edit{{relayCore, "\t\treturn Decision{Reason: Unknown}", "\t\treturn Decision{Verdict: Wait, Reason: Unknown}"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "relay-probes-uncapped",
		Breaks: "the probe port answers a bounded number of probes a second across the relay, since a probe's source can be forged",
		Edits:  []Edit{{relayCore, "if !p.b.take(now) {", "if false {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "pgstore-relay-delete-keeps-ports",
		Breaks: "deleting a relay deletes its released ports and cursors, so a relay created under the same ID starts with none",
		Edits:  []Edit{{pgTx, "\tif err := t.check(t.q.DeleteRelayPorts(t.ctx, string(id))); err != nil {\n\t\treturn err\n\t}\n", ""}},
		Catch:  []string{"pgstore"},
	},
	{
		ID:     "attach-answered-before-resolver",
		Breaks: "an attach is answered once its namespace's stub resolver listens, so a workload that resolves at start is answered",
		Edits:  []Edit{{agentDaemon, "if d.Resolver != nil && a.Err == nil && a.Interface.Ready {", "if false {"}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "resolver-forwards-inline",
		Breaks: "a forwarded query waits off the read loop, so a slow upstream delays no local answer",
		Edits:  []Edit{{agentResolv, "\t\tgo func() {\n\t\t\tdefer func() { <-forwards }()", "\t\tfunc() {\n\t\t\tdefer func() { <-forwards }()"}},
		Catch:  []string{"agent-resolver"},
	},
	{
		ID:     "resolver-tcp-uncapped",
		Breaks: "each namespace's resolver holds a bounded number of TCP connections",
		Edits:  []Edit{{agentResolv, "conns := make(chan struct{}, tcpConns)", "conns := make(chan struct{}, 1<<20)"}},
		Catch:  []string{"agent-resolver"},
	},
	{
		ID:     "egress-refresh-not-retried",
		Breaks: "a failed egress filter refresh retries until it succeeds or a newer set replaces it",
		Edits:  []Edit{{agentDaemon, "retry = time.After(d.cfg.EgressRetry)", "_ = d.cfg.EgressRetry"}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "egress-ignores-host-change",
		Breaks: "an underlay change refreshes the egress filter with the host's current prefixes",
		Edits:  []Edit{{agentDaemon, "\t\t\t\td.egressRelays = d.EgressKept\n\t\t\t}\n\t\t\td.refreshEgress()\n", "\t\t\t\td.egressRelays = d.EgressKept\n\t\t\t}\n"}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "underlay-drops-trailing-change",
		Breaks: "an underlay change inside the throttle window runs when the window ends, so the address the host settles on registers",
		Edits:  []Edit{{agentMain, "\t\t\t\tdue = time.After(wait)\n", ""}},
		Catch:  []string{"agent-cmd"},
	},
	{
		ID:     "egress-nat64-unblocked",
		Breaks: "an egress link cannot reach a blocked IPv4 address through its NAT64 form",
		Edits:  []Edit{{linuxEgress, "\t\tout = append(out, netip.PrefixFrom(netip.AddrFrom16(b), 96+p.Bits()))", "\t\t_ = b"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "egress-filter-forgets-blocked",
		Breaks: "the egress filter records what it blocks, so a restarted agent keeps blocking every relay it knew of",
		Edits:  []Edit{{linuxEgress, "\t\t\tUserData: []byte(blockedTag + p.String())})", "\t\t})"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "held-by-descriptor-missed",
		Breaks: "a namespace only a descriptor holds is found and reaped",
		Edits:  []Edit{{linuxNetns, "if onNSFS(path, self.Dev) && isNetNS(path) {", "if onNSFS(path, self.Dev) && isNetNS(path) && false {"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "unmounted-name-accepted",
		Breaks: "a namespace name a crash left as a plain file is replaced by a mounted namespace",
		Edits:  []Edit{{linuxNetns, "\tcase err == nil && mounted:\n", "\tcase err == nil && (mounted || true):\n"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "nft-model-deletes-missing-element",
		Breaks: "the model fails a transaction deleting a missing set element, as the kernel fails the batch",
		Edits:  []Edit{{nftTx, "\t\t\tif !slices.Contains(s.Addrs, a) {\n\t\t\t\treturn nil, fmt.Errorf(\"%w: set %s element %v\", ErrMissing, e.Set, a)", "\t\t\tif false {\n\t\t\t\treturn nil, fmt.Errorf(\"%w: set %s element %v\", ErrMissing, e.Set, a)"}},
		Catch:  []string{"nft"},
	},
	{
		ID:     "metric-increment-dropped",
		Breaks: "every local attach and detach counts in sdn_agent_local_calls_total by result",
		Edits:  []Edit{{agentDaemon, "\td.m.localCalls.WithLabelValues(r.kind, result).Inc()\n", "\t_ = result\n"}},
		Catch:  []string{"agent-daemon", "e2e"},
	},
	{
		ID:     "census-gauges-stale",
		Breaks: "the agent's interface, namespace and peer gauges follow the core's census",
		Edits:  []Edit{{agentDaemon, "\t\td.m.census(c)\n", "\t\t_ = c\n"}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "relay-sends-no-ack",
		Breaks: "a relay acknowledges each registration it commits, from the direction's port, so an agent knows the port is bound",
		Edits:  []Edit{{relayServer, "\t\t\ts.ack(acked)\n", ""}},
		Catch:  []string{"relay-server"},
	},
	{
		ID:     "new-relay-peer-slotted-before-ack",
		Breaks: "no slot names a relay peer new to a namespace until the active relay acknowledges it, or AckWait passes",
		Edits:  []Edit{{agentTarget, "tp.awaiting = c.awaitsAck(now, st, port, p, tp)", "tp.awaiting = false && c.awaitsAck(now, st, port, p, tp)"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "handover-ignores-waiting-slots",
		Breaks: "a namespace is handed over only once the slots it holds back are in, or AckWait passes",
		Edits:  []Edit{{agentPlan, "if len(st.awaiting) > 0 && now.Before(i.handoverBy) {", "if false {"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "ack-releases-nothing",
		Breaks: "a relay's acknowledgment releases the wait of the peer it names",
		Edits:  []Edit{{agentRelays, "\t\t\tw.acked = true\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "failover-holds-slots-back",
		Breaks: "a peer installed before never waits for an acknowledgment, so a failover holds back no slot",
		Edits:  []Edit{{agentTarget, "\t\tif _, installed := st.peers[p.PublicKey]; installed {\n\t\t\treturn false\n\t\t}\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "ack-filter-reads-the-wrong-word",
		Breaks: "the agent's raw IPv4 socket passes relay acknowledgments, judged past the IP header's own length",
		Edits:  []Edit{{agentUnder, "{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_IND, K: 8},", "{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_IND, K: 12},"}},
		Catch:  []string{"underlay"},
	},
	{
		ID:     "registration-never-resent",
		Breaks: "a fresh direction's registration is sent again on a tripling schedule, since one that beats the relay's bind is lost",
		Edits:  []Edit{{agentRelays, "r.left, r.gap = c.cfg.RegisterRetries, c.cfg.RegisterRetry", "r.left, r.gap = 0, c.cfg.RegisterRetry"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "relay-drops-what-races-the-peer",
		Breaks: "a packet that reaches a bound port before the peer direction registers waits for that registration instead of dropping",
		Edits:  []Edit{{relayCore, "if ok && t.wait(now, d, src, len(b)) {", "if false && t.wait(now, d, src, len(b)) {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "acked-direction-resent",
		Breaks: "a relay's acknowledgment ends that direction's resends to it, so registrations stay bounded under churn",
		Edits:  []Edit{{agentRelays, "\t\t\tdelete(r.paths, from)\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "rearm-replans-everyone",
		Breaks: "a finished batch replans only the namespaces waiting on its device, so waits on acknowledgments cost nothing per batch",
		Edits: []Edit{{agentPlan, "\tfor _, name := range slices.Sorted(maps.Keys(c.reverseWait[changed.iface])) {\n\t\tif st, ok := c.ns[name]; ok && st != changed {\n",
			"\tfor _, name := range slices.Sorted(maps.Keys(c.ns)) {\n\t\tif st, ok := c.ns[name]; ok && st != changed && len(st.awaiting) > 0 {\n"}},
		Catch: []string{"agent-core"},
	},
	{
		ID:     "backend-hands-over-before-relay",
		Breaks: "a backend's attach answers once the relay holds its edges' ports, though no slot of its own names its clients",
		Edits:  []Edit{{agentTarget, "\t\t\tdefault:\n\t\t\t\t// A peer no slot names holds nothing back", "\t\t\tcase len(x.Reach) > 0:\n\t\t\t\t// A peer no slot names holds nothing back"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "unawaited-ack-reports-change",
		Breaks: "an acknowledgment nobody awaits changes nothing, so the agent's loop skips its pass over every namespace",
		Edits:  []Edit{{agentRelays, "\tif !ok {\n\t\treturn changed\n\t}\n\tif c.Debug", "\tif !ok {\n\t\treturn true\n\t}\n\tif c.Debug"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "stale-ack-wake-spins",
		Breaks: "a network that leaves desired state takes its acknowledgment waits with it, so no past deadline keeps waking the loop",
		Edits:  []Edit{{agentPlan, "\t} else {\n\t\tc.dropWaits(st)\n", "\t} else {\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "resend-forgets-its-port",
		Breaks: "a resend schedule ends with its namespace, so acknowledgment lookups stay bounded",
		Edits:  []Edit{{agentRelays, "delete(c.resendAck, ackKey{r.paths[path], path})", "delete(c.resendAck, ackKey{0, path})"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "convergence-only-after-batches",
		Breaks: "convergence is observed whenever a namespace settles, batch or no batch",
		Edits:  []Edit{{agentDaemon, "\tidle := d.core.Stats.Idle != d.stats.Idle\n", "\tidle := false\n"}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "underlay-change-drops-kept-filter",
		Breaks: "an underlay change before desired state keeps blocking the relays an earlier run's filter named",
		Edits:  []Edit{{agentDaemon, "\t\t\tif !d.egressSent {\n\t\t\t\td.egressRelays = d.EgressKept\n\t\t\t}\n", ""}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "agent-sockets-hold-nothing",
		Breaks: "the agent's sockets hold a namespace its name no longer reaches, so its device keeps its peers until the agent tears it down",
		Edits:  []Edit{{kmodelGo, "\tif ns.Held == 0 && ns.opened == \"\" && ns.Name == \"\" && k.anon[ns.Ref] == ns {", "\tif ns.Held == 0 && ns.Name == \"\" && k.anon[ns.Ref] == ns {"}},
		Catch:  []string{"kmodel"},
	},
	{
		ID:     "cached-handle-trusted",
		Breaks: "every open checks the namespace's name still reaches it, which is how the agent learns an operator deleted it",
		Edits: []Edit{{linuxKernel, "\tpath := filepath.Join(netnsDir, name)\n\tvar st unix.Stat_t\n",
			"\tpath := filepath.Join(netnsDir, name)\n\tif h, ok := k.handles[name]; ok {\n\t\treturn h, nil\n\t}\n\tvar st unix.Stat_t\n"}},
		Catch: []string{"kernel"},
	},
	{
		ID:     "egress-duplicates-kept",
		Breaks: "refreshing the egress filter from what it holds leaves one rule per prefix",
		Edits:  []Edit{{linuxEgress, "\treturn slices.Compact(kernel.SortPrefixes(all))\n", "\treturn all\n"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "relay-weight-one-sided",
		Breaks: "both ends of an edge weigh a relay the same, so they choose the same relay",
		Edits:  []Edit{{modelWeight, "\tif b < a {\n\t\ta, b = b, a\n\t}\n", ""}},
		Catch:  []string{"model", "e2e"},
	},
	{
		ID:     "relay-chosen-per-network",
		Breaks: "each edge chooses its relay by its own weight, so a network's edges spread over its relays",
		Edits:  []Edit{{agentRelays, "w := model.RelayWeight(self, p.Interface, rp.Relay)", "w := model.RelayWeight(\"\", \"\", rp.Relay)"}},
		Catch:  []string{"agent-core", "e2e"},
	},
	{
		ID:     "relay-choice-ignores-health",
		Breaks: "an edge sends through a relay its agent's probes find up",
		Edits:  []Edit{{agentRelays, "\t\tup := !probed || h.up\n", "\t\tup := !probed || h.up || true\n"}},
		Catch:  []string{"agent-core", "e2e"},
	},
	{
		ID:     "relay-loss-not-replanned",
		Breaks: "a relay's loss moves the edges it carried",
		Edits:  []Edit{{agentRelays, "\tif len(down) > 0 {\n\t\tc.relaysChanged(down)\n\t}\n", ""}},
		Catch:  []string{"agent-core", "e2e"},
	},
	{
		ID:     "relay-return-not-replanned",
		Breaks: "a relay that answers again takes back the edges whose heaviest relay it is",
		Edits:  []Edit{{agentRelays, "\t\th.up = true\n\t\tc.relaysChanged(map[model.RelayID]bool{relay: true})\n", "\t\th.up = true\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "detach-releases-after-teardown",
		Breaks: "a detach tells the control plane while its device is deleted, so peers stop routing to it without waiting out the deletion",
		Edits:  []Edit{{agentLife, "\t// deleting a device waits a grace period per peer it holds.\n\tc.release(i)\n", "\t// deleting a device waits a grace period per peer it holds.\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "release-retry-waits-for-teardown",
		Breaks: "a detach's failed release is sent again while its teardown runs",
		Edits:  []Edit{{agentLife, "if (i.tornDown || i.phase == detaching) && i.attachSent", "if i.tornDown && i.attachSent"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "stored-socket-made-blocking",
		Breaks: "a resolver socket handed to the descriptor store stays non-blocking, so closing it on detach returns",
		Edits: []Edit{{agentFDStore, "\tif err := rc.Control(func(fd uintptr) {\n\t\tserr = unix.Sendmsg(s.fd, []byte(msg), unix.UnixRights(int(fd)), s.addr, 0)\n\t}); err != nil {\n\t\treturn err\n\t}\n",
			"\tif f, ok := c.(interface{ File() (*os.File, error) }); ok {\n\t\tif file, err := f.File(); err == nil {\n\t\t\tdefer file.Close()\n\t\t\tserr = unix.Sendmsg(s.fd, []byte(msg), unix.UnixRights(int(file.Fd())), s.addr, 0)\n\t\t}\n\t}\n\t_ = rc\n"}},
		Catch: []string{"agent-resolver", "e2e"},
	},
}
