# Development Plan

## Overarching Goal

Ship a control plane, host agent, and relay that give short-lived workloads per-workload network identity across hosts in different places, with nothing on the path between two workloads able to read a packet. The design is in [SPEC.md](SPEC.md), which also holds every measurement; the positioning is in [README.md](README.md). This plan sequences the build and records what is proven.

v1 is deliberately smaller than the spec. These are designed and deferred, not missing:

- **`drain` mode and generation acknowledgment.** The spec already states this is not a lock, so narrowing the overlap window waits until a user needs it.
- **Direct paths.** An endpoint rewrite over a working relay, so it is an optimization of a shipped path rather than a second architecture.
- **Guest-owned keys.** The control plane already only ever sees public keys, so this needs no protocol change later.
- **Application health checking.** An interface joins a service when its lease is live and its agent reports the interface up.
- **`sk_lookup` or XDP in the relay.** Required for the stated edge capacity, so the userspace relay ships with a documented edge ceiling and this follows in Phase 7.

The **device pool** has left the plan rather than being deferred: creating a device straight into the workload namespace removes the namespace move, which was the only reason a pool was worth its bookkeeping.

## Implementation Principles

- **Create devices into the workload namespace, never create-then-move.** A device records the requesting socket's namespace as its socket's, so creating with `IFLA_NET_NS_FD` puts plaintext in the workload and ciphertext on the host with no move. Measured 621/s against 99/s at 64-way concurrency.
- **Know which netdev operations overlap.** A destroy defers its grace period past `rtnl_unlock` and scales 20× with concurrency; a namespace move holds RTNL across its own and scales 1.1×. Apply destroys concurrently; do not expect concurrency to rescue a move.
- **Peer work runs under RTNL: one lane per host, ~10–12k operations a second, not growing with cores.** `wg_set_device` holds `rtnl_lock()` for the whole call, so peer changes serialize against each other and against device, address, route and link work. Neighbour additions parallelize only across hosts. Raising the ceiling needs a kernel change; the userspace lever is grouping every pending change for a device into one call.
- **Budget a detach like an attach.** A single-peer removal waits an expedited grace period under RTNL: 60µs on an 8-vCPU KVM guest, a quarter of an addition, but 90–100µs on a c6i.xlarge with Linux 7.0, the same as one. Each removed peer pays its own grace period even inside one call; only a full flush is cheaper per peer. Every expedited grace period interrupts every non-idle CPU on the host.
- **`persistent-keepalive` is set per path.** Relay peers carry none: the registration datagram registers each direction and holds the NAT mapping, so an idle peer costs nothing and two agents installing an edge at once do not collide on its first handshake. A co-located pair carries it on exactly one side, which keeps a session up and owns every rekey; two peers that initiate together stay in a failed-handshake lockstep. Direct paths keep it for their NAT pinholes.
- **The relay batches its syscalls.** `recvmmsg`/`sendmmsg` with `SO_REUSEPORT` sockets. A per-packet loop overflows its receive queue and carries less than a terminating gateway, which removes the reason to relay.
- **One relay port per direction.** The port a packet arrives on must name its sender. An address-based scheme cannot survive NAT that reassigns addresses, and cannot disambiguate two interfaces sharing one address at all.
- **Enforcement lives at the receiver.** `AllowedIPs` and nftables both run in the destination's kernel, one address per family per peer. Nothing a sender does to its own namespace may widen what it reaches.
- **Roaming owns the peer endpoint.** Any authenticated packet from a new source rewrites it, and the relay path depends on that. A reconciler that treats a roamed endpoint as drift will fight the data plane.
- **The agent never mints a key it does not keep.** Private keys stay on the host; the control plane sees public keys only.
- **Teardown follows the workload, not the control plane.** An agent holds its configuration through an outage of any length, because revocation runs through peers and costs nothing from the holder.
- **Every intermediate state is safe.** Order peer installation around the nftables transaction; a revocation skips the grace period that a planned removal uses.
- **Check every netlink call.** Discarding errors in a harness turned three failures into three published figures. The same mistake in an agent produces an interface that looks attached and is not.

## Testing Strategy

- **Semantics run inside one Linux kernel, in CI.** Namespaces stand in for hosts: a relay in one, several hosts in others, each host handing a workload a namespace of its own, veth pairs for the underlay. This covers device placement, the slot table, convergence ordering, roaming on the return path, policy enforcement, and revocation. `ubuntu-latest` on GitHub Actions is a full VM with root, kernel WireGuard and nftables.
- **An isolation claim needs a cannot-reach assertion.** Every claim in SPEC.md under Trust needs a test that asserts a peer fails to reach something, not that a permitted flow works.
- **Performance figures need real hardware, and the substrate is not incidental.** Anything bound by an RCU grace period measured 2–3× apart between a KVM guest on 6.8 and a microVM on 6.18, in both directions. Record which substrate produced a number.
- **Measure the plain-TCP underlay ceiling in the same run.** Without it a throughput figure is meaningless: a path that reads as a design limit is often 95% of the network.
- **The relay-against-gateway comparison is the thesis regression test.** Both roles on the same machine against the same hosts, or it compares hardware rather than architectures.
- **Purge stray state between runs.** `ip netns del` only removes the name: a namespace a process still holds keeps its WireGuard device keepaliving and will claim a relay direction. One orphaned `iperf3` silently contaminated three consecutive runs.
- **`nft list` segfaults on a `jhash`-keyed map on nftables 1.0.9.** The ruleset works; the inspection tool crashes. Use `numgen random` until a newer `nft` is the floor.

## Phase 1: Host agent spike, attach and detach from static config

Goal:
An agent that attaches and detaches interfaces against a file on disk, with no control plane, proving the kernel path and the shape the API has to serve.

Scope:
- Mint a keypair, create the device into the workload namespace, key it, install peers, addresses and routes in each family, MTU.
- Install the nftables table and hand over a namespace without `CAP_NET_ADMIN`.
- Hold one netlink socket per namespace, opened inside it.
- Apply destroys through a concurrent worker pool; do not rely on concurrency for moves.
- Reconcile observed kernel state against the file, including after an agent restart, and reclaim namespaces a process still holds.

Out of scope:
- Any control plane, lease renewal, or policy compilation.
- The stub resolver.

Completion gate:
At a policy degree of 20: attach reaches first packet in under 100ms against an already-converged peer, and a sustained attach-and-detach loop exceeds 100/s on a 4-vCPU host. Both are stated per degree because the peer lane bounds `attaches × degree`. An agent killed at any step of attach leaves no orphaned device or namespace after restart.

Testing plan:
- Assert the device's socket is in the host namespace and the workload namespace holds no underlay interface, verified by traffic rather than inspection.
- Assert a workload namespace cannot reach the underlay or another network.
- A churn test measuring attaches per second, which must fail if destroys become serial.
- A crash-recovery test: kill at each step, restart, assert convergence and no leaks, including a namespace held open by a stray process.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Decision | Create into the workload namespace; the socket stays on the host | `cmd/hostbench` H1: two devices created into two namespaces handshook through the host loopback; SPEC.md "Creating into the namespace removes the move". |
| Complete | Decision | Destroys overlap under concurrency, moves do not | `cmd/hostbench` H2: destroy 32→639/s, move 128→142/s across 1→64 goroutines. |
| Complete | Doc | Per-operation kernel costs on three substrates | `cmd/hostbench`; SPEC.md "Measured". The c6i.xlarge / Linux 7.0 column came from two runs with keys derived outside every timer. |
| Incomplete | Scope | Mint, create, key, peer, addresses and routes in each family, MTU | Missing: agent implementation. |
| Incomplete | Scope | nftables table and handover without `CAP_NET_ADMIN` | Missing: implementation. |
| Incomplete | Work | 1A: Per-namespace held netlink socket | Missing: implementation. Hypothesis confirmed in `cmd/hostbench`. |
| Incomplete | Work | 1B: Concurrent destroy pool | Missing: implementation. |
| Incomplete | Work | 1C: Reconciler, restart-safe, reclaims process-held namespaces | Missing: implementation and crash-recovery tests. |
| Incomplete | Gate | Attach to first packet under 100ms at degree 20; attach/detach over 100/s | Missing: measurement. Device work is ~5ms and the interface's own peer table ~3ms at degree 20; the 64-way figures are throughput, not latency. |
| Incomplete | Test | Workload cannot reach the underlay or another network | Missing: adversarial test. |
| Incomplete | Test | Kill-at-each-step recovery with no orphans | Missing: test. |

## Phase 2: Control plane and API

Goal:
A control plane that stores the model and serves the desired state the Phase 1 agent reconciles against.

Scope:
- Resources for network, service, interface, lease, policy rule, relay, and directed edge-port allocation.
- Address allocation, one pool per family, with IPv4 drawn only for services that opt in. IPv6 addresses are never reused within a network; IPv4 addresses are, with quarantine on the right clock: an address needs only the grace period plus convergence, provided each host removes the old peer and flushes its conntrack before a new peer claims the address; relay ports need to outlast stale senders, which makes them the scarcer pool. **Settling the quarantine length belongs here**, because allocation depends on it.
- Lease issue, renew, and revoke, accepting only public keys.
- The policy compiler: expand service-level rules into per-interface peer sets and address sets, each set emitted in every family the two services share.
- Desired-state push, batched per host rather than per namespace.

Out of scope:
- Generation acknowledgment (deferred with `drain`).
- Multi-region or sharded control plane.

Completion gate:
A test creates two networks with overlapping address space, attaches four interfaces across two hosts, writes policy between them, and the compiled desired state for each host names exactly the peers policy permits and no others. A released address cannot be reallocated inside the quarantine window.

Testing plan:
- Unit tests for allocation, including exhaustion, quarantine, the service/interface split, and an IPv6-only service drawing nothing from the IPv4 pool.
- Unit tests for the policy compiler: sparse, fully connected, a rule naming a service with zero interfaces, and a rule between an IPv4-capable service and an IPv6-only one compiling to IPv6 alone.
- A test asserting a revoked lease disappears from every other host's desired state with no grace period.
- A test asserting the control plane never stores a private key.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Incomplete | Scope | Resource model and store | Missing: schema and implementation. |
| Incomplete | Scope | Address and edge-port allocation with quarantine | Missing: allocator, exhaustion and quarantine tests. |
| Incomplete | Scope | Lease lifecycle, public keys only | Missing: implementation. |
| Incomplete | Work | 2A: Policy compiler | Missing: implementation plus sparse and dense tests. |
| Incomplete | Work | 2B: Per-host batched desired-state push | Missing: implementation. |
| Incomplete | Gate | Overlapping networks compile to exactly the permitted peers | Missing: the end-to-end test. |
| Incomplete | Gate | Quarantine prevents early reuse | Missing: test. |
| Incomplete | Test | Revocation removes the key everywhere, no grace | Missing: adversarial test. |
| Incomplete | Decision | API surface and transport | Needs: writing now that Phase 1 has shaped it. |

## Phase 3: The relay in production shape

Goal:
A relay fit to run as a fleet: configured by the control plane, observable, and honest about its ceiling.

Scope:
- Take the pushed directed-port table from the control plane instead of trusting whoever arrives first.
- **The registration protocol, settled here rather than deferred.** An agent datagram carrying the direction, a counter, and a MAC over all of it plus the relay address and port, sent to the active relay and every standby. The key is derived per relay from the direction's secret, so a compromised relay cannot register at its peers. The counter derives from a clock at the agent and is persisted at the relay, so neither restart reopens replay or locks the agent out. The agent sends on underlay address change and on resume, with a 25-second floor, since on the relay path this datagram is the only thing holding the NAT mapping open. Binding the relay address stops cross-relay replay, and because the agent sends it, recovery does not wait on a WireGuard handshake. Admission and standby registration are one design, and Phase 3's gate depends on it.
- Relay persistence: the pushed port table, the per-relay registration keys, and the highest counter accepted per direction survive a restart.
- Per-port rate limits and metrics for forwarded, unroutable, rejected and write-failed packets.
- Multiple local addresses, so the table keys on `(local address, port)`.
- Agent-side relay probing and endpoint rewrite on failover, with both sides registered on every relay in the set.
- Relay peers configured without `persistent-keepalive`, once the NAT test below passes. Until the registration datagram ships, relay peers keep keepalive, because the current relay learns endpoints only from traffic.

Out of scope:
- `sk_lookup` and XDP, which Phase 7 covers.
- Anycast relay addressing.

Completion gate:
On three machines in one datacenter the relay carries more traffic per CPU-second than a WireGuard-terminating gateway on the same box, with the underlay ceiling measured in the same run. Relay failover completes in under 1s. A direction cannot be claimed by a sender the control plane has not authorized.

Testing plan:
- The three-path comparison — direct, relay, gateway — as a committed benchmark, ceiling first. It records round-trip p50 and p99 on each path against the plain underlay's, both idle and while the throughput run saturates the path.
- A test asserting an unknown port and an unauthorized source are both dropped.
- A NAT test: a host whose public address and port change re-registers and traffic resumes.
- A NAT-mapping test, run in CI against a conntrack NAT built from namespaces: a registration datagram from a raw socket on the interface's listen port keeps the same mapping alive that WireGuard's own socket uses, so a relay peer with no keepalive still receives after the mapping's idle timeout has passed.
- An attach test: two agents install a new edge at the same moment, and the first packet arrives without losing a 5-second handshake round.
- A hijack test asserting an unauthorized sender cannot take over a live or dormant direction.
- A failover test measuring time from relay loss to resumed traffic on both sides.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | Directed-port relay, batched reads and writes | `cmd/relay/main.go`; two senders sharing one address disambiguated by port, rebind logged as `sender moved`. |
| Complete | Risk | A per-packet syscall loop loses to a terminating gateway | Measured at 413 Mbit/s with `UdpRcvbufErrors` climbing; recorded in SPEC.md. |
| Complete | Risk | A keyless relay cannot authenticate an endpoint change | Demonstrated unintentionally: one stray UDP packet from the same host on a new port took over a live direction. |
| Incomplete | Scope | Pushed directed-port table replacing trust-on-first-use | Missing: implementation and the control-plane push. |
| Incomplete | Work | 3A: Endpoint admission | Missing: implementation. The design is in SPEC.md "The relay"; the packet format, key distribution, and behavior before a direction's key arrives are open. |
| Incomplete | Work | 3B: Rate limits and per-port metrics | Missing: implementation. |
| Incomplete | Work | 3C: Multiple local addresses | Missing: implementation. |
| Incomplete | Work | 3D: Agent probing and two-sided endpoint rewrite | Missing: implementation. |
| Incomplete | Work | 3E: Relay peers without `persistent-keepalive` | Missing: implementation, gated on the NAT-mapping test. |
| Incomplete | Test | Raw-socket registration holds WireGuard's NAT mapping; simultaneous attach loses no round | Missing: both tests. |
| Incomplete | Gate | Relay beats gateway per CPU-second, ceiling in the same run | Missing: committed benchmark. Measured once by hand; see SPEC.md. |
| Incomplete | Test | Round-trip time per path, idle and under load, against the plain underlay | Missing: measurement. Only throughput has been measured; under load the relay's socket buffers decide it. See SPEC.md "Targets". |
| Incomplete | Test | Unknown port, unauthorized source, and hijack all rejected | Missing: tests. |

## Phase 4: Services, selection and convergence

Goal:
Services as the user-facing object, with a change that lands in one step per client and established connections that drain rather than break.

Scope:
- The fixed slot table, `typeof numgen random mod 1024 : ip daddr`, every slot filled, weight by slot count. An IPv4-capable service gets a second map in the other family, with every slot assigned to the same backend and both maps changed in one transaction. **Measuring the slot-map rewrite across many namespaces belongs here**, since the convergence gate depends on it; nftables commits take a per-namespace lock, so these can run in parallel even though peer work, which is on RTNL, cannot.
- Backend changes as element updates in one transaction, never a rule rebuild.
- Peer installation ordered around that transaction; revocation skipping the grace period.
- A service with no backends installing a reject rule rather than blackholing.
- `cutover` as the alternative to the default grace behavior.
- The stub resolver, with its listening descriptors handed across restarts so queries wait in the socket buffer rather than failing, and its state reloaded behind them. It answers A only where both the client's service and the target have IPv4.
- **Verifying the IPv6 nftables forms.** Every confirmed selection form is IPv4 (`ip daddr`), and IPv6 is the family every service has, so the `ip6 daddr` map declaration and `dnat ip6 to` translation are checked on nftables 1.0.9 before the slot table is built on them.

Out of scope:
- `drain` mode and generation acknowledgment.
- `jhash` affinity selection, until `nft list` stops crashing on a `jhash`-keyed map.

Completion gate:
Replacing a single-instance service flips every client in one step, with no client observing a partial backend set and no established connection broken. Convergence p99 in one region stays under 250ms with the slot-map rewrite included.

Testing plan:
- A test asserting a partially filled slot map is never written, in either family.
- A test asserting an IPv4-capable service's two maps assign every slot to the same backend.
- A test asserting an IPv6-only client receives no A record.
- A test asserting established connections survive a replace while new connections reach the new instance.
- A test asserting no client reads a half-applied backend set under concurrent changes.
- A test asserting a zero-backend service rejects rather than hanging.
- A convergence measurement under churn that includes rewriting the slot map in many namespaces.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Decision | Slot map declaration form, `typeof` on both sides | Verified on nftables 1.0.9; `: ipv4_addr` and `type integer` both rejected. |
| Complete | Decision | `numgen` ships first; `jhash` deferred | `nft list` segfaults printing a `jhash`-keyed map on 1.0.9. |
| Complete | Decision | `numgen random`, not `numgen inc` | `nft_ng_inc_init` starts each rule's counter at slot 0, so every client namespace begins on the same backend. By traffic on nftables 1.0.9 and Linux 6.10: twenty fresh namespaces with one connection each all reached one backend under `inc` and split 8 and 12 under `random`. Both forms load, and `nft list` prints a `random`-keyed map. |
| Complete | Doc | Convergence batch cost, one peer into each of H namespaces | `cmd/hostbench`; 111–126µs per namespace on c6i.xlarge / Linux 7.0, H=40 in 5ms, with fresh keys derived outside the timer and no flush inside it. The KVM figures (235–252µs) derived keys inside the timer and overstate the kernel cost. |
| Incomplete | Decision | IPv6 slot map and `dnat ip6 to` forms | Missing: verification on nftables 1.0.9; every confirmed form is IPv4. |
| Incomplete | Scope | Fixed slot table, every slot filled, one map per family | Missing: implementation, the partial-map test and the same-backend test. |
| Incomplete | Scope | Element-update transactions | Missing: implementation. |
| Incomplete | Work | 4A: Peer ordering, including revocation without grace | Missing: implementation. Orders are in SPEC.md. |
| Incomplete | Work | 4B: Zero-backend reject rule | Missing: implementation. |
| Incomplete | Work | 4C: `cutover` conntrack eviction | Missing: implementation. |
| Incomplete | Work | 4D: Stub resolver with descriptors handed across restarts | Missing: implementation; persisting state alone still drops queries, since the sockets close with the process. |
| Incomplete | Gate | Single-instance replace flips atomically, nothing broken | Missing: test. |
| Incomplete | Gate | Convergence p99 under 250ms including the slot-map rewrite | Missing: measurement. Rewriting 1024 entries across hundreds of namespaces is unmeasured. |

## Phase 5: Isolation, policy enforcement and failure behavior

Goal:
The security and failure claims hold under test, including the ones that assert something cannot happen.

Scope:
- Default-deny nftables policy compiled per interface, installed before handover.
- `AllowedIPs` carrying exactly one address per family per peer.
- Internet egress as a separate grant: a veth to the host namespace, NAT there, and a host-side filter dropping the link-local ranges and metadata service in both families, **the host's own addresses**, the underlay prefix, every relay address, and ungranted private ranges. The host matters as much as the rest: the veth's host end otherwise reaches host services and every co-located interface's WireGuard listen port.
- Revocation enforced through peers with no cooperation from the holder.
- Control-plane partition: agents hold configuration, teardown follows workload liveness, and recovery waits out a grace period before acting on leases that expired during the outage.

Out of scope:
- Sender-side policy for `CAP_NET_ADMIN` workloads.

Completion gate:
Every isolation claim in SPEC.md under Trust has a corresponding failing-to-reach assertion in each family, including two tenants with identical addresses, a revoked interface, a workload attempting a forbidden flow, and a granted-egress workload attempting to reach the metadata endpoint and the relays.

Testing plan:
- Two networks with identical addresses, each reaching only its own peer.
- A revoked interface reaching nothing while its own host still has it configured.
- A forbidden flow dropped at the receiver.
- An egress-granted workload denied the metadata address in both families (`169.254.169.254`, `fd00:ec2::254`), the underlay, and the relays.
- A peer spoofing a source address in either family, dropped at the receiver.
- A partition test asserting traffic continues, change freezes, and recovery does not revoke the fleet at once.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Doc | Two networks on one address space reach only their own peers | SPEC.md "Two networks, one address space"; distinct servers answered the same address. |
| Incomplete | Scope | Default-deny policy installed before handover | Missing: implementation. |
| Incomplete | Scope | One address per family per peer in `AllowedIPs` | Missing: compiler enforcement plus test. |
| Incomplete | Work | 5A: Egress grant with a host-side filter | Missing: implementation. Must drop `169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`, **the host's own addresses**, the underlay, and relay addresses. |
| Incomplete | Work | 5B: Revocation through peers, holder uncooperative | Missing: test asserting the holder keeps config and reaches nothing. |
| Incomplete | Work | 5C: Partition behavior and workload-liveness teardown | Missing: implementation and test, including the recovery grace period. |
| Incomplete | Gate | Every Trust claim has a cannot-reach assertion | Missing: the suite. |
| Incomplete | Risk | Island partitions serve stale state | Documented in SPEC.md; needs a test pinning the behavior rather than fixing it. |

## Phase 6: Development machines

Goal:
A developer joins a network from a laptop with a stock WireGuard client and reaches services by name, under the same policy, leases and revocation as any interface.

Scope:
- A gateway interface: agent-managed, on a host with an inbound UDP port, routing the network's prefixes, translating service addresses in `prerouting`, and serving the network's names.
- Config generation that mints the keypair on the developer's machine, registers only the public key, and writes a standard `wg-quick` file that the macOS app imports unmodified.
- The policy compiler treating a development machine as an interface: a peer on its gateway, its addresses in each permitted backend's entry for that gateway, and nftables rules naming it.
- Fixed-term leases, extended by regenerating the config, and revocation that removes the machine from its gateway and from the backends' entries with no grace period.

Out of scope:
- Reaching a gateway through a relay, since a stock client cannot send the registration datagram.
- Failover between gateways.
- An agent on macOS or Windows.

Completion gate:
A generated config, imported unmodified into the macOS WireGuard app, reaches a service by name, keeps working through a backend replacement, and reaches nothing once its lease is revoked, while every flow policy does not name stays dropped at the receiver.

Testing plan:
- In CI, a namespace running `wg-quick` with a generated config stands in for the laptop: it reaches a service by name, and the backend sees the laptop's own address as the source.
- A backend replacement while the laptop holds a connection open: established connections stay with the old backend, new ones reach the new backend, and the config is unchanged.
- Revocation: the laptop reaches nothing, with no grace period.
- Cannot-reach assertions in each family: a service policy does not name, and one laptop sending as another laptop's address through the same gateway.
- A test asserting the control plane never receives the laptop's private key.
- A manual run importing the generated file into the macOS WireGuard app.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Incomplete | Scope | Gateway interface: prefixes, `prerouting` translation, resolver | Missing: implementation. |
| Incomplete | Work | 6A: Config generation with the key minted on the developer's machine | Missing: implementation. |
| Incomplete | Work | 6B: Policy compilation for development machines | Missing: implementation plus compiler tests. |
| Incomplete | Work | 6C: Fixed-term leases and revocation through the gateway | Missing: implementation. |
| Incomplete | Gate | A stock macOS client reaches a service by name and loses access on revocation | Missing: test. |
| Incomplete | Test | One laptop cannot send as another through a shared gateway | Missing: adversarial test. |

## Phase 7: Performance hardening

Goal:
Take the throughput levers the measurements identified, in the order their payoff warrants.

Scope:
- `sk_lookup` or an XDP relay data path, which the stated edge capacity requires.
- Underlay MTU probing per host pair, raising the overlay MTU where the path carries it.
- Direct paths: hole punching, endpoint rewrite, relay fallback.
- Loopback short-circuit for co-located interfaces, with `persistent-keepalive` on exactly one side of each pair, chosen deterministically.

Out of scope:
- Anycast relay addressing.

Completion gate:
Each lever is measured against the path it replaces on real hardware, with the underlay ceiling in the same run, and any that fails to pay is dropped from the design rather than carried.

Testing plan:
- `sk_lookup`/XDP against the batched userspace relay: pps per core, CPU per Gbit, and edges per process.
- MTU: throughput and CPU at 1380 against the discovered maximum, per path, noting that the lever is unavailable across the internet.
- Direct paths: latency and throughput against relayed, plus a fallback test when punching fails.
- Loopback: throughput and CPU against the relayed path for two interfaces on one host, plus a test that both workloads sending at the same instant after an idle period complete a handshake without falling into lockstep.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Doc | Per-core one-way encryption, ~1.3–1.5 Gbit/s at a 1380-byte MTU | SPEC.md "Encryption at the edge". |
| Complete | Doc | MTU lever is worth 4.4× for 1.15× CPU, on paths that carry large frames | SPEC.md; measured on loopback, so it does not apply across the internet. |
| Incomplete | Work | 7A: XDP or TC relay data path | Missing: implementation. Userspace baseline carried ~118k pps on a hot edge; `sk_lookup` alone fixes only the receive side, so sends need a raw socket or the whole path moves to XDP/TC. |
| Incomplete | Work | 7B: Underlay MTU probing and overlay raise | Missing: implementation. |
| Incomplete | Work | 7C: Direct paths with relay fallback | Missing: implementation. |
| Incomplete | Work | 7D: Loopback short-circuit, keepalive on one side only | Missing: implementation and the simultaneous-send test. Both sides armed was observed to lock step for minutes on Linux 7.0; see SPEC.md "Paths". |
| Incomplete | Gate | Every lever measured against the path it replaces | Missing: measurements. |

## Phase 8: Open questions

Goal:
Settle what the design leaves open, with measurement rather than argument.

Scope:
- Softirq CPU accounting on a loaded multi-tenant host, the standing risk to the density thesis.
- Whether the ~10–12k per-host peer ceiling can be raised at all. RTNL is what serializes it, so a kernel change is the only way through; the userspace lever is grouping every pending change for a device into one call.
- Whether the registration datagram's counter scheme survives clock irregularities on an agent that derives it from time.

Completion gate:
Each question has a measurement or a decision recorded in SPEC.md.

Testing plan:
- A loaded host with many interfaces and one deliberately chatty tenant, comparing cgroup-attributed CPU against CPU actually spent on that tenant's crypto.
- A peer-rate run under `perf lock contention -ab` on a host with many cores, to measure what `rtnl_mutex` contention costs other RTNL users at high attach rates.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Decision | Peer work runs under RTNL; ceiling ~10–12k/s per host, not per core | `wg_set_device` takes `rtnl_lock()` before the per-device lock (netlink.c); `cmd/hostbench` sizes the ceiling on two substrates, and on c6i.xlarge adding writers added neither throughput nor CPU. |
| Complete | Decision | A detach is budgeted like an attach | `cmd/hostbench`: a single-peer removal, the figure a detach pays, is 60µs on 8-vCPU KVM (a quarter of an addition) and 90–100µs on c6i.xlarge / Linux 7.0 (equal to one). `synchronize_net()` is expedited when RTNL is held (net/core/dev.c). |
| Complete | Decision | `mac1` rejected as admission; authenticated registration instead | `mac1` is replayable from any address and at any relay, and every peer of the receiver holds the key that computes it. |
| Incomplete | Risk | Softirq CPU attribution on a loaded host | Needs: a loaded multi-tenant measurement. |
| Incomplete | Risk | RTNL contention at higher attach rates | Device creates ran 1.9–3.2× slower under saturation on c6i.xlarge in four runs (inconclusive on 8-vCPU KVM), under a millisecond per create at these rates. Needs `perf lock contention -ab` looking for `rtnl_mutex`. |
