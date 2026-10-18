# sdn.sh

`SPEC.md` is the design contract and holds every measurement. Read it before changing behavior, and when code and spec disagree, fix one of them in the same change. `PLAN.md` is the build plan: work in its order and update its ledgers with evidence. `README.md` carries the positioning; numbers live in `SPEC.md` only, so they cannot drift between the two.

## Core rules

- **Create devices into the workload namespace; never create-then-move.** A WireGuard device records the *requesting* socket's namespace as the one its encrypted socket belongs to, so `IFLA_NET_NS_FD` at creation puts plaintext in the workload and ciphertext on the host. Creating inside the workload namespace instead would put the underlay where the workload can reach it.
- **Know which netdev operations overlap.** A destroy defers its grace period past `rtnl_unlock` and scales 20× with concurrency. A namespace move holds RTNL across its own and scales 1.1×. Apply destroys concurrently; never expect concurrency to rescue a move.
- **One relay port per direction.** The port a packet arrives on must name its sender. Identifying senders by source address cannot survive NAT that reassigns addresses and cannot disambiguate two interfaces behind one address at all.
- **The relay batches its syscalls.** `recvmmsg`/`sendmmsg` with `SO_REUSEPORT` sockets. A per-packet loop overflows its receive queue and carries less than a terminating gateway, which removes the reason to relay.
- **A relay holds no key that decrypts or forges traffic.** It does hold a per-direction registration secret, which is how it authenticates an endpoint change. Verifying a WireGuard handshake's `mac1` is not enough and was rejected: it is replayable from any address and at any relay, and every peer of the receiver already knows the key that computes it.
- **A relay persists what it is pushed.** Port table and secrets survive a restart, or a relay returning during a control-plane outage strands every edge it serves.
- **A packet that loses an endpoint race is dropped, never forwarded.** Forwarding it would make the relay a reflector for anyone who knows the port.
- **Enforcement lives at the receiver.** `AllowedIPs` and nftables both run in the destination's kernel, one address per family per peer. Nothing a sender does to its own namespace may widen what it reaches.
- **Roaming owns the peer endpoint.** Any authenticated packet from a new source rewrites it, and the relay path depends on that. A reconciler that treats a roamed endpoint as drift will fight the data plane.
- **The agent mints keys and keeps them.** Private keys never leave the host; the control plane sees public keys only.
- **Teardown follows the workload, not the control plane.** Hold configuration through an outage of any length — revocation runs through peers, so it costs the fence nothing.
- **Set `persistent-keepalive` per path.** None on relay peers once the registration datagram ships, exactly one side of a co-located pair, both sides on a direct path. A two-peer test on one host arms it on one side only. Why: SPEC.md "Paths".
- **Peer work runs under RTNL: one lane per host, ~10–12k operations a second, and it will not grow with cores.** `wg_set_device` takes `rtnl_lock()` before the per-device lock and holds both for the whole call, and reads take the same locks. So peer changes serialize against each other and against device, address, route and link changes. Neighbour peer additions parallelize only across hosts.
- **A per-call peer cap is not a lever.** `wgctrl` already splits over 32 peers into separate messages, so RTNL is released between chunks and a cap above 32 never fires. The tail comes from a tight loop winning an unfair mutex: yield between chunks or bound concurrent writers. Never bypass `wgctrl` to pack one huge message — that holds RTNL for all of it.
- **Budget a detach like an attach.** A single-peer removal waits an expedited grace period under RTNL: 60µs on an 8-vCPU KVM guest, where it was a quarter of an addition, and 90–100µs on a c6i.xlarge with Linux 7.0, where it matched one. Each removed peer pays its own grace period even when several share a call; only a full flush (`ReplacePeers`) pays one for all, so never quote the flush figure as a batched removal. Expedited grace periods interrupt every non-idle CPU, so removal churn costs the whole host.
- **Hold one netlink socket per namespace, opened inside it.** It keeps configuring its device from outside, so an attach pays one namespace switch and an update pays none.
- **Every slot in a service's map carries an entry.** A missed lookup leaves the packet addressed to the service address, which goes nowhere. A service with no backends installs a reject rule instead.
- **Select slots with `numgen random`, never `numgen inc`.** Each rule owns its counter and starts it at slot 0 (`nft_ng_inc_init`), so every client namespace begins on the same backend, and short-lived clients that open a few connections never leave it.
- **Order peer installation around the nftables transaction.** Add the peer before its slots, remove its slots before the peer — except a revocation, which removes both at once with no grace period. Removing a peer also flushes the conntrack entries translated to its address **and destroys the sockets addressed to it** (`SOCK_DESTROY`), because flushing conntrack leaves the socket and a later write would reach whoever holds the address next.
- **Check every netlink call.** Discarding errors once turned three failures into three published measurements. The same mistake in the agent produces an interface that looks attached and is not.

## Testing

- **Semantics run inside one Linux kernel, and belong in CI.** Namespaces stand in for hosts: a relay in one, several hosts in others, each handing a workload a namespace of its own, veth pairs for the underlay. `ubuntu-latest` on GitHub Actions is a full VM with root, kernel WireGuard and nftables.
- **An isolation claim needs a cannot-reach assertion in each family.** Every claim in `SPEC.md` under Trust needs a test that asserts a peer fails to reach something, not that a permitted flow works.
- **A claim about locking or ordering cites the source line. Measurements size it; they do not decide it.** Three rounds of this project produced three wrong mechanisms inferred from timing — RCU overlap generalized from a destroy-only run, a cost attributed to Curve25519 on a keyless device, and a lock topology read off latencies that `netlink.c` answers in one line. The numbers were right every time; the causes were invented. Read the source first, then measure to size it.
- **Enumerate namespaces, not just host links.** A WireGuard device left in a stale namespace keeps its UDP socket bound in the *host* namespace, so deleting the namespace name alone leaks a listen port with nothing in `ip link` to explain it. A process holding a deleted namespace keeps its device keepaliving too. A reconciler that only lists links it can see will drift.
- **Count successes in a concurrent benchmark and assert the count.** A loop that discards errors reports a throughput figure for work that may not have happened; this is how three published numbers turned out to be the cost of failing.
- **Use fresh keys every round when measuring peer installation, and derive them outside the timer.** Re-adding an existing peer skips the static-static precompute and reads 20–60% cheaper. `PublicKey()` is a userspace scalar multiplication the agent never pays; left inside the timer it inflated the convergence figure from ~115µs to ~205µs per namespace.
- **Verify placement by traffic, not by inspection.** `/proc/net/*` resolves through `/proc/self`, which is the process rather than the thread that switched namespace — use `/proc/thread-self`. The decisive test is whether packets cross a path that only exists in one namespace.
- **The substrate is not incidental.** Anything bound by an RCU grace period measured 2–3× apart between a KVM guest on 6.8 and a microVM on 6.18, in both directions. Record which substrate produced a number.
- **Measure the plain-TCP underlay ceiling in the same run.** Without it a throughput figure is meaningless: a path that reads as a design limit is often 95% of the network.
- **The relay-against-gateway comparison is the thesis regression test**, and the CPU-per-byte column is the part that holds. Both roles on the same machine against the same hosts.
- **Purge stray state between runs.** `ip netns del` only removes the name: a namespace a process still holds keeps its WireGuard device keepaliving and will claim a relay direction. Check `/proc/*/ns/net` for namespaces outside the host's. One orphaned `iperf3` contaminated three consecutive runs.
- **WireGuard initiates nothing without a reason.** No traffic and no `persistent-keepalive` means no handshake, so a test that waits for one will wait forever. A socket also appears only once the device is up, since it is created in `ndo_open`.
- **`nft list` segfaults on a `jhash`-keyed map on nftables 1.0.9.** The ruleset works; the inspection tool crashes. Use `numgen random` until a newer `nft` is the floor.

## Commands

```console
go build ./... && go vet ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" ./...   # from a non-Linux machine

sudo ./hostbench                        # kernel costs, device placement, netdev and peer concurrency
                                        # names everything hb-*, and sweeps only that prefix first
./relay 7001:7002                       # one port pair per edge; WORKERS and BATCH tune it
sysctl -w net.core.rmem_max=268435456   # on a relay host, or SetReadBuffer is capped
nstat -az | grep -i UdpRcvbufErrors     # a climbing count means the relay is dropping
ls -l /proc/*/ns/net                    # find namespaces a process is holding open
```
