# Benchmark fleet

`wirenet-lab` runs named benchmark plans against a fleet and writes one report per plan, ready to copy into `SPEC.md`. The fleet is either namespaces on this machine (`--env local`) or EC2 instances (`--env aws`); the plans are the same against both.

| Path | What it is |
|---|---|
| `aws/terraform` | A VPC with one public subnet, and the fleet: a control-plane host running Postgres, agent hosts, relays, and a middle box that plays both the relay and the WireGuard-terminating gateway. |
| `hostprep.sh` | Prepares an Ubuntu 24.04 machine for its role: packages, sysctls, and checks that fail loudly when the kernel lacks WireGuard or `CONFIG_INET_DIAG_DESTROY`. |
| `purge.sh` | Stops the daemons and removes what earlier runs left: namespaces, the processes holding them, WireGuard devices, journals and relay state. |
| `systemd/` | Units for `wirenet-cp`, `wirenet-agent` and `wirenet-relay`, each reading its flags from `/etc/wirenet/*.env`. |
| `monitoring/` | The Prometheus scrape configuration and a Grafana dashboard for every metric the daemons export. |

## Plans

| Plan | Measures |
|---|---|
| `hostbench` | `cmd/hostbench` on each agent host: device placement, netdev and peer concurrency, peer costs. |
| `paths` | The plain-TCP ceiling between two hosts first, then the overlay through the relay on the middle box, then through a WireGuard gateway on the same box: throughput at 1 and `--streams` streams, middle-box CPU per Gbit, and round trips idle and under load. |
| `attach` | Attach to first connection at policy degree `--degree`, `--rounds` times. |
| `churn` | Attach-and-detach pairs per second on every host at once, `--concurrency` workers each; every pair is counted and the counts asserted. |
| `converge` | A service change under churn: a cold replacement of a backend, then removal of one of two warm backends, timed until every client's new connections reach the backend that stays. |
| `failover` | Killing the relay an edge sends through, mid-flow: the established flow's stall and a new connection's wait. |
| `density` | Interfaces on one host until an attach fails, attach latency degrades tenfold, or `--max-interfaces`. |
| `spread` | `--edges` edges streaming at once through one relay, then two, then three: aggregate throughput, edges and CPU per relay, and each host's CPU, which shows when the endpoints rather than the relays bound the aggregate. Run it with `relay_count = 3` and an even `agent_count`, so clients and servers split the hosts evenly. |
| `policy` | `--clients` sandboxes spread over the hosts dial a db that `* -> db` opens to every other service; times a `box -> db` deny from its commit until every sandbox's new connections fail, and its removal until they reach db again. |

Every plan starts from a fresh fleet, measures the plain-TCP underlay ceiling in the same run, and purges the fleet afterwards. `wirenet-lab plans` lists them.

## Run the plans locally

The local environment builds the fleet with `internal/lab`: an underlay bridge, a namespace per host and relay, and the real daemons. It needs root, kernel WireGuard, nftables and conntrack. Labs on one machine take turns under `/run/lock/wirenet-lab.lock`, so a plan waits while an end-to-end test runs.

```console
scripts/lab run --env local --plan paths --duration 3s
scripts/lab run --env local --plan all --duration 3s
scripts/lab run --env local --plan converge --store postgres://user:password@127.0.0.1:5432/db
scripts/lab run --env local --plan attach --log-level debug --keep-logs /tmp/wirenet-logs
```

`scripts/lab` builds every binary as you and runs `wirenet-lab` under `sudo`. `--store` gives each run a fresh schema in that database. All the hosts share one kernel, so local figures show that each plan runs end to end and what its report looks like; the figures for `SPEC.md` come from EC2.

## Build the fleet on EC2

With AWS credentials in the environment:

```console
cd deploy/aws/terraform
terraform init
terraform apply \
  -var operator_cidr=203.0.113.7/32 \
  -var key_name=wirenet-bench \
  -var ssh_public_key="$(cat ~/.ssh/wirenet-bench.pub)" \
  -var placement_group=true
terraform output -json > ../../../fleet.json
```

Leave `ssh_public_key` unset to use a key pair that already exists. The instance types (`c6i.xlarge` by default), the region, and the agent and relay counts (3 and 2) are variables. At first boot each machine runs `hostprep.sh` for its role and logs to `/var/log/wirenet-hostprep.log`.

## Deploy

Build Linux binaries, then copy them and the scripts and units to every machine:

```console
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/ \
  ./cmd/wirenet-cp ./cmd/wirenet-agent ./cmd/wirenet-relay ./cmd/wirenetctl ./cmd/wirenet-bench ./cmd/hostbench
go build -o bin/ ./cmd/wirenet-lab
bin/wirenet-lab deploy --tf-output fleet.json --ssh-key ~/.ssh/wirenet-bench --bin bin
```

`--known-hosts FILE` keeps the fleet's host keys out of your own `known_hosts`, since EC2 hands the addresses to other machines once the fleet is gone.

Each machine gets its role's binaries in `/usr/local/bin`, `hostprep.sh` and `purge.sh` in `/usr/local/lib/wirenet`, and the units in `/etc/systemd/system`; `hostprep.sh` runs again. The control-plane host also gets the Prometheus configuration and its targets. Add `--dry-run` to any `wirenet-lab` command to print every remote command instead of running it; a dry run needs no credentials, only a `fleet.json`.

## Run a plan

```console
bin/wirenet-lab run --env aws --tf-output fleet.json --ssh-key ~/.ssh/wirenet-bench --plan paths
bin/wirenet-lab run --env aws --tf-output fleet.json --ssh-key ~/.ssh/wirenet-bench --plan all --deploy
```

Before each plan `wirenet-lab` purges every machine, empties the control plane's database, registers the relays and hosts, writes their credentials and flags, and starts the daemons; after it, it purges again. `bin/wirenet-lab purge` does the purge alone.

## Reports

Each plan writes `reports/<time>-<plan>-<env>.md` and `.json` under the directory `wirenet-lab` runs in (`--reports` moves them). The markdown opens with the substrate: environment and region, instance types, each machine's kernel, CPU model, CPU count and `rmem_max`, and the underlay ceiling. Its tables follow the form of `SPEC.md` "Measured". The JSON holds every raw result. A report that ends in "Failed assertions" lists what did not hold; `wirenet-lab` then exits nonzero.

## Monitoring

Prometheus runs on the control-plane host at `127.0.0.1:9099`, because `wirenet-cp` serves its own metrics on `:9090`. It scrapes `wirenet-cp` on 9090, every `wirenet-agent` on 9091, every `wirenet-relay` on 9092 and every node_exporter on 9100, from file_sd targets `wirenet-lab deploy` writes into `/etc/prometheus/wirenet`; `wirenet-lab monitoring --tf-output fleet.json --out DIR` writes the same targets for a Prometheus elsewhere. To see the dashboard:

```console
ssh -i ~/.ssh/wirenet-bench -L 9099:127.0.0.1:9099 ubuntu@<cp public address>
```

Then add a Prometheus data source at `http://localhost:9099` to Grafana and import `monitoring/grafana-dashboard.json`.

## Tear down

```console
terraform -chdir=deploy/aws/terraform destroy
```
