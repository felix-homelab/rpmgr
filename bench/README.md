# Benchmark suite

The suite measures the targets of [03](../docs/03-connections.md#targets-t) and compares the two
transports with each other and with a direct TCP connection
([12](../docs/12-testing-and-quality.md#benchmarks)). It drives real `rpmgr` processes of the
`rpmgrtest` build, configured with `rpmgr testseed`, in Docker containers on one host, with
`tc netem` on the gateway↔connector link.

It is the harness of spike S1 (tag `spike/s1`, [S1](../docs/spikes/S1.md)), moved here as
[D36](../docs/14-open-decisions.md#project-and-process) planned:

| From `spike/s1` | Here |
|---|---|
| `spikes/s1/internal/load/load.go` | `load/load.go`: the sink, source and echo, goodput and setup latency, unchanged in what they measure |
| `spikes/s1/cmd/s1/loadcmd.go` | `cmd/bench/loadcmd.go`: one measurement, one JSON line, now with more workloads |
| `spikes/s1/cmd/s1/summarize.go`, `summarize_test.go` | `cmd/bench/summarize.go` and its tests: the tables and the targets of 03; the D19 rule, which decided ADR-0004, is gone, and a regression check against a baseline is new |
| `spikes/s1/scripts/run-matrix.sh` | `cmd/bench/run.go`, `compose.yaml`: the matrix against real `rpmgr` processes |
| `spikes/s1/internal/tunnel`, `internal/pki` | dropped: the spike's stand-ins for rpmgr |

## Running it

```sh
PROFILE=smoke .github/scripts/run-bench.sh local          # a few minutes: does it work?
PROFILE=standard .github/scripts/run-bench.sh local       # RTT 1 and 80 ms, loss 0 and 1 %
```

The results go to `bench-results/<testbed>.jsonl`, the host to `.meta.txt` and the summary to
`.md`. `BENCH_ARGS` passes more flags of `go run ./bench/cmd/bench run -h`, such as `-gso off`. A
local run shares one kernel and its CPUs among all containers, and its links are far faster than
any network: its numbers only show that the suite works.

On GitHub-hosted runners ([D49](../docs/14-open-decisions.md#project-and-process)), the maintainer
starts the workflow `bench` by hand, for x86-64 and arm64 at once:

```sh
gh workflow run bench.yml --ref main -f profile=standard
```

## Workloads

| Workload | What it measures | Scaled down on one runner |
|---|---|---|
| `throughput` | Goodput of 1 and 32 streams up and down, for direct, QUIC and TLS + HTTP/2; gateway and connector CPU per Gbit/s from their `process_cpu_seconds_total` | — |
| `setup` | Connection-setup latency p50 and p99 at a fixed rate, open loop | — |
| `http` | HTTP/2 requests per second and latency through an http route, 32 workers | — |
| `udp` | Datagrams per second and loss at 1 200 and 1 400 bytes, and the share on the oversize path from `rpmgr_udp_oversize_total`; 3 000 bytes show that counter works | — |
| `vb18` | VB-18: the share of new connections a connector gets on a route two connectors serve, before and while its session's writers are blocked by uploads through its link limited to 10 Mbit/s | — |
| `changes` | One configuration change per second: apply time from the commit until the gateway's `rpmgr_agent_applied_revision` moves, and held connections lost on an unchanged route | `-routes`: 1 000 in the full profile, 200 in the standard one |
| `kill` | SIGKILL of the gateway, then of the controller, while connections are held: recovery time and connections lost | — |
| `idle` | The gateway's memory and CPU with idle connectors holding sessions, and without them | `-idle`: 20 in the full profile and 10 in the standard one, not 10 000 |

Not covered:
- the Raspberry Pi 5 connector of the reference testbed (VB-20);
- `perf stat` cycles per byte: CPU time stands in for them, and whether hosted runners allow perf
  events was not checked;
- GSO and buffer settings as axes of one run: a run takes `-gso off`, and the workflow's
  `host-tuning` input runs without raised UDP buffer limits.

## Baselines

The regression check reads `bench/baselines/<testbed>.jsonl`. After a release's benchmark run, the
maintainer downloads its artifacts and commits the `.jsonl` files there, in the release PR.
