# Spike S1 — transport benchmark harness

QUIC versus TLS + reverse HTTP/2 against a direct TCP connection, for the default transport policy
([13](../../docs/13-roadmap.md#phase-0--spikes), [ADR-0004](../../docs/adr/0004-quic-default-transport-policy.md),
D19, D30, D34, D37). Result: [docs/spikes/S1.md](../../docs/spikes/S1.md).

This directory lives on the never-merged branch `tmp/s1-transport-benchmark` and is archived as
tag `spike/s1`. In Phase 1 the harness becomes `bench/` through a normal PR (D36).

## What it is

| Part | What it does |
|---|---|
| `internal/tunnel` | A minimal gateway and connector: one stream per public TCP connection, `StreamOpen` without waiting, `StreamResult` before service bytes, half-close preserved. QUIC with the parameters of [03](../../docs/03-connections.md#quic-parameters); TLS 1.3 + reverse HTTP/2 with the parameters of [03](../../docs/03-connections.md#transports-and-fallback) and two TCP connections per gateway. Mutual TLS with a generated test CA, SPIFFE IDs and `ServerName` per peer |
| `internal/load` | Service (sink with byte-count acknowledgement, timed source, echo) and load generator (goodput for N streams up or down; connection-setup latency at a fixed rate, open loop) |
| `cmd/s1` | Roles `certs`, `service`, `gateway`, `connector`, `load` (one JSON line per measurement, with gateway and connector CPU seconds from their stats listeners) and `summarize` (tables, targets of 03, the D19 rule) |
| `scripts/run-matrix.sh` | The matrix: RTT × loss × {direct, quic, h2} × {1 and 32 streams up and down, setup at 1 000 connections/s}, `REPS` times; `docker` mode (local dry run) or `testbed` mode (SSH) |
| `scripts/setup-host.sh` | Host tuning of a testbed VM (UDP buffers 7 MiB) and a record of kernel, congestion control and offloads |

Not modelled: session control streams, `OpenRequest`, UDP datagrams, the window budget, happy
eyeballs. They do not change throughput, setup latency or CPU per byte of TCP routes.

**Direct baseline.** netem shapes only the gateway↔connector link (half the RTT and the full loss
rate per direction, queue limit raised so netem does not cap the bandwidth-delay product).
"direct" is a plain TCP connection over that link, opened from the gateway host to the service;
tunnel runs start on the client host and add the client↔gateway LAN hop.

## Tests

```sh
export PATH=$HOME/.local/go1.27.1/bin:$PATH   # or any Go ≥ 1.26 with GOTOOLCHAIN=auto
go -C spikes/s1 vet ./...
go -C spikes/s1 test -race -count=1 ./...
```

Covers, for both transports: 8 MiB echo integrity, half-close (service keeps sending after the
client's FIN), acknowledged uploads with 8 streams, unknown route and refused target close the
client connection, setup-latency measurement; framing limits; invalid load arguments; a connector
certificate cannot pose as the gateway; every branch of the D19 rule, including ties, the 5 %
margin, pooling across testbeds and missing data.

## Local dry run (Docker; does not decide, D37)

```sh
spikes/s1/scripts/run-matrix.sh docker spikes/s1/results/docker-dryrun.jsonl
go -C spikes/s1 run ./cmd/s1 summarize -in results/docker-dryrun.jsonl > spikes/s1/results/docker-dryrun.md
```

Defaults: RTT {1, 80} ms, loss {0, 1} %, 3 repetitions, 10 s per throughput run, 5 s at 1 000
connections/s for setup. A dry run shares one kernel and its CPUs among all three "hosts", uses the
host's UDP buffer limits (they cannot be raised per container), and its veth links are far faster
than any NIC, so its numbers only show that the harness works.

## Reference testbed run sheet (maintainer, D30, D37)

1. **Provision** three short-lived VMs with 2 vCPUs each — `client`, `gateway`, `connector` — on
   x86-64, Debian 12 or Ubuntu 24.04, in one region. Connect client↔gateway and gateway↔connector
   by private networks (two networks, or one network where netem is applied only to the
   gateway↔connector addresses' interfaces). Allow SSH from your machine with host aliases
   `s1-client`, `s1-gateway`, `s1-connector` in `~/.ssh/config` and passwordless `sudo`.
2. **Build and copy** (on your machine):

   ```sh
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go -C spikes/s1 build -trimpath -o /tmp/s1 ./cmd/s1
   /tmp/s1 certs -dir /tmp/s1-certs
   for h in client gateway connector; do
     ssh s1-$h 'sudo mkdir -p /opt/s1 && sudo chown $USER /opt/s1'
     scp -r /tmp/s1 /tmp/s1-certs s1-$h:/opt/s1/ && ssh s1-$h 'mv /opt/s1/s1-certs /opt/s1/certs'
     scp spikes/s1/scripts/setup-host.sh s1-$h:/opt/s1/
     ssh s1-$h "sudo /opt/s1/setup-host.sh $h" | tee -a spikes/s1/results/ref-x86.hosts.txt
   done
   ```

3. **Run** (on your machine; addresses are the VMs' private addresses, interfaces the ones
   facing the gateway↔connector link; `tc` runs through `sudo`, `SUDO=` disables that):

   ```sh
   export TESTBED=ref-x86 REPS=5 DUR=20s SETUP_DUR=10s
   export GATEWAY_PUB=<gateway, client side> GATEWAY_PRIV=<gateway, connector side>
   export CONNECTOR_IP=<connector, gateway side> CONNECTOR_MGMT=<connector, reachable from client>
   export GATEWAY_IF=<gateway iface to connector> CONNECTOR_IF=<connector iface to gateway>
   spikes/s1/scripts/run-matrix.sh testbed spikes/s1/results/ref-x86.jsonl
   ```

4. **Repeat** steps 1–3 on arm64 VMs (`TESTBED=ref-arm64`, `GOARCH=arm64`) and with the
   Raspberry Pi 5 as connector (`TESTBED=ref-pi5`, connector binary `GOARCH=arm64`). Also run
   [S8](../../docs/13-roadmap.md#phase-0--spikes)'s arm64 test binary on the Pi (D38).
5. **Decide:** `cat results/ref-*.jsonl > results/ref-all.jsonl` and
   `go -C spikes/s1 run ./cmd/s1 summarize -in results/ref-all.jsonl > results/ref-all.md`. The
   last line names the default transport under the D19 rule as operationalised in
   [S1.md](../../docs/spikes/S1.md). Commit the results to this branch, then update S1.md and
   ADR-0004 in a result PR. Delete the VMs.

Optional per-run CPU detail: `perf stat -e cycles -p <pid>` on gateway and connector during a run.
