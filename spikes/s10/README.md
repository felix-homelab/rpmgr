# Spike S10: socket hand-off (VB-08)

Prototype of spike S10 ([issue #880](https://github.com/felix-homelab/rpmgr/issues/880); result in
`docs/spikes/S10.md`; design in ADR-0022). It is never merged. It answers the rules S-1 to S-7 of
ADR-0022's Verification section with a **model gateway** that hands its sockets to a re-executed
binary, model connectors, and small experiments for the facts the design rests on.

## What is here

| File | What |
|---|---|
| `handoff.go` | The hand-off core: binary check (root-owned, no group or other write, same for every directory), re-exec with inherited sockets, a manifest and a status pipe, descriptor checks in the new process, `sd_notify` (`MAINPID=`, `READY=1`), `s10 handoff` (what `ExecReload` runs) |
| `server.go` | The model gateway: a visitor TCP port (a `tcp` route) served through connector streams, a visitor UDP port (a `udp` route, echo per flow), connector data sessions over QUIC and over TCP; the hand-off with the UDP modes `relay` (ADR-0022's default), `pause` (the rule's fallback) and `norelay` (counterfactual) |
| `relay.go` | The UDP socket shared by two processes: reads from the socket or the predecessor's relay, passes datagrams to the successor; QUIC connection IDs carrying the process generation |
| `load.go` | Load: new visitor TCP connections at a rate, long-lived ones, UDP flows (long and a new short one every second), model connectors (QUIC, TCP, or `auto`: QUIC with TCP 300 ms later) that move at once on `DRAIN`, bulk streams for throughput |
| `experiments.go` | `reuseport`, `sharedqueue` (TCP queue facts) and `sqlite` (S-6, the all-in-one's database) |
| `docker/` | Two systemd hosts pinned by digest (Ubuntu 22.04: systemd 249; Debian 13: systemd 257) and the unit (`Type=notify`, `NotifyAccess=all`, `ExecReload=s10 handoff`) |
| `run.sh` | One scenario on one host, results in `results/<host>-<scenario>/` |
| `results/` | Raw results of every run: `load.json` (all events and counts), `load.txt`, `journal.txt`, `states.txt` (the unit's main PID and state every 100 ms), `reload.txt`, `crash.txt` |

## Pinned versions

Go 1.27.3 (`toolchain`), quic-go v0.64.1, modernc.org/sqlite v1.60.1 (the product's), systemd 249
(`mirror.gcr.io/library/ubuntu@sha256:0a9887931b0e38af2e3487ed39e29436b0535c4f3f52e57745baaf79d1898956`)
and 257 (`mirror.gcr.io/library/debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308`,
the image of `test/ota`), Docker 29.9.2 on WSL2 kernel 6.18.33.2, 20 cores, 31 GiB.

## Repeat every run

From `spikes/s10/`, with Docker and Go:

```sh
go vet ./... && CGO_ENABLED=0 go build -o /tmp/s10 .
/tmp/s10 reuseport -n 200          # S-7: SO_REUSEPORT resets the connections queued in a closed listener
/tmp/s10 sharedqueue -n 200        # S-7: a listening socket held by two processes loses none
/tmp/s10 sqlite -db /tmp/s6.db -migrate 2s                    # S-6, success
/tmp/s10 sqlite -db /tmp/s6.db -migrate 1s -fail-migration    # S-6, injected migration failure
for h in debian13 ubuntu2204; do
  for sc in E A F B C; do ./run.sh $h $sc; done
done
./run.sh debian13 D                 # counterfactual: no relay
```

Scenarios (`run.sh` has the details): **A** relay mode, one hand-off, 4 QUIC connectors, bulk
streams before, during and after the drain; **B** pause mode, two hand-offs in a row; **C** pause
mode, hand-offs that must fail (binary group-writable, unexpected descriptor, wrong descriptor,
never ready) and then a good one; **D** no relay; **E** baseline, quic-go on the plain socket;
**F** pause mode, one hand-off, three connectors on `auto` and one pinned to QUIC. Every scenario
ends by killing the unit's main process with SIGKILL, to see whether systemd notices a main
process it did not start. The load runs in a second container on a Docker bridge network, at 500
new visitor connections per second.

Summaries of a run: `python3 summary.py results/*-?` prints bulk medians per phase (before, during,
after the drain), visitor failures by kind, UDP losses, the connectors' move times and how old
sessions ended.
