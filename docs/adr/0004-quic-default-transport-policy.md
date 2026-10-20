# ADR-0004: QUIC and TCP as first-class transports, with an operator-set default

Status: Accepted (decided by the product owner, D45, 2026-10-07) · Date: 2026-10-06

## Context

The data session between a Connector and a Gateway carries every user connection and every UDP
flow of a route. The transport choice drives latency, throughput and behaviour under packet loss.

QUIC (quic-go) has concrete advantages for rpmgr:

- **No head-of-line blocking between streams.** A single multiplexed TCP connection stalls every
  stream on one lost packet.
- **A 1-RTT handshake**, versus TCP + TLS 1.3 at 2 RTT.
- **DATAGRAM frames (RFC 9221)** for UDP routes, instead of UDP packets wrapped in a reliable
  stream.
- **It survives NAT rebinding.**

There are equally concrete limits, verified in quic-go v0.61.0:

- **Fixed congestion control.** It hard-codes NewReno
  [F quic-go:internal/ackhandler/sent_packet_handler.go:132-138] and caps the congestion window at
  10 000 packets [F quic-go:internal/protocol/params.go:15].
- **No receive offload.** It uses GSO and ECN on Linux but has no receive-side GRO.
- **About one core per session.** Each connection is driven by one goroutine
  [F quic-go:connection.go:563].
- **Default windows are small for high-RTT paths:** 6 MiB per stream and 15 MiB per connection
  [F quic-go:internal/protocol/params.go:31,34].
- **Datagram size is capped.** A datagram must fit in one packet: about 1240 bytes before path-MTU
  discovery, at most about 1412 after [F quic-go:connection.go:3021-3041].

Kernel TCP, by contrast, gets segmentation and receive offload in the kernel and a choice of
congestion control. "QUIC is faster" is therefore a **hypothesis**, not a premise
([03](../03-connections.md#what-quic-does-and-does-not-buy)).

## Decision

- **Both transports are first-class:** QUIC (`rpmgr-tunnel/1` on UDP/443) and TLS 1.3 + reverse
  HTTP/2 (`rpmgr-tunnel-h2/1` on TCP/443, [ADR-0005](0005-reverse-http2-fallback.md)). Neither is
  only an emergency fallback.
- **The transport is a setting** ([D45](../14-open-decisions.md#engineering),
  [03](../03-connections.md#transport-selection)) with the values `auto`, `quic` and `h2`:
  - `auto` races the two with **happy eyeballs**: QUIC first, TCP 300 ms later, the winner cached
    per network for 24 h, QUIC re-probed every 10 min;
  - `quic` and `h2` pin one transport, which then never falls back: routes that need it are
    `not_ready(transport_unavailable)` where it cannot be established.
- **Three levels:** the instance default `default_transport`, shipped as `auto`; a connector's
  `transport`; a route's `transport`. The most specific level that is set applies.
- **Measurements inform, they do not decide.** The better transport depends on the network (loss,
  how UDP is treated, CPU), so no single benchmark fixes one default for everyone. The benchmark
  suite measures both transports against a direct connection before every release
  ([12](../12-testing-and-quality.md#benchmarks)), and the documentation recommends a setting per
  kind of network.
- Tuned values (defined in [03](../03-connections.md#quic-parameters)):
  - stream window 512 KiB → 16 MiB;
  - connection window up to **256 MiB** (≥ 16 × the stream maximum, so a few stalled streams cannot
    pin all connection credit), with growth bounded by `AllowConnectionWindowIncrease` against the
    process-wide budget (default 1 GiB), with **separate budgets per ALPN** (`rpmgr-tunnel/1` vs
    public `h3`), so public HTTP/3 cannot consume the tunnels' share;
  - stall detection only under connection-window pressure: backpressure is normal (a suspended ssh
    client, a paused download, a slow consumer) and is allowed indefinitely, subject only to the
    route idle timeout. When unread bytes held by streams without read progress for ≥ 30 s exceed
    50 % of the connection window, the receiver resets those streams oldest-first until below the
    threshold;
  - neither quic-go nor net/http's HTTP/2 exposes the connection-level send window, so the gateway
    deprioritises a session whose stream writers have been blocked for more than 200 ms when
    choosing where to open new streams [V VB-18];
  - liveness from transport-level PINGs (QUIC keepalive and idle timeout), which are not
    flow-controlled; the application `Ping` only measures RTT;
  - `MaxIncomingStreams` 10 000 on connectors;
  - datagrams enabled;
  - 0-RTT off;
  - `StatelessResetKey` persisted, with the session `Ping` padded to ≥ 64 bytes: quic-go does not
    answer packets of 42 bytes or less with a stateless reset
    [F quic-go:transport.go:633-637] [F quic-go:internal/protocol/protocol.go:124], and a QUIC
    keepalive PING is smaller. A restarted gateway is then detected within one ping interval (15 s)
    instead of after the 30 s idle timeout.
- quic-go sits **behind an internal `Session`/`Stream` interface** (`internal/tunnel`), so it can be
  upgraded or replaced without touching gateway or connector logic
  ([02](../02-architecture.md#source-layout-proposed)).

## Consequences

**Positive**

- Loss on one user connection does not stall the others.
- UDP routes are carried as datagrams, without reliable-stream overhead.
- One handshake fewer when a session is set up.
- Operators choose the transport per installation, connector or route, for the network they
  actually have; measurements inform that choice instead of fixing it once for everyone.

**Negative**

- Two transports to implement, test and support.
- At 100 ms RTT a single QUIC session tops out around **1.16 Gbit/s**, whatever the windows are
  (congestion-window cap; arithmetic in [03](../03-connections.md#what-quic-does-and-does-not-buy)).
  High-bandwidth links need several sessions or TCP.
- **Host tuning is needed.** UDP socket buffers must be at least 7 MiB
  [F quic-go:internal/protocol/params.go:6,9], or quic-go warns and throughput drops.
- Some networks block or throttle UDP/443. Happy eyeballs hides this, but diagnosing it needs good
  metrics.
- A pinned transport can leave routes not ready where it is blocked; only `auto` adapts by itself.
- Connectors may hold sessions of both transports to one gateway when routes pin different ones.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| TCP + TLS + yamux only | Head-of-line blocking across streams; UDP over a reliable stream; yamux v0.1.1 has no usable half-close ([ADR-0005](0005-reverse-http2-fallback.md)) |
| QUIC only | Fails on UDP-blocked networks and behind HTTP proxies; its throughput ceiling is unproven |
| KCP | No standard encryption; FEC overhead; QUIC covers lossy links with standard cryptography |
| A different QUIC library or a kernel QUIC module | Nothing mature in pure Go; cgo would break static builds |
| A default fixed by a benchmark (the S1 rule, [D19](../14-open-decisions.md#engineering)) | One global answer from one testbed, while the better transport depends on the network; it also needed a reference testbed before Phase 1. Replaced by D45 |

## Verification

- **S1** ([S1](../spikes/S1.md)): the benchmark harness for QUIC, TCP + h2 and a direct
  connection, and a local dry run. Under D45 its comparison no longer decides a default; the
  harness becomes the benchmark suite of [12](../12-testing-and-quality.md#benchmarks), which
  records both transports before every release.
- **S3**: dispatching on a shared UDP/443 listener (`h3` + `rpmgr-tunnel/1`). If one listener
  cannot serve both well, tunnels move to a separate UDP port (gateway boot-file key
  `listen.tunnel_udp`, [10](../10-operations.md#configuration)).
  **Result (2026-10-06, [S3](../spikes/S3.md)): passed; the rule is not triggered.** One quic-go
  v0.63.0 listener served both ALPNs on one socket under concurrent load, with per-ALPN TLS
  settings through `GetConfigForClient` and per-ALPN window budgets; tunnels share UDP/443 by
  default, and `listen.tunnel_udp` remains the option for tunnel transport parameters that differ
  from public HTTP/3.

### Phase 1 measurements

**Runner measurements** (2026-10-11 and 12, slice 12.3): the benchmark suite of
[12](../12-testing-and-quality.md#benchmarks), full profile, on GitHub-hosted x86-64 and arm64
runners, not the reference testbed ([D49](../14-open-decisions.md#project-and-process); VB-20 in
[13](../13-roadmap.md#verification-backlog)). Each run puts the client, the gateway, two connectors
and the services in containers on one runner, with `tc netem` on the gateway↔connector link. The
full profile ran in parts, one per RTT, on the harness of #415, #418 and #419: `bench` workflow
runs 38166921665, 38166927250, 38166933320 and 38166939366, and for the workloads that run after
the cells, 38176585179 and 38179217082. Their artifacts hold the records and `bench summarize`
tables for 90 days; the tables below are taken from them.

| Target of [03](../03-connections.md#targets-t) | Result | Met |
|---|---|---|
| Added connection-setup latency p99 ≤ 1 × RTT + 2 ms | +0.95 to +1.77 ms at RTT 1, 20, 80 and 200 ms, both transports, both runners | yes |
| Snapshot apply p99 ≤ 2 s, 1 000 routes | 0.41 to 0.54 s | yes |
| 0 resets on unchanged routes during changes | 0 of 8 held connections lost | yes |
| Single stream ≥ 80 % of direct TCP, 0 % loss | not met: see below | no |
| 32 streams at 1 % loss: QUIC ≥ 1.5 × TCP + h2 | 0.38 to 1.07 × | no |
| CPU per Gbit/s | recorded as the baseline: QUIC 1.2 to 5.8, TCP + h2 0.45 to 2.0 CPU s per Gbit | — |

**Single stream, 0 % loss** (Mbit/s, the median of three runs, the lower of the two directions):

| Runner | RTT | Direct | QUIC | TCP + h2 |
|---|---|---|---|---|
| gh-amd64 | 1 ms | 18 102 | 1 104 | 1 738 |
| gh-amd64 | 20 ms | 88 | 231 | 1 169 |
| gh-amd64 | 80 ms | 369 | 159 | 323 |
| gh-amd64 | 200 ms | 133 | 189 | 128 |
| gh-arm64 | 1 ms | 24 065 | 1 046 | 1 507 |
| gh-arm64 | 20 ms | 1 414 | 287 | 1 134 |
| gh-arm64 | 80 ms | 47 | 140 | 327 |
| gh-arm64 | 200 ms | 8.2 | 139 | 135 |

- **At 1 ms** the direct path is the kernel's path between containers of one host, at 18 to
  24 Gbit/s. The tunnel crosses two user-space relays with TLS and is bound by the runner's four
  CPUs, at 1.0 to 1.7 Gbit/s.
- **From 20 ms on**, TCP + h2 reaches 80 to 145 % of a well-behaved direct baseline. QUIC reaches
  140 to 290 Mbit/s. A qlog showed quic-go's Cubic sender ending slow start with losses and then
  marked application-limited thousands of times, which keeps resetting its growth; neither flow
  control nor rpmgr's relay was the limit (#421).
- **The direct baseline is erratic** on the runners: one TCP connection through the same shaped
  link measured 8 to 1 414 Mbit/s in comparable cells, so a ratio to it says little there.

**32 streams at 1 % loss** (Mbit/s): direct 29 to 424 at RTT 20 to 200 ms against 1.6 to 17 for
either transport. Every stream to a gateway shares one congestion-controlled connection (one QUIC
connection, or the two TCP connections of h2), so loss throttles all of them together, and QUIC's
per-stream loss recovery cannot make up for it (#422).

**Decisions on the misses** ([14](../14-open-decisions.md#engineering)):
- **D69, single stream:** recorded as a runner measurement. The target stays and the reference
  testbed (VB-20) decides it; #421 studies QUIC's single-stream behaviour in Phase 2.
- **D70, 32 streams at 1 % loss:** recorded as a runner measurement. The target stays for VB-20;
  #422 evaluates several data sessions per gateway in Phase 2.
- **D71, the default:** stays `auto`, QUIC first, as D45 decided. QUIC served HTTP better under
  loss: in 22 of the 24 cells with 0.5 to 2 % loss it handled more requests per second (up to
  1.4 ×) at a lower p99 latency (up to a third lower). TCP + h2 carried bulk transfers better from
  20 ms on. Routes and connectors that carry bulk transfers over high-delay paths can pin `h2`
  ([10](../10-operations.md#runtime-settings-ui--settings)).

**Other results:**
- **VB-18:** the signal works on both transports. A connector whose session's writers were
  blocked got 11 to 13 % of new connections on QUIC and 23 % on TCP + h2, from 50 % before.
- **SIGKILL of the gateway:** QUIC routes answered again after 10.2 and 15.2 s: a connector
  notices the restarted gateway by a stateless reset within one session ping interval
  ([03](../03-connections.md#failure-modes)), then reconnects. TCP + h2 routes answered again after
  1.0 and 1.5 s. A SIGKILL of the controller cost no held connection.
- **20 idle connectors** added 7 to 10 MiB to the gateway, at 0.006 to 0.007 CPU s/s.

### Phase 2 study of QUIC's single stream (#421)

**Question:** why one QUIC stream stays at 140 to 290 Mbit/s from 20 ms RTT on, where TCP + h2
reaches 1 Gbit/s on the same path (D69), and whether a change inside rpmgr helps.

**Method** (2026-10-19): the benchmark suite's `throughput` workload on GitHub-hosted x86-64 and
arm64 runners, as in Phase 1, at RTT 1, 20 and 80 ms without loss, three repetitions, medians. Each
variant was one `bench` workflow run on a branch that is never merged, the
`tmp/quic-single-stream-study` branch and a copy of it. A switch read from the environment chose the
variant; the runs were these:

- 39247303350, as on `main`;
- 39247313172, a relay buffer of 256 KiB instead of 32 KiB;
- 39247323174, a relay that reads the next buffer while it writes the last one;
- 39247332539, QUIC receive windows that start at their maxima;
- 39250834685, a changed quic-go congestion controller, described below.

Three more runs, 39254669867, 39256029869 and 39257380013, wrote qlogs at 20 and 80 ms, the last one
without GSO. They summarised the qlogs and the containers' UDP counters into their artifacts. Their
single repetition makes their throughput an indication only.

**Single stream, 0 % loss** (Mbit/s, the median of three runs, the lower of the two directions):

| Runner | RTT | As on `main` | Relay 256 KiB | Read-ahead | Windows at maximum | Changed Cubic sender |
|---|---|---|---|---|---|---|
| gh-amd64 | 1 ms | 856 | 918 | 883 | 948 | 977 |
| gh-amd64 | 20 ms | 290 | 315 | 293 | 237 | 237 |
| gh-amd64 | 80 ms | 224 | 176 | 181 | 138 | 158 |
| gh-arm64 | 1 ms | 1 057 | 1 081 | 1 116 | 1 030 | 1 145 |
| gh-arm64 | 20 ms | 297 | 205 | 274 | 252 | 281 |
| gh-arm64 | 80 ms | 157 | 144 | 174 | 151 | 132 |

TCP + h2 reached 973 to 1 172 Mbit/s at 20 ms and 308 to 331 Mbit/s at 80 ms in the same runs. 32
QUIC streams together reached no more than one: 170 to 300 Mbit/s at 20 ms. The limit is the
connection's congestion window, not a stream.

**Findings:**

- **rpmgr's relay is not the limit.** A larger buffer and a read-ahead change the results by −31 to
  +11 % at 20 and 80 ms, in no consistent direction; on the runners that is noise. At 1 ms both gain
  up to 7 %, within the runners' variance.
- **Flow control is not the limit.** Starting with the maximum windows gained nothing.
- **The sender counts as application-limited because acknowledgements arrive in clumps.** In the
  qlogs the sender fills its congestion window and waits. Then several ACKs are processed one after
  another before it sends again, so from the second ACK on fewer bytes are in flight than the window
  less three packets. quic-go v0.63.0 then calls the sender application-limited and restarts Cubic's
  growth epoch [F quic-go v0.63.0 `internal/congestion/cubic_sender.go:236-239,267-275`]. This
  happened up to about 270 times a second. At 80 ms a window of 2.4 MB grew by 15 to 20 KB a second.
  A changed sender counted as window-limited for one smoothed RTT after it last filled the window.
  The marks disappeared, but throughput did not rise, because of the next finding.
- **Most of the losses on x86-64 were spurious.** Of the packets quic-go declared lost, 86 to 100 %
  were acknowledged later, in each of the four connections; on arm64 4 to 100 %. Almost every loss
  was declared by the packet threshold of three [F quic-go v0.63.0
  `internal/ackhandler/sent_packet_handler.go:23`], so most packets were reordered on the runner's
  veth and netem path, not lost. No UDP receive-buffer error was counted. quic-go notices a spurious
  loss but only records it in the qlog [F quic-go v0.63.0 `sent_packet_handler.go:485-522`]: the
  threshold stays, and the window stays reduced by 30 % per loss event [F quic-go v0.63.0
  `internal/congestion/cubic.go:31`]. Linux TCP detects reordering with RACK (RFC 8985) and undoes a
  spurious recovery [V], which would explain why TCP + h2 is unaffected on the same path.
- **Slow start overshoots.** At 80 ms the first window reached up to 12.2 MB in flight, close to
  quic-go's limit of 10 000 packets [F quic-go v0.63.0 `internal/protocol/params.go:9`], and lost up
  to 909 packets on arm64, most of them real. Cubic then needs several seconds to grow back, longer
  than a cell.
- **Without GSO** fewer losses were spurious: 109 instead of 668 on x86-64 and 62 instead of 206 on
  arm64. One repetition on arm64 reached 385 to 518 Mbit/s at 80 ms, on x86-64 no change. That is
  too little to judge.
- **The ceiling of about 1 Gbit/s at 1 ms is CPU.** QUIC costs 2 to 3 times the CPU per Gbit/s of
  TCP + h2 (Phase 1 baseline above). quic-go v0.63.0 reads up to 8 datagrams per system call,
  without UDP GRO [F quic-go v0.63.0 `sys_conn_helper_linux.go:24`]; the runner's four CPUs carry
  the client, the gateway, the connectors and the services.

**Outcome:**

- No change to rpmgr. None of the variants within rpmgr's design helped consistently. The limits sit
  in quic-go's congestion control and loss recovery, which quic-go exposes no setting for.
- The target of 03 stays for VB-20 ([D69](../14-open-decisions.md#engineering)). The runner's
  reordering may not occur on the reference testbed's network interfaces. [R] VB-20 (slice 16.12)
  also counts the spurious losses and runs QUIC with GSO and without (`-gso off`).
- Whether to report the two quic-go behaviours upstream, the application-limited mark on clumped
  ACKs and the missing reaction to spurious losses, is left to the maintainer.

### Phase 2 study: several data sessions per gateway

**Question** (#422, [D70](../14-open-decisions.md#engineering)): every stream to a gateway shares
one congestion-controlled connection, one QUIC connection or the two TCP connections of h2, so loss
throttles all of them together. Do several data sessions per gateway help on lossy links, and at
what cost?

**Method** (2026-10-19): a prototype on the branch `tmp/multi-session-study` (never merged) lets a
connector keep N sessions per gateway and link, set by an environment variable, and `bench run`
pass it with `-sessions-quic N` or `-sessions-h2 N`. Nothing else changed: the gateway already
admits up to 16 data sessions per connector and spreads a route's streams over them by power of
two choices ([03](../03-connections.md#data-session)). The `bench` workflow ran the standard
profile's throughput and idle workloads at RTT 20 and 80 ms and loss 0 and 1 % on GitHub-hosted
x86-64 and arm64 runners (D49): runs 39247738394 (the product's counts, QUIC 1 and h2 2),
39248365034 (QUIC 4), 39248386939 (h2 4), 39248374783 (QUIC 8; its x86-64 job lost its runner,
so only arm64) and 39247748163 (QUIC 4 and h2 4). The numbers are medians of three runs, as
Mbit/s, with the range over both directions and both runners.

**32 streams at 1 % loss:**

| Sessions per link | QUIC 20 ms | h2 20 ms | QUIC 80 ms | h2 80 ms |
|---|---|---|---|---|
| Product: QUIC 1, h2 2 | 17 to 18 | 16 to 17 | 4.0 to 4.2 | 4.3 to 4.6 |
| QUIC 4 | 64 to 68 | — | 14 to 15 | — |
| QUIC 8 (arm64 only) | 132 to 133 | — | 28 to 31 | — |
| h2 4 | — | 28 to 33 | — | 6.6 to 8.4 |
| Direct, 32 TCP connections | 516 to 611 | | 58 to 110 | |

**32 streams without loss:** QUIC 201 to 335 with one session, 625 to 688 with four and 1 155 to
1 190 with eight at 20 ms (149 to 209, 416 to 548 and 807 to 912 at 80 ms); h2 2 095 to 2 689 with
two sessions and 2 197 to 4 889 with four at 20 ms (690 to 702 and 1 355 to 1 385 at 80 ms).

**Results:**

- **Goodput grows almost linearly with the sessions** on lossy links, as N congestion controllers
  each recover from their own losses: four QUIC sessions carried 3.4 to 4.0 times as much as one,
  eight 6.5 to 7.7 times; four h2 connections 1.4 to 2.1 times as much as two. Each transport's gain
  depends only on its own count: four QUIC sessions left h2 unchanged, and the other way round.
- **With four QUIC sessions the target of 03 is met on the runners:** 32 streams at 1 % loss on
  QUIC reached 3.7 to 4.2 times the product's h2 at 20 ms and 3.1 to 3.6 times at 80 ms, and 1.7
  to 2.3 times h2 with four connections.
  The gap to 32 direct TCP connections stays: eight QUIC sessions reach a quarter of them.
- **A single stream** uses one session and gains nothing. On x86-64, a single QUIC stream at 80 ms
  carried 116 to 129 Mbit/s with four sessions against 193 to 213 with one; arm64 showed no such
  drop. A likely cause, not verified, is that the stream may land on a session whose congestion
  window was never opened by the cell's earlier runs.
- **CPU per Gbit/s** stayed the same or fell (QUIC at 20 ms and 1 % loss on arm64: 8.2 CPU s per
  Gbit with one session, 5.2 to 5.4 with eight).
- **Idle cost:** 10 idle connectors with four QUIC sessions each, instead of one, changed the
  gateway's memory by less than the measurement's noise of about ±10 MiB, and its CPU by less than
  0.001 CPU s/s. Each session adds its own handshake at every connect, also after a gateway
  restart, its keepalives and session pings
  ([03](../03-connections.md#timeouts-keepalive-and-backoff)), a NAT mapping, and a share of the
  16 sessions a gateway admits per connector.
- **Fairness:** N sessions take N shares of a congested bottleneck that other traffic shares, as N
  TCP connections do.
- **The h2 window budget (a Phase 1 defect found by the study):** a gateway admits a reverse-HTTP/2
  session only with a connection window of at least 4 MiB, and each one takes up to half of the free
  process-wide budget of 1 GiB, which QUIC sessions share. With the defaults a gateway therefore
  holds at most nine h2 sessions, that is four connectors on h2, and refuses the others; the idle
  workload logged 139 to 381 refused sessions per run. Several h2 sessions per gateway make it
  worse, so they wait for that fix.

**No protocol change is needed:** the gateway accepts several sessions of a connector and spreads
streams over them already, so a connector of a later release can open more sessions to a gateway
of v0.1.0 within its cap of 16 per connector. The product owner decided on four QUIC sessions
per gateway as a constant ([D123](../14-open-decisions.md#engineering)); h2 stays at two
connections per gateway, so that a gateway's window budget admits the h2 sessions of about forty
connectors ([D124](../14-open-decisions.md#engineering)). The target of 03 stays as D70 recorded it, for
VB-20, which measures the build with four sessions.

### Phase 2 study: HTTP, UDP and many-route performance (local, indicative)

**Question:** the runner records cover TCP bulk, setup and aggregate loss; they do not answer what
the tunnel adds to an HTTP request, what a UDP route's latency is, or whether routes sharing one
tunnel starve each other.

**Method** (2026-10-20): the bench suite on one macOS arm64 host with Docker Desktop, 10 CPUs,
4 MiB UDP buffers, and `tc netem` on the gateway↔connector link. The harness gained a direct
HTTPS/HTTP-2 reference beside the connector, a send-time sample in each UDP echo, and a fairness
workload: four routes through one connector and gateway, 16 streams on the first and one on each of
the other three, with a setup echo at 200 connections/s in parallel. HTTP: 32 workers, 5 s, three
repetitions. UDP: 2 000 datagrams/s for 5 s, one repetition. Fairness: 5 s, one repetition. The
direct HTTP cell runs from the gateway host, which also runs the gateway process, so it is
conservative on CPU. This is a local run, not the reference testbed (VB-20); its numbers are
indicative and decide no target ([D49](../14-open-decisions.md#project-and-process)).

**HTTP/2 through a route, direct vs tunnel** (requests/s and p99; direct is the same handler over
TLS beside the connector):

| RTT / loss | Direct | QUIC | TCP + h2 |
|---|---|---|---|
| 1 ms / 0 % | 26 691 rps, 1.69 ms | 15 840, 4.95 ms | 17 368, 3.52 ms |
| 1 ms / 1 % | 10 005, 8.82 ms | 15 656, 4.02 ms | 11 596, 6.10 ms |
| 20 ms / 0 % | 1 311, 31.7 ms | 1 357, 33.6 ms | 1 349, 34.1 ms |
| 20 ms / 1 % | 673, 93.5 ms | 1 079, 67.6 ms | 728, 91.1 ms |
| 80 ms / 0 % | 347, 345.7 ms | 361, 104.6 ms | 364, 96.3 ms |
| 80 ms / 1 % | 211, 347.6 ms | 250, 257.9 ms | 177, 348.6 ms |

- The tunnel adds 2–5 ms to HTTP p99 at 1 ms RTT; RPS falls to 59–65 % of direct.
- At 1 % loss QUIC is the best HTTP transport: 1.56× direct at 1 ms, 1.60× at 20 ms, 1.18× at 80 ms.
- Without loss at 20 and 80 ms the path RTT dominates; all three are equal within noise. The direct
  p99 at 80 ms without loss (345.7 ms) is one long tail, not a tunnel advantage.

**UDP echo latency** (2 000 datagrams/s, 10 000 sent; p50/p99 and datagrams that missed a 1 s
receive window):

| RTT / loss | QUIC | TCP + h2 |
|---|---|---|
| 1 ms / 0 % | 1.3 / 1.7–2.2 ms, 0 | 1.3 / 1.5–1.6 ms, 0 |
| 20 ms / 0 % | 20.4 / 21.1 ms, 0 | 20.4 / 32–58 ms, 0–1 |
| 80 ms / 0 % | 80.4 / 81–188 ms, 0 | 80.4 / 296–403 ms, 513–717 |
| 20 ms / 1 % | 200–586 / 320–812 ms, 4 947–7 831 | 346–1 836 / 832–3 717 ms, 6 400–8 254 |
| 80 ms / 1 % | 706–2 374 / 1 479–3 057 ms, 8 495–9 366 | 1 116–2 610 / 1 760–4 409 ms, 8 931–9 362 |

- At 0 % loss a QUIC datagram is one-way delay plus a fraction of a millisecond, at every RTT.
- h2 has no datagrams; at 80 ms its reliable framing gives p99 296–403 ms and misses 5–7 % even
  without loss. This is why 03 now prefers QUIC for UDP routes on high-RTT paths.
- At 1 % loss and 20/80 ms the 2 000/s flow collapses on both transports; the 1 s window turns
  queueing into what the record calls loss.
- The 3 000-byte oversize path is visible at 1 ms: QUIC's framed payload loses nothing, while its
  datagrams lose their 1 %.

**Many routes on one tunnel** (four routes, 16 + 1 + 1 + 1 streams, one connector and gateway;
setup echo runs concurrently):

| RTT / loss | Transport | Heavy Mbit/s | Per stream | Lights Mbit/s | Stream Jain | Setup p99 |
|---|---|---|---|---|---|---|
| 1 ms / 0 % | QUIC | 1 072 | 67.0 | 67.2 ×3 | 1.000 | 6.6 ms |
| 1 ms / 0 % | h2 | 9 571 | 598.2 | 536–634 | 0.996 | 9.7 ms |
| 20 ms / 0 % | QUIC | 209 | 13.1 | 13.1 ×3 | 1.000 | 52.6 ms |
| 20 ms / 0 % | h2 | 2 073 | 129.6 | 114–144 | 0.993 | 614.0 ms |
| 20 ms / 1 % | QUIC | 16.4 | 1.0 | 1.0–1.1 | 1.000 | 97.2 ms |
| 20 ms / 1 % | h2 | 15.1 | 0.9 | 0.8–1.1 | 0.988 | 9 988.2 ms |

- Per-stream fairness is already good on both transports (Jain 0.955–1.000); one saturating route
  does not starve the others.
- The aggregate difference is the one-session QUIC ceiling against two h2 connections (9.57 against
  1.07 Gbit/s at 1 ms), the subject of D70 and D123, not a per-route scheduler failure.
- Setup is where isolation fails on h2: its setup stream shares the two TCP connections with the
  bulk uploads, so p99 reaches 614 ms and then the 10 s open timeout; QUIC stays at 6.6–97.2 ms.
- The record's route-level Jain (~0.34) is arithmetic from 16 against 1 stream; use per-stream
  goodput for isolation.

**Outcome:**

- No decision and no target change. [R] Prefer QUIC for UDP routes on high-RTT paths; h2's reliable
  framing is the wrong path for datagrams there ([03](../03-connections.md#known-limitations)).
- The harness changes are in `bench/` (direct HTTP, UDP RTT, fairness) and
  [12](../12-testing-and-quality.md#benchmarks) lists them.
- [V] Confirm on GitHub-hosted runners and VB-20; move the direct HTTP client onto the shaped link
  before using it for a target; add Go allocation microbenchmarks for the per-message paths.
- The local numbers are not committed as baselines; `bench/baselines/` stays empty until a runner
  or reference-testbed run is recorded.
