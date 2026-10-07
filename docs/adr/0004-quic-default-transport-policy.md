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
