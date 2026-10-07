# ADR-0005: Reverse HTTP/2 as the TCP transport, not yamux

Status: Accepted (spike S2 and the product owner's decision, 2026-10-06) · Date: 2026-10-06

## Context

When QUIC is blocked or slower ([ADR-0004](0004-quic-default-transport-policy.md)), rpmgr needs a
TCP-based data session that still multiplexes many user connections. It must:

- preserve **half-close** (one side sends FIN, the other keeps sending);
- support **abort** (reset);
- provide **per-stream flow control** and **liveness pings**;
- pass through HTTP CONNECT/SOCKS5 proxies and, wrapped in WSS, TLS-intercepting proxies.

The obvious candidate is yamux. Evidence from hashicorp/yamux v0.1.1:

- There is **no `CloseWrite`**.
- After a local `Close()`, the stream's `Read` returns `io.EOF` whenever the receive buffer is
  momentarily empty, even though the peer may still be sending [F yamux:stream.go:95-110]. So there
  is **no usable half-close**.
- Its default stream window is 256 KiB.

HTTP/2 already has the required semantics:

- streams;
- `END_STREAM` for half-close;
- `RST_STREAM` for abort;
- `WINDOW_UPDATE` flow control;
- `PING`.

Go has a mature implementation in net/http itself since Go 1.27, including PING health checks
(`SendPingTimeout`, `PingTimeout`) [F Go 1.27.1 `net/http/http.go:302,307`];
`golang.org/x/net/http2` is now a deprecated wrapper around it
[F x/net v0.59.0 `http2/transport_wrap.go:5`]. Its server cannot end a response while it still
reads the request: when a handler finishes early, it resets the request stream
[F Go 1.27.1 `net/http/internal/http2/server.go:1207-1224`] ([S2](../spikes/S2.md)).

## Decision

- The TCP transport is **TLS 1.3 + reverse HTTP/2**, ALPN `rpmgr-tunnel-h2/1`, on TCP/443:
  - The **Connector dials** the Gateway, which keeps agents outbound-only.
  - The connector sets ServerName `<gateway-id>.gateway.<td>` (IDs come from its snapshot) and checks
    the gateway's SPIFFE URI ([ADR-0008](0008-internal-ca-mtls-spiffe.md)).
  - After the mutual-TLS handshake, the **Connector acts as the HTTP/2 server** on that connection
    and the **Gateway acts as the HTTP/2 client**, both with net/http's HTTP/2 speaking HTTP/2
    with prior knowledge on the authenticated connection (ALPN `rpmgr-tunnel-h2/1` is checked
    first).
  - For each user connection the gateway sends **one request**. The `StreamOpen` preamble and the
    client→service bytes go in the request body; `StreamResult` and the service→client bytes come
    back in the response body ([03](../03-connections.md#framing)).
- **All streams are opened by the gateway.** An HTTP/2 server cannot open request streams, so on
  this transport (and inside WSS) the connector never opens one:
  - The **session control stream** is the first request the gateway opens right after the
    connection is up (on QUIC it is the first bidirectional stream the connector opens).
  - **Connector-initiated streams** (`RELAY_OUT`, `CONTROL_PASSTHROUGH`) are requested with
    `OpenRequest{open_id, kind, …}` on the session control stream. The gateway answers either with
    `OpenRejected{open_id, code}` on the session control stream, or by opening a request stream
    whose `StreamOpen` carries the `open_id` **and the result**; the connector writes no
    `StreamResult` on such a stream. `open_id` is unique per session; an unanswered `OpenRequest`
    times out after 10 s.
  - Cost: **+1 RTT** before the connector can send on such a stream, on the TCP transport only.
    `OpenRequest` carries the first chunk when the connector has one (≤ 16 KiB, normally the inner
    TLS ClientHello), and the gateway forwards it at once: S2 measured the first answer after
    1 RTT with it and 2 RTT without ([S2](../spikes/S2.md)).
  - `StreamOpen` is written by the side that opens the stream; on h2 that is always the gateway.
  - The h2 session control stream is an ordinary request stream; it is not called "stream 0" (in
    HTTP/2, stream 0 is the connection-level stream).
  - Session setup on this transport: TCP + TLS 1.3 = 2 RTT, plus ½–1 RTT for the gateway-opened
    control stream.
- **Half-close.** Gateway → connector: the request's `END_STREAM`. Connector → gateway: an
  **in-band FIN**, because net/http's server cannot end the response while it still reads the
  request: after `StreamResult` the connector's bytes are chunks of `varint(length) ‖ bytes`, a
  zero-length chunk is its FIN, and the response's `END_STREAM` follows only when both directions
  have ended ([03](../03-connections.md#framing)). Abort maps to `RST_STREAM` in both directions.
- **Parameters** (the net/http defaults are too small for a first-class transport):

  | Setting | net/http default | rpmgr value |
  |---|---|---|
  | Connector h2 server `MaxConcurrentStreams` | 250 [F Go 1.27.1 `net/http/internal/http2/server.go:61`] | 10 000 |
  | Connector h2 server receive window per stream | 1 MiB [F Go 1.27.1 `net/http/internal/http2/config.go:60`] | 16 MiB |
  | Connector h2 server receive window per connection | 1 MiB [F Go 1.27.1 `net/http/internal/http2/config.go:55`] | 256 MiB |
  | Gateway h2 client receive window per stream | 4 MiB [F Go 1.27.1 `net/http/internal/http2/transport.go:50`] | 16 MiB |
  | Gateway h2 client receive window per connection | 1 GiB [F Go 1.27.1 `net/http/internal/http2/transport.go:45`] | 256 MiB |
  | Both: largest frame accepted (`MaxReadFrameSize`, advertised as `SETTINGS_MAX_FRAME_SIZE`) | 1 MiB [F Go 1.27.1 `net/http/internal/http2/http2.go:82`] | 16 KiB |

  Both sides set these through `http.HTTP2Config`; the gateway's client is an `http.Transport`
  whose `DialContext` returns the accepted connection, created with `NewClientConn`
  [F Go 1.27.1 `net/http/clientconn.go:113`]. With the 1 MiB server defaults, client→service
  traffic is capped near 84 Mbit/s per connection at 100 ms RTT (S2 measured 80 Mbit/s; with the
  rpmgr windows 1.25 Gbit/s). The frame size is lowered because net/http's client holds a
  request-body buffer of min(the peer's frame size, 512 KiB) per open stream
  [F Go 1.27.1 `net/http/internal/http2/transport.go:1607-1620`]; with 16 KiB frames S2 measured
  62 KiB per stream for both ends together. The connection window is ≥ 16 × the stream maximum,
  so a few stalled streams cannot pin all connection credit. HTTP/2 has no window-budget hook like
  quic-go's, so h2 sessions are **admitted against the same process-wide budget** (the sum of their
  maximum connection windows); when the budget is tight, new h2 sessions get smaller windows.
  **Stall detection** applies only under connection-window pressure: backpressure is normal and is
  allowed indefinitely, subject only to the route idle timeout; when unread bytes held by streams
  without read progress for ≥ 30 s exceed 50 % of the connection window, the receiver resets those
  streams oldest-first until below the threshold. net/http does not expose a stream's unread bytes,
  so a stalled stream counts with its full receive window; a reset on the gateway also closes the
  response body, because only that returns the connection window
  [F Go 1.27.1 `net/http/internal/http2/transport.go:2402-2421`]. The gateway reserves a slot with
  the non-blocking `ClientConn.Reserve` before opening a stream (`RoundTrip` alone would wait)
  [F Go 1.27.1 `net/http/clientconn.go:254,301`]; at the limit it uses another session or returns
  503 / resets — it never blocks. net/http's `ClientConn` reports only stream counts, not the
  connection send window, so the gateway deprioritises a session whose stream writers have been
  blocked for more than 200 ms when choosing where to open new streams [V S1]
- Liveness comes from transport-level HTTP/2 PING frames (`SendPingTimeout` 15 s, `PingTimeout`
  10 s, on both ends; S2 detected a blackholed connection after 25 s) plus TCP keepalive 15 s,
  which are not flow-controlled; the application `Ping` on the session control stream only
  measures RTT and never takes a session out of service on its own
  ([03](../03-connections.md#timeouts-keepalive-and-backoff)).
- [R] A connector keeps **2 TCP connections per gateway** and spreads streams across them, which
  limits loss-induced head-of-line blocking to half the streams.
- UDP flows over this transport are length-prefixed frames on the flow's stream; there are no
  datagrams ([03](../03-connections.md#udp-routes)).
- Behind TLS-intercepting proxies (Phase 2), the same mutual-TLS + h2 connection runs inside a WSS
  connection. WSS is served on **each gateway's own** WSS hostname (ACME certificate, part of the
  gateway's `tunnel_endpoints`) at `/.rpmgr/tunnel` via HTTP Upgrade, so the connector knows which
  gateway it reached; inside it the connector runs TLS 1.3 mutual TLS to
  `<gateway-id>.gateway.<td>` and then reverse HTTP/2. The outer TLS goes to the proxy; the inner
  TLS stays end to end.
- The pre-agreed fallback, a patched yamux, is not needed: S2 met every criterion with the in-band
  connector FIN ([S2](../spikes/S2.md)).

## Consequences

**Positive**

- Correct half-close and abort semantics, built on a standard, well-tested protocol.
- The same framing works direct, through HTTP CONNECT/SOCKS5 proxies, and inside WSS.
- Flow control and health checks come from the library, not from rpmgr code.

**Negative**

- The direction is unusual (the server dials out, the client accepts), and reviewers must be told.
- HTTP/2 framing adds some per-frame overhead compared with yamux (an inference, to be measured in
  S1), and the connector-to-gateway direction adds 1–3 bytes per chunk of up to 16 KiB for its
  in-band FIN.
- The in-band FIN makes the two directions of a stream differ on this transport; QUIC streams need
  no such framing.
- TCP still has head-of-line blocking within each TCP connection. This is inherent; QUIC remains
  the default policy for that reason.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| hashicorp/yamux v0.1.1 | No usable half-close [F yamux:stream.go:95-110]; small default window |
| xtaci/smux | Not reviewed here; same category as yamux, with no standard semantics to lean on |
| Forward HTTP/2 (gateway as server) | Would require the gateway to dial connectors, violating "agents only dial out" ([00](../00-vision-and-scope.md#design-principles)) |
| One TCP connection per user connection | A TCP and TLS handshake per user connection, which adds round trips to every connection setup |

## Verification

**S2**: full-duplex request/response bodies over reverse HTTP/2 (concurrent reads and
writes, half-close in both directions, `RST_STREAM` propagation, behaviour at the stream limit),
the tuned parameters above, stall detection, and connector-initiated streams via `OpenRequest`
(+1 RTT; how much a first chunk carried in `OpenRequest` hides).
Throughput and CPU are compared in **S1**.

**Rule:** if S2 fails any of its pass criteria ([13](../13-roadmap.md#phase-0--spikes)), the TCP
transport uses yamux with a patch that adds half-close, kept as a separate module, instead of
reverse HTTP/2; this ADR is then superseded.

**Result (S2, 2026-10-06, [S2](../spikes/S2.md)):** every criterion passes except one: as decided
above, the connector's half-close cannot be the response's `END_STREAM`, because Go's HTTP/2
server — net/http's in Go 1.27, and x/net's own — resets the request stream when a handler ends
its response while the request is still open, so the client-to-service bytes after the service's
FIN are lost. With the connector's FIN carried in-band, every criterion passes. The rule did not
foresee that variant; the product owner chose reverse HTTP/2 with the in-band connector FIN over
the rule's yamux fallback ([14](../14-open-decisions.md)), and the decision above includes it.
