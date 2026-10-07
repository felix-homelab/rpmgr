# ADR-0016: ConnectRPC for the public API, grpc-go for the agent protocol

Status: Accepted (spike S4, 2026-10-06) · Date: 2026-10-06 · Supersedes
[ADR-0010](0010-connectrpc.md)

## Context

rpmgr has three kinds of API client ([ADR-0010](0010-connectrpc.md)): the browser SPA, the CLI and
other automation, and agents with one long-lived bidirectional stream each over mutual TLS. ADR-0010
proposed ConnectRPC for all three, with grpc-go for the agent protocol as the fallback named by a
rule agreed before spike S4 ([D20](../14-open-decisions.md#engineering)).

S4 ran connect-go v1.21.0 on `net/http` with Go 1.27.1 ([S4](../spikes/S4.md)):

- **Passed:** full-duplex streams with half-close, HTTP/2 PING liveness through
  `HTTP2Config.SendPingTimeout` and `PingTimeout`, 10 000 idle sessions (about 71 KiB per session on
  the controller), a TLS-passthrough route in front of the controller.
- **Cancellation failed.** A cancelled context ends neither a `Receive` the agent waits in nor the
  controller's call. Go's HTTP/2 client stops watching the request context while a streaming request
  body is open [F Go 1.27.1 `net/http/internal/http2/transport.go:1672`], and connect-go relies on
  the transport [F connect v1.21.0 `duplex_http_call.go:297-310`].
- **Deadlines failed** the same way, also on the controller: a handler waiting in `Receive` does not
  end at its deadline.
- **Message-size limits failed** on open streams: when the client's read limit refuses a message,
  `Receive` waits for the response to end so it can read the trailers
  [F connect v1.21.0 `protocol_grpc.go:319-321`].

grpc-go v1.84.0 handles the same cases: a cancel or an expired deadline ends both sides within
about 1 ms, and a read-limit error returns at once and resets the stream.

## Decision

**Public API (unchanged from ADR-0010)**
- ConnectRPC (connect-go on the controller, connect-es in the SPA) with protobuf schemas managed by
  buf, protovalidate rules, and `option (rpmgr.v1.authz)` on every method, enforced by one
  fail-closed interceptor ([04](../04-security.md#one-enforcement-point-with-defence-in-depth)).
- All public handlers mount on the controller's `net/http` server: browsers use the Connect
  protocol, the CLI and automation either protocol.

**Agent protocol**
- **grpc-go carries `rpmgr.agent.v1`** at both ends: agents use a grpc-go client, the controller
  grpc-go's own HTTP/2 server (`grpc.NewServer`). The protobuf contract is the same; buf generates
  the grpc-go code next to the connect-go code.
- Not `grpc.Server.ServeHTTP`: it is experimental and lacks parts of grpc-go's server, among them
  keepalive enforcement [F grpc v1.84.0 `server.go:1132-1140`].
- **Liveness** ([03](../03-connections.md#timeouts-keepalive-and-backoff)): the agent pings after
  20 s without activity and closes after 10 s without an answer, also without an active RPC; the
  controller does the same and sets `EnforcementPolicy{MinTime: 10 s, PermitWithoutStream: true}`,
  because grpc-go's default `MinTime` of 5 minutes would close agents for pinging every 20 s
  [F grpc v1.84.0 `internal/transport/defaults.go:40`]. grpc-go raises a client interval below 10 s
  to 10 s [F grpc v1.84.0 `dialoptions.go:576-578`].
- **Message limit** 4 MiB in both directions, set on both ends
  ([03](../03-connections.md#framing)). The control session uses **no compression**, so the limit
  counts message bytes on both sides: both stacks check the sender's limit against the compressed
  size. Large items travel by content hash with `FetchResource` anyway.
- **Port 443 stays shared.** The controller's TCP/443 listener reads the ClientHello like the
  gateway ([03](../03-connections.md#port-443-multiplexing)) and hands `controller.<td>` and
  `reauth.controller.<td>` to the grpc-go server, every other name to `net/http`. TLS for both agent
  names terminates in the grpc-go server, with the constructors of
  [04](../04-security.md#pki-and-identity) (`GetConfigForClient` per name). In all-in-one mode the
  gateway's SNI router makes the same split.
- **Authorization:** a grpc-go interceptor (unary and stream) authorizes every agent method by the
  peer's SPIFFE ID and refuses methods it does not know. `Enroll` is reachable without a client
  certificate ([04](../04-security.md#threat-model)); every other agent method requires one.
- An agent's reader goroutine treats any stream error as a lost session and reconnects with the
  backoff of [03](../03-connections.md#timeouts-keepalive-and-backoff).

## Consequences

**Positive**

- Cancellation, deadlines and message limits work on agent streams without workarounds, which the
  agent's shutdown, imperative operations and certificate renewal depend on.
- grpc-go's keepalive enforcement protects the controller from agents that ping too often.
- One protobuf contract still drives the agents, the API, the SPA and the documentation; standard
  gRPC tooling works against the agent service.

**Negative**

- Two RPC stacks in the controller and two sets of generated Go code; the agent side has its own
  interceptor and error mapping.
- The controller needs a ClientHello-peeking listener on TCP/443 in front of two servers instead of
  one `net/http` server.
- grpc-go is a larger dependency than connect-go (for example `golang.org/x/net` and genproto).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| ConnectRPC everywhere, closing the stream on cancel (`context.AfterFunc` → `CloseResponse`) | Works in S4 (both sides end within about 1 ms), but deadlines and read limits need the same care at every call site, and the rule asked whether ConnectRPC carries the session as it is |
| grpc-go clients against the connect-go handler | Cancellation and deadlines work in S4, but a handler waiting in `Receive` still does not end at its own deadline, and the rule names grpc-go for the agent protocol, not only for the agents |
| `grpc.Server.ServeHTTP` on the controller's `net/http` server | Keeps one listener, but experimental and without grpc-go's keepalive enforcement [F grpc v1.84.0 `server.go:1132-1140`] |
| grpc-go + grpc-gateway for the public API too | Rejected in ADR-0010: REST mapping and a gRPC-Web proxy for browsers |

## Verification

[S4](../spikes/S4.md) (tag `spike/s4`): every criterion on connect-go, and the failing ones again on
grpc-go, with the native server, `ServeHTTP` and the connect-go handler. Not yet run: the
controller's SNI split, `Enroll` without a client certificate on the grpc-go server, and grpc-go
keepalive at the real 20 s / 10 s values (only scaled values ran); Phase 1 tests them
([12](../12-testing-and-quality.md#end-to-end-topology-matrix)).
