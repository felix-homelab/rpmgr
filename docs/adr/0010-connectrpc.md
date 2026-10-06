# ADR-0010: ConnectRPC and protobuf for the public API and the agent control service

Status: Proposed (design phase) · Date: 2026-10-06

## Context

rpmgr has three kinds of API client:

- **the browser SPA**, which needs JSON-friendly HTTP/1.1 or HTTP/2 calls and server streaming for
  logs and events;
- **the CLI and third-party automation**, which needs a stable, documented API with tokens;
- **agents**, which need a long-lived bidirectional stream with mutual TLS.

Serving each client type with its own stack (a REST framework for the browser, separate gRPC
servers for agents, extra WebSocket and event-stream endpoints for shells and logs) multiplies the
code that must authenticate, authorize and validate every request.

The rest of the Controller is a plain `net/http` server: SPA, OIDC callbacks, ACME challenges,
`/install.sh`, `/dl/` and `/.well-known/rpmgr/trust-bundle`.

One schema should drive the API, the agent protocol, validation and the TypeScript types. That is
design principle P7 together with goal 4 ([00](../00-vision-and-scope.md#goals)).

## Decision

**ConnectRPC**
- Use **ConnectRPC** (connect-go on the server, connect-es in the SPA) with **protobuf** schemas
  managed by **buf**: lint, and breaking-change detection against the last release.
- All handlers mount on the Controller's one `net/http` server on 443:
  - **browsers** use the **Connect protocol** (JSON or binary, HTTP/1.1 or HTTP/2, server
    streaming);
  - **agents** use the **gRPC protocol** over HTTP/2 with mutual TLS (SNI
    `controller.<td>`) ([03](../03-connections.md#control-session));
  - **the CLI and automation** may use either protocol.

**Schemas and validation**
- Packages: `rpmgr.v1` (public, resource-oriented) and `rpmgr.agent.v1` (agent protocol). Generated Go
  and TypeScript types are the only definitions of these messages.
- **protovalidate** annotations define validation once. The server is authoritative; the SPA
  reuses the rules for form feedback ([08](../08-software-stack.md)).
- Authorization is declared per method in the proto with `option (rpmgr.v1.authz)` and enforced by
  one fail-closed interceptor ([04](../04-security.md#one-enforcement-point-with-defence-in-depth)).

**gRPC keepalive fallback**
- If the ConnectRPC path fails spike S4, the agent service falls back to **grpc-go** on the same
  protobufs.
- In that case the server must set `EnforcementPolicy{MinTime: 10 s, PermitWithoutStream: true}`,
  because grpc-go's default `MinTime` of 5 minutes would disconnect rpmgr's 20 s liveness pings
  [F grpc:keepalive/keepalive.go:36-59].

## Consequences

**Positive**

- One schema drives server, agents, SPA, CLI and the documentation.
- One HTTP server, one TLS listener and one middleware chain: authentication, CSRF and logging
  are applied in exactly one place.
- Browsers need neither a gRPC-Web proxy nor a REST translation layer.
- Standard gRPC tooling still works against the agent service.

**Negative**

- ConnectRPC is less widely deployed than grpc-go. Its bidirectional streaming over `net/http`
  HTTP/2 with mutual TLS must be verified (S4).
- Bidirectional streaming in browsers is not available over HTTP/1.1, so the terminal still needs a
  WebSocket (Phase 3, guarded by single-use tickets,
  [04](../04-security.md#human-authentication-and-sessions)).
- Third parties used to REST get RPC-style URLs (`POST /rpmgr.v1.RouteService/UpdateRoute`) rather
  than resource paths. This is mitigated by the CLI and by generated client libraries.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| grpc-go + grpc-gateway (REST) + grpc-web proxy | Three stacks; REST mapping annotations to maintain; separate server from `net/http` |
| Plain REST/JSON with OpenAPI | No streaming semantics for agents; hand-written client types drift from the server's schema |
| GraphQL | Poor fit for streaming agent protocols; authorization per field is harder to make fail-closed |
| gin | Extra framework surface for no gain over Go's pattern-routing `net/http` |

## Verification

**S4** must confirm, for ConnectRPC over mutual TLS:
- bidirectional streaming;
- cancellation propagation;
- message-size limits (4 MiB control, [03](../03-connections.md#framing));
- HTTP/2 PING liveness with `ReadIdleTimeout` 20 s / `PingTimeout` 10 s;
- 10 000 concurrent idle sessions, with the memory per session recorded;
- behaviour behind a TLS-passthrough route.

**Rule** ([D20](../14-open-decisions.md#engineering)): if any check fails, grpc-go carries the
agent protocol, with the keepalive enforcement policy from
[03](../03-connections.md#control-session); browsers and the CLI stay on ConnectRPC. The protobuf
contract does not change.
