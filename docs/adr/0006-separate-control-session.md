# ADR-0006: A separate control session from each agent to the Controller

Status: Accepted (decided by the product owner on 2026-10-06) · Date: 2026-10-06

## Context

Connectors need two kinds of connection:

- **configuration and status**, exchanged with the Controller;
- **user traffic**, exchanged with Gateways.

The control traffic could either travel on its own connection to the Controller, or ride inside
the data session to a Gateway, which would then forward it.

Arguments for riding inside the data session:

- one connection per connector;
- a fully private Controller "for free".

Arguments against:

- **Authority.** Gateways are internet-facing edge components with the largest attack surface. If
  control messages pass through a gateway's protocol logic, a compromised gateway can withhold,
  delay or replay configuration. If the gateway terminates the control channel, it can also forge
  configuration.
- **Independence.** Gateways restart for upgrades and scaling. Control must survive that, and
  controller high availability must not depend on gateways being available.

## Decision

- Every agent (Gateway or Connector) keeps **its own control session to the Controller**:
  - HTTP/2 over TLS 1.3 with mutual TLS;
  - SNI `controller.<trust-domain>`;
  - gRPC protocol ([ADR-0016](0016-connectrpc-public-api-grpc-go-agents.md),
    [03](../03-connections.md#control-session)).
- **A private Controller** is reached through a **TLS-passthrough route** on a gateway:
  - the gateway forwards encrypted bytes and never terminates the control TLS;
  - the agent still verifies the controller against the pinned root
    ([03](../03-connections.md#reaching-a-private-controller)).
- Agents receive an ordered list of controller endpoints (direct, and via gateways) in every
  snapshot and try them in order.
- Last resort for networks with UDP only: a `CONTROL_PASSTHROUGH` stream kind on the data session,
  which the gateway splices at layer 4. The TLS stays end to end
  ([03](../03-connections.md#framing)). On QUIC the connector opens this stream itself; on the
  reverse-HTTP/2 transport it asks for it with `OpenRequest` on the session control stream and the
  gateway opens it ([ADR-0005](0005-reverse-http2-fallback.md)).
- In `all-in-one`, the same session runs in-process against the embedded controller.

## Consequences

**Positive**

- Gateways can never forge configuration. At most they can drop the bytes of a passthrough route,
  which agents detect as a failed connection.
- Gateway restarts do not interrupt configuration or status reporting.
- Controller HA, load balancing and maintenance are independent of the data plane.
- The Controller can still be fully private.

**Negative**

- One more long-lived connection per agent. At the scale rpmgr targets this costs file descriptors,
  not throughput.
- Without the passthrough route, agents need a network path to the Controller. The installer's
  connectivity check reports this clearly.
- Through a passthrough route, a gateway outage also cuts the control path for agents that have
  no direct path. Agents keep running their last-known-good snapshot
  ([03](../03-connections.md#failure-modes)).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Control multiplexed inside the data session, terminated at the gateway | The gateway becomes a configuration authority; a compromised gateway can forge or withhold configuration |
| Gateway as a message relay with end-to-end signatures | Re-invents TLS at the application layer; replay and ordering problems; more custom cryptography |
| Controller dials agents | Violates "agents only dial out"; fails behind NAT |
| Agents poll over plain HTTPS | Latency and load: every change waits for the next poll, and idle agents keep loading the controller |
