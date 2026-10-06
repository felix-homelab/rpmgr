# ADR-0003: rpmgr defines its own versioned protocol

Status: Accepted (decided by the product owner on 2026-10-06) · Date: 2026-10-06

## Context

rpmgr's security and reliability goals ([00](../00-vision-and-scope.md#goals)) put requirements on
the wire protocol itself, not only on the code around it:

- **Identity, not shared secrets.** Every agent must authenticate with its own key and certificate;
  no shared token, no self-asserted identity, no credential that can be replayed.
- **Verified peers.** Every connection must verify the peer against a pinned root; there is no mode
  that skips verification.
- **Standard cryptography.** All traffic runs inside TLS 1.3; no custom encryption or key
  derivation.
- **End-to-end private services.** A gateway relaying a private service must see ciphertext only.
- **Typed, reconciled configuration.** Routes are assigned to connector identities, and
  configuration is desired state that agents apply atomically and acknowledge
  ([ADR-0007](0007-desired-state-reconciliation.md)).
- **Performance properties.** No extra round trip per user connection, UDP carried as datagrams,
  and real half-close ([03](../03-connections.md#performance-budget)).

These properties have to be designed together with the control plane. A protocol shaped by
compatibility with another tool would constrain every one of them.

The product owner confirmed the direction: **an own protocol plus an importer** for existing
configurations.

## Decision

- rpmgr defines its own protocols ([03](../03-connections.md#overview)):
  - an enrollment endpoint;
  - a control session (gRPC protocol over HTTP/2 + TLS 1.3 mTLS);
  - a data session (QUIC `rpmgr-tunnel/1`, or TLS + reverse HTTP/2 `rpmgr-tunnel-h2/1`);
  - end-to-end (`rpmgr-e2e/1`) and P2P (`rpmgr-p2p/1`) sessions between connectors.
- **Wire compatibility with other tunnel tools is a non-goal.** There is no compatibility ingress,
  not even an optional legacy port.
- Existing configurations are converted into rpmgr resources by the importer, with a dry-run diff
  ([11](../11-migration.md)).
- Every protocol is versioned by **ALPN major version** plus capability strings, so rpmgr can evolve
  its protocol on its own terms ([03](../03-connections.md#versioning-and-capabilities)).

## Consequences

**Positive**

- Per-agent identities, mutual TLS everywhere, no shared tunnel secret, no replayable credentials.
- One protocol designed together with the control plane: routes are assigned to connector
  identities, and configuration is reconciled rather than pushed blindly.
- Concrete protocol properties:
  - zero extra round trips per user connection;
  - QUIC datagrams for UDP;
  - real half-close;
  - end-to-end encryption for private services.

**Negative**

- No incremental rollout from another tool. Its agents cannot join an rpmgr installation, so a
  migration replaces every agent (per site, with the importer and the cutover plan in
  [11](../11-migration.md)).
- Ecosystem tools built for other tunnel tools (dashboards, plugins) do not work with rpmgr.
- The protocol is new and has not been battle-tested. This is mitigated by:
  - standard building blocks (TLS 1.3, QUIC, HTTP/2, protobuf) instead of custom cryptography;
  - fuzzing of all framing ([12](../12-testing-and-quality.md#security-testing)).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Wire compatibility with an existing tunnel tool | Inherits that tool's authentication and framing; rpmgr's security goals cannot be met |
| Own protocol plus an optional legacy ingress | A second, weaker authentication path to secure, test and document forever; the importer covers migration |
| Embedding an existing tunnel engine as a library | Configuration becomes an opaque blob owned by another project, with a second authentication system next to rpmgr's |
