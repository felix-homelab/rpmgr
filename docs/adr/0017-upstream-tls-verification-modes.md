# ADR-0017: A route target's user may mark its HTTPS upstream unverified

Status: Accepted (decided by the product owner, D82, 2026-10-14) · Date: 2026-10-14 · Supersedes
the lint rule of [ADR-0008](0008-internal-ca-mtls-spiffe.md) in part · Exceptions extended by
[ADR-0018](0018-pin-the-key-a-target-presents.md)

## Context

- **Self-signed targets.** Many services that rpmgr publishes from a home or office network serve
  HTTPS with a certificate nothing can verify: hypervisors, NAS systems and network controllers
  make their own, and some make a new one on every upgrade. A target verified as
  [04](../04-security.md#controller-certificates) describes works only with a CA bundle that holds
  that certificate, and only if the certificate names the host the connector dials. A key pin
  does not help, because it is checked on top of the chain.
- **The ban.** [ADR-0008](0008-internal-ca-mtls-spiffe.md) bans `InsecureSkipVerify` in rpmgr code,
  so that no rpmgr client can skip verifying a peer. Its reason concerns rpmgr's own sessions: the
  per-identity DNS SANs mean no rpmgr client ever needs to skip verification. An HTTPS upstream is
  not an rpmgr peer, and its certificate is the user's.
- **Where the risk lies.** The gateway's TLS to an upstream runs inside a tunnel stream, which is
  mutually authenticated between gateway and connector. Only the hop from the connector to the
  target crosses a network rpmgr does not control, provided that a connector cannot make the
  gateway apply one target's TLS settings to a stream it answers for another.

## Decision

**A verification mode per target** (`UpstreamTLSSettings.verification`)
- `VERIFIED`, the default and the only mode before this decision: the chain against the target's
  CA bundle or the gateway host's roots, the name against the server name, and the key against the
  pin if one is set.
- `UNVERIFIED`: nothing is checked. The traffic stays encrypted and the server name is still
  sent; a CA bundle or a pin cannot go with it.

**Guard rails**
- `UNVERIFIED` is never a default; the user chooses it per target. The web UI warns when it is
  chosen and marks such targets "unverified" in the route's targets.
- A gateway applies a target's TLS settings only to a stream that the target's own connector
  answered; a stream for which a connector names a target of another connector is closed. A
  connector therefore cannot turn verified traffic into unverified traffic.
- A gateway that does not know a mode verifies the target, so it fails closed.

**The ban stays, with exactly one exception**
- `InsecureSkipVerify` stays banned by `tools/bannedapi` and golangci's forbidigo. `tools/bannedapi`
  allows it in one function only: `UpstreamTLS.config` in `internal/gateway/upstreamtls.go` of the
  rpmgr module, which builds the TLS configuration of an upstream from its mode. forbidigo skips
  that one file, where `tools/bannedapi` still reports any other use. A test keeps the exception
  list at that one entry, and any other use, in the same file or package or in a module nested
  in the repository, is still reported.
- rpmgr's own sessions never skip verification
  ([03](../03-connections.md#properties-common-to-all-rpmgr-internal-sessions)).

## Consequences

**Positive**

- A self-signed target works without exporting its certificate.
- The exception is visible in one place and reviewed like the `Reveal` allow-list.

**Negative**

- A user can expose a target's traffic to its local network by choice; the warning and the badge
  are the only defence.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Only "trust the current certificate" (pin the key the target presents) | Verification is never skipped, but the pin breaks on every certificate a target regenerates, and some users only want the route to work. D82 decides it as well, as an addition; it is recorded with its implementation |
| A CA bundle with the target's certificate | Exists already; it fails when the certificate does not name the host the connector dials, and it needs the certificate exported by hand |
