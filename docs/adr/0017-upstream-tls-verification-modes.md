# ADR-0017: A route target's user chooses how its HTTPS upstream is verified

Status: Accepted (decided by the product owner, D82, 2026-10-14) · Date: 2026-10-14 · Supersedes
the lint rule of [ADR-0008](0008-internal-ca-mtls-spiffe.md) in part

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
  target crosses a network rpmgr does not control. Skipping verification lets anyone on that
  network read and change the traffic; it does not weaken any rpmgr session.

## Decision

**Three modes per target** (`UpstreamTLSSettings.verification`)
- `VERIFIED`, the default and the only mode before this decision: the chain against the target's
  CA bundle or the gateway host's roots, the name against the server name, and the key against the
  pin if one is set.
- `PINNED_KEY`: only the pinned key is checked, not the chain or the name. The user pins the key
  the target presents now, which the connector reads for them.
- `UNVERIFIED`: nothing is checked. The traffic stays encrypted and the server name is still
  sent; a CA bundle or a pin cannot go with it.

**Guard rails**
- No mode but `VERIFIED` is ever a default; the user chooses it per target. The web UI warns when
  `UNVERIFIED` is chosen and marks such targets "unverified" in the route's targets.
- A gateway that does not know a mode verifies the target, so it fails closed.

**The ban stays, with one exception**
- `InsecureSkipVerify` stays banned by `tools/bannedapi` and golangci's forbidigo. Both allow it in
  one function, `UpstreamTLS.config` in `internal/gateway/upstreamtls.go`, which builds the TLS
  configuration of an upstream from its mode. An exception names its file, its function and its
  decision, and a test keeps it from widening.
- rpmgr's own sessions never skip verification
  ([03](../03-connections.md#properties-common-to-all-rpmgr-internal-sessions)).

## Consequences

**Positive**

- A self-signed target works without exporting its certificate, and a user who wants it protected
  pins its key in one step.
- The exception is visible in one place and reviewed like the `Reveal` allow-list.

**Negative**

- A user can expose a target's traffic to its local network by choice; the warning and the badge
  are the only defence.
- A pinned key breaks when the target makes a new key, until the user trusts the new one.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Only "trust the current certificate" | Verification is never skipped, but the pin breaks on every certificate a target regenerates, and some users only want the route to work |
| Only "HTTPS, unverified" | No protection against a later interception for a user who wants it |
| A CA bundle with the target's certificate | Exists already; it fails when the certificate does not name the host the connector dials, and it needs the certificate exported by hand |
