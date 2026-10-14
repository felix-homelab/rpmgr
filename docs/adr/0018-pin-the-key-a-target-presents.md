# ADR-0018: A route target's user may pin the key it presents, read through its connector

Status: Accepted (decided by the product owner, D82, 2026-10-14) · Date: 2026-10-14 · Supersedes
the single exception of [ADR-0017](0017-upstream-tls-verification-modes.md) in part

## Context

- **Between verified and unverified.** [ADR-0017](0017-upstream-tls-verification-modes.md) lets a
  user mark a self-signed HTTPS target unverified. A user who wants such a target protected from
  a later interception still has to export its certificate and upload it as a CA bundle, which
  also fails when the certificate does not name the host the connector dials. A key pin is checked
  on top of the chain, so it does not help on its own.
- **Reading the key.** The certificate a target presents can only be read where the target can be
  reached: by its connector, under the connector's local policy. A self-signed certificate fails
  every chain check, so reading it takes a TLS handshake that checks nothing.

## Decision

**A third verification mode** (`UpstreamTLSSettings.verification`)
- `PINNED_KEY`: only the pinned key is checked, by the SHA-256 of its SubjectPublicKeyInfo, not
  the chain or the name. A pin must be set and a CA bundle cannot go with it; a new key fails until
  it is pinned. As for `UNVERIFIED`, the gateway applies the settings only to streams of the
  target's own connector.

**Trust the certificate it shows now**
- `RouteService.ProbeTargetCertificate` (`routes.write`) asks a connector of the org for the
  certificate a target presents. The controller sends `ProbeTarget` to a connector that announced
  the capability `probe.target` ([03](../03-connections.md#service-sketch)); the connector dials
  the target under its local policy, as a stream would, completes a TLS handshake that checks
  nothing, sends nothing else, closes, and returns the leaf.
- The user sees the certificate's names, issuer, expiry and key fingerprint and confirms before
  the key is pinned; nothing is pinned without that confirmation.

**A second exception to the ban**
- Besides `UpstreamTLS.config` ([ADR-0017](0017-upstream-tls-verification-modes.md)), which now
  also builds the pinned-key configuration, `tools/bannedapi` allows `InsecureSkipVerify` in one
  more function of the rpmgr module: `readCertificate` in `internal/connector/probe.go`, which
  only reads the leaf. A test keeps the list at these two entries.

## Consequences

**Positive**

- A self-signed target is protected against a later interception without exporting its
  certificate.

**Negative**

- A target that makes a new key on every upgrade fails until its user trusts the new
  certificate.
- A probe reaches only the controller replica that holds the connector's control session; another
  one answers that the connector has no session there.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Pin on top of the chain, as `VERIFIED` does | A self-signed certificate never passes the chain check |
| Read the certificate at the gateway | The gateway reaches a target only through its connector anyway, and the connector's local policy must decide whether the target may be dialled |
