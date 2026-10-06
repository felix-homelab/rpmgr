# ADR-0008: Internal CA, mutual TLS everywhere, SPIFFE identities

Status: Accepted (spike S7, 2026-10-06) · Date: 2026-10-06

## Context

Common ways to authenticate tunnel components fall short of rpmgr's security goals
([04](../04-security.md#security-goals)):

- **Shared tokens** let any holder impersonate any client, and token-derived login messages can be
  replayed.
- **Skipped certificate verification**, or a CA fetched trust-on-first-use, lets a network attacker
  impersonate the server.
- **Long-lived bearer secrets** per agent leak through configuration files and logs, prove nothing
  about the key holder, and are hard to revoke.

rpmgr needs per-component identities that can be issued, renewed, revoked and authorized, with no
dependency on a public CA for internal traffic.

## Decision

**Trust domain and identities**
- Each installation generates a **trust domain** (`rpmgr-<random>`) with its own **internal CA**.
- Identities are **SPIFFE IDs** in the single URI SAN of each certificate
  ([04](../04-security.md#trust-domain-and-identities)):
  - `spiffe://<td>/org/<org>/connector/<id>`
  - `spiffe://<td>/org/<org>/gateway/<id>`
  - `spiffe://<td>/controller/<node>`
- Every leaf certificate also has a **DNS SAN derived from its identity**:
  `<connector-id>.connector.<td>`, `<gateway-id>.gateway.<td>`, and for controller nodes
  `<node-id>.controller.<td>` plus the shared `controller.<td>` and `reauth.controller.<td>`. This is
  needed because Go's `crypto/tls` refuses a client handshake without `ServerName` unless
  `InsecureSkipVerify` is set [F Go 1.27.1 `crypto/tls/handshake_client.go:47`], and with a
  `ServerName` it matches DNS/IP SANs only.
- Controller node certificates carry **clientAuth as well as serverAuth**, for controller-to-controller
  mutual TLS in HA; a `controller_nodes` table records `node_id`, `internal_address` and `last_seen`.
- **Trust-domain discovery**: the root certificate carries the trust domain as its URI SAN
  (`spiffe://<td>`). After selecting the root by pin, the agent reads `<td>` from it, so the trust
  domain is authenticated by the pin.

**CA hierarchy** ([04](../04-security.md#ca-hierarchy))
- Root: ECDSA P-256, 10 years, KEK-encrypted online by default, optionally offline.
- One issuing intermediate: 1 year, rotated at 6 months, name-constrained to the trust domain
  (`PermittedURIDomains` and `PermittedDNSDomains` = [`<td>`], critical). Go enforces both; the URI
  constraint also admits sub-domains of `<td>`, so `VerifyConnection` requires the trust domain
  exactly ([S7](../spikes/S7.md)).

**Leaf certificates**
- Key: ECDSA P-256, **generated on the agent**, never leaving it.
- Lifetime: **7 days**, renewed at **50 %** with a **new key**.
- `NotBefore` is backdated 5 min.
- An expired agent may re-authenticate within a **30-day grace period counted from the
  certificate's `NotAfter`** ([04](../04-security.md#leaf-certificates)). `Reauth` is an RPC over
  mutual TLS with the expired certificate, reached via its own SNI `reauth.controller.<td>` so the
  handshake selects the expired-certificate-tolerant verifier. Acceptance: the certificate chains to
  a trusted CA, the identity exists and is not revoked, the serial is **neither revoked nor
  superseded**, and it expired at most the grace period ago. A serial is marked **superseded** once
  a newer serial for the same identity has been seen in an authenticated session (control session or
  `Renew`); supersession marks are also written to the revocation log. This still survives a lost
  `Renew` response (the newer serial was never used) and restores (marks are re-applied from the
  log), but an old leaked key or a cloned VM image can no longer obtain a fresh identity. A CSR with
  a new key yields a new certificate. The Reauth configuration verifies the chain itself in
  `VerifyConnection` and disables session tickets, because a configuration returned by
  `GetConfigForClient` shares its parent's ticket keys ([S7](../spikes/S7.md)).

**Mutual TLS everywhere**
- Every internal connection uses mutual TLS 1.3 against the **pinned root**, never the system trust
  store.
- Clients always set `ServerName` to the expected peer's DNS name **and** `VerifyConnection` checks
  the SPIFFE URI. Connectors dial each gateway with `ServerName` `<gateway-id>.gateway.<td>` (IDs
  come from the snapshot), so the key of a gateway in another group or org cannot impersonate it;
  the gateway SNI router matches the `.gateway.<td>` suffix.
- Authorization reads the URI SAN in `VerifyConnection`. The certificate CN is never used.
- Every check runs in `VerifyConnection`, which Go also calls on resumed sessions, never in
  `VerifyPeerCertificate`, which resumption skips; TLS session resumption therefore stays on
  ([03](../03-connections.md#properties-common-to-all-rpmgr-internal-sessions)).

**Enrollment** ([04](../04-security.md#enrollment))
- The enrollment token is **1 h, single use**, and only its hash is stored.
- The join command carries `--ca-pin sha256:<root SPKI>`, so there is no trust-on-first-use:
  - the agent fetches `/.well-known/rpmgr/trust-bundle` over any channel, keeps **only** the root whose
    SPKI SHA-256 equals the pin, and discards every other root;
  - the agent reads the trust domain `<td>` from the pinned root's URI SAN;
  - `Enroll` runs over TLS with RootCAs = {pinned root} and `ServerName` `controller.<td>`;
  - the authenticated `Enroll` response returns the trust bundle; additional roots are accepted only
    if cross-signed by an already-trusted root (this is also how root rotation works).
- The CSR of `Enroll`, `Renew` and `Reauth` carries the connection's `tls-exporter` value
  (RFC 9266); a CSR without it, or bound to another connection, is refused
  ([04](../04-security.md#flow)).
- Root rotation drops the old root only after the longest leaf lifetime **plus** the Reauth grace
  period (7 + 30 days), so agents that were offline in between can still re-authenticate.

**Revocation**
- The database is authoritative.
- The deny-list travels as a **separate control message**, `DenyListUpdate`, carrying the full
  current set (~100 B per entry; ~7 000 entries ≈ 0.7 MB with 1 000 ephemeral connectors per day
  [T]; [R] deltas keyed by `(db_epoch, n)` above 1 MiB, with a periodic full set). Entries are removed
  after the covered certificate's `NotAfter`: agents never accept expired certificates, and `Reauth`
  checks the database, not the deny-list. It is applied unconditionally, independent of snapshot
  acceptance, checked in `VerifyConnection`, and kills live sessions when it changes.
- Agents merge updates by **union** and drop an entry only after its own expiry — never because of a
  version number or a new `db_epoch` (for example after a restore).
- Agents **persist** the deny-list next to the last-known-good snapshot (signed) and load it before
  accepting any session; the **control-session** `Hello` (gateways and connectors both have one)
  carries a deny-list digest, and on mismatch the controller resends. `SessionHello` on data
  sessions does not carry it.
- `enroll --replace` revokes the replaced certificates **by serial**, because the connector ID and
  SPIFFE ID are reused.
- Short lifetimes bound the exposure.
- No OCSP ([04](../04-security.md#revocation)).

**Lint rule**
- `InsecureSkipVerify` is banned in rpmgr code by lint
  ([12](../12-testing-and-quality.md#security-testing)). The per-identity DNS SANs make the ban
  workable: no rpmgr client needs to skip verification to reach a peer that has no public name.

## Consequences

**Positive**

- No shared secret exists whose leak compromises the fleet. Each key is bound to one agent and
  rotates weekly.
- Revocation takes effect immediately for connected relying parties. When a deny-list cannot be
  pushed, exposure is bounded by 7 days.
- Identities carry org and role, so authorization stays simple and uniform.
- P-256 keeps hardware-backed keys (TPM, PKCS#11, KMS) possible later.

**Negative**

- rpmgr operates a CA: rotation, backup and KEK handling become operator duties. Runbooks are in
  [10](../10-operations.md#runbooks).
- Agents whose certificate expired more than 30 days ago must re-enroll.
- Clock skew of more than 5 minutes breaks handshakes. Agents report skew explicitly
  ([03](../03-connections.md#failure-modes)).
- A root compromise cannot be repaired in-band; every agent must re-enroll.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Shared token or per-agent bearer secret | Replayable or leakable; no proof of possession; revocation means rotating everyone |
| Public WebPKI certificates for agents | Agents have no public names; rate limits; public CT logs would expose the fleet |
| WireGuard-style static keys without certificates | No expiry, no hierarchy, no SAN-based authorization; rotation is manual |
| Ed25519 X.509 | Supported in Go TLS 1.3, but poorly supported by TPM/PKCS#11/KMS ([04](../04-security.md#ca-hierarchy)) |
| OCSP | Online dependency with no benefit, because every relying party already receives the deny-list |

## Verification

**S7** must confirm:
- renewal and revocation on resumed TLS sessions (`VerifyConnection` runs on resumption);
- that Go enforces URI and DNS name constraints on the intermediate;
- the `Reauth` endpoint's verifier, selected by the SNI `reauth.controller.<td>`: accepts
  certificates expired by at most the grace period, and nothing else; a superseded serial is refused;
- binding a CSR to the TLS session via exported keying material.

**Rules**, agreed before S7 runs ([13](../13-roadmap.md#phase-0--spikes)):
- If Go does not enforce the name constraints, rpmgr relies on its `VerifyConnection` checks
  alone and keeps the constraints as defence in depth for other verifiers.
- If `VerifyConnection` does not run on resumed sessions, TLS session resumption is disabled for
  all rpmgr-internal sessions.
- If CSR binding works, it is mandatory for `Enroll`, `Renew` and `Reauth`; otherwise it is not
  used.

**Result** ([S7](../spikes/S7.md), 2026-10-06, Go 1.27.1): every check passed. Go enforces both name
constraints, so they stay; `VerifyConnection` runs on resumed sessions and refuses an identity
revoked after the first handshake, so resumption stays allowed; CSR binding works, so it is
mandatory for `Enroll`, `Renew` and `Reauth`. The ADR moved to *Accepted*.
