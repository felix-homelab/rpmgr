# 04 — Security

> Status: Phase 1, being implemented. Tags: [F] fact · [R] recommendation · [T] target · [V] verify
> at implementation ([README](../README.md#how-to-read-these-documents)).
>
> **This document is the single source of truth for identities, lifetimes, cryptographic parameters
> and authorization rules.** Connection timeouts and sizes live in
> [03-connections.md](03-connections.md).

## Security goals

1. **No shared secrets between components.** Every agent and every controller node has its own
   private key, generated where it is used and never copied.
2. **Every connection is mutually authenticated** with TLS 1.3 against a pinned root, and every
   request is authorized against the caller's identity.
3. **Least privilege everywhere**: per-org isolation, roles, scoped and expiring tokens, routes
   bound to specific connectors.
4. **Bounded blast radius.** A compromised gateway cannot read private-service traffic or serve
   routes it was not assigned. A compromised controller cannot make a connector exceed its host's
   local policy.
5. **Secure defaults, no foot-guns.** No default passwords, no default secrets, no option to skip
   certificate verification, risky features off until enabled on the host itself.
6. **Accountability.** Every change is attributable and recorded in a tamper-evident audit log.

## Threat model

Actors and what the design lets them do. "Can" lists residual capability; "cannot" lists what the
design prevents and the control that prevents it.

| Actor | Can | Cannot (control) |
|---|---|---|
| **Internet attacker** | Reach gateway listeners, the controller's login and enrollment endpoints; attempt denial of service | Call agent APIs (mutual TLS required everywhere except `Enroll`). Guess tokens (256-bit random, hashed lookup, per-IP and per-account rate limits, uniform errors). Reach metrics or pprof (admin listener bound to localhost). Claim a hostname (domain verification). |
| **Network attacker (MITM)** | See metadata: SNI, IPs, timing, volume | Impersonate the controller or a gateway (pinned root, no trust-on-first-use, `InsecureSkipVerify` banned in code). Replay anything (TLS 1.3, no 0-RTT, no timestamp tokens). Read tunnel contents. |
| **Malicious user of another org** | Act within their own org and role | See or change another org's resources (one authorization interceptor, org-scoped store, composite foreign keys). Escalate (token scopes ⊆ creator's permissions; roles only grantable by higher roles). Open a shell or log stream on someone else's connector (resource-bound authorization and single-use tickets). Take another org's domain (verified, globally unique claims). |
| **Malicious user in the same org (low role)** | Read what Viewer/Operator may read | Mint enrollment tokens, change gateways, domains, members or settings beyond their role (permission matrix). |
| **Compromised connector** | Serve, blackhole or tamper with **its own** routes' traffic; report false health or metrics; use its own visitor grants | Serve other routes (gateways serve a route only for connectors listed for it in the signed route table). Read other agents' configuration (snapshots are compiled per identity). Reach private services it has no grant for. Survive revocation (deny-list pushed to all relying parties, sessions killed, renewal refused). Exhaust a gateway (per-identity stream and bandwidth quotas). |
| **Compromised gateway** | See plaintext of the HTTP routes it terminates; drop or delay traffic; use the TLS keys of hostnames it serves | Read private-service traffic (end-to-end TLS between connectors). Obtain routes or keys of other gateway groups (snapshots are per gateway). Make a connector dial an arbitrary address (`StreamOpen` names a route, the connector dials only its own snapshot's targets). Impersonate a connector or another gateway (role and ID are part of the identity, and clients check the expected peer's DNS name and SPIFFE ID). Open shells (the shell path is controller → connector only). |
| **Compromised controller (process, or database plus KEK)** | Everything in the control plane: re-route public hostnames, issue certificates (and so MITM traffic that is not end-to-end), deny service, push any configuration. With connected DNS providers (Phase 2): rewrite **any** record in the connected zones, including MX, SPF/DKIM and third-party verification records, and use the provider tokens from elsewhere unless they are IP-restricted | Make a connector exceed its **local policy** (dial outside `allow_targets`, enable shell, functions, virtual-network routes, P2P, listeners). Install an unsigned or older binary (OTA verified against keys compiled into the binary, with a persisted anti-rollback floor). Read agent or WireGuard private keys (never stored centrally). |
| **Database dump without the KEK** | Read topology, configuration, emails, audit log | Use any credential: passwords are argon2id; session, API and enrollment tokens are SHA-256 hashes of 256-bit random values; CA, ACME, TOTP, OIDC and other secrets are AES-256-GCM-encrypted under a KEK held outside the database. |
| **Holder of a stolen DNS-provider token** (Phase 2) | Change any record the token covers, from anywhere the token is accepted | Use it from another network, if the token is restricted to the controller's egress addresses; use it after its expiry; use it beyond the zones it is scoped to ([15](15-dns.md#connecting-importing-and-disconnecting)). rpmgr never shows the token after it is saved (write-only) |
| **Malicious insider with Admin role** | Any configuration action within the org | Use the shell on hosts that did not opt in. Read secrets back (write-only fields). Act unnoticed (hash-chained audit log with external checkpoints). Grant Owner (Owner-only). Skip step-up re-authentication for dangerous actions. |
| **Supply-chain attacker** | Compromise a dependency or a CI run | Ship an update agents will install (release-signing keys offline, separate from CI). Redirect downloads usefully (the signature is trusted, not the URL). Go unnoticed (go.sum, govulncheck, SBOM, SLSA provenance, reproducible-build check, actions pinned by SHA). |

What the design does **not** protect against, stated plainly:

- A compromised gateway sees plaintext of HTTP routes it terminates. Use `tls_passthrough` routes
  when the gateway must not see plaintext.
- A compromised controller can re-route a public hostname to an attacker's backend and obtain
  certificates for it. Local policy protects the connector hosts, not public users. With a
  connected DNS provider it can also take over every name in the connected zones, mail included.
  [R] Keep the zones rpmgr manages separate from the zone that carries mail and corporate records,
  and scope provider tokens to those zones ([15](15-dns.md)).
- Cloudflare sees the plaintext of routes whose hostnames are proxied through it. Proxying is an
  explicit per-route opt-in ([15](15-dns.md#proxied-http-routes)).
- A compromised connector host is out of scope beyond the connector's own identity and routes.
- Denial of service against public gateways is mitigated (limits, quotas) but not solved.

## PKI and identity

### Trust domain and identities

- Each installation generates a **trust domain** at init: `rpmgr-<8 random base32 chars>`. It never
  changes; a separate display name can.
- Identities are **SPIFFE IDs** in the certificate's single URI SAN:

| Principal | SPIFFE ID |
|---|---|
| Connector | `spiffe://<td>/org/<org-id>/connector/<connector-id>` |
| Gateway | `spiffe://<td>/org/<org-id>/gateway/<gateway-id>` (shared gateways belong to the system org) |
| Controller node | `spiffe://<td>/controller/<node-id>` |

- Every certificate also carries a **DNS SAN derived from its identity**, because Go's TLS client
  verifies a server by DNS name and refuses to handshake without a `ServerName` unless verification
  is disabled [F Go 1.27.1 `crypto/tls/handshake_client.go:47`]:

| Principal | DNS SAN |
|---|---|
| Connector | `<connector-id>.connector.<td>` (used when it is the TLS server in `rpmgr-e2e`/`rpmgr-p2p`) |
| Gateway | `<gateway-id>.gateway.<td>` |
| Controller node | `<node-id>.controller.<td>` and the shared `controller.<td>` and `reauth.controller.<td>` |

- IDs keep their form in DNS SANs (`gw_01JA…`): `_` and upper-case letters are valid there
  [F Go 1.27.1 `crypto/x509/parser.go:1411-1415`], and names match `ServerName` case-insensitively.
- Clients always set `ServerName` to the **expected** peer's DNS name (a connector knows each
  gateway's ID from its snapshot), and `VerifyConnection` additionally checks the SPIFFE URI:
  exactly one URI SAN, scheme `spiffe`, a host **equal** to `<td>` (the name constraint below also
  admits sub-domains of `<td>`), and the expected role and ID. A gateway of another group or org
  therefore cannot impersonate this connector's gateway, even with a valid certificate
  ([S7](spikes/S7.md)). `InsecureSkipVerify` is never used.
- Every rpmgr check runs in `VerifyConnection`, which Go calls on full and resumed handshakes alike;
  never in `VerifyPeerCertificate`, which resumed connections skip
  ([03](03-connections.md#properties-common-to-all-rpmgr-internal-sessions)).
- Authorization always parses the URI path; the certificate CN is never used.

### CA hierarchy

| Key | Algorithm | Lifetime | Storage | Use |
|---|---|---|---|---|
| **Root CA** | ECDSA P-256 | 10 years | Controller DB, envelope-encrypted under the KEK (default); or offline (`rpmgr ca offline-root`, Phase 2, [D58](14-open-decisions.md#project-and-process)) | Signs intermediates only (`pathlen=1`) |
| **Issuing intermediate** | ECDSA P-256 | 1 year, rotated at 6 months with overlap | Controller DB, envelope-encrypted | Signs leaf certificates (`pathlen=0`), name-constrained (critical) to URI domain and DNS domain `<td>`; Go enforces both [F Go 1.27.1 `crypto/x509/constraints.go:525`] ([S7](spikes/S7.md)) |
| **Config-signing key** | ECDSA P-256 | rotated yearly | Controller DB, envelope-encrypted | Signs snapshots (agents verify last-known-good on disk) |
| **Audit-checkpoint key** | ECDSA P-256 | rotated yearly | Controller DB, envelope-encrypted | Signs audit checkpoints |

- **Signing keys.** The config-signing and audit-checkpoint keys get certificates from the issuing
  intermediate, not the root, so a root that goes offline does not block their yearly rotation. The
  certificate's only SAN is `spiffe://<td>/controller/config-signing` or
  `spiffe://<td>/controller/audit-checkpoint`, with key usage digitalSignature and no extended key
  usage. Agents accept a snapshot or deny-list signature only from a key whose certificate chains
  to the pinned root with that URI. The URI is not an identity, so the certificate never
  authenticates a TLS peer.
- **Signatures.** A signature is ECDSA with SHA-256 over the signed bytes, ASN.1-encoded. It names
  its key by `key_id`, the lower-case hexadecimal SHA-256 of the key certificate's
  SubjectPublicKeyInfo, so an agent that holds the current and the next key picks the right one.
- **No certificate outlives its issuer**: `NotAfter` is capped at the issuer's. Serial numbers are
  128 random bits.

[R] One issuing intermediate per trust domain: per-node intermediates add no isolation, because HA
replicas share the database and the KEK. **ECDSA P-256** rather than Ed25519 for X.509, because it
is what TPM 2.0, PKCS#11 tokens and cloud KMS all support, which keeps hardware-backed keys possible
later.

### Leaf certificates

| Holder | Lifetime | Renewal | Notes |
|---|---|---|---|
| Connector, gateway | **7 days** | at **50 %** of lifetime (jitter: anywhere in 45–55 %), over the control session, **new key every time** | `NotBefore` backdated **5 min**; EKU clientAuth **and** serverAuth. One certificate per agent serves every session: a gateway is the TLS client of its control session and the TLS server of data sessions (`<gateway-id>.gateway.<td>`); a connector is the TLS client of its control and data sessions and the TLS server in `rpmgr-e2e` and `rpmgr-p2p` sessions ([D42](14-open-decisions.md#engineering)) |
| Controller node certificate (`controller.<td>`, `reauth.controller.<td>`, `<node-id>.controller.<td>`) | 30 days | automatic | EKU serverAuth **and clientAuth** (replicas call each other over mutual TLS in HA, [10](10-operations.md#high-availability)). The node's key exists only in memory: every start and every renewal gets a new key and certificate |

- **After a renewal** the agent stores the new key and certificate and then reconnects its control
  session with them, so the controller sees the new serial at once and supersedes the old one. A
  certificate it cannot store is not used; the old one stays renewable.
- **Expired certificate.** An agent offline longer than 7 days calls `Reauth` over **mutual TLS
  with its expired certificate**, at SNI `reauth.controller.<td>`, which selects a verifier that
  accepts client certificates that expired at most the **30-day grace period** ago (counted from
  `NotAfter`). The certificate must chain to a trusted CA; neither its serial nor its identity may
  be revoked; and the serial must not be **superseded** — a serial is marked superseded once a newer
  serial for the same identity has been seen in an authenticated session (control session or
  `Renew`), and the mark is also written to the revocation log. An old leaked key or a cloned VM
  image therefore cannot obtain a fresh identity, while a lost `Renew` response (the newer serial
  was never used) and a restore (marks are re-applied from the log) still work. The controller then
  issues a new certificate for a CSR with a new key, bound to the connection ([Flow](#flow)). No
  signed application messages are involved, so nothing can be replayed. [R] 0 disables the grace
  period, and so does a grace period the controller cannot read from its settings. After it, the
  agent must re-enroll. `Renew` applies the same database checks; both refuse a certificate that
  `issued_certificates` does not record.
- **The Reauth verifier** ([S7](spikes/S7.md)). `GetConfigForClient` selects it for SNI
  `reauth.controller.<td>`. It requests any client certificate and verifies the chain itself, in
  `VerifyConnection`, at a time inside the certificate's validity; crypto/tls still checks the
  client's CertificateVerify, its proof of possession of the key. It **disables session tickets**:
  a configuration returned by `GetConfigForClient` shares the ticket keys of its parent, so a ticket
  from `controller.<td>` would otherwise resume there, and a Reauth session never yields a ticket.
  The normal endpoint never accepts an expired certificate.
- **Clock skew.** The 5-minute backdating absorbs ordinary skew. Agents compare their clock with
  `Welcome.server_time` and warn above 30 s ([03](03-connections.md#failure-modes)).
- **Settings.** The agent leaf lifetime and the grace period are instance settings in
  **Settings → PKI** (Instance Admin): lifetime 1–30 days (default 7), grace 0–90 days (default 30,
  0 disables). Renewal stays at 50 % of the lifetime ([14](14-open-decisions.md) D8).
- **TLS session tickets.** Session-ticket keys for rpmgr-internal sessions rotate **daily**
  ([03](03-connections.md#properties-common-to-all-rpmgr-internal-sessions)). rpmgr sets no ticket
  key: crypto/tls rotates its automatic keys every 24 h and drops them after 7 days
  [F Go 1.27.1 `crypto/tls/common.go:964-970`]. A ticket never outlives its certificates: on
  resumption the server re-checks the client certificate's expiry and stored chain
  [F Go 1.27.1 `crypto/tls/handshake_server_tls13.go:362-381`], and the client the server's
  [F Go 1.27.1 `crypto/tls/handshake_client.go:405-429`].

### Revocation

- The **database is authoritative**: `issued_certificates` records serial, identity, expiry and
  revocation.
- A **deny-list** (revoked serials and identities) is sent to every gateway, connector and
  controller node as a **separate control message**, `DenyListUpdate`, not inside the snapshot. It
  carries the full current set, which stays small because an entry lives only until the covered
  certificate's `NotAfter` — agents never accept expired certificates, and `Reauth` checks the
  database, not the deny-list. At ~100 bytes per entry, 1 000 ephemeral connectors per day with
  7-day certificates give ~7 000 entries ≈ 0.7 MB [T]; [R] above 1 MiB the controller sends deltas
  keyed by `(db_epoch, n)` with a periodic full set. Agents apply it unconditionally — an agent that
  rejects a snapshot still receives revocations — and merge it by **union**: an entry is dropped
  only after its own expiry, never because of a version number or a new `db_epoch` after a restore.
- Agents **persist** the deny-list next to the last-known-good snapshot (signed) and load it before
  accepting any session, so a gateway restarted while the controller is down still refuses revoked
  connectors. The control-session `Hello` carries a digest of the agent's list (gateways and
  connectors both have a control session); on a mismatch the controller resends it. The list is checked in `VerifyConnection`; a change closes affected live
  sessions immediately ([03](03-connections.md#service-sketch)).
- Short lifetimes bound the damage when a deny-list cannot be pushed (controller down).
- **Revoking** a certificate (by serial) or an identity (every certificate of it, also one issued
  later; no new certificate is issued and none renewed) is committed with an audit record. The
  controller then ends the control sessions of the agents it covers with `Goodbye{revoked}`, sends
  the new list to every other session, and refuses the certificates at its TLS layer. Each replica
  reloads the list at every revision check ([03](03-connections.md#timeouts-keepalive-and-backoff)),
  so a revocation committed by another replica or an admin command is enforced too. Phase 1 always
  sends the full set.
- Every revocation is also appended to the **revocation log** outside the database, so a restore
  from an older backup cannot resurrect revoked credentials ([Audit log](#audit-log)).
- [R] **No OCSP and no CRL**: every relying party already receives the deny-list; OCSP would
  add an online dependency for no benefit, and no consumer needs a CRL
  ([14](14-open-decisions.md) D31).

### Controller certificates

- **UI and public API**: an ACME certificate (certmagic) or one the operator supplies.
- **Agent endpoint**: the internal certificate for `controller.<td>`, selected by SNI via
  `GetConfigForClient` on the same 443 listener, which also sets the client-certificate requirement
  per name ([S3](spikes/S3.md)). For `controller.<td>` a client certificate is optional at the TLS
  layer, because `Enroll` comes from agents that have none yet; a certificate that is presented must
  chain to the pinned root and pass the identity checks, and every method except `Enroll` requires
  one ([03](03-connections.md#transport)). The UI hostnames ask for none. Agents trust **only** the
  pinned root for this name, never the system trust store.
- If the controller sits behind a reverse proxy or CDN, the agent hostnames (`controller.<td>` and
  `reauth.controller.<td>`) must be passed through at layer 4 (TLS passthrough), or served on a
  separate port.
- **Route certificates** ([D17](14-open-decisions.md#tenancy-and-data)): the controller runs ACME
  for route hostnames. For HTTP-01 and TLS-ALPN-01 it pushes each challenge to **every gateway
  that serves the name** with the control-session message `AcmeChallenge` and lets the CA validate
  only after all of them acknowledged ([03](03-connections.md#service-sketch), D41); gateways
  answer from what was pushed and never read the database. Issued certificates go to the same
  gateways. certmagic supports this through the storage hook of its distributed solving
  ([S6](spikes/S6.md)); the run against Let's Encrypt staging is pending [V VB-19].

### CA rotation

- **Intermediate**: automatic, with overlap; agents receive the new chain at their next renewal.
- **Root** (planned, Phase 2, [D58](14-open-decisions.md#project-and-process)): 1) generate root
  R2 and cross-sign it with R1; 2) push the trust bundle
  {R1, R2} in snapshots; 3) wait until every agent acknowledges (the UI lists stragglers);
  4) issue from an intermediate under R2; 5) drop R1 only after the longest leaf lifetime **plus the
  Reauth grace period** (7 + 30 days) has passed, so agents that were offline can still reauthenticate.
- **Root compromise** cannot be repaired in-band: every agent must re-enroll with a new pin. The
  runbook is in [10-operations.md](10-operations.md#runbooks).

## Enrollment

### Tokens

| Property | Value |
|---|---|
| Format | `rpmgr_enr_<base62(32 random bytes)>_<6-char CRC32 checksum>`, GitHub-style: typos and secret scanners detect it offline. The same scheme is used for `rpmgr_pat_` (personal API tokens), `rpmgr_sat_` (service-account tokens) and `rpmgr_ses_` (session tokens). |
| Storage | SHA-256 of the token, unique index; the plaintext is shown once |
| Lifetime | **1 hour** default, maximum 30 days |
| Uses | **1** by default; N or unlimited only for ephemeral connectors, always with a lifetime |
| Scope | org, role (connector or gateway), gateway group, labels, ephemeral flag; for re-enrollment (`rpmgr enroll --replace`) the token is bound to **one connector ID** when it is minted (with step-up), so the host cannot choose which identity it replaces. Because the connector ID and SPIFFE ID are reused, the replacement revokes the old certificates **by serial**, not the identity |
| Bookkeeping | creator, use count, last use (time, IP), revoked time; listable and revocable in the UI |

Consumption is one atomic statement, so a token cannot be used twice concurrently. `$now` is
supplied by the application, which keeps the statement portable to SQLite:

```sql
UPDATE enrollment_tokens
   SET use_count = use_count + 1, last_used_at = $now, last_used_ip = $ip
 WHERE token_hash = $hash AND revoked_at IS NULL AND expires_at > $now
   AND (max_uses IS NULL OR use_count < max_uses)
RETURNING id, org_id, role, gateway_group_id, connector_id, ephemeral;
```

The statement runs in the **same transaction** as the CSR check and the certificate issuance, so a
malformed CSR does not burn the token. If the response is lost, a retry with the same token and the
same CSR public key within 10 minutes returns the same certificate.

### Join command

```sh
curl -fsSL https://panel.example.com/install.sh | sudo sh -s -- \
  --controller https://panel.example.com --ca-pin sha256:3q2+7w...   # prompts for the token
```

- **Token delivery.** With `curl … | sh`, the script's standard input *is* the script, and `sudo`
  resets the environment. The install script therefore takes the token from, in order:
  1. `--token-file <path>` (unattended installs; the file should be 0600 and deleted afterwards);
  2. `RPMGR_ENROLL_TOKEN`, if explicitly passed through (`sudo --preserve-env=RPMGR_ENROLL_TOKEN …`);
  3. otherwise an interactive prompt on the terminal (`/dev/tty`) with echo off.
- The token is **never** written to argv, a unit file, a config file or a log, and it is discarded
  after enrollment. Because it is single-use, a token that leaks after it was consumed (e.g. from a
  terminal scrollback) is worthless; a token that leaks before use expires within its lifetime and
  can be revoked in the UI.
- `--ca-pin` is the SHA-256 of the root's SubjectPublicKeyInfo. It is not a secret and may appear in
  argv. From the downloaded trust bundle the agent keeps **only the root that matches the pin** and
  discards every other root, then enrolls over TLS that trusts only that root. Further roots are
  accepted later only from the authenticated `Enroll` response or a snapshot, and only if
  cross-signed by an already-trusted root. Appending a root to the bundle in transit therefore gains
  an attacker nothing, and there is no trust-on-first-use.
- The install script and binary come from the controller's own mirror and are signature-checked
  ([Supply chain and updates](#supply-chain-and-updates)).

### Flow

Shown in [03-connections.md](03-connections.md#enrollment). Security-relevant rules:

- The agent generates a **P-256 key locally** (file mode 0600, owned by the service user). The
  private key never leaves the host.
- The CSR is proof of possession (`CheckSignature`). The controller **ignores** the CSR's subject
  and SANs and assigns the ID and SPIFFE URI itself.
- The controller records every issued certificate (serial, identity, public-key fingerprint,
  validity) in `issued_certificates`; revocation and `Reauth` decisions use these records.
- The root certificate carries the trust domain as its URI SAN (`spiffe://<td>`). After selecting
  the root by pin, the agent reads `<td>` from it, so the trust domain is authenticated by the pin
  and needs no separate parameter.
- The CSR is **bound to the TLS connection** that carries it; the binding is **mandatory** for
  `Enroll`, `Renew` and `Reauth` ([S7](spikes/S7.md)). The agent exports the connection's
  `tls-exporter` value (RFC 9266, Section 2: label `EXPORTER-Channel-Binding`, empty context,
  32 bytes), base64-encoded, into the CSR's PKCS #9 `challengePassword` attribute, which its key
  signs; EST binds requests to `tls-unique` the same way (RFC 7030, Section 3.5)
  ([D62](14-open-decisions.md#engineering)). The controller compares it with its own value for
  that connection and refuses a CSR without it, with another connection's value, or with any other
  shape (two attributes, two values, not 32 bytes), so a captured CSR cannot be replayed.
  Consequences:
  - the agent sends the CSR on the connection it computed the value on (its control-session
    connection, not a pool); if that connection was replaced meanwhile, the request is refused and
    the agent builds a new CSR;
  - crypto/x509 neither writes nor exposes the attribute, so the agent builds the request itself
    and the controller reads the attribute from the signed request. A CSR extension under an OID of
    the arc 2.25 (D47, superseded) cannot carry it: Go's `encoding/asn1` refuses OID arcs above
    2^31−1 [F Go 1.27.1 `encoding/asn1/asn1.go:301-331`].

### Lifecycle

- **Renewal**: over the control session with a new key; the requested identity must equal the
  identity of the presented certificate.
- **Decommission**: `rpmgr leave` or an admin's revoke → deny-list push, sessions killed, renewal
  refused; a tombstone is kept for 90 days.
- **Deleting an org** starts a **30-day grace period**; the org is purged afterwards
  ([06](06-data-model.md#lifecycle-and-deletion)).
- **Ephemeral connectors** (CI runners, short-lived containers) are purged **30 minutes** after
  their last disconnect by a leader-elected job, and their certificates added to the deny-list.

## Human authentication and sessions

| Topic | Design |
|---|---|
| **Passwords** | argon2id (`x/crypto/argon2.IDKey` [F]), PHC string format. Default **t=3, m=64 MiB, p=4**, 16-byte salt, 32-byte tag (RFC 9106's second recommended option). A semaphore limits concurrent hashes to 4 to bound memory. Low-memory profile for small devices: t=2, m=19 MiB, p=1. The profile is the instance setting `password_hash_profile` (Settings → PKI); `rpmgr controller init` picks the low-memory profile when the host has less than 1 GiB of RAM. Hashes are upgraded on login when parameters change. Length 12–256, no composition rules. |
| **Password reset, invitations** | One-time links (256-bit random, stored hashed). SMTP is optional: without it, an Owner or Admin creates the link for a member of their org (the Instance Admin for any user) and passes it on; with SMTP, links are also e-mailed and users can request a reset themselves. On the controller host, `rpmgr user reset-password` creates a link without the UI (local administration, [Roles](#roles)). A completed reset revokes all sessions of the user. |
| **MFA** | TOTP (RFC 6238, ±1 step, the last used step is stored so a code cannot be replayed; seed encrypted). WebAuthn/passkeys [V VB-01]. 10 hashed recovery codes. Org policy "require MFA". |
| **SSO** | OIDC authorization code flow with PKCE (S256), `state` and `nonce`, verified with `go-oidc`. Group claims map to roles. Existing accounts are linked only if `email_verified` is true **and** linking is enabled by an admin. A local break-glass Owner remains when SSO is enforced. |
| **Sessions** | Opaque random token, stored as a SHA-256 hash server-side; no JWTs. Cookie `__Host-rpmgr_session`: `Secure`, `HttpOnly`, `Path=/`, no `Domain`, `SameSite=Lax`. Idle timeout **8 h**, absolute **7 days**. Rotated at login and at step-up. Users can list and revoke their sessions; changing password or MFA revokes all others. |
| **CSRF** | No CORS. State-changing calls are POST only; Connect GET is allowed only for methods marked side-effect free. Go's `http.CrossOriginProtection` (available since Go 1.25 [F Go 1.25.14 `net/http/csrf.go:36`]) allows `Sec-Fetch-Site: same-origin`/`none`, otherwise compares the `Origin` host with `Host`, and lets requests with neither header through as non-browser requests [F Go 1.25.14 `net/http/csrf.go:15-27,137-160`]. rpmgr adds two rules on mutating calls: an `Origin`, when present, must exactly match the configured public origin or one of the configured aliases (scheme included), and only non-simple content types (`application/json`, `application/proto`) are accepted, which a cross-site form cannot send without a CORS preflight. |
| **WebSockets** | Used only for the terminal (Phase 3); logs and events use Connect server streaming. The upgrade requires an exact `Origin` match, the session cookie, and a single-use **30 s ticket** minted by an authorized POST and sent as the first WebSocket message, bound to {session, resource, action}. No credential in the URL. |
| **Step-up** | Fresh WebAuthn user verification, TOTP or password within the last **10 min** is required for: shell, CA/KEK operations, minting enrollment or gateway tokens, creating API tokens or service accounts, MFA/SSO changes, granting Admin or Owner, exporting the audit log, deleting the org, connecting a DNS provider or rotating its token, approving a held DNS zone's plan. |
| **Rate limiting** | Token buckets per IP and per account on login, MFA, enrollment and password reset; enrollment: 10 per minute per IP. A full table of buckets refuses new addresses instead of dropping ones that are being limited. Per-account **progressive delay** instead of hard lockout (attackers must not be able to lock admins out). A dummy hash is computed for unknown users so response times do not reveal which accounts exist. |
| **API tokens** | Personal (`rpmgr_pat_`) and service-account (`rpmgr_sat_`) tokens, stored hashed. Expiry is mandatory: default **90 days**, maximum **1 year**. Effective permissions = token scopes ∩ the owner's **current** permissions, evaluated per request, so demoting a user immediately limits their tokens. Listable (name, prefix, scopes, last use, IP) and revocable. Accepted only as `Authorization: Bearer`, never in a query string. |

## Authorization

### Roles

| Permission | Owner | Admin | Operator | Viewer |
|---|:-:|:-:|:-:|:-:|
| View resources, status, metrics | ✓ | ✓ | ✓ | ✓ |
| Routes, targets, health checks, access policies, private services and grants | ✓ | ✓ | ✓ | |
| Enroll and revoke connectors | ✓ | ✓ | org setting | |
| Gateways, gateway groups, port pools, domains, certificates | ✓ | ✓ | | |
| DNS providers, managed zones and their gates, DNS names; adopt, release, approve plans; view foreign records (Phase 2) | ✓ | ✓ | | |
| Members (Admins cannot change Owners) | ✓ | ✓ | | |
| Service accounts and their tokens | ✓ | ✓ | | |
| Audit log read and export | ✓ | ✓ | | |
| SSO, MFA policy, org settings | ✓ | | | |
| `connector.shell` (Phase 3) | explicit per-user grant, plus host opt-in, plus step-up | | | |

**Instance Admin** is a separate, instance-level role for the CA, the KEK, system gateways,
system-org DNS providers and zones, and instance settings. In a single-org installation, the first
user holds both Owner and Instance Admin.

**Local administration.** Administrative commands run on the controller host (`rpmgr ca …`,
`rpmgr kek …`, `rpmgr backup`, `rpmgr restore …`, `rpmgr user reset-password`, `rpmgr migrate`,
`rpmgr migrate-db`) are authorised by **host access**: they run as root or as the rpmgr service
user and use the database and the KEK directly. They need no API token and no step-up, and every
one is audited with the actor `local-cli`. The same actions through the UI or API need the Instance
Admin role and step-up.

Operators can create routes, and a route hostname in a managed zone is published automatically. The
zone's gates, set by Owners and Admins, decide whether route hostnames are published, and whether
proxied or wildcard names are allowed ([15](15-dns.md#publication-rules)). Foreign records of a
managed zone (records rpmgr does not own) are shown only to Owners and Admins, read live from the
provider and never stored.

### One enforcement point, with defence in depth

1. **API layer.** Every RPC declares its permission in the proto:
   `option (rpmgr.v1.authz) = { permission: "route.update", resource_field: "route.id" }`. One
   interceptor resolves the target's org and checks the caller's role. **A method without the
   annotation is rejected at startup** and a test walks the service registry to prove every method
   is annotated ([12](12-testing-and-quality.md#security-testing)), so no method can exist
   without an enforced permission check.
2. **Store layer.** Queries on org-owned tables require an `OrgScope` value that only the
   authorization layer can construct: a deny-by-default Ent privacy policy, an interceptor that
   filters every query by the scope's org, and a hook that does the same for every update and
   delete ([06](06-data-model.md#tenancy-enforcement), [S5](spikes/S5.md)). Because Ent's policies
   can be skipped with `privacy.DecisionContext`, the filtering is in the interceptor and the hook,
   and lint bans `privacy.DecisionContext` outside `internal/store`. System jobs use an explicit
   system scope that is granted only together with an audit record.
3. **Database.** Every org-owned table has `org_id NOT NULL`, and foreign keys between org-owned
   tables are composite `(org_id, id)`, so a row cannot reference another org's row, not even with
   plain SQL — on SQLite and on PostgreSQL ([06](06-data-model.md#tenancy-enforcement)).
4. [R] **PostgreSQL row-level security: not in v1.** SQLite, the default, has none, and correct RLS
   with connection pooling (`SET LOCAL` per transaction) is easy to get wrong. The schema keeps it
   possible later.

### Route and hostname ownership

- **Domains are verified per org** (DNS TXT record at `_rpmgr-challenge.<domain>`, or an HTTP token).
  A verified FQDN is globally unique within the instance. A route's hostnames must fall under a
  verified domain of the same org.
- **Trusted domains** (Phase 1, [D13](14-open-decisions.md#tenancy-and-data)). The Instance Admin
  can mark a domain claim as verified without a DNS or HTTP proof (method `trusted`, step-up
  required). Global uniqueness still applies: a later claim by another org for the same name is
  refused, and the Instance Admin decides.
- **Delegated labels** (Phase 2, [D23](14-open-decisions.md#tenancy-and-data)). The Instance Admin
  delegates `<org-slug>.<base domain>` of the instance base domain to an org as a verified claim
  (method `delegated`, step-up required). Flat names directly under the base domain need an approved
  nested claim (next rule).
- On **shared gateway groups**, only DNS TXT verification is accepted: an HTTP token would be
  answered by the shared gateway itself, so any org could "verify" a hostname that already points at
  it. A claim nested under, or containing, another org's verified domain gets the status
  `pending_approval` and stays unusable until an Instance Admin approves it (Phase 2, with step-up).
  No hostname is ever handed out first-come-first-served.
- **TXT proofs are read at the zone's authoritative nameservers**, never through the controller's
  resolver, so split-horizon DNS and negative caching cannot fake or delay a result.
- **DNS automation (Phase 2) publishes only within the same org.** A managed zone receives records
  only for its own org's sources, and challenge TXTs only for its own org's pending claims;
  otherwise any org could make rpmgr write a proof into another org's zone with that org's token.
  API access to a provider zone is never proof of ownership, because a domain can be added to a
  Cloudflare account as a pending zone without proof [V VB-12]. The controller's own hostnames are
  never written ([15](15-dns.md#publication-rules)).
- **TCP/UDP ports** come from `port_allocations`, unique per (gateway group, protocol, port).
- **Gateways serve a route only for the connector identities listed for it** in the gateway's
  signed snapshot. A connector cannot announce routes; it can only report readiness for routes it
  was assigned.

## Connector-local policy

The **local policy** is a file on each connector host that limits what the connector does,
whatever any snapshot says ([ADR-0009](adr/0009-connector-local-policy.md)). It is the one control
that survives a compromised controller.

```yaml
# /etc/rpmgr/policy.yaml — owner root, mode 0644; read-only for the rpmgr service user
version: 1
allow_targets:                  # what the connector may dial for routes and private services
  - cidr: 127.0.0.1/32          # example; the default is an empty list (nothing allowed)
    ports: [8080]
  - cidr: 192.168.10.0/24
    ports: [80, 443, 8000-8099]
  - unix: /run/app/app.sock
allow_listen:                   # where visitor listeners for private services may bind
  - 127.0.0.1:20000-20999
allow_remote_shell: false       # Phase 3; default false
allow_functions: false          # Phase 3; default false
allow_vnet_routes: []           # Phase 3; CIDRs this host may route for virtual networks
allow_p2p: false                # Phase 3; default false
allow_egress_proxy: false       # Phase 3; SOCKS5/HTTP proxy target kinds
auto_update: auto               # auto | notify | off
update_channel: stable          # stable | prerelease
```

Rules:

- The controller **never writes** this file. A missing file means the built-in defaults: **no
  targets allowed** (`allow_targets: []`), all `allow_*` features off, `auto_update: auto`,
  `update_channel: stable` ([14](14-open-decisions.md) D5, D6). Loopback is *not* allowed by
  default: loopback-only services (databases, admin UIs, the Docker API, `rpmgr`'s own admin
  listener) are often the least protected. The installer adds targets from `--allow-target` flags
  or asks interactively, and always writes `auto_update` and `update_channel` explicitly.
- Windows and macOS connectors (Phase 2) keep the same file in a platform-specific location with
  equivalent permissions ([10](10-operations.md#install)).
- A file that does not parse means **deny everything**: every target becomes
  `not_ready(policy_invalid)`; the snapshot itself is still applied.
- Checks happen **at dial time on the resolved IP and port** (`net.Dialer.Control`), which defeats
  DNS rebinding. IPv4-mapped IPv6 addresses are unmapped before checking. Link-local and cloud
  metadata addresses (169.254.0.0/16, fe80::/10, `fd00:ec2::254/128`, `100.100.100.200/32`) are denied unless listed
  explicitly.
- A target the policy forbids does **not** reject the snapshot. The snapshot is applied, and the
  affected target reports `not_ready(blocked_by_local_policy: 10.0.0.5:5432)`; the UI shows the
  reason and the exact command to allow it: `sudo rpmgr policy allow-target 10.0.0.5:5432`. One
  disallowed target therefore never blocks unrelated changes
  ([03](03-connections.md#configuration-reconciliation)).
- `rpmgr policy …` edits the file and triggers a reload (`systemctl reload`, i.e. SIGHUP); the
  connector also watches the file. On reload it re-evaluates the current snapshot and reports the
  new readiness.
- The policy only protects if the binary enforcing it is genuine: OTA installs only signed binaries
  at or above a locally persisted version floor, and `auto_update` lets the host refuse automatic
  updates entirely ([Supply chain and updates](#supply-chain-and-updates)).
- It does **not** protect public users of a route (a compromised controller can still re-route a
  hostname), and it does not limit a shell once a host has allowed it. For high-value hosts,
  [R] prefer SSH over a private service to a built-in shell
  ([14-open-decisions.md](14-open-decisions.md)).

## Secrets at rest and in logs

| Secret | Treatment |
|---|---|
| User passwords, recovery codes | argon2id hash |
| Session, API, enrollment tokens | SHA-256 hash (tokens are 256-bit random, so a fast hash is sufficient) |
| Route basic-auth credentials | argon2id hash; gateways receive the hash, never the password. Because browsers send basic-auth credentials with **every** request, a gateway verifies with argon2id once and then caches `HMAC-SHA256(gateway-local random key, policy_id ‖ credential_version ‖ len(user) ‖ user ‖ password)` together with the matched user, for 5 minutes in a bounded LRU. The policy ID and credential version keep an entry from being reused on another route, org or credential; the length prefix prevents ambiguous user/password splits; entries for a policy are flushed as soon as a snapshot changes that policy, so tightened policies apply immediately; failed attempts are rate-limited per client IP **before** hashing, and hashing has a per-gateway concurrency cap. This keeps argon2id from becoming a CPU/memory amplifier for unauthenticated clients |
| CA, intermediate, config-signing and audit keys; ACME account key; TLS private keys of public certificates; TOTP seeds; OIDC client secrets; DNS-provider tokens (one per `dns_providers` row, per org); SMTP and webhook secrets | **Envelope encryption**: a random data key per secret encrypts it with AES-256-GCM (AAD = table, column, row ID); the data key is wrapped by the KEK with AES-256-GCM (AAD = the same plus the KEK version). Rotating the KEK re-wraps only data keys, never the secrets. The KEK version is derived from the key itself (the first 8 bytes of a SHA-256 over it), so it needs no configuration |
| Agent private keys, WireGuard private keys | **Never stored centrally**. Generated on the agent; only public keys reach the controller |

**KEK sources**, in order of preference:

| Source (`kek.source`) | Phase | Notes |
|---|---|---|
| `kms`: HashiCorp Vault or OpenBao Transit | P2 | Plugin interface; cloud KMS (AWS, GCP, Azure) added by demand |
| `systemd-credential`: systemd `LoadCredentialEncrypted=` | P1 | TPM-sealable where available [V VB-03]; needs systemd ≥ 250, otherwise the installer falls back to `file` (VB-03: Ubuntu 22.04 has 249). The credential `<name>` is read from `$CREDENTIALS_DIRECTORY`, in the format of `file` |
| `file`: a 0600 file | P1 | Containers mount secrets as files. The file holds the base64 encoding of 32 random bytes; symbolic links are followed (container platforms mount secrets that way), but the file must be regular and closed to its group and other users (0600 or 0400) |

**Not** an environment variable: no secret is kept in the environment of a long-running process.
`rpmgr kek rotate` re-wraps all data keys.

**API behaviour**: secret fields are write-only. They can be set or rotated, never read back.
DNS-provider tokens are sent only to the compiled-in provider API URL; no runtime setting can
redirect them ([15](15-dns.md#cloudflare-specifics)).

**Logs**:

- A `secret.Value` type. `String`, `GoString`, `Format`, `MarshalJSON`, `MarshalText` and
  `LogValue` all return `[REDACTED]`; only `.Reveal()` returns the value, and its use is restricted
  by lint. The value is captured by an unexported function rather than stored in a field: where fmt
  cannot call the methods (an unexported struct field, a wrong verb), it prints by reflection, and
  reflection shows a pointer or a byte slice with its contents but a function only as an address.
- The logger redacts every attribute whose key contains `token`, `secret`, `password`,
  `authorization`, `cookie` or `private_key` (case and `-`/`_` ignored), whatever its type.
- Proto fields carrying secrets are annotated `(rpmgr.v1.sensitive) = true` (plus `debug_redact`
  [V VB-04]); the logging handler redacts them.
- **Whole requests are never logged.** Access logs omit query strings and authentication headers.
- No secret appears in argv, in the environment of long-running processes, or in unit files.

## Supply chain and updates

### Release signing

- [R] **Ed25519 manifest signing** (minisign-compatible), with the root verification keys **compiled
  into the binary**. Two offline root keys sign **signing-key statements**; the current signing key
  signs each **release manifest**:

```json
{ "seq": 87, "version": "1.4.2", "floor": "1.3.0", "channel": "stable",
  "issued_at": "2027-03-01T12:00:00Z",
  "artifacts": [ { "os": "linux", "arch": "amd64", "variant": "full", "sha256": "…",
                   "size": 21876736 } ] }
```

- **Key custody** (one maintainer, [14](14-open-decisions.md) D10):
  - The two root keys live on **two hardware tokens** (e.g. YubiKey, Ed25519). **Either root
    alone** can sign a signing-key statement (1-of-2), so losing one token is not fatal. One token
    is kept at the maintainer's home, the other off-site.
  - The routine **signing key** lives on a third token and never enters CI. A signing-key statement
    is valid for **12 months**; a new signing key is introduced with a new statement before the old
    one expires.
  - Losing both root tokens means shipping a new binary through an out-of-band trust path.
  - Producing minisign-format signatures with the chosen token is verified before the first
    release with OTA [V VB-13]; if that is not possible, rpmgr uses its own documented raw Ed25519
    signature format.
  - **Phase 1 (v0.x, no OTA)** uses interim keys: two root keys and a signing key, generated on an
    offline machine and kept as encrypted files on offline media, one root copy off-site. The first
    release with OTA (Phase 2) carries the hardware-token roots; hosts installed in Phase 1 install
    that binary by hand anyway, so nothing depends on the interim roots afterwards
    ([D48](14-open-decisions.md#security-defaults)).
  - Only the real root keys are compiled into release builds. Tests use the build tag `rpmgrtest`,
    which swaps in generated test roots; release builds refuse that tag, and the release job checks
    the key fingerprints printed by `rpmgr version --verbose`
    ([D60](14-open-decisions.md#security-defaults)).
- `channel` is `stable` or `prerelease`. The root updater installs a manifest only if its channel
  matches the host's `update_channel` in the local policy, so a prerelease never reaches a stable
  host, even through a compromised controller. `variant` is `full` or `connector` (the optional
  connector-only build, Phase 2); the updater installs only the variant recorded in `install.json`.
  Both builds install as the binary `rpmgr`.
- `seq` is a **monotonic manifest number**. Agents persist the highest `seq` they have accepted and
  their version floor, and accept a manifest only if its `seq` is at least that high. `floor` raises
  the persisted version floor; it can be **lowered** only by a manifest with a higher `seq` than any
  seen. Replaying an older, genuinely signed manifest therefore cannot roll an agent back.

- This works fully offline (air-gapped installations), the verifier is small, and signing keys can
  rotate without a new binary.
- For the wider ecosystem, releases also carry **cosign** signatures, **SLSA provenance** and an
  **SBOM** (SPDX JSON, generated with syft) [V VB-05]. These are not used for in-binary OTA because
  verifying them needs a transparency-log trust root and a large dependency tree.
- Builds: `CGO_ENABLED=0`, `-trimpath`, pinned toolchain, reproducibility check in CI, signed
  `SHA256SUMS`, CI actions pinned by commit SHA.

### Over-the-air updates

OTA covers script installs and standalone binaries on **Linux with systemd**. Windows and macOS
connectors (Phase 2) are updated through their package managers or by hand; OTA for them is a
Phase 3 item ([13](13-roadmap.md#phase-3--advanced)).

1. The controller fetches the release manifest from the **release source**, the GitHub Releases of
   `felix-homelab/rpmgr` (the release check is on by default and can be disabled,
   [14](14-open-decisions.md) D4), or an admin uploads it on air-gapped installs. It verifies the
   signature and mirrors the artifacts under `/dl/`. Agents never contact the release source.
   Phase 1, which has no rollouts, mirrors only the controller's own version, which `/install.sh`
   installs; air-gapped installations import it with `rpmgr release import <dir>` on the
   controller host ([D59](14-open-decisions.md#security-defaults)).
2. An admin approves a **staged rollout** (canary agents, then a percentage, then all). The target
   version becomes desired state.
3. The agent (running as the unprivileged service user) downloads the artifact and manifest from
   the controller's mirror and **stages** them in `/var/lib/rpmgr/update/`. The URL is not trusted;
   the signature is. The service user can never write the installed binary — otherwise a
   compromised process could persist a build that ignores the local policy.
4. A **root-owned updater** (`rpmgr-update.path` triggering the oneshot `rpmgr-update.service`)
   reads `auto_update` and `update_channel` from the local policy **itself** (it does not trust the
   agent's decision), opens the staging directory through a directory file descriptor with
   `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`, accepts only regular files (`fstat` →
   `S_ISREG`) no larger than the manifest's size and a hard cap of 256 MiB (checked before and while
   copying), **copies** them into the root-only `/var/lib/rpmgr-update/staging/`, and verifies
   **the copy**: manifest signature, `seq`, version floor, `channel` (against the policy's
   `update_channel`), OS/arch, `variant` (against `install.json`), size and SHA-256. Verifying a
   copy the service user cannot touch removes the time-of-check/time-of-use gap; refusing symlinks,
   FIFOs and oversized files keeps a compromised agent from hanging the updater or filling the
   disk.
5. It copies the verified file into the target directory as `.rpmgr.new` (same filesystem, so no
   cross-filesystem rename), fsyncs and re-hashes it, keeps the previous binary as `.prev`, renames
   `.rpmgr.new` over the binary at the path recorded in `/var/lib/rpmgr-update/install.json`
   (`/usr/local/bin/rpmgr` for script installs), and restarts the role service. **Package installs
   (deb/rpm) are not updated by OTA**: they are updated by the package manager from the signed
   repository, because the next package run would silently revert a binary replaced behind its back;
   the updater refuses to replace a package-owned binary.
6. The updater polls the agent's admin `/readyz`, which reports ready only when the control session
   is established and a snapshot is applied. If it is not ready within 5 minutes, the updater
   **rolls back** to `.prev` and the agent reports the failure.
7. The agent reports the new version; the persisted floor and `seq` are raised only after success.
   They are stored by the updater in `/var/lib/rpmgr-update/`, owned by root and not writable by the
   service user, so a compromised agent process cannot lower them ([10](10-operations.md#install)).
   They are **initialised at install time** from the binary's embedded release metadata (its version
   and the `seq` of its own release manifest), so a freshly installed host is protected against
   replayed old manifests from day one. Afterwards the running version plays no role: a manifest
   with a higher `seq` may lower the floor, which makes **signed downgrades** possible. The automatic
   rollback to `.prev` is exempt, because floor and `seq` are only raised after success.

### Install scripts

- `/install.sh` (Linux) is **served by the controller** from an embedded template and downloads from
  the controller's own mirror, on the same endpoint as the UI. It verifies the chain **root key**
  (embedded in the script) → **signing-key statement** → **manifest signature** → artifact
  **SHA-256** with OpenSSL ≥ 3.0, and refuses to install when OpenSSL is missing or older [V VB-15].
- There is no `/install.ps1`. Windows connectors are installed with winget or an MSI, macOS
  connectors with a Homebrew tap (Phase 2, [10](10-operations.md#install)).
- No third-party download proxy, and no download URL chosen at runtime by the controller.
- Caveat: a compromised controller can serve a malicious install script. High-assurance installs
  should use distribution packages or verify the release (GitHub release + `cosign verify-blob`)
  before running it. After installation, updates are protected by the compiled-in keys.

## Audit log

- Every state-changing request and every security event (logins, failed logins, step-ups, token
  creation and use, enrollments, revocations, shell sessions) is recorded with: actor, session or
  token, authentication method, IP, user agent, request ID, action, target and org, result, a
  **redacted** before/after diff, and an optional reason.
- Every write the DNS job makes at a DNS provider is recorded as a system-actor entry in the
  chain of the zone's org, with the record before and after
  ([15](15-dns.md#ownership-ledger)).
- Entries form a **per-org hash chain** (`hash = SHA-256(prev_hash ‖ canonical entry)`).
  Instance-level events (system-scope grants, local administration, the Instance Admin's changes to
  instance resources) form one more chain, the **instance chain**.
  - The canonical entry is a version label, the seq and the time (microseconds) as signed varints,
    then every stored field in a fixed order with a length prefix, the chain's name among them. The
    first entry's `prev_hash` is a genesis hash over the chain's name, so an entry verifies only at
    its own place in its own chain.
  - An entry is appended in the transaction of the change it records, so both commit or neither
    does. Each chain has a head row with its last seq and hash; an append locks and increments it
    first, so concurrent appends to one chain stay linear.
  - Verification walks a chain and names the first entry that is missing, out of order, or does not
    match its own hash or its predecessor's; it compares the last entry with the head row, so a
    deleted tail is found too. An org scope verifies only its own org's chain.
  - An org's request appends only to its own chain or the instance chain. Events before any scope
    exists (a failed login, the grant of a system scope) are appended without one.
- Signed **checkpoints** (chain head + count, signed with the audit-checkpoint key) are shipped to an
  external sink (syslog, OTLP, webhook, or object storage with retention lock). The external copy
  is what makes tampering evident: anyone with database write access could recompute a chain.
- **Phase 1 has no external sink.** Checkpoints are signed and stored in the database and in
  `/var/lib/rpmgr/audit-checkpoints.log`, which is included in every backup. Until an external sink
  is configured (Phase 2, optional, [14](14-open-decisions.md) D11), an attacker with write access
  to the controller host can rewrite both, so tamper evidence is limited to attackers who reach
  only the database.
- **Webhook signatures** (Phase 2, [07](07-api.md#webhooks-phase-2)): receivers reject signatures
  older than **5 minutes**.
- Only the audit package writes the audit tables: the store refuses every create, update and delete
  through Ent. On PostgreSQL, the application role has no `UPDATE`/`DELETE` permission on the audit
  table.

### Revocation log

Checkpoints prove tampering but cannot restore content, so revocations get their own durable,
**readable** record outside the database:

- An append-only **revocation log** records certificate revocations, API-token revocations, member
  removals and role downgrades, session revocations, and **credential supersessions** (password, MFA
  and recovery-code changes; removed shell grants and visitor grants; superseded certificate
  serials).
- **Security actions never wait for the log.** A revocation is committed and enforced immediately.
  Its entry is appended in the revoking transaction, before the commit, so a crash cannot commit a
  revocation without its entry; an append that fails is reported and does not stop the revocation.
  Each controller replica first appends the entry to a durable, fsync'd local log
  (`/var/lib/rpmgr/revocations.log`, included in every backup), then ships it asynchronously, with
  retries, to a shared sink that can be read back; syslog and webhooks are not enough. While a
  replica has an unshipped backlog, the UI raises an alert ("revocation log not yet off-host").
- **Sink types**: S3-compatible object storage (conditional create with `If-None-Match: *`) or a
  filesystem path, e.g. a file share (exclusive create). Phase 1 offers the filesystem sink; the
  S3-compatible sink comes with HA in Phase 2 ([D58](14-open-decisions.md#project-and-process)).
- Sink sequence numbers are allocated by **conditional create** of the object named `<seq>`
  (allocation is the write), so the sink has no gaps; entries are hash-chained.
- **Local format.** One line of JSON per entry: sequence number from 1, time, kind, org, subject,
  detail, the covered certificate's `NotAfter` where there is one, actor, the previous entry's hash
  and its own: the SHA-256 of the entry encoded with an empty hash. Text fields hold at most
  512 bytes. Appends from several processes on one host, such as an admin command beside the
  controller, are serialised by a file lock. An append returns after `fsync`; a last line without
  its newline was never acknowledged and is replaced by the next append. Reading verifies the whole
  chain: numbering, links and hashes.
- **Single node**: the sink is optional. Without it, the local log, included in every backup, is the
  only copy; a restore reads it with `--revocation-log <file>`. The "not yet off-host" alert fires
  only when a sink is configured; without one, the UI shows a standing hardening warning instead.
- **More than one controller replica**: a sink is required. A second replica refuses to start while
  no sink is configured.
- On restore from an older backup, the sink is merged with every reachable replica's local log;
  every entry newer than the backup is re-applied; all sessions and unused enrollment tokens are
  invalidated; and a new `db_epoch` is generated ([10](10-operations.md#backup-and-restore)).
- **Restore fails closed** if the sink's hash chain is broken, or a replica that reported an
  unshipped backlog has an unreachable local log: all API tokens and service accounts are
  suspended, all sessions invalidated, every user must reset their password and re-verify MFA, and
  the instance stays in read-only *restore review* mode. The **Instance Admin** ends the
  instance-wide review with `rpmgr restore confirm` on the controller host; each org's Owner
  re-confirms only their own org's memberships and roles, and an org stays read-only until then.
