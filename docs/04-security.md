# 04 — Security

> Status: Phase 1 is implemented. Tags: [F] fact · [R] recommendation · [T] target · [V] verify
> at implementation ([README](README.md#how-to-read-these-documents)).
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
| **Internet attacker** | Reach gateway listeners, the controller's login and enrollment endpoints; attempt denial of service | Call agent APIs (mutual TLS required everywhere except `Enroll`). Guess tokens (256-bit random, hashed lookup, per-IP and per-account rate limits, uniform errors). Reach metrics or pprof (the admin listener is never on a public address and listens on loopback by default, D67). Claim a hostname (domain verification). |
| **Network attacker (MITM)** | See metadata: SNI, IPs, timing, volume | Impersonate the controller or a gateway (pinned root, no trust-on-first-use, `InsecureSkipVerify` banned in code; its one exception is an HTTPS upstream its user marks unverified, [ADR-0017](adr/0017-upstream-tls-verification-modes.md)). Replay anything (TLS 1.3, no 0-RTT, no timestamp tokens). Read tunnel contents. |
| **Malicious user of another org** | Act within their own org and role | See or change another org's resources (one authorization interceptor, org-scoped store, composite foreign keys). Escalate (token scopes ⊆ creator's permissions; an Owner made only by an Owner, Admin and lower roles granted by Owners and Admins, Admin and Owner with a step-up, D66). Open a shell or log stream on someone else's connector (resource-bound authorization and single-use tickets). Take another org's domain (verified, globally unique claims). |
| **Malicious user in the same org (low role)** | Read what Viewer/Operator may read | Mint enrollment tokens, change gateways, domains, members or settings beyond their role (permission matrix). |
| **Compromised connector** | Serve, blackhole or tamper with **its own** routes' traffic; report false health or metrics; use its own visitor grants; leave with `rpmgr leave`, which deletes the routes only it serves, with their hostnames, ports and policy links ([D78](14-open-decisions.md#engineering)) | Serve other routes (gateways serve a route only for connectors listed for it in the signed route table). Read other agents' configuration (snapshots are compiled per identity). Reach private services it has no grant for. Survive revocation (deny-list pushed to all relying parties, sessions killed, renewal refused). Exhaust a gateway (a stream limit per data session and a cap on the data sessions of one connector, [03](03-connections.md#establishment); per-route bandwidth limits come in Phase 2, [05](05-features.md#edge-access-control-and-limits)). |
| **Compromised gateway** | See plaintext of the HTTP routes it terminates; drop or delay traffic; use the TLS keys of hostnames it serves | Read private-service traffic (end-to-end TLS between connectors). Obtain routes or keys of other gateway groups (snapshots are per gateway). Make a connector dial an arbitrary address (`StreamOpen` names a route, the connector dials only its own snapshot's targets), or a target of a route of another gateway group (the connector serves a stream only for a route its snapshot lists for the opening gateway, [03](03-connections.md#one-stream-per-user-connection)). Impersonate a connector or another gateway (role and ID are part of the identity, and clients check the expected peer's DNS name and SPIFFE ID). Open shells (the shell path is controller → connector only). |
| **Compromised controller (process, or database plus KEK)** | Everything in the control plane: re-route public hostnames, issue certificates (and so MITM traffic that is not end-to-end), deny service, push any configuration. With connected DNS providers (Phase 2): rewrite **any** record in the connected zones, including MX, SPF/DKIM and third-party verification records, and use the provider tokens from elsewhere unless they are IP-restricted | Make a connector exceed its **local policy** (dial outside `allow_targets`, enable shell, functions, virtual-network routes, P2P, listeners). Install an unsigned or older binary (OTA verified against keys compiled into the binary, with a persisted anti-rollback floor). Read agent or WireGuard private keys (never stored centrally). |
| **Database dump without the KEK** | Read topology, configuration, emails, audit log | Use any credential: passwords are argon2id; session, API and enrollment tokens are SHA-256 hashes of 256-bit random values; CA, ACME, TOTP, OIDC and other secrets are AES-256-GCM-encrypted under a KEK held outside the database. |
| **Holder of a stolen DNS-provider token** (Phase 2) | Change any record the token covers, from anywhere the token is accepted | Use it from another network, if the token is restricted to the controller's egress addresses; use it after its expiry; use it beyond the zones it is scoped to ([15](15-dns.md#connecting-importing-and-disconnecting)). rpmgr never shows the token after it is saved (write-only) |
| **Malicious insider with Admin role** | Any configuration action within the org. Make a reset link for a non-Owner member of the org alone, which takes over the account of one without a second factor, in the org's audit log ([Account recovery](#account-recovery)) | Use the shell on hosts that did not opt in. Read secrets back (write-only fields). Act unnoticed (hash-chained audit log with external checkpoints; account recoveries are in the org's log too). Grant Owner (Owner-only). Recover an Owner's or Instance Admin's account, or that of a member of another org ([Account recovery](#account-recovery)). Skip step-up re-authentication for dangerous actions. |
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
  ([S7](spikes/S7.md)). `InsecureSkipVerify` is never used for rpmgr's own sessions.
- Every rpmgr check runs in `VerifyConnection`, which Go calls on full and resumed handshakes alike;
  never in `VerifyPeerCertificate`, which resumed connections skip
  ([03](03-connections.md#properties-common-to-all-rpmgr-internal-sessions)).
- Authorization always parses the URI path; the certificate CN is never used.

### CA hierarchy

| Key | Algorithm | Lifetime | Storage | Use |
|---|---|---|---|---|
| **Root CA** | ECDSA P-256 | 10 years | Controller DB, envelope-encrypted under the KEK (default); or offline (`rpmgr ca offline-root`, Phase 2, [D58](14-open-decisions.md#project-and-process)) | Signs intermediates only (`pathlen=1`) |
| **Issuing intermediate** | ECDSA P-256 | 1 year, rotated at 6 months with overlap | Controller DB, envelope-encrypted | Signs leaf certificates (`pathlen=0`), name-constrained (critical) to URI domain and DNS domain `<td>`; Go enforces both [F Go 1.27.1 `crypto/x509/constraints.go:525`] ([S7](spikes/S7.md)) |
| **Config-signing key** | ECDSA P-256 | certificate 1 year (at most the intermediate's); a next key 90 days before it expires, which replaces it 60 days before | Controller DB, envelope-encrypted | Signs snapshots and deny-lists (agents verify last-known-good on disk) |
| **Audit-checkpoint key** | ECDSA P-256 | as the config-signing key | Controller DB, envelope-encrypted | Signs audit checkpoints |

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
| Controller node certificate (`controller.<td>`, `reauth.controller.<td>`, `<node-id>.controller.<td>`) | 30 days | automatic, at **50 %** of lifetime, new key every time; new handshakes present the new certificate at once | EKU serverAuth **and clientAuth** (replicas call each other over mutual TLS in HA, [10](10-operations.md#high-availability)). The node's key exists only in memory: every start and every renewal gets a new key and certificate |

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
  revocation; after a restore, `revoked_serials` adds the certificates revoked since the backup
  that the backup does not hold ([Revocation log](#revocation-log)).
- A **deny-list** (revoked serials and identities) is sent to every gateway, connector and
  controller node as a **separate control message**, `DenyListUpdate`, not inside the snapshot. It
  carries the full current set, which stays small because an entry lives only until the covered
  certificate's `NotAfter` — agents never accept expired certificates, and `Reauth` checks the
  database, not the deny-list. At ~100 bytes per entry, 1 000 ephemeral connectors per day with
  7-day certificates give ~7 000 entries ≈ 0.7 MB [T]; [R] above 1 MiB the controller sends deltas
  keyed by `(db_epoch, n)` with a periodic full set. Agents apply it unconditionally — an agent that
  rejects a snapshot still receives revocations — and merge it by **union**: an entry is dropped
  only after its own expiry, never because of a version number or a new `db_epoch` after a restore.
- Agents **persist** the deny-list next to the last-known-good snapshot, as the signed lists that
  still contribute an unexpired entry, and load it before accepting any session; a stored list that
  no longer verifies is dropped and the others are kept. A gateway restarted while the controller
  is down therefore still refuses revoked connectors. The control-session `Hello` carries a digest
  of the agent's list (gateways and connectors both have a control session); on a mismatch the
  controller resends it. The list is checked in `VerifyConnection`; a change closes affected live
  sessions immediately ([03](03-connections.md#service-sketch)).
- Short lifetimes bound the damage when a deny-list cannot be pushed (controller down).
- **Revoking** a certificate (by serial) or an identity (every certificate of it, also one issued
  later; no new certificate is issued and none renewed) is committed with an audit record. The
  controller then ends the control sessions of the agents it covers with `Goodbye{revoked}`, and
  with them their imperative operations, such as live logs
  ([03](03-connections.md#control-session)), sends the new list to every other session, and refuses
  the certificates at its TLS layer. Each replica reloads the list at every revision check
  ([03](03-connections.md#timeouts-keepalive-and-backoff)), so a revocation committed by another
  replica or an admin command is enforced too. Phase 1 always sends the full set.
- Every revocation is also appended to the **revocation log** outside the database, so a restore
  from an older backup cannot resurrect revoked credentials ([Audit log](#audit-log)).
- [R] **No OCSP and no CRL**: every relying party already receives the deny-list; OCSP would
  add an online dependency for no benefit, and no consumer needs a CRL
  ([14](14-open-decisions.md) D31).

### Controller certificates

- **UI and public API**: an ACME certificate (certmagic) or one the operator supplies.
- **The controller's own ACME certificate** [R]: without `tls.cert_file` and `tls.key_file`, a
  controller whose public URL has a public DNS name (two labels or more; not an IP address,
  `localhost` or a name under `.local`, `.internal` or `.home.arpa`) obtains and renews the
  certificate of that name from the instance's ACME CA and account, as read at start. It answers
  the challenges itself: HTTP-01 on `listen.http`, if set, and TLS-ALPN-01 on 443; on all-in-one
  both reach it through the gateway. The certificate and the account are stored in the database,
  encrypted, so a restart or another replica serves it without a new order. Until the first
  certificate arrives, and for a name no public CA certifies, the controller serves a self-signed
  certificate; a renewal that fails keeps the certificate in use (retry timing in
  [03](03-connections.md#timeouts-keepalive-and-backoff)).
- **HSTS on the UI** [R]: while the public URL has a certificate from files or from ACME, every
  response on it carries `Strict-Transport-Security: max-age=31536000` (one year), without
  `includeSubDomains`, as other names under the same domain may not be rpmgr's. A browser ignores
  the header over a connection with certificate errors [F RFC 6797, section 8.1], so a self-signed
  certificate gets none.
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
- **ACME route certificates** [R]: the singleton job `acme` gives every hostname of an enabled
  http route in `acme` mode a certificate of its own from the instance's ACME CA (Let's Encrypt
  by default) and account, obtained and renewed with certmagic: renewal follows ACME Renewal
  Information where the CA offers it, else a third of the lifetime left. A renewal's order names
  the certificate it replaces when the directory is the same; a CA refuses that for a certificate
  of another account, as after a change of the account's e-mail address, and the job then orders
  once more without naming it, before any challenge is tried. The certificate goes
  into the certificates of the route's org and from there to the gateways. A hostname that gets
  none has a `failed` row with the CA's error, and one whose renewal fails keeps serving its
  certificate with the error recorded. A wildcard hostname in `acme` mode is refused with that
  reason, as its certificate needs DNS-01 (Phase 2, R42). The ACME client honours `HTTPS_PROXY`,
  else `ALL_PROXY`, and `NO_PROXY` (R44, [D93](14-open-decisions.md#engineering)).
- **ACME for CONNECT listeners** (Phase 2) [R]: the job treats the hostname of a TLS CONNECT
  listener with an enabled route and no certificate of its own as it treats a WSS hostname
  ([Route edge rules](#route-edge-rules)): an uploaded certificate of the listener's org that
  covers the name serves it instead; otherwise the job obtains and renews one, with its challenges
  answered by the gateways of the listener's group, which alone get it. A hostname that lies
  under no verified domain of the org any more is not renewed: its row records the reason, and
  the certificate it has serves until it expires. A listener that closes with its last route
  takes its hostname out of the job ([03](03-connections.md#http-connect-routes-phase-2)).
- **Failed ACME attempts** [R]: a hostname whose attempt failed, such as one whose DNS does not
  point at its gateways yet, must not use up the account's limits at the CA. Let's Encrypt allows
  5 failed authorizations per name and account an hour, and pauses a name after 1 152 failures in
  a row [F le:docs/rate-limits]; a failed attempt of the job orders once per challenge type.
  - **Waits.** The job tries such a hostname again only after a wait that doubles with each
    failure in a row; the waits are in [03](03-connections.md#timeouts-keepalive-and-backoff).
    "Renew now" tries at once. A success ends the waits.
  - **Rehearsal.** Every retry rehearses at the CA's test directory first, and orders at the CA
    only once the test directory validated the name: the job marks the attempt as a retry, and
    certmagic then uses the test directory and orders at the CA after a success there
    [F certmagic v0.25.6 `acmeissuer.go:380-399`, `acmeissuer.go:448`]. The test directory is
    Let's Encrypt's staging one when the CA is Let's Encrypt's production one
    [F certmagic v0.25.6 `acmeissuer.go:194-199`]; for another CA there is none, and a retry
    orders at the CA [F certmagic v0.25.6 `acmeclient.go:178`].
  - **Memory.** The job keeps the failures in memory. A hostname whose row is `failed`, without a
    certificate, counts as failed already, so that a controller that starts or takes the job over
    rehearses it as well.
  - Many hostnames under one domain are best served by one uploaded wildcard certificate, which
    asks the CA nothing ([10](10-operations.md#many-hostnames-under-one-domain)).
- **Uploaded route certificates** [R]: the controller accepts a PEM chain, leaf first, of at most
  10 certificates, each signed by the next, and the leaf's PEM key. The leaf must be valid at the
  upload, must not be a CA, must allow TLS server use (no extended key usage, or `serverAuth`) and
  must name at least one valid DNS name; its key must match it and be ECDSA P-256 or P-384, or RSA
  of 2048 to 8192 bits. The key is stored under the KEK; gateways fetch chain and key together by
  their SHA-256, which the controller computes at the upload.
- **TLS of http routes** [R]: public clients connect with TLS 1.3, or TLS 1.2 with ECDHE and
  AES-GCM or ChaCha20-Poly1305 only, and ALPN `h2` or `http/1.1`; rpmgr's own sessions stay
  TLS 1.3 only ([03](03-connections.md#properties-common-to-all-rpmgr-internal-sessions)). A name
  without a valid certificate gets the gateway's self-signed default certificate, so a browser
  shows a certificate error rather than a reset. A name no route serves gets, with the same TLS
  versions and suites, a valid certificate the gateway holds whose own names cover it, such as a
  route's wildcard certificate, or else the default certificate; the gateway's site-not-available
  page follows, or the route, if one serves the name by the time of the request
  ([03](03-connections.md#port-443-multiplexing), [D87](14-open-decisions.md#engineering)).
- **HTTPS upstreams** [R]: the gateway connects with TLS 1.2 or 1.3 and verifies the upstream's
  chain against the target's CA bundle, or else the gateway host's trust store, and its name
  against the target's server name; a target may also pin the SHA-256 of its leaf's
  SubjectPublicKeyInfo, checked in addition. A CA bundle holds 1 to 100 PEM certificates, each of
  which counts as a trust anchor, so a self-signed upstream certificate can trust itself. A
  connection whose verification settings change is not reused. One still open, of any earlier
  settings, ends at once with what it carries when the target's new settings would not accept it:
  any change but to unverified settings of the same connector. A connection whose dial ends after
  a change is checked against the settings then. When the target or the route's HTTPS goes, its
  connections finish ([03](03-connections.md#timeouts-keepalive-and-backoff)).
- **Unverified HTTPS upstreams** [R]: a target's user may mark it unverified
  ([ADR-0017](adr/0017-upstream-tls-verification-modes.md),
  [D82](14-open-decisions.md#engineering)). The gateway then speaks TLS to it and sends its
  server name, but checks neither chain, nor name, nor pin, and a CA bundle or a pin cannot go
  with it. The tunnel between gateway and connector stays mutually authenticated, and the gateway
  applies a target's settings only to a stream that the target's own connector answered: the
  snapshot names each target's connector, the gateway compares it with the identity of the data
  session the stream came on, and closes a stream for which a connector names another connector's
  target ([03](03-connections.md#http-routes)). So only the network between the connector and the
  target can read and change the traffic, and a compromised connector cannot make the gateway skip
  verification for a verified target's traffic. Nothing is unverified by default; the web UI warns
  when the mode is chosen and marks such targets.
- **Pinned-key HTTPS upstreams** [R]: a target's user may instead pin the key it presents
  ([ADR-0018](adr/0018-pin-the-key-a-target-presents.md)). The gateway then accepts exactly that
  SubjectPublicKeyInfo, by its SHA-256, and checks neither chain nor name; a CA bundle cannot go
  with it, a new key fails until it is pinned, and the settings apply only to the target's own
  connector's streams, as for an unverified target. "Trust the certificate it shows now" asks the
  target's connector to read the certificate: the connector dials it under its local policy and
  sends nothing but a TLS handshake ([03](03-connections.md#service-sketch)), and the user confirms
  the names, issuer, expiry and key fingerprint before the key is pinned. Probing takes
  `routes.write`.
- **The exceptions to the ban** of `InsecureSkipVerify` serve these two modes alone:
  `Settings.Config` of `internal/upstreamtls/upstreamtls.go`
  ([ADR-0017](adr/0017-upstream-tls-verification-modes.md)), the one place that builds a target's
  TLS settings, which the gateway uses for the route's traffic and the connector for the target's
  HTTPS health check, so both check the certificate alike (ADR-0017 names its first home,
  `UpstreamTLS.config` of `internal/gateway/upstreamtls.go`; it moved so that the connector-only
  build, which links no gateway code, shares it, D119; the depguard rule `upstream-tls` of
  `.golangci.yml` lets only the gateway and the connector import the package), and the connector's
  `readCertificate` of `internal/connector/probe.go`
  ([ADR-0018](adr/0018-pin-the-key-a-target-presents.md)).
  `tools/bannedapi` allows them in those functions of the rpmgr module and nowhere else, a module
  nested in the repository included. golangci skips forbidigo's findings in `upstreamtls.go` and
  gosec's G402 finding in `probe.go` (forbidigo does not see the field there); in both files
  `tools/bannedapi` still reports any other use.
- **Route certificates on gateways** [R]: a gateway keeps each fetched chain and key in its state
  directory, readable by the gateway's user only, as any TLS server keeps its keys, so that a
  gateway restarted while the controller is unreachable still terminates TLS. It checks a kept copy
  against its hash before use and removes it once no route needs it
  ([10](10-operations.md#filesystem-layout)). For a TLS server name it uses a certificate listed
  for that route hostname, or, only if none is, one for the wildcard hostname a label up; an
  expired certificate never gives way to another route's.

### CA rotation

- **Intermediate**: automatic, with overlap; agents receive the new chain at their next renewal.
  The new intermediate issues from half the old one's lifetime on; the retired one keeps verifying
  the leaves it issued until it expires, months after their lifetime plus the Reauth grace period.
- **Signing keys**: the next config-signing key is created 90 days before the active key's
  certificate expires and replaces it 60 days before. `Welcome` and enrollment deliver every
  config-signing certificate that has not expired, the next one included, with the intermediates
  that issued them; an agent gets the next key's certificate in its next session, at the latest
  after its next renewal, which reconnects, long before the key signs. When the next key replaces
  the active one, every agent receives its snapshot and deny-list signed by the new key, so its
  stored copies still verify after the old key's certificate expires. The audit-checkpoint key
  follows the same schedule.
- **Schedule**: a singleton job checks it every hour and commits a rotation with an audit record;
  every replica reloads the keys every minute
  ([03](03-connections.md#timeouts-keepalive-and-backoff)).
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
| Format | `rpmgr_enr_<base62(32 random bytes)>_<6-char CRC32 checksum>`, GitHub-style: typos and secret scanners detect it offline. The same scheme is used for `rpmgr_pat_` (personal API tokens), `rpmgr_sat_` (service-account tokens), `rpmgr_ses_` (session tokens), `rpmgr_prs_` (password-reset links) and `rpmgr_inv_` (invitations). |
| Storage | SHA-256 of the token, unique index; the plaintext is shown once |
| Lifetime | **1 hour** default, maximum 30 days |
| Uses | **1** by default; N or unlimited only for ephemeral connectors, always with a lifetime |
| Scope | org, role (connector or gateway), gateway group, labels, ephemeral flag; for re-enrollment (`rpmgr enroll --replace`) the token is bound to **one connector ID** when it is minted (with step-up), so the host cannot choose which identity it replaces. Because the connector ID and SPIFFE ID are reused, the replacement revokes the old certificates **by serial**, not the identity, in the transaction that issues the new one, and records them in the revocation log. [R] A gateway token for a gateway that has enrolled before does the same |
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
curl -fsSLO https://panel.example.com/install.sh && sudo sh install.sh \
  --controller https://panel.example.com --ca-pin sha256:3q2+7w...   # prompts for the token
```

- **Download, then run.** The command saves the script in the current directory and runs the file
  with `sudo`; it does not pipe it into `sudo sh`. Piped, `sudo`'s standard input is the script,
  and sudo-rs, Ubuntu's `sudo` since 25.10, then passes nothing typed at the terminal on to the
  command: the token prompt would wait for good, while classic sudo passes the input on.
  `TestInstall_TypedToken` types the token under both
  ([12](12-testing-and-quality.md#continuous-integration)).
  A script that is piped all the same says so before it prompts, and how to stop and run it from a
  file.
- **Token delivery.** `sudo` resets the environment, and a piped script's standard input is the
  script itself. The install script therefore takes the token from, in order:
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
- The command comes from `GetInstallCommand` ([07](07-api.md#services)): the controller's URL and
  the pin, `--role gateway` for a gateway, and for a connector one `--allow-target` per target it
  may reach and one `--deny-target` per target it must not reach. A target is checked as the local
  policy reads it, and every value is quoted for the shell, so a pasted command runs nothing but
  the installer.

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
  The last disconnect is the session's recorded end, its last-seen time if no controller recorded
  one, or the enrollment if it never connected. [R] The purge deletes the connector's route
  targets with it, and each route left with no target, as a decommission does
  ([06](06-data-model.md#lifecycle-and-deletion)). An ephemeral connector gets no re-enrollment
  token, which would hold it.
- [R] **Tombstones** are deleted after 90 days by the same job, with the records of their
  certificates, which have all expired by then. A tombstone stays while one of its certificates
  has not expired. The job also deletes the route targets a decommissioned connector still has,
  left by a controller from before D78, and each route left with no target.

## Human authentication and sessions

| Topic | Design |
|---|---|
| **Passwords** | argon2id (`x/crypto/argon2.IDKey` [F]), PHC string format. Default **t=3, m=64 MiB, p=4**, 16-byte salt, 32-byte tag (RFC 9106's second recommended option). A semaphore limits concurrent hashes to 4 to bound memory. Low-memory profile for small devices: t=2, m=19 MiB, p=1. The profile is the instance setting `password_hash_profile` (Settings → PKI); `rpmgr controller init` picks the low-memory profile when the host has less than 1 GiB of RAM. Hashes are upgraded on login when parameters change. Length 12–256 characters (Unicode code points), no composition rules. [R] A stored hash is verified only within m ≤ 256 MiB, t ≤ 10 and p ≤ 16, so a tampered row cannot make a login costlier than that; a user without a password costs one hash under the current profile, like any other. |
| **Password reset, invitations** | One-time links (256-bit random, stored hashed). SMTP is optional: without it, an Owner or Admin creates the link for a member of their org, or the Instance Admin for any user ([Account recovery](#account-recovery)), and passes it on; with SMTP, links are also e-mailed and users can request a reset themselves. On the controller host, `rpmgr user reset-password` creates a link without the UI (local administration, [Roles](#roles)). A completed reset revokes all sessions of the user. Setting a password, by a reset link or by changing it oneself, also ends every other unused reset link of the user in the same transaction, so a link made before the change never sets the password again; a link of a disabled user sets none. [R] A reset link lasts **24 h**. Until the first user exists, a **first-user link** (7 days) creates that user, who becomes Instance Admin and Owner of the first org (created as "Default" if there is none); `controller init` prints one, and no such link can be made once any user exists. E-mail addresses are stored and compared in lower case. [R] Mail goes only over TLS 1.2 or later with the system roots: STARTTLS, which the relay must offer, or TLS from the start. A requested reset is answered before the address is looked up and e-mailed in the background, so neither the answer nor its time tells whether the address has an account; an address gets 3 links at once, then one every 20 minutes, besides the limit per IP. An invitation answer says whether the link was also e-mailed; why a relay refused goes to the log. Changing one's own password needs the current one, whose failures count like failed step-ups, and ends the user's other sessions; it is a credential supersession in the revocation log. |
| **MFA** | TOTP (RFC 6238, ±1 step, the last used step is stored so a code cannot be replayed; seed encrypted). WebAuthn/passkeys [V VB-01]. 10 hashed recovery codes. Org policy "require MFA". [R] TOTP as every authenticator app computes it: HMAC-SHA-1, 6 digits, 30 s steps, a 160-bit secret; one authenticator per user, which counts once a first code of it is confirmed and must be removed before another is set up. A code is used up by one conditional update, so the same code tried twice at once works once. Recovery codes carry 80 random bits each, are stored as SHA-256 hashes (their entropy needs no slow hash), work once, and are replaced together. Setting up, removing and replacing are credential supersessions in the revocation log, and end the user's other sessions; the session that made the change stays signed in. New recovery codes end them in the transaction that replaces the codes, whose audit entry says how many ended ([D96](14-open-decisions.md#security-defaults)). Once a user has an authenticator, login takes the second factor in the same request; without it the answer is `UNAUTHENTICATED` with reason `MFA_REQUIRED`, which, as in any two-step sign-in, tells that the password was right, and counts no failure. Under the org policy "require MFA", a member signed in without a second factor is refused in that org (`PERMISSION_DENIED`, `MFA_REQUIRED`) until they sign in with one; setting one up is always possible. |
| **SSO** | OIDC authorization code flow with PKCE (S256), `state` and `nonce`, verified with `go-oidc`. Group claims map to roles. Existing accounts are linked only if `email_verified` is true **and** linking is enabled by an admin. A local break-glass Owner remains when SSO is enforced. |
| **Sessions** | Opaque random token, stored as a SHA-256 hash server-side; no JWTs. Cookie `__Host-rpmgr_session`: `Secure`, `HttpOnly`, `Path=/`, no `Domain`, `SameSite=Lax`. Idle timeout **8 h**, absolute **7 days**. Rotated at login (a session the browser still carries ends) and at step-up. Users can list and revoke their sessions; changing password or MFA revokes all others. |
| **CSRF** | No CORS. State-changing calls are POST only; Connect GET is allowed only for methods marked side-effect free. Go's `http.CrossOriginProtection` (available since Go 1.25 [F Go 1.25.14 `net/http/csrf.go:36`]) allows `Sec-Fetch-Site: same-origin`/`none`, otherwise compares the `Origin` host with `Host`, and lets requests with neither header through as non-browser requests [F Go 1.25.14 `net/http/csrf.go:15-27,137-160`]. rpmgr adds two rules on mutating calls: an `Origin`, when present, must exactly match the configured public origin or one of the configured aliases (scheme included), and only non-simple content types (`application/json`, `application/proto`) are accepted, which a cross-site form cannot send without a CORS preflight. |
| **WebSockets** | Used only for the terminal (Phase 3); logs and events use Connect server streaming. The upgrade requires an exact `Origin` match, the session cookie, and a single-use **30 s ticket** minted by an authorized POST and sent as the first WebSocket message, bound to {session, resource, action}. No credential in the URL. |
| **Step-up** | Fresh WebAuthn user verification, TOTP or password within the last **10 min** is required for: shell, CA/KEK operations, minting enrollment or gateway tokens, creating API tokens or service accounts, MFA/SSO changes (an org's MFA requirement included, [R]), granting Admin or Owner, granting or revoking Instance Admin, recovering another user's account ([Account recovery](#account-recovery)), exporting the audit log, deleting the org, connecting a DNS provider or rotating its token, approving a held DNS zone's plan, uploading a release and creating, advancing, resuming or cancelling a rollout (pausing one takes none, [D121](14-open-decisions.md#engineering)). [R] A user with an authenticator steps up with a second factor; the password alone counts only for a user without one. A step-up gives the session a new token, and failed step-ups count per user like failed logins. A test lists the API methods that make these changes and checks each asks for a step-up; methods whose requests only sometimes make one, such as `UpdateMember` and `CreateInvitation` with Admin or Owner, check it themselves. A personal API token steps up on its own ([D63](14-open-decisions.md#engineering)): `StepUp` with the token checks the owner's second factor, or the password for an owner without one, and the step-up covers that token only, for the same 10 minutes. `StepUp` is the one method of a signed-in caller's own account that a token may call; besides it, a token may make the account recoveries below. |
| **Rate limiting** | Token buckets per IP and per account on login, MFA, enrollment and password reset; enrollment: 10 per minute per IP. A full table of buckets refuses new addresses instead of dropping ones that are being limited. Per-account **progressive delay** instead of hard lockout (attackers must not be able to lock admins out). A dummy hash is computed for unknown users so response times do not reveal which accounts exist. [R] Login and completing a password reset: **10 per minute per IP, burst 20**. Per account: after the **5th failure** in a row each attempt waits, **1 s** at first, doubling up to **60 s**; a success resets it. A limited attempt is refused with the time to wait, before any hash; a wrong address and a wrong password give the same error. Failed API tokens delay their client address the same way, as an account's failed logins do: after the 5th each further token from it waits before any lookup, with the error of any refused token, and a valid token resets it. |
| **API tokens** | Personal (`rpmgr_pat_`) and service-account (`rpmgr_sat_`) tokens, stored hashed. Expiry is mandatory: default **90 days**, maximum **1 year**. Effective permissions = token scopes ∩ the owner's **current** permissions, evaluated per request, so demoting a user immediately limits their tokens. Listable (name, prefix, scopes, last use, IP) and revocable. Accepted only as `Authorization: Bearer`, never in a query string. [R] A personal token belongs to one org and is made only from a session, after a step-up, so a token never makes another; its scopes are permissions its owner's role grants there when it is made (`instance.admin` for an Instance Admin). An org's MFA policy accepts a token made from a session with a second factor. Its last use is written at most once a minute; a revocation goes to the revocation log. A change of its owner's password or second factor, new recovery codes included, ends sessions, not tokens: a token lasts until it expires or is revoked, so an owner who fears a leak revokes their tokens as well ([D96](14-open-decisions.md#security-defaults)). |

### Account recovery

[R] An administrator recovers the account of a user who forgot the password or lost the second
factor ([D95](14-open-decisions.md#security-defaults)):

- **A password-reset link** (`CreatePasswordResetLink`), as above: a reset sets the password only,
  and an authenticator stays.
- **The removal of the second factor** (`RemoveUserTOTP`), for a user who lost both the
  authenticator and the recovery codes: it removes them, ends the user's sessions, as the user's
  own removal does, and keeps their API tokens. It is a credential supersession in the revocation
  log, with the administrator as actor. The user then signs in with the password and sets up a new
  authenticator; an org that requires one makes them do so at once. A user removes their own
  authenticator under their account instead.

Who may, each after a step-up and in the audit log:

| Recovery | Instance Admin | Owner | Admin |
|---|:-:|:-:|:-:|
| Reset link | any user | a user all of whose orgs they hold as Owner, or as Admin where the user is no Owner | the same |
| Second factor | any user | a user all of whose orgs they own | |

An Owner or Admin never recovers an Instance Admin, a user in no org, nor a user who is also a
member of an org they do not hold, so that no org's administrator reaches another org, or the
instance, through an account they share. A user they may not recover is not found; nobody recovers
their own account this way. Further rules:

- **A link is checked again when it is used.** A link an Owner or Admin made sets the password only
  while they may still recover the user, so that it does not outlive the user becoming Instance
  Admin or joining another org, or the maker losing the role.
- **Removing a second factor** needs the administrator signed in, or their token made, with their
  own second factor.
- **An org's MFA policy** binds its Owners and Admins: signed in without a second factor, they
  recover none of its members.
- **Restore review** ([10](10-operations.md#backup-and-restore)): no account is recovered through
  the API while the instance is in review, nor by an Owner or Admin while an org of the user is;
  `rpmgr user reset-password` on the controller host still makes links.
- **Audit:** each recovery is in the instance's audit log and in that of each org of the user
  (`member.reset_link`, `member.mfa_remove`), so that its Owners and Admins see it.
- **Tokens:** a personal API token recovers with the scope `members.write`, within its own org, or
  `instance.admin`, and a step-up of its own ([D63](14-open-decisions.md#engineering)).

## Authorization

### Roles

| Permission | Owner | Admin | Operator | Viewer |
|---|:-:|:-:|:-:|:-:|
| View resources, status, metrics (`org.read`) | ✓ | ✓ | ✓ | ✓ |
| Routes, targets, health checks, access policies, private services and grants (`routes.write`) | ✓ | ✓ | ✓ | |
| Enroll, decommission and revoke connectors; a decommission deletes the routes only the connector serves (`connectors.write`) | ✓ | ✓ | org setting | |
| Gateways, gateway groups, port pools and quotas, domains, certificates and CA bundles (`infrastructure.write`) | ✓ | ✓ | | |
| DNS providers, managed zones and their gates, DNS names; adopt, release, approve plans; view foreign records (Phase 2) | ✓ | ✓ | | |
| Members (Admins cannot change Owners) (`members.write`) | ✓ | ✓ | | |
| Service accounts and their tokens (Phase 2) | ✓ | ✓ | | |
| Audit log read and export; an export also takes a step-up (`audit.read`) | ✓ | ✓ | | |
| Live logs of the org's connectors and gateways (`agents.logs`, Phase 2) | ✓ | ✓ | | |
| Webhook endpoints, their secrets and deliveries (`webhooks.write`, Phase 2) | ✓ | ✓ | | |
| SSO, MFA policy, org settings (`org.write`) | ✓ | | | |
| `connector.shell` (Phase 3) | explicit per-user grant, plus host opt-in, plus step-up | | | |

[R] **Live logs** (Phase 2): logs of a gateway of a group shared with other orgs are for the
Instance Admin only, as they show other orgs' traffic. A host cannot refuse live logs in Phase 2.
Opening a log, and raising its level, is audited as `agent.logs_open` with the level and filter
([D140](14-open-decisions.md#engineering)). As permissions are evaluated per request, a live log,
one long request, admits its viewer again while it runs: a session or token that is no longer
valid ends it with `UNAUTHENTICATED`, and a viewer who lost `agents.logs` or left the org with
`PERMISSION_DENIED`, within the interval of [03](03-connections.md#timeouts-keepalive-and-backoff).
The recheck is not the user's activity: it does not move a session's idle expiry, so a live log
left open in a forgotten tab ends when its session's idle timeout passes.

[R] `connectors.write` reaches routes: decommissioning a connector deletes each route left with no
target, with its hostnames, ports and policy links, so a token with that scope and without
`routes.write` can still delete those routes ([D78](14-open-decisions.md#engineering)). Each
deletion is in the audit log as `route.delete`.

[R] The API names the permission of each row as in brackets. Three more are granted by no org
role: `public` (no sign-in), `authenticated` (any signed-in caller, on their own account) and
`instance.admin` (the Instance Admin role).

[R] **Members.** Only an Owner makes, changes or removes an Owner, and an org keeps at least one
Owner. An invitation is a one-time link (`<public URL>/invite#rpmgr_inv_…`, 7 days) for an e-mail
address and a role: for a new address it creates the account, with the display name and password
the holder chooses; the holder of an existing account signs in as it first. A lower role and a
removal take effect at the next request and are recorded in the revocation log.

**Instance Admin** is a separate, instance-level role for the CA, the KEK, system gateways,
system-org DNS providers and zones, and instance settings. In a single-org installation, the first
user holds both Owner and Instance Admin. [R] An Instance Admin grants and revokes the role, after a
step-up; the instance keeps at least one active Instance Admin. A revocation applies from the next
request and goes to the revocation log, so that a restore re-applies it, unless that would leave the
restored instance without an active Instance Admin ([D95](14-open-decisions.md#security-defaults)).

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
   `option (rpmgr.v1.authz) = { permission: "routes.write", resource_field: "route.id" }`. One
   interceptor resolves the target's org and checks the caller's role. **A method without the
   annotation is rejected at startup** and a test walks the service registry to prove every method
   is annotated ([12](12-testing-and-quality.md#security-testing)), so no method can exist
   without an enforced permission check. [R] The rules of the interceptor:
   - An unknown permission name stops startup, as a missing annotation does.
   - An org permission needs a resource field: an `org_…` ID names the org itself, any other ID
     the org that owns the resource. A caller who is no member of that org gets `NOT_FOUND`, the
     same as for an ID nothing has, so no caller learns what other orgs hold. Instance Admin
     alone is no membership.
   - A member whose role lacks the permission gets `PERMISSION_DENIED`, which names it. Step-up
     is checked last, so a request that would be refused anyway does not ask for it.
   - A token's scopes narrow its owner's roles; a session has all of them.
   - A public method serves a caller whose credentials are not valid as anonymous, so an expired
     session can log in again; every other method refuses such a caller.
   - The request is validated with protovalidate only after authorization.
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
  resolver, so split-horizon DNS and negative caching cannot fake or delay a result. The host's
  own resolver, which finds the zone's nameservers and their addresses, is the operator's and is
  trusted wherever it is. The nameservers themselves are named by the claimed zone, so the queries
  to them, over UDP and TCP, connect only to public addresses, checked at the connect as for HTTP
  proofs below (`internal/egress`): a zone whose NS records point at a loopback, private,
  link-local or metadata address gets no query there. The claim's last error names only the kind
  of failure (no zone, a nameserver's name that does not resolve, an address that is not public,
  no answer in time, an answer without authority with its response code), never an address or a
  nameserver's or resolver's name. [R] As for HTTP proofs, the kinds still tell the claimant
  whether a nameserver's name resolves in the controller's DNS ("does not resolve" against "not
  public"); that much is accepted. A zone whose nameservers are reachable only on the local
  network is marked trusted by the Instance Admin (D13).
- **HTTP proofs reach only public addresses.** The controller fetches
  `http://<domain>/.well-known/rpmgr-challenge/<claim ID>` without following redirects, and
  without a proxy it connects only to a public unicast address: the address it actually dials is
  checked at the connect, so a name that resolves, or is rebound, to a loopback, private,
  link-local, shared (`100.64.0.0/10`), reserved, documentation, benchmarking or multicast address,
  in IPv4-mapped, IPv4-translated, NAT64 or 6to4 form too, is refused (`internal/egress`). A claim
  therefore cannot make the controller probe its own network. A NAT64 prefix an operator chose
  itself (RFC 6052) cannot be told from a public address and is not recognised. The claim's last
  error names only the kind of failure (the name does not resolve, an address that is not public,
  refused, timed out, the HTTP status code), never an address, a resolver or a server's own text,
  as every member of the org reads it. [R] The kinds still tell a member whether a name resolves in
  the controller's DNS ("does not resolve" against "not public"); that much is accepted.
  With a proxy (`HTTP_PROXY`, else `ALL_PROXY`, [10](10-operations.md#ports)) the proxy resolves
  the name and decides where it connects; the proxy's own rules are the boundary then. A domain
  that resolves only on the local network, as in a homelab, is proved with a TXT record or marked
  trusted by the Instance Admin (D13).
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

## Route edge rules

The rules a gateway applies to visitors in Phase 2 beyond IP rules and basic auth
([03](03-connections.md#access-policies), [D130](14-open-decisions.md#engineering)–
[D135](14-open-decisions.md#engineering)). The rules a gateway enforces on a route are gated by
capabilities, so a gateway of an earlier release never serves a route without them
([03](03-connections.md#versioning-and-capabilities)).

- **Reserved path and identity headers.** `/.rpmgr/` on an http route hostname never goes
  upstream, and the gateway removes every header and trailer whose name starts with `Rpmgr-User-`
  from every client request on every http route, also when the name is spelt with `_` for `-`,
  which CGI-style servers read alike, so that only the gateway sets them
  ([03](03-connections.md#http-routes), [D135](14-open-decisions.md#engineering)).
- **Per-client rate limits** count each client address, or IPv6 /64, in bounded tables on each
  gateway ([03](03-connections.md#access-policies)). A UDP source address can be forged at will, so
  udp flows count in tables of their own: a flood of forged sources never fills the table that
  limits real clients of http and tcp routes. When a table is full, a new address passes rather
  than being refused, so that a flood never locks real clients out; the route's own limits still
  bound what passes ([D137](14-open-decisions.md#engineering)).
- **Require-header values** are shared secrets of at least 32 characters, such as a CDN's origin
  header. The controller keeps only their SHA-256, which the gateways receive; a value is
  write-only and never read back. Plain, unsalted SHA-256 suffices only because a value is
  **random**, such as one of `openssl rand -base64 32` or the web UI's generator, and so cannot be
  guessed as a password can; the API refuses a value with fewer than 8 different characters, and
  the docs, the CLI and the web UI say that a value must be random. The gateway compares in
  constant time and removes the header before the request goes upstream.
- **Custom pages** of a gateway group are set only by the group's owner org
  (`infrastructure.write`), for a shared group by the Instance Admin, and audited. A page is
  served under a policy that forbids script and every load from elsewhere, and each placeholder
  is filled in as escaped HTML text, so neither a page's author nor a hostile hostname or
  maintenance message can run script in a visitor's browser
  ([03](03-connections.md#http-routes)). The web UI previews a page through the controller
  ([D136](14-open-decisions.md#engineering)): `PreviewGatewayPage`, which needs the same
  permission, returns a link signed with a key derived from the KEK, which names the group, the
  kind and the page's hash and ends after the time of
  [03](03-connections.md#timeouts-keepalive-and-backoff). The link alone shows the page, rendered
  by the gateways' code with sample values, under the page's own policy plus `sandbox`, so it has
  an opaque origin and runs no script; only the web UI may frame it, and it is not cached or used
  across origins. The controller serves the page only to a frame of its own origin, as a browser
  states in `Sec-Fetch-Dest: iframe` and `Sec-Fetch-Site: same-origin`: opened on its own, framed
  by another site, or requested without these headers, the link shows a 404 text under a policy
  that allows nothing, so an org member's page never appears as a page of the controller's
  hostname. A link of a page that changed since shows nothing.
- **CONNECT listeners** belong to one org ([D130](14-open-decisions.md#engineering)). In the mode
  `plain_basic` the proxy password crosses the network in the clear: anyone on the path between
  client and gateway can read it and use it. rpmgr allows it for clients that speak no HTTPS
  proxy, and the API, the CLI and the web UI warn each time it is chosen. `tls_basic` protects
  the password with TLS, with the versions and suites of http routes
  ([Controller certificates](#controller-certificates)); `none` relies on IP rules alone. The
  passwords are hashed as for route basic auth ([Secrets at rest and in
  logs](#secrets-at-rest-and-in-logs)).
- **WSS hostnames** of gateways lie under a verified domain of the gateway group's owner org, the
  system org for a shared group, so that no org can make a gateway present a name it does not hold;
  a WSS hostname is no route hostname of the group, also not one a wildcard route hostname of the
  group covers, and no other gateway's, and a route cannot take one, nor a wildcard covering one.
  The certificate, from ACME or an upload, is an ordinary public certificate; the data
  session's identity is only the inner mutual TLS to `<gateway-id>.gateway.<td>`
  ([03](03-connections.md#transport-selection)). An uploaded certificate of the org that covers the
  name serves it; otherwise the ACME job obtains and renews one, as for routes, with its challenges
  answered by that gateway alone ([Controller certificates](#controller-certificates)). Once the
  name lies under no verified domain of the org any more, the job renews nothing: the certificate's
  row says why, and the certificate it has serves until it expires.

### OIDC sign-in on routes

Built with P2-M10 ([05](05-features.md#edge-access-control-and-limits)); designed here so that the
gateway's side of P2-M03 leaves room for it.

- **Separate providers.** Route identity providers are their own records, apart from the SSO
  providers of the web UI, so that letting visitors of a route sign in never lets them into the
  control plane. The client secret is kept under the KEK and **never leaves the controller**:
  gateways hold no secret of the provider.
- **Flow.**
  1. The gateway sets a state cookie `__Host-rpmgr-state` (256-bit random) and redirects the
     browser to the controller's public URL, naming the route, the hostname, a hash of the state
     and the **path** the visitor asked for. The controller looks the route and hostname up in its
     own records: a hostname that is not one of the named route's, a route of another org than the
     rule's, a disabled route or one without an `oidc` rule gets an error page from the
     controller, never a redirect.
  2. The controller runs the authorization code flow with PKCE (S256), `state` and `nonce` at the
     route's provider, verified as for SSO ([Human authentication and
     sessions](#human-authentication-and-sessions)). Its `redirect_uri` is fixed: the callback
     under the controller's configured public URL, registered at the provider, never derived from
     the request. It checks the claims against the rule: an e-mail address or domain counts only
     with `email_verified` true; groups come from the provider's group claim. A user the rule does
     not accept gets the gateway's 403 page.
  3. The controller signs an **assertion** and redirects the browser only to
     `https://<hostname>/.rpmgr/oidc`, for the hostname of the route it looked up in step 1. The
     assertion names the hostname, the route and rule, the hash of the state cookie, the subject,
     the e-mail address, the groups the rule names that the user holds, the session's end and the
     path to return to.
  4. The gateway checks the signature, that the hostname is the request's, that the state hash is
     that of its own state cookie, and that the assertion is fresh, then sets the session cookie
     `__Host-rpmgr-auth` to the signed session part of the assertion and removes the state
     cookie. An assertion carried to another browser fails the state check.
  5. The gateway then redirects to the path to return to on the **same hostname**, and only to a
     path: one that starts with a single `/`, without a scheme or authority and without a leading
     `//` or `/\`. Anything else, and a path that does not survive these checks after
     percent-decoding, sends the visitor to `/`. No step ever redirects to a URL taken from the
     request.
- **Signing key.** An Ed25519 key of its own (`route_assertion`), kept and rotated like the other
  keys of the CA ([CA rotation](#ca-rotation)); gateways get the active and next public keys in
  their snapshots.
- **Each request** with a session cookie is checked against the signature, the hostname and the
  session's end, and its claims against the rule **as it is now**, so a tightened rule shuts out
  users it no longer accepts at once. A user removed at the provider keeps access until the
  session ends; that is the weakness of a self-contained cookie, and why the session length is
  bounded ([D134](14-open-decisions.md#engineering)). `/.rpmgr/oidc/logout` clears the cookie.

| Item | Value |
|---|---|
| State cookie | 256-bit random, valid 10 min; `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` |
| Assertion in the redirect | valid 60 s |
| Session (`__Host-rpmgr-auth`) | a setting of each `oidc` rule: 12 h by default, 5 min to 7 d; `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` |
| Groups carried | only those the rule names, at most 50 |

## Connector-local policy

The **local policy** is a file on each connector host that limits what the connector does,
whatever any snapshot says ([ADR-0009](adr/0009-connector-local-policy.md)). It is the one control
that survives a compromised controller, except on an all-in-one, where the controller and the
connector share a process ([below](#connector-local-policy)).

```yaml
# /etc/rpmgr/policy.yaml — owner root, mode 0644; read-only for the rpmgr service user
version: 1
allow_targets:                  # what the connector may dial for routes and private services
  - cidr: 127.0.0.1/32          # example; the default is an empty list (nothing allowed)
    ports: [8080]
  - cidr: 192.168.10.0/24
    ports: [80, 443, 8000-8099]
  - 127.0.0.1:200-500           # an entry may also be a target string
  - 10.0.0.0/16                 # no port: all ports
  - unix: /run/app/app.sock
deny_targets:                   # wins over allow_targets; the same forms
  - 127.0.0.1:345
  - 10.0.9.0/24
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
- **Targets** ([D84](14-open-decisions.md#engineering)) are written the same way in the file's
  string entries, `rpmgr policy`, `rpmgr setup` and the install command: an address or a subnet,
  optionally followed by a port or a port range, IPv6 always in brackets, or an absolute socket
  path: `127.0.0.1`, `10.0.0.1/16`, `127.0.0.1:200-500`, `10.0.0.0/16:443`, `[fd00::/64]:8000-8099`,
  `/run/app/app.sock`. A mapping entry gives `cidr` (an address or a subnet) and `ports` (numbers or
  ranges), or `unix`. A subnet's host bits are cleared, so `10.0.0.1/16` means and is shown as
  `10.0.0.0/16`. An entry **without ports allows all of them**; `rpmgr policy show` says "all
  ports".
- **`deny_targets` wins.** A target that any of its entries matches is refused, whatever
  `allow_targets` says, so with `127.0.0.1:200-500` allowed and `127.0.0.1:345` denied, port 345 is
  refused. A deny entry without ports denies all of them; a deny entry may name a socket. The
  refusal names the deny entry: `not_ready(blocked_by_local_policy: 127.0.0.1:345 denied by
  127.0.0.1:345)`, and the UI's command is then `sudo rpmgr policy remove-deny-target
  127.0.0.1:345`.
- A file that does not parse, or that its group or other users may write, means **deny everything**:
  every target becomes `not_ready(policy_invalid)`; the snapshot itself is still applied. Unknown
  keys and values, a key given twice in an entry, an empty `ports` list, a bad entry in either list,
  and YAML anchors, aliases and merge keys (`<<`) anywhere in the file, are parse errors; the
  editing commands refuse such a file too. An edit changes a node in place, so an alias of it would
  change with it, such as a deny list's ports shared with an allow entry. A connector from before
  D84 reads `deny_targets`, a target string, an entry without ports and a subnet with host bits set
  as such errors, so it fails closed and dials nothing, also after an automatic update rolled it
  back to `.prev` ([10](10-operations.md#install)).
- Checks happen **at dial time on the resolved IP and port** (`net.Dialer.Control`), which defeats
  DNS rebinding. IPv4-mapped IPv6 addresses are unmapped before checking. Link-local and cloud
  metadata addresses (169.254.0.0/16, fe80::/10, `fd00:ec2::254/128`, `100.100.100.200/32`) are denied unless listed
  explicitly, by an entry no broader than the protected range; `0.0.0.0/0` without ports does not
  let them through.
- **The all-in-one's own connector** ([ADR-0019](adr/0019-all-in-one-runs-a-connector.md)) reads
  the policy at the all-in-one boot file's `policy_file`, `/etc/rpmgr/policy.yaml` by default, and
  never dials one of rpmgr's own ports on an address of its host, whatever the policy allows. The
  ports are those rpmgr listens on: the admin listener, 80, 443 (TCP and UDP), tunnel UDP, and
  every route port the gateway has bound. The host's addresses are loopback, the unspecified
  addresses, the addresses of its interfaces, and those the public URL's host and the gateway
  group's public hostnames resolve to, for a host that reaches its public address through its
  router (hairpin NAT); they are looked up again at most every 10 s, and after a failed lookup at
  the next dial. The group's public hostnames are read again at each revision, so a hostname added
  or removed counts without a restart. Such a target is `not_ready(blocked_by_local_policy: 127.0.0.1:7381 is one of
  rpmgr's own ports)`, and the UI offers no command for it. This keeps the metrics out of reach
  and routes from looping through the gateway; the host's other loopback services are reachable as
  far as the policy allows. Another path to these ports, such as a router or a container that
  forwards an address of its own to them (DNAT), is not detected: never allow such a target for
  rpmgr's ports.
- On an all-in-one the policy does **not** survive a compromised controller: the controller runs
  in the same process and could dial anything the `rpmgr` user can. There it limits the routes made
  through the API and the configuration, not an attacker inside the process.
- A target the policy forbids does **not** reject the snapshot. The snapshot is applied, and a
  route none of whose targets is allowed reports `not_ready(blocked_by_local_policy:
  10.0.0.5:5432)`; the UI shows the reason and the exact command to allow it:
  `sudo rpmgr policy allow-target 10.0.0.5:5432`. One disallowed target therefore never blocks
  unrelated changes ([03](03-connections.md#configuration-reconciliation)). A target given as a
  name counts as allowed until a dial is refused on its resolved address; that target then counts
  as blocked until a dial of it is allowed, the policy is reloaded or a snapshot arrives. A route is
  `not_ready(blocked_by_local_policy: <ip:port>)` only while none of its targets on the connector
  is allowed; a blocked target beside an allowed one leaves the route ready, and its streams go to
  the allowed target.
- `rpmgr policy allow-target`, `remove-target`, `deny-target` and `remove-deny-target` edit the file
  as root, under a lock file, atomically and keeping its comments and other keys. A target an entry
  already covers is not added twice; a port goes into the entry of its subnet. A target that only a
  broader entry or a port range covers cannot be removed by splitting the entry: the command says so
  and suggests `deny-target`. Each edit triggers a reload (`systemctl reload`, i.e. SIGHUP); the
  connector also watches the file. On reload it re-evaluates the current snapshot, reports the new
  readiness, and resets the open connections to targets the policy no longer allows, a target a new
  deny entry matches included. A target taken out is then not reachable through a connection opened
  before, such as an upstream's pooled HTTP/2 connection, nor one being set up: a connection is
  recorded before its stream is answered and checked against the policy in force then.
- `rpmgr policy set-auto-update auto|notify|off` and `set-update-channel stable|prerelease` set the
  update keys the same way. They refuse a file the root updater would count as `auto_update: off`
  (a symbolic link, a file root does not own, or one its group or other users may write,
  [D120](14-open-decisions.md#security-defaults)) instead of rewriting it, and trigger no reload:
  the agents read the update keys again at the intervals of
  [03](03-connections.md#timeouts-keepalive-and-backoff), and the updater reads them itself before
  every install ([Over-the-air updates](#over-the-air-updates)).
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
| Route basic-auth credentials | argon2id hash; gateways receive the hash, never the password. Because browsers send basic-auth credentials with **every** request, a gateway verifies with argon2id once and then caches `HMAC-SHA256(gateway-local random key, policy_id ‖ credential_version ‖ len(user) ‖ user ‖ password)` together with the matched user, for 5 minutes in a bounded LRU. The policy ID and credential version keep an entry from being reused on another route, org or credential; the length prefix prevents ambiguous user/password splits; entries for a policy are flushed as soon as a snapshot changes that policy, so tightened policies apply immediately; failed attempts are rate-limited per client IP **before** hashing, and hashing has a per-gateway concurrency cap. This keeps argon2id from becoming a CPU/memory amplifier for unauthenticated clients. [R] The cache holds 10 000 entries; a client address gets 20 verifications at once, refilled at 10 per minute; a gateway runs 2 at once; a request without credentials is refused without one; a gateway verifies only hashes within m ≤ 256 MiB, t ≤ 10, p ≤ 16. The same holds for the proxy passwords of CONNECT listeners (Phase 2) |
| Require-header values (Phase 2) | SHA-256; write-only, at least 32 characters, compared in constant time on the gateway ([Route edge rules](#route-edge-rules)) |
| CA, intermediate, config-signing and audit keys; ACME account key; TLS private keys of public certificates; TOTP seeds; OIDC client secrets; DNS-provider tokens (one per `dns_providers` row, per org); SMTP, webhook and audit-sink secrets (an S3 secret key, a syslog client key) | **Envelope encryption**: a random data key per secret encrypts it with AES-256-GCM (AAD = table, column, row ID); the data key is wrapped by the KEK with AES-256-GCM (AAD = the same plus the KEK version). Rotating the KEK re-wraps only data keys, never the secrets. The KEK version is derived from the key itself (the first 8 bytes of a SHA-256 over it), so it needs no configuration |
| Agent private keys, WireGuard private keys | **Never stored centrally**. Generated on the agent; only public keys reach the controller |

**KEK sources**, in order of preference:

| Source (`kek.source`) | Phase | Notes |
|---|---|---|
| `kms`: HashiCorp Vault or OpenBao Transit | P2 | Plugin interface; cloud KMS (AWS, GCP, Azure) added by demand |
| `systemd-credential`: systemd `LoadCredentialEncrypted=` | P1 | TPM-sealable where available [V VB-03]; needs systemd ≥ 250, otherwise the installer falls back to `file` (VB-03: Ubuntu 22.04 has 249). The credential `<name>` is read from `$CREDENTIALS_DIRECTORY`, in the format of `file`; as newer systemd versions pass it to a service that runs as another user with mode 0440 in the service's group, a credential that its own group may read is accepted, one other users may read is not |
| `file`: a 0600 file | P1 | Containers mount secrets as files. The file holds the base64 encoding of 32 random bytes; symbolic links are followed (container platforms mount secrets that way), but the file must be regular and closed to its group and other users (0600 or 0400) |

**Not** an environment variable: no secret is kept in the environment of a long-running process.
`rpmgr kek rotate` re-wraps all data keys, in one transaction, with every controller stopped: a
running controller holds the old KEK and could neither open the re-wrapped secrets nor seal new
ones under the new KEK. [R] With HKDF-SHA256 and one label per purpose, the KEK
also yields keys that need no storage: the key that authenticates API page tokens. They change
with the KEK.

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
- Proto fields carrying secrets are annotated `(rpmgr.v1.sensitive) = true`. rpmgr redacts them
  itself wherever a message is written out, in audit diffs among others: a string becomes
  `[REDACTED]`, so the record shows that a value was given, and any other value is cleared. The
  standard option `debug_redact` would not do it: Go's protobuf libraries read it nowhere outside
  the descriptor code, so text and JSON output print such fields as they are [F protobuf-go
  v1.36.12: only `types/descriptorpb`, `internal/genid` and `reflect/protoreflect/source_gen.go`
  name it] (VB-04).
- **Whole requests are never logged.** Access logs omit query strings and authentication headers.
- [R] **Live logs** (Phase 2) leave the agent only after the logger's redaction and a second pass
  over the text of each message and attribute, as a message may quote what a field annotation
  never saw ([D145](14-open-decisions.md#engineering), E7). The pass replaces with `[REDACTED]`: an
  `rpmgr_` token prefix and its random part; PEM blocks; the values of `Authorization`,
  `Proxy-Authorization`, `Cookie` and `Set-Cookie`; the values of `password=`, `passwd=`, `secret=`
  and `token=` pairs; and strings shaped like a JWT. A raised level changes what is logged, never what
  is redacted.
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

- **Key custody** (one maintainer, [14](14-open-decisions.md) D10, D48, D126,
  [ADR-0021](adr/0021-offline-file-release-keys.md)):
  - Two Ed25519 **root keys** and the routine **signing key**, generated in the key ceremony before
    v0.1.0 on a live system booted from read-only media with networking off
    ([RELEASING](../RELEASING.md#release-signing-keys)). Each is a minisign key file, encrypted
    with its own passphrase, on offline media: one medium at the maintainer's home with `root-1`
    and the signing key, one off-site with `root-2`. The passphrases are kept apart from the media.
  - A medium is only ever read by that offline live system; signing-key statements and release
    manifests are signed there. No key ever enters CI. A key file can be copied without a trace,
    so this rule is the keys' whole protection. [R] A second copy of each medium, kept with the
    first, guards against a medium that fails.
  - **Either root alone** can sign a signing-key statement (1-of-2), so losing one medium is not
    fatal. A signing-key statement is valid for **12 months**; a new signing key, also one that
    replaces a compromised key, is introduced with a new statement, and the old one expires.
  - Losing both root keys, or their compromise, means shipping a new binary through an out-of-band
    trust path.
  - The same keys signed the v0.x releases of Phase 1, which have no OTA, and sign every release
    with OTA from v0.2.0 on; no release changes the roots
    ([D126](14-open-decisions.md#security-defaults)).
  - Only the real root keys are compiled into release builds. Tests use the build tag `rpmgrtest`,
    which swaps in generated test roots; release builds refuse that tag, and the release job checks
    the key fingerprints printed by `rpmgr version --verbose`
    ([D60](14-open-decisions.md#security-defaults)).
- **Formats** (`internal/release`):
  - **Signatures** are minisign signature files in minisign's default, prehashed form (`ED`: the
    Ed25519 signature of the file's BLAKE2b-512 hash, then a global signature over that signature
    and the trusted comment). The legacy unhashed form (`Ed`) is refused. Keys are minisign public
    keys. [F] minisign 0.12 makes signatures that `internal/release` verifies, and verifies the
    signatures of its test signer; the test vectors in `internal/release/testdata` were made with
    throwaway keys, checked 2026-10-09.
  - **Signing-key statement**, signed by a root:
    `{"statement": 1, "signer": "<minisign public key>", "not_before": "…", "not_after": "…"}`.
    `signer` is the signing key's public key; the name has no "key" in it, which secret scanners
    would read as a secret's name. A key the statement does not know is refused, and it is valid
    for at most 12 months. Its validity is
    checked at the current time, so a signing key stops being accepted when its last statement
    expires; a renewed statement for the same key keeps that key's earlier manifests verifiable.
  - **Each release** carries `signing-key.json`, `manifest.json` and their `.minisig` files. Its
    artifacts are named `rpmgr-<version>-<os>-<arch>`, followed by `-<variant>` for variants other
    than `full`, and by `.exe` on Windows; OS, architecture and variant are lower-case letters and
    digits: `rpmgr-1.4.2-linux-arm64`, `rpmgr-1.4.2-linux-arm64-connector`,
    `rpmgr-1.4.2-windows-amd64-connector.exe` ([D119](14-open-decisions.md#engineering)).
  - **A manifest** must also be well-formed:
    - `seq` at least 1, and an issue time;
    - `version` and `floor` as full SemVer without `v` or build metadata, with `floor` ≤ `version`;
    - a pre-release version only on `prerelease`;
    - at least one artifact, each with OS, architecture, variant, a size above 0 and a lower-case
      SHA-256.

    Keys a manifest has beyond these are ignored, so later formats can add fields.
  - An artifact is accepted only with the manifest's size and SHA-256; reading stops one byte past
    the size.
- **Roots in the binary:** release builds carry the two roots of the key ceremony, since #429
  (D48, D126); a release build without roots verifies no release.
  - `rpmgr version --verbose` prints the minisign key ID and SHA-256 fingerprint of each root
    ([16](16-cli.md)).
  - `rpmgrtest` builds carry two test roots instead. Their private keys are derived from fixed
    names in `internal/release/releasetest`, so no private key is stored.
- `channel` is `stable` or `prerelease`. The root updater installs a manifest only if its channel
  matches the host's `update_channel` in the local policy: a host on `stable` takes stable releases
  only, and a host on `prerelease` takes both. A prerelease therefore never reaches a stable host,
  even through a compromised controller. `variant` is `full` or `connector` (the optional
  connector-only build of `cmd/rpmgr-connector`, Phase 2, [02](02-architecture.md#roles)); the
  updater installs only the variant recorded in `install.json`. Both builds install as the binary
  `rpmgr` (`rpmgr.exe` on Windows). Windows and macOS releases have the connector variant only
  ([D122](14-open-decisions.md#project-and-process)).
- `seq` is a **monotonic manifest number**. Agents persist the highest `seq` they have accepted and
  their version floor, and accept a manifest only if its `seq` is at least that high. `floor` raises
  the persisted version floor; it can be **lowered** only by a manifest with a higher `seq` than any
  seen. A host that has seen none (`seq` 0, set up by `rpmgr setup` without an install script)
  takes no manifest below its floor at all. Replaying an older, genuinely signed manifest therefore
  cannot roll an agent back.

- This works fully offline (air-gapped installations), the verifier is small, and signing keys can
  rotate without a new binary.
- For the wider ecosystem, releases also carry **SLSA provenance** and an **SBOM** (SPDX JSON,
  generated with syft) [V VB-05]. The provenance attestations sign every release file keylessly
  with the release workflow's identity, and no separate signature files are published
  ([D72](14-open-decisions.md#project-and-process)); container images are signed with **cosign**.
  These are not used for in-binary OTA because verifying them needs a transparency-log trust root
  and a large dependency tree.
- Builds: `CGO_ENABLED=0`, `-trimpath`, pinned toolchain, reproducibility check in CI, signed
  `SHA256SUMS`, CI actions pinned by commit SHA.

### Over-the-air updates

OTA covers script installs and standalone binaries on **Linux with systemd**, and replaces the
binary of **every role**: connectors and gateways through a rollout, and controllers and
all-in-ones, started by an Instance Admin, after a backup and before their agents
([D158](14-open-decisions.md#engineering), which supersedes D102;
[Controllers and all-in-ones](#controllers-and-all-in-ones-over-the-air)). Windows and macOS connectors (Phase 2) are
updated by hand; OTA for them is a Phase 3 item ([13](13-roadmap.md#phase-3--advanced)). The
timeouts and size limits named below are in [03](03-connections.md#timeouts-keepalive-and-backoff).

1. The controller fetches release manifests from the **release source**, the GitHub Releases of
   `felix-homelab/rpmgr` (the release check is on by default and can be disabled,
   [14](14-open-decisions.md) D4), or an Instance Admin uploads one on air-gapped installs. It
   verifies the signature and mirrors the artifacts under `/dl/`. Agents never contact the release
   source. **The mirror:**
   - **What it lists:** the daily check asks GitHub's API for one page of the newest releases
     and verifies the manifest of every one of the instance's channel that is newer than the
     oldest kept version and not recorded yet, so that the Instance Admin sees which releases
     exist; an instance on `stable` lists stable releases only, one on `prerelease` both, and a
     manifest signed for `prerelease` counts as a pre-release whatever the listing says. A listed
     release is recorded without its artifacts, which are downloaded once the mirror keeps it.
   - **What it keeps** ([D119](14-open-decisions.md#engineering)): the controller's own version,
     the target of every rollout that is running or paused, and the version the controller ran
     before its last upgrade, each with all its artifacts: both variants (`full` and `connector`)
     for every OS and architecture the manifest names. Phase 1 kept only the controller's own
     version ([D59](14-open-decisions.md#security-defaults)).
   - **What it serves:** `/dl/<version>/` serves `signing-key.json`, `manifest.json`, their
     `.minisig` files and the release's artifacts, and nothing else. A development build serves
     nothing.
   - **When it checks:** at start, then daily, while the release check is on, and when a rollout
     needs a release it has not kept yet, also while the release check is off: creating such a
     rollout, or uploading a manifest the mirror does not hold, starts a check at once
     ([D125](14-open-decisions.md#engineering)). While the release check is on, an Instance Admin
     can also start one at once with "Check now" (`ReleaseService.CheckReleases`), audited, which
     joins a check that runs and waits out a short gap after the last one and the source's rate
     limit ([03](03-connections.md#timeouts-keepalive-and-backoff)); the controller reports when
     its last check ended and how: ok, failed with its error, or off (#890). A failed or rate-limited check is tried again sooner
     ([03](03-connections.md#timeouts-keepalive-and-backoff)). Each controller keeps its own copy
     on its disk, so each one checks; the release's "mirrored" mark tells the time the checking
     controller last held it complete.
   - **How it keeps files:** a file is kept only after the whole chain verifies and the file matches
     its size and SHA-256. The manifest is written last, so a version with a manifest is complete,
     and a failed check keeps what was there. The directory of a version goes once nothing above
     keeps it, also while the release check is off. The controller records its own version in the
     mirror's directory, so that it knows the version it ran before after an upgrade.
   - **Upload and import:** `ReleaseService.UploadRelease` takes a release's signed manifest,
     signing-key statement and their signatures ([07](07-api.md#services)); the artifacts then
     come from the release source, or, on an air-gapped installation, from
     `rpmgr release import <dir>` on the controller host. Import, run as root, gives the files to
     the state directory's owner. An uploaded manifest with a higher `seq` than the release
     source's, such as a signed downgrade signed again so that hosts take it, is the one the mirror
     verifies and serves, with the source's artifacts; recording it clears the release's
     "mirrored" mark until the mirror holds it ([D125](14-open-decisions.md#engineering)).
2. An Instance Admin creates a **rollout** of one release to the connectors and gateways, either
   a **staged rollout** (the advanced mode, [D121](14-open-decisions.md#engineering)) as below, or
   an [easy rollout](#easy-rollouts), a queue of agents updated one after another
   ([D129](14-open-decisions.md#engineering)). Its target and the last item below hold for
   both:
   - **Target:** the controller's own version, or an older release the Instance Admin uploaded on
     purpose (a signed downgrade). A target newer than the controller is refused, so no agent runs
     ahead of its controller, and so is one below the controller's `min_agent_version`
     ([03](03-connections.md#versioning-and-capabilities)), whose agents it would refuse. A
     pre-release is a target only while the instance's update channel is `prerelease`, since every
     host on `stable` would refuse it.
   - **Stages:** the canary agents chosen when the rollout is created, then percentages the Instance
     Admin approves one at a time, then all. An agent's place in the percentages is a stable hash of
     its ID, so a later stage includes every agent of an earlier one.
   - **Gateways** are updated one at a time per gateway group, each after a drain that moves its
     connectors to the group's other gateways ([03](03-connections.md#multiple-gateways)); the
     rollout disables the gateway to drain it and enables it again once its target is done. A
     gateway an operator disabled stays disabled and is skipped, as a group with one gateway has no
     other to move to, which the rollout shows before the stage starts.
   - **A rollback pauses the rollout:** an agent whose updater rolled back stops the stage, and the
     rollout waits until the Instance Admin resumes or cancels it. A target whose agent reports
     nothing for 30 minutes counts as stalled and pauses it too. Agents that are offline, or whose
     local policy says `notify` or `off`, are listed and skipped; they never block a stage.
   - Only one rollout, staged or easy, runs or is paused at a time. Creating, advancing, resuming
     and cancelling one, and adding an agent to one, takes Instance Admin and a step-up, and is
     audited.
3. The controller **offers** the target to each agent of the current stage in its snapshot, but
   only to an agent that announced the capability `ota`
   ([03](03-connections.md#versioning-and-capabilities)), and in an easy rollout only to the agent
   whose turn it is: gateways and connectors on Linux that
   run on their own on a host with the root updater installed (its directory
   `/var/lib/rpmgr-update/` exists and the unit `rpmgr-update.path` is enabled, so that a host the
   v0.1.0 install script or `rpmgr setup --no-unit` left without the units is never offered a
   release nothing would install), never all-in-one's, nor one in the container image, which has no updater. A host with a controller or all-in-one
   is updated by the Instance Admin's own request instead
   ([below](#controllers-and-all-in-ones-over-the-air)), never by a rollout. The offer
   names the version, the controller's public URL (the `public_url` of [10](10-operations.md),
   which `/install.sh` and enrollment use), its manifest's `seq` and its files under `/dl/` with
   sizes and SHA-256; the controller offers a release only while its rollout runs, the agent's
   target is `offered` and the mirror holds the release with its recorded manifest. A rollout of a
   release the mirror does not hold yet offers it to no agent and drains no gateway until it does,
   and a change of the "mirrored" mark of a rollout's target is a configuration change, so the
   snapshots offer the release, or stop offering it, at once. While the mirror does not hold it, no
   agent the release was offered to counts as stalled, and its wait starts afresh when the mirror
   holds the release again ([D125](14-open-decisions.md#engineering)).
   The agent, running as the unprivileged service user, reads the local policy (a gateway the
   host's `/etc/rpmgr/policy.yaml`, for `auto_update` and `update_channel` only): with
   `auto_update: off`, or a policy file that does not load, it declines the offer, and with
   `notify` it reports the update as available; it reads the policy again at the interval of
   [03](03-connections.md#timeouts-keepalive-and-backoff), so that a changed policy takes the
   offer. Otherwise it downloads the signed files from the controller's
   mirror, verifies them as the updater does, declines a release its channel does not take or
   that has no artifact for its OS, architecture and variant, and downloads that artifact with a
   size cap and a free-space check. It **stages** the files in `/var/lib/rpmgr/update/`, removing
   what earlier releases left and writing the manifest last, and reports each step: declined,
   available, downloading, staged, or failed, which it tries again later. The URL is not trusted;
   the signature is: the agent fetches only from `/dl/<version>/` at the controller's public URL,
   over HTTPS with TLS 1.3 and the system's certificate roots, like `/install.sh`, with file names
   it makes itself, and follows no redirect. Integrity comes from the release's
   signatures and the offer's `seq`, which must be the manifest's, not from the connection. The
   public URL, not the endpoint of the control session, is where the agent downloads from: a
   private controller behind a gateway's `controller.passthrough`, and the control-passthrough
   fallback, reach the controller at a name or address its web certificate does not serve. An
   offer whose URL is not `https` with a host is declined. The service user can never write the
   installed binary — otherwise a compromised process could persist a build that ignores the local
   policy.
4. A **root-owned updater** (`rpmgr-update.path` triggering the oneshot `rpmgr-update.service`)
   reads `auto_update` and `update_channel` from the local policy **itself** (it does not trust the
   agent's decision); a policy file that does not parse, that its group or other users may write,
   that root does not own, or that is a symbolic link counts as `auto_update: off`
   ([D120](14-open-decisions.md#security-defaults)). It reads `install.json` and `state.json` by
   the same rule, and stops if either fails it. It opens
   the staging directory through a directory file descriptor with
   `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`, accepts only regular files (`fstat` →
   `S_ISREG`) no larger than the manifest's size and the updater's hard cap (checked before and
   while copying), **copies** them into the root-only `/var/lib/rpmgr-update/staging/` (a plain
   directory of mode 0700 owned by root, else nothing is copied; copies of earlier runs are removed
   first, and each copy is a new file renamed to its final name only once verified), and
   verifies **the copy**: manifest signature, `seq`, version floor, `channel` (against the policy's
   `update_channel`), OS/arch, `variant` (against `install.json`), size and SHA-256. Verifying a
   copy the service user cannot touch removes the time-of-check/time-of-use gap; refusing symlinks,
   FIFOs and oversized files keeps a compromised agent from hanging the updater or filling the
   disk. A version that was rolled back on this host is refused until a manifest with a higher
   `seq` offers it again (D120). A host whose `install.json` lists a controller or all-in-one
   role is checked and backed up first, as
   [below](#controllers-and-all-in-ones-over-the-air).
5. It copies the verified file into the target directory as `.rpmgr.new` (same filesystem, so no
   cross-filesystem rename), fsyncs and re-hashes it, keeps the previous binary as `.prev`, renames
   `.rpmgr.new` over the binary at the path recorded in `/var/lib/rpmgr-update/install.json`
   (`/usr/local/bin/rpmgr` for script installs), and restarts each role service `install.json`
   lists. From Phase 2 a role is restarted by a hand-off ([Socket hand-off](#socket-hand-off-phase-2))
   when the installed release and the running one have it and its unit is `Type=notify`: the
   updater runs `rpmgr handoff <role>` from the installed path, never from the running image, which
   reads `(deleted)` after the rename, and the old process keeps serving until the new one is
   ready, so a lone gateway refuses no visitor connection during an update. Any other role is
   restarted. Before the restart the updater writes the role's hand-off drop-in, into a directory the install
   scripts or setup created (its write set is the binary's directory, its state, the status file and
   the three `rpmgr-<role>.service.d` directories, never a unit)
   ([D155](14-open-decisions.md#engineering)) where it is missing, which is all a host set up
   before the drop-in needs; that first restart is a plain one.
6. The updater polls each role's admin `/readyz`, which reports ready only when the control session
   is established and a snapshot is applied, and counts a role as ready only while systemd has it
   active. If a role is not ready within the readiness window, or its service fails or restarts in
   a loop before then, the updater **rolls back** to `.prev`, restarts the roles again, and records
   the version as failed. A hand-off whose new process is not ready leaves the old process
   serving, so the rollback only puts `.prev` back and restarts nothing for it; a role already handed
   over is restarted by the rollback, which never signals an older process. Before the rename it
   records the install as pending in its own directory, so that a run that a crash or a reboot
   interrupts is finished by the next one: the updater also runs once at boot, checks the roles
   and rolls back if one is not ready.
   A run that finds no staged manifest (the agent writes it last), as at boot or while the agent
   is still staging, does nothing else and reports nothing.
7. The updater writes the outcome to `/run/rpmgr-update/status.json` (root-owned, readable by the
   service user): `updated`, `rolled_back`, `rollback_failed` (the previous binary could not be put
   back, which needs an operator) or `refused`, with the version, the previous one and a
   reason. The agent reads it at start and reports it, and again while a release is staged, at the
   policy recheck interval of [03](03-connections.md#timeouts-keepalive-and-backoff), so that an
   outcome that restarts nothing, such as `refused`, is reported too; the rollout records it. The
   persisted floor and `seq` are raised only after success. They are stored by the updater in
   `/var/lib/rpmgr-update/state.json`, owned by root and not writable by the service user, so a
   compromised agent process cannot lower them ([10](10-operations.md#install)). They are
   **initialised at install time** by the install scripts from the release they verified (its
   version and the `seq` of its manifest), so a freshly installed host is protected against
   replayed old manifests from day one; an installer run on a host that has them raises them and
   never lowers them. `rpmgr setup` knows no manifest: it leaves a state a script wrote, and starts
   a missing one at the binary's own version with `seq` 0. Such a state takes no manifest below its
   floor, whatever that manifest's `seq`, so a replayed manifest of an older version is refused;
   one at or above the floor can only move the host to a validly signed release that is not
   older, and the first update records its `seq`. A development build has no release version and
   gets no state, so the updater refuses every release
   ([10](10-operations.md#hardened-systemd-units)). Afterwards the running version plays no role: a manifest with a higher `seq` may lower the
   floor, which makes **signed downgrades** possible. The automatic rollback to `.prev` is exempt,
   because floor and `seq` are only raised after success.

#### Controllers and all-in-ones over the air

[D158](14-open-decisions.md#engineering). The control plane is updated by the same root-owned
updater, under the same checks (the steps above), and the controller never trusts more than an
agent's offer is trusted: the **signed manifest, `seq`, floor, channel and SHA-256** decide, not
the request that started the update. What differs:

- **Trigger and target.** The Instance Admin requests "Update to x.y.z" for the controller or
  all-in-one, with a step-up, audited like a rollout's steps. The target is a release newer than
  the controller, which the mirror holds with its recorded manifest and the controller's
  `update_channel` takes: never a downgrade, because the database may be migrated and an older
  binary refuses it. The controller
  stages the files itself in `/var/lib/rpmgr/update/` and writes the manifest last, as an agent
  does, so the updater cannot tell who staged them, and verifies them again
  ([D120](14-open-decisions.md#security-defaults)). A compromised controller process can stage no
  release the maintainer's keys did not sign; it can ask for the update of a release that is signed,
  not older than the floor and newer than the `seq` it replaces, which an Instance Admin could ask
  for too. A host whose local policy sets `auto_update` to `notify` or `off` refuses it.
- **Backup first.** Before it replaces anything the updater runs the installed binary's
  `rpmgr backup` ([10](10-operations.md#backup-and-restore)) into `<binary>.backup`, next to the
  binary and its `.prev`, mode 0600, and replaces the backup of an earlier update only when the new
  one is complete. A backup that fails is a refusal: nothing is changed. The archive holds the
  database with its secrets envelope-encrypted and no KEK, as any backup; it lives in the binary's
  directory, which only root writes. **First version SQLite only** (D158): on a PostgreSQL
  controller the updater refuses, naming P2-M08, which provides a backup method; such a controller
  is updated by hand.
- **Restart.** An all-in-one is handed over ([Socket hand-off](#socket-hand-off-phase-2)); a
  controller, which has no hand-off, is restarted and answers nothing for the seconds it takes.
- **Failure.** Before the migration, the old process of an all-in-one serves on and the rollback
  only puts `.prev` back. When the new process ends after migrating the database, or a restarted
  controller is not ready, the rollback **stops the role, asks the previous binary whether the
  database is still at its schema** (`rpmgr migrate` applies nothing then, and refuses a newer
  schema with `ErrUnknownMigration`, which ends it with exit code 3), and only on that code
  restores the backup with `rpmgr restore`
  and starts the previous binary. The status is `rolled_back` and names the restore. An old binary
  never runs on a newer schema; any other failure of the check does not restore, because nothing
  says the schema is newer: the role stays stopped, the status is `rollback_failed` with the
  error, and the operator decides. When the restore fails the role stays stopped, the status is
  `rollback_failed` and its reason names the command that restores the backup. What a restore
  keeps and loses is in [10](10-operations.md#backup-and-restore): writes since the backup are
  lost except the revocations, which are applied again, and sessions are invalidated.
- **Write set and links.** The updater unit also writes the state directory `/var/lib/rpmgr`,
  because `rpmgr backup` and `rpmgr restore` work in the database's directory, but not its
  `update/` staging directory, which stays read-only (`ReadOnlyPaths=`); a boot file whose database
  lives elsewhere makes the backup fail and so the update refuse until a drop-in adds that
  directory ([10](10-operations.md#hardened-systemd-units)). That directory belongs to the
  unprivileged service user, so what root does there must not follow a link the user plants, at any
  moment. `rpmgr restore` therefore does every SQLite operation, and reads the state directory's
  revocation log, in a **staging directory only root writes**, `/var/lib/rpmgr-update/restore/`
  (mode 0700, passed as `--stage-dir`; run by hand it defaults to a new private directory under
  the temporary one), with the database's `-wal` and `-shm` files there too. Only the finished files
  go into the state directory, through an `os.Root` handle that follows no link out of it: each is
  copied into a temporary name created exclusively (a planted name is removed first, never
  written through), the live files are renamed aside and the copies renamed into place, and the
  owner is set through the handle. A live, `-wal` or `-shm` name that is no regular file is refused
  with `ErrUnsafeStateFile` first. A test plants links at every name before the restore and at each
  of its steps. The **backup** touches nothing of the user's directory as root: the updater runs the
  installed binary's `rpmgr backup --out -` as the owner of the state directory (the service user,
  read from the directory's own entry, with no supplementary groups) and streams its standard
  output into root's own file `<binary>.backup.new`, created exclusively with mode 0600 after any
  planted name there is removed, then renamed. A test asserts the credential and that a planted
  link is not written through.
- **Running release.** Both the backup and the restore are those of the running release, so an
  update of a controller or all-in-one starts only from a release that has them, v0.3.0 and later
  (`update.SelfUpdateSince`). A controller on an earlier release is updated by hand once
  (`install.sh --upgrade --restart`); the API refuses with "update this controller by hand once
  (install.sh --upgrade --restart); later updates can start here", the web UI shows that text
  instead of the button, and the updater refuses too.
- **Status.** While it works the updater writes `updating` with a `step` (`verifying`,
  `backing_up`, `handing_over`, `waiting`) to the status file, which the outcome replaces.

#### Easy rollouts

An easy rollout updates the agents an Instance Admin chose, **one after another**, without stages
to approve ([D129](14-open-decisions.md#engineering)). It is meant for small installations, where
a few connectors and gateways are updated at once and watched while they are.

- **Mode.** The instance setting `rollout_mode` (`easy` or `advanced`) picks which kind of rollout
  Settings → Updates starts ([09](09-web-ui.md#settings)). It is `easy` unless an Instance Admin
  set it, so an installation upgraded from a release without the setting gets `easy` too. Each
  rollout records its own mode, so a staged rollout that runs or is paused when the setting changes,
  or when the controller is upgraded, finishes as a staged rollout. The API takes the mode with
  each new rollout, whatever the setting says.
- **Queue.** The rollout holds an ordered queue of agents, the connectors first and then the
  gateways, each by name; the Instance Admin may reorder it before starting it. Its target follows
  the same rules as a staged rollout's. Each agent added must be able to take the release: an
  agent that is built in or decommissioned, or that has not announced `ota`, is refused with its
  reason.
- **One at a time.** The controller offers the release to the first agent of the queue that has
  not had its turn, and to the next only once that one is `updated`, `rolled_back`, `refused` or
  `stalled`. An agent that is offline at its turn, or that declines the offer because its local
  policy says `notify` or `off`, is skipped with its reason at once; the local policy decides on
  each host, as for every offer, and a rollout cannot override it. A gateway drains before its
  update and is enabled again afterwards, and one an operator disabled is skipped, as in a staged
  rollout; one agent at a time keeps the gateways of a group from updating together.
- **A failure moves on.** A rollback, a refusal or a stall (the stall time of
  [03](03-connections.md#timeouts-keepalive-and-backoff), the same as a staged rollout's) marks
  the agent with its reason, and the queue continues with the next agent. A stalled agent that
  reports the release later is marked `updated`. So that a broken release does not fail on every
  agent in turn, the rollout **pauses** after the number of failures in a row that 03 names, until
  the Instance Admin resumes it, which continues the queue, or cancels it.
- **Update on an agent.** **Update** on a connector or a gateway adds it to the end of the queue of
  the easy rollout that runs or is paused, when that rollout's target is the controller's own
  version. When no rollout runs, it starts an easy rollout of the controller's own version with
  that agent alone. It is refused with its reason while a staged rollout runs or is paused, or an
  easy rollout of another release does; an agent already in the queue keeps its place. It works
  whatever `rollout_mode` says. A signed downgrade is started from its release, never from an
  agent.
- **End.** Pausing, resuming and cancelling work as for a staged rollout. Cancelling stops the
  offer to the agent whose turn it is; an install its updater has already begun finishes, and its
  outcome is still recorded. Agents already updated stay on the release, because the version
  floor rose with their update ([step 7](#over-the-air-updates)); taking them back needs a signed
  downgrade. The rollout completes once every agent of the queue has had its turn, and reports how
  many were updated, failed and skipped.

### Install scripts

- `/install.sh` (Linux) is **served by the controller** from an embedded template and downloads from
  the controller's own mirror, on the same endpoint as the UI. It verifies the chain **root key**
  (embedded in the script) → **signing-key statement** → **manifest signature** → artifact
  **SHA-256** with OpenSSL ≥ 3.0, and refuses to install when OpenSSL is missing or older (VB-15,
  resolved in [13](13-roadmap.md#verification-backlog)).
  - **What it trusts:** it embeds the version and the root keys of the controller's own binary. It
    downloads over HTTPS only, from `--controller`'s `/dl/<version>/`.
  - **How it verifies:** with `openssl dgst -blake2b512` and `openssl pkeyutl -rawin` for each
    signature and its trusted comment. The statement must be valid now and for at most 12 months,
    the manifest of that version, and the binary of the manifest's size and SHA-256.
  - **What it can read:** statement and manifest as compact JSON, with the artifact keys in the
    order of the example above (`os`, `arch`, `variant`, `sha256`, `size`), as `json.Marshal`
    writes `release.Manifest`. Anything else it refuses.
  - **Options:** `--controller <url> --ca-pin <pin> [--role gateway|connector]
    [--variant full|connector] [--allow-target <target>]... [--deny-target <target>]...
    [--token-file <file>] [--tcp-bbr] [--verify-only]`.
    `--verify-only` stops after the verification, and needs neither root nor a pin. `--variant
    connector` installs the connector-only build from the manifest's `connector` entry, for the
    connector role only, and records the variant in `install.json`
    ([D119](14-open-decisions.md#engineering)).
  - **What it installs:** the binary in `/usr/local/bin`, the boot file, the policy file, the
    updater's record, state and units (`rpmgr updater install`) and the host tuning
    ([10](10-operations.md#filesystem-layout)). It then enrolls
    with `rpmgr enroll`, which reads the token itself, so the token never passes through the
    script. Last come the unit of `rpmgr systemd-unit`, enabled and started.
  - **A controller that cannot serve installs** (a development build, or no root keys) serves a
    script that says so and fails, because `curl … | sh` would run an error page's empty body and
    exit 0.
- The **global install script**, `deploy/install.sh`, installs the first host from a GitHub release
  ([D74](14-open-decisions.md#project-and-process)). It shares the verification above, root keys
  included: both scripts are rendered from one template (`internal/installsh`), and a test keeps
  the repository's copy equal to the rendering with the keys of `internal/release/roots.go`.
  - **What it trusts:** the script itself is trust on first use, fetched over HTTPS from GitHub; the
    copy attached to a release is pinned to that release's version and carries a provenance
    attestation of the release workflow ([D72](14-open-decisions.md#project-and-process)), which
    `gh attestation verify` checks before it runs. What it downloads, it verifies against the root
    keys it embeds, from `https://github.com/felix-homelab/rpmgr/releases/download/v<version>/`
    only, over HTTPS with curl or wget.
  - **Which release:** the pinned version, or `--version`; the repository's copy asks the GitHub
    API for the latest release, and with `--prerelease` for the latest including pre-releases.
  - **Options:** `[--version <version>] [--prerelease] [--variant full|connector] [--no-setup]
    [--upgrade] [--restart] [--dir <directory>] [--verify-only]`. `--upgrade` replaces the binary
    of a host that has one, installs the updater as below and does nothing else, and keeps the
    host's variant: the one `install.json` records,
    else the one the binary reports ([10](10-operations.md#filesystem-layout)); it refuses to guess
    when it can tell neither, and both scripts refuse an explicit other `--variant`. The global
    script installs the updater's record, state and units with `rpmgr updater install`, also with
    `--upgrade`, which is how a host installed with v0.1.0 gets them; a release from before the
    updater gets only `install.json`, when the host has none;
    `--restart` restarts the rpmgr services that run
    ([10](10-operations.md#upgrades-and-version-skew)).
  - **What it installs,** only after the verification: the binary in `/usr/local/bin` (replaced in
    one rename), the system user `rpmgr`, `/etc/rpmgr`, `/var/lib/rpmgr` and the updater's
    record, state and units (enabled on a host with systemd). It writes no
    configuration, and running it again leaves the user, the directories and the configuration as
    they are. It then offers `rpmgr setup` on the terminal
    ([D75](14-open-decisions.md#project-and-process)).
- There is no `/install.ps1`. Windows and macOS connectors (Phase 2) are installed by hand from
  the verified release download ([10](10-operations.md#install-paths)).
- No third-party download proxy, and no download URL chosen at runtime by the controller.
- Caveat: a compromised controller can serve a malicious install script. High-assurance installs
  should verify the release (GitHub release + `gh attestation verify`) before running it. After
  installation, updates are protected by the compiled-in keys.

### Socket hand-off (Phase 2)

A restart with hand-off passes a role's listening sockets, which may sit on privileged ports, from
the running process to a new one ([03](03-connections.md#restarts-with-socket-hand-off-phase-2),
[ADR-0022](adr/0022-socket-hand-off-by-re-exec.md)). Only the installed binary may receive them:

- **Who triggers it.** `SIGUSR2` to the role's main process, which only root and the service user
  may send; `rpmgr handoff <role>`, `systemctl reload`, the install scripts and the root updater all
  send it. A trigger never names a binary or a descriptor.
- **Which binary.** The old process starts only the binary at the path of `install.json`, or the
  path it was started from, and only if it is a regular file owned by root that neither its group
  nor others may write, in directories that follow the same rule, so the service user cannot put a
  binary of its own there. It passes the descriptors by inheritance to that child alone; no socket
  or file is opened for another process to collect them. Anything else refuses the hand-off. After
  an update or an install replaced the file, Linux names the running image `<path> (deleted)`: the
  old process then starts the same path without the suffix, and only if that passes the same
  check.
- **Which descriptors.** The new process accepts only the descriptors the manifest on its status
  pipe names, checks each one's socket type, listening state and local address against its own boot
  file, and closes, and logs, any other it inherited. It never serves a socket its configuration
  does not name.
- **A connector's `handoff_from`.** The new process of a connector names the old one's `boot_id`
  in `SessionHello.handoff_from`, taken from an environment variable only a process a hand-off
  started reads, and only if it is a hexadecimal string of at most 64 digits. The gateway looks the
  `boot_id` up among the live sessions of the connector whose certificate opened the new session,
  so a session never drains, or learns of, another connector's; a name that matches none is
  ignored and the earlier sessions close as a restart's. A connector the deny-list names is
  refused as ever, and its drained sessions close at once with the next recheck.
- **What the old process keeps.** It keeps its identity and serves its open connections until the
  hand-off drain ends them; the new process uses the identity on disk, as on a restart. The old
  process's control session was superseded, so it learns of no change itself: when the new process
  applies a deny list or a snapshot that revokes, tightens an access policy or removes a route, it
  tells the old one over the status pipe, which then cuts its open connections at once, as
  security beats continuity ([03](03-connections.md#timeouts-keepalive-and-backoff)).
- **Ending the old process's drain** ([D160](14-open-decisions.md#engineering)). The status pipe
  carries the request from the new process, so only a process the old one started can end its
  drain. Through the API it needs the right to change the agent: `infrastructure.write` for a
  gateway and `connectors.write` for a connector, held by the Owner and Admin of the agent's org,
  and for the all-in-one's own agents (`built_in`) the Instance Admin. It needs a step-up, as
  it resets connections, and is audited like every other call that changes state
  (`rpmgr.v1.GatewayService.EndGatewayDrain`, `rpmgr.v1.ConnectorService.EndConnectorDrain`, the
  agent as target). A token needs the scope of the permission. The counts shown are those of the
  agent's own org.
- **Containers** restart without a hand-off: the process is the container's first process
  ([D149](14-open-decisions.md#engineering)).

## Webhooks and the egress guard (Phase 2)

- **Who.** An org's endpoints are managed by its Owners and Admins (`webhooks.write`); instance
  endpoints, which receive instance events, by the Instance Admin
  ([07](07-api.md#webhooks-phase-2)). An org's endpoint receives only that org's events.
- **Envelope.** [R] An event is a thin envelope: its ID, type, time, org, the IDs of its actor and
  subject, a short summary and the names of the fields that changed. It never carries a resource,
  a secret or anything of another org ([D144](14-open-decisions.md#engineering)).
- **Signing.** `Rpmgr-Signature: t=<unix>,v1=<HMAC-SHA256(secret, t.body)>`. A secret is
  `rpmgr_whs_` and 256 random bits, shown once when it is made or rotated, stored under the KEK and
  never read back. After a rotation the old secret signs too, as a second `v1=` value, for the
  period in [03](03-connections.md#timeouts-keepalive-and-backoff), so receivers switch without a
  gap. **Receivers reject signatures older than 5 minutes.** Timestamps are used because receivers
  are third-party HTTP endpoints without mutual TLS; rpmgr-internal authentication never uses them.
  The HMAC is keyed with the secret as it is shown, its `rpmgr_whs_` prefix included.
- **Delivery.** HTTPS only, the receiver's certificate verified against the system roots, with
  TLS 1.3 or 1.2, as for other third-party servers; a URL with credentials in it is not delivered
  to; a redirect is never followed; at least once, each request naming its event in
  `Rpmgr-Event-Id` so a receiver drops duplicates. An endpoint without a successful delivery for the period in 03 is
  disabled, with an event, an e-mail to the org's Owners and Admins and a notice in the UI; only a
  person enables it again ([D143](14-open-decisions.md#engineering)).
- **Egress guard** ([D138](14-open-decisions.md#engineering)). The controller dials every receiver
  through one guard, which checks each address the name resolves to at the moment it dials, so a
  name that changes its answer (DNS rebinding) gains nothing:
  - **Always denied:** loopback, unspecified, link-local (`169.254.0.0/16`, `fe80::/10`), the cloud
    metadata addresses (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`), multicast and
    broadcast, the controller's own addresses (every address of its host's interfaces), and the
    IPv4-mapped, IPv4-compatible, NAT64 and 6to4 forms of each.
  - **Private ranges** (RFC 1918, `fc00::/7`, `100.64.0.0/10` and every other non-global unicast
    range) are denied unless the Instance Admin lists the range in the instance setting
    `webhook_private_ranges`. A refused delivery names the range, which the UI offers to list, but
    never the address the name resolved to, so a webhook does not map the controller's network. A
    listed range never admits an always-denied address.
  - **Instance endpoints and audit sinks**, which only the Instance Admin sets, may reach private
    ranges and loopback; link-local, metadata, multicast and broadcast addresses stay denied
    ([D145](14-open-decisions.md#engineering), E5).
  - **Through a proxy** (`HTTPS_PROXY`, an `http://` or `https://` proxy; `NO_PROXY` applies), the
    controller resolves and checks the receiver itself and asks the proxy to connect to the checked
    address, with the receiver's name for TLS and `Host`. A SOCKS proxy is not used for webhooks:
    such a delivery fails and says so.

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
- [R] **Requests through the public API**: a method marked free of side effects
  (`idempotency_level = NO_SIDE_EFFECTS`) is not recorded; every other request is. Each
  configuration or write transaction it runs appends its entry, as a success, before committing.
  A request that changes nothing, fails or is refused gets its entry in a transaction of its own,
  in the chain of the org the caller is a member of, else in the instance chain. The diff is the
  request as JSON with its sensitive fields redacted, until a method records a before and after.
- [R] **Each change is recorded once.** A service that records a change itself, such as a token
  made or revoked, a member's role, an authenticator or a revoked identity, appends its entry in
  the request's transaction. That entry takes the request's IP, user agent, request ID and diff,
  and its session or token when the request's actor acted. The request's own entry is then left
  out for that transaction.
- [R] **Sign-ins.** A login's entry names the user who signed in, the session they got and the
  factors they used, such as `pwd+otp`. A failed login is an anonymous refusal in the instance
  chain with the address given and the password redacted. It is the same for an unknown address
  as for a wrong password, so the log tells no more than the answer did. A step-up's entry names
  its factor; a failed one names its user. A logout's entry names the session it ends.
- [R] **Token use.** A personal API token's use is recorded when its last use is written, at most
  once a minute per token: its first use, and a use from another address than the last one
  written. Every recorded request a token makes names it as the credential.
- [R] **Enrollments.** A refused or failed enrollment is an anonymous entry in the instance chain
  with the address and the reason, never the token.
- [R] **Floods.** A rate limit's refusal of an anonymous caller, at login or enrollment, is not
  recorded: the limit bounds such requests, and an entry for each would let a flood write the log,
  and lock its chain, at the flood's pace. A metric counts them instead
  ([10](10-operations.md#metrics)).
- Signed **checkpoints** (chain head + count, signed with the audit-checkpoint key) are shipped to an
  external sink (Phase 2: syslog over TLS, a webhook, or object storage with Object Lock; OTLP in
  Phase 3, [D141](14-open-decisions.md#engineering)). The external copy is what makes tampering
  evident: anyone with database write access could recompute a chain.
- [R] A checkpoint's signature covers a version label, the chain's name, the seq, the head's hash
  and the time; the schedule is in the timeout table of
  [03](03-connections.md#timeouts-keepalive-and-backoff). A chain verifies from its genesis, or,
  once retention removed its first entries, from the signed checkpoint just before the first entry
  left. Every checkpoint must verify with a key the CA certified for audit checkpoints at its time,
  and must match its entry while the entry is left, so a chain rewritten under a checkpoint, or a
  tail cut below one, is found.
- **Phase 1 has no external sink.** Checkpoints are signed and stored in the database and in
  `/var/lib/rpmgr/audit-checkpoints.log`, which is included in every backup. Each line of the file
  carries the signer's certificate, so the file verifies with the CA's root and intermediates
  alone. Until an external sink is configured (Phase 2, optional, [14](14-open-decisions.md) D11),
  an attacker with write access to the controller host can rewrite both, so tamper evidence is
  limited to attackers who reach only the database.
- [R] **External sinks** (Phase 2, [D141](14-open-decisions.md#engineering)) are instance-level and
  set by the Instance Admin. Each sink always receives every chain's checkpoints and, if chosen,
  the entries too. Each keeps its own cursor per chain, advanced only after the sink acknowledged a
  batch, so shipping is at least once and a sink that was down catches up from its cursor. An
  append never waits for a sink. A sink has a backlog metric and an alert
  ([10](10-operations.md#suggested-alerts)); the schedule is in
  [03](03-connections.md#timeouts-keepalive-and-backoff).
  - **Syslog**: RFC 5425 framing over TLS only, never UDP or plain TCP; the server is verified
    against the sink's CA bundle. Each message is an RFC 5424 record holding the checkpoint or entry
    as JSON (VB-23).
  - **Webhook**: delivered and signed as a webhook ([Webhooks and the egress
    guard](#webhooks-and-the-egress-guard-phase-2)), with the event type `audit.checkpoint` or
    `audit.entry`. `Rpmgr-Event-Id` is the ID of the checkpoint or entry, so a receiver drops a
    repeat of the at-least-once shipping. The body is the item as JSON with its chain and seq. An
    entry larger than a delivery may be ([03](03-connections.md#timeouts-keepalive-and-backoff))
    is shipped without its `diff` and marked `"truncated": true`, so one entry never holds a
    sink's cursor.
  - **Object storage** (S3-compatible, the client of the revocation log): each checkpoint or batch
    is an object written with `If-None-Match: *` into a bucket with Object Lock in compliance
    mode, so not even the sink's own credentials can rewrite or delete it before the lock ends; a
    bucket without Object Lock, or a store without conditional create, is refused when the sink is
    saved (VB-24). Verification can read the sink back and finds a chain rewritten under a
    checkpoint it holds. The client (`internal/objstore`) signs with AWS Signature Version 4 and
    reads the access key from a file that neither group nor others can read, or from memory
    (unsealed from the KEK by the caller); the secret key never appears in a log line or an error.
    The endpoint is `https` (TLS 1.2 or later, certificate verified against the system roots or the
    sink's CA bundle), or `http` on a loopback address only; a redirect is never followed, so a
    signature does not leave for another host; `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` apply. A
    conditional create that finds the key taken is not an error of the store but the answer `exists`
    (412), and a refusal of Object Lock is any 4xx (AWS answers 403, SILO 400). Limits are in
    [03](03-connections.md#timeouts-keepalive-and-backoff).
- [R] **Export** (Phase 2, `ExportAudit`): an org's chain, for `audit.read` with a step-up, or the
  instance chain for the Instance Admin with a step-up; audited as `audit.export`. The export is
  JSON Lines: a header line (format version, chain, first and last seq, the signers' certificates),
  then each entry with every stored field as in its canonical form plus `prev_hash` and `hash`,
  with each checkpoint in its place. It ends at the newest checkpoint; entries after it are listed
  as an unanchored tail, flagged so, which a later export anchors. `rpmgr audit verify-export
  --ca-pin <sha256>` verifies an export offline against the CA root pin alone: links, hashes,
  checkpoint signatures and their keys' certificates, and that nothing was removed, reordered or
  edited.
- **Webhook signatures** (Phase 2) and their maximum age are under
  [Webhooks and the egress guard](#webhooks-and-the-egress-guard-phase-2).
- Only the audit package writes the audit tables: the store refuses every create, update and delete
  through Ent. On PostgreSQL, the application role has no `UPDATE`/`DELETE` permission on the audit
  table.
- [R] **Retention** is the one deletion. Entries are kept for the instance's audit retention
  ([10](10-operations.md#runtime-settings-ui--settings)). Past it, a chain loses only a whole prefix:
  its entries up to its newest checkpoint whose entry is past the retention, and the checkpoints
  before that one. The chain then verifies from that checkpoint, and the removal is recorded in the
  chain. With PostgreSQL (Phase 2), the deletion runs through a function the schema owner provides,
  since the application role has no `DELETE`.

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
  invalidated; and a new `db_epoch` is generated ([10](10-operations.md#backup-and-restore)). A
  revoked certificate that the restored `issued_certificates` does not hold, because it was issued
  after the backup, is recorded in `revoked_serials` and stays on the deny-list until it expires.
- **Restore fails closed** if the sink's hash chain is broken, or a replica that reported an
  unshipped backlog has an unreachable local log: all API tokens and service accounts are
  suspended, all sessions invalidated, every user must reset their password and set up their second
  factor again, and the instance stays in read-only *restore review* mode. The **Instance Admin** ends the
  instance-wide review with `rpmgr restore confirm` on the controller host; each org's Owner
  re-confirms only their own org's memberships and roles, and an org stays read-only until then.
