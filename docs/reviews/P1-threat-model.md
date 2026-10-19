# Phase 1 threat-model review

This record checks the threat model of [04](../04-security.md#threat-model) against the code at the
end of Phase 1. It is slice 12.4 of [13](../13-roadmap.md#phase-1--mvp). Each "cannot" of the
threat model is mapped to the code that enforces it, the tests that prove it, and its gaps. Each
gap ends in a fix, an issue draft or a decision proposal for the product owner.

## Scope and method

- **Code:** `main` at `c7c2169`, with every Phase 1 slice merged, including two fixes found while
  this record was written:
  - #393, which fixes G1 and G2 below;
  - #397, which serialises the deny-list's refreshes.
- **First reading:** the review started at `09b260a`, the restore review of slice 11.6. It was
  repeated on the code above once slices 11.7 to 11.10, 10.16, 12.1, 12.5 and 12.7 had merged.
- **Evidence:** every Code cell names a file and a function, with a line where it is stable. Lines
  are left out for the two files #393 changed. This review read each cell; they are `[F]` facts of
  this review. A claim it could not check carries `[V]`.
- **Tests:** the named security regression tests are those of
  [12](../12-testing-and-quality.md#security-testing), registered in
  `.github/scripts/security-tests.txt`. Other tests are named where they prove a control.
- **Status values:**
  - **Holds:** the control exists in Phase 1 and a test proves it.
  - **Fixed:** this review found a gap, and the named pull request closes it.
  - **Partial:** part of the control exists, or it exists without a test.
  - **Gap:** the control is missing in Phase 1.
  - **Later phase:** the capability the control protects does not exist in Phase 1, so neither
    does the threat; the phase that adds it adds the control.
- **Read late:** the API's authenticator, which turns a session cookie or a bearer token into the
  API's caller, was at first not read: a read rule of the review environment refuses every file
  whose name starts with `credentials`, its old name. The maintainer renamed it to
  `internal/apisvc/callers.go`, and the review read it then (G7).

## Security goals

| Goal | How Phase 1 meets it | Status |
|---|---|---|
| 1. No shared secrets between components | Agents generate their key and send a CSR (`internal/agent/enroll.go`, `pki.NewKey` at line 87). Controller nodes get a new in-memory key at every start and renewal (`internal/pki/store.go` `CA.NodeCertificate`, line 320). | Holds |
| 2. Mutual TLS 1.3 against a pinned root; every request authorized | Every rpmgr-internal client and server is TLS 1.3 only (`internal/pki/tls.go` `ClientConfig`, `ServerConfig`, lines 70 and 85). The agent endpoint requires a client certificate for every method but `Enroll` (`internal/controller/agentserver.go` `authorizer.authorize`, from line 95). Every public API method is authorized by one interceptor ([One enforcement point](#malicious-user-of-another-org)). | Holds |
| 3. Least privilege | Org scope in the store, roles, token scopes bounded by the creator, routes bound to connectors (rows below). | Holds |
| 4. Bounded blast radius | A gateway serves only the routes and keys of its snapshot. A connector dials only its routes' targets, within its host's local policy. Since #393 it serves a stream only for a route of the opening gateway ([G1](#gaps-and-follow-ups)). | Holds (with #393) |
| 5. Secure defaults | No default password: the first user comes from a one-time link (`internal/accounts/accounts.go` `FirstUserLink`). The KEK is generated at init. `tools/bannedapi` refuses `InsecureSkipVerify` and `Allow0RTT` (lines 29 and 32); `check-go.sh` runs it. Without a policy file a connector may dial nothing (`internal/policy/policy.go` `Defaults`, line 59; `TestPolicy_MetadataAlwaysDenied`, `TestPolicy_AutoUpdateAndChannelDefaults`). Images run as a non-root user ([Supply-chain attacker](#supply-chain-attacker)). | Holds |
| 6. Accountability | Every state-changing API request is audited by the interceptor (`internal/api/audit.go` `Server.newRecord`). Local commands are audited as `local-cli`: backup, restore and `restore confirm` (`internal/controller/backup.go`, `restore.go`, `review.go`), `ca rotate-intermediate`, `kek rotate` and `migrate` (`localadmin.go`). The chains are hashed per org and per instance (`internal/audit/audit.go` `Append`, `Verify`, lines 140 and 293). | Holds; external checkpoints in a later phase (row below) |

## Threat model rows

### Internet attacker

| Cannot (control) | Code | Tests | Status |
|---|---|---|---|
| Call agent APIs without mutual TLS, except `Enroll` | `internal/pki/tls.go` `AgentEndpointConfig` (line 113: a certificate is optional only for `Enroll`); `internal/controller/agentserver.go` `authorizer.authorize`: a method allow-list, each with its certificate rule, `Leave` included | `TestAgentServer_Access`, `TestAgentServer_EveryMethodHasARule` | Holds |
| Guess tokens: 256-bit random, hashed lookup | `internal/token/token.go` `New` (32 random bytes from `crypto/rand`, line 48), `Hash` (SHA-256, line 78); every token table stores only `token_hash` | `internal/token` tests | Holds |
| Guess tokens: per-IP and per-account limits, uniform errors | Logins and resets: `internal/apisvc/auth.go` `Auth.IPLimit` and `Auth.Backoff` (lines 80 and 87). Unknown e-mail and wrong password give one error after one hash (`internal/accounts/accounts.go` `Authenticate`, line 236; `internal/password/password.go` `Verify`, line 103). Enrollment: 10 per minute per address (`internal/enroll/service.go`, line 92) and one "invalid token" for every bad token (line 121). API tokens: 256 bits from `crypto/rand` (`internal/token/token.go`, lines 33 and 53), found by their hash (`internal/accounts/tokens.go` `Tokens.Authenticate`, line 147); malformed, unknown, revoked, suspended and expired tokens and inactive owners all give `ErrToken` (lines 144 to 156), which the API reports as one "the credentials are not valid" (`internal/api/interceptor.go`, line 152); since this review, failed tokens delay their address, after the 5th before any lookup (`internal/apisvc/callers.go` `Credentials.Authenticate`, lines 45 to 56). A guessed token names no account, so the per-account delay does not apply to it. | `TestAuth_Limits`, `TestAuthenticate`, `internal/enroll` tests, `TestTokenScopesBoundedByCreator`, `TestTokens_FailedAddressesWait` | Fixed: API tokens had no per-address limit; now they have one, as 04 states |
| Reach metrics or pprof | `internal/telemetry/admin.go` `CheckAdminAddr` (line 63) refuses all interfaces and public addresses; defaults are loopback (`internal/config/config.go`). No pprof handler exists in Phase 1. | `internal/telemetry` admin tests | Holds. 04 says "bound to localhost"; code and [10](../10-operations.md#ports) also allow a private address ([G4](#gaps-and-follow-ups)) |
| Claim a hostname | Routes refuse a hostname outside the org's verified domains (`internal/apisvc/route.go`, `DOMAIN_NOT_VERIFIED`, line 214); `domains.fqdn` is unique across orgs (`internal/store/ent/schema/domains.go`, line 51) | `TestUnverifiedDomainRejected`, `TestDomains`, `TestDomain_TrustedOnlyByInstanceAdmin` | Holds |

### Network attacker

| Cannot (control) | Code | Tests | Status |
|---|---|---|---|
| Impersonate the controller or a gateway: pinned root, no trust on first use | Enrollment needs the root's pin; every later connection verifies against that root and checks the expected SPIFFE ID (`internal/pki/tls.go` `Expect.VerifyConnection`, line 40) | `TestRejectsUnpinnedCA` (enrollment, control and data sessions), `TestEnroll_BundleWithExtraRootRejected`, `TestTLS_WrongGatewayIDRejected`, `TestSPIFFE_TrustDomainExact` | Holds |
| `InsecureSkipVerify` | Banned by `tools/bannedapi` and by golangci-lint's forbidigo rule (`.golangci.yml`) | `tools/bannedapi` tests; `test-checks.sh` cases | Holds |
| Replay: TLS 1.3, no 0-RTT, no timestamp tokens | TLS 1.3 only (above); `Allow0RTT` banned; Reauth issues and resumes no session ticket (`internal/pki/tls.go`, line 131) | `TestNoReplayableHandshake`, `TestReauth_NoSessionTickets`, `TestTLS_VerifyConnectionOnResumption`, `TestCSR_BoundToConnection` | Holds |
| Read tunnel contents | Data sessions are mutual TLS 1.3 between connector and gateway (`internal/connector/sessions.go`, `internal/gateway/sessions.go`) | `TestRejectsUnpinnedCA` (data-session clause) | Holds |

### Malicious user of another org

| Cannot (control) | Code | Tests | Status |
|---|---|---|---|
| See or change another org's resources: one authorization interceptor | `internal/api/api.go` `Check` (line 138) refuses to mount a method without an authorization option; `internal/api/interceptor.go` `Server.authorize` resolves the resource's org and finds nothing outside the caller's memberships | `TestAnnotations`, `TestCheck`, `TestServer_Authorization`, `TestCrossTenantLeaks` (every method of every service, generated from the registry) | Holds |
| … org-scoped store | `internal/store/ent/schema/scope.go` `scopePolicy`, `filterInterceptor`, `orgMutationHook` (lines 35, 56, 71) | `TestScope_*` in `internal/store/scope_test.go`; `TestForOrg`, `TestScopeCannotBeForged` | Holds |
| … composite foreign keys | `internal/store/compositefk.go` `CompositeForeignKeys`, `RewriteForeignKeys` | `TestOrgForeignKey_RawSQL`, `TestRewriteForeignKeys` | Holds |
| … page tokens of another query | A page token carries a MAC over its position and the query's other fields (`internal/api/helpers.go` `Server.PageToken`, `Server.AfterPage`, line 56). Since #391 only the one encoding `PageToken` makes is accepted: the nightly fuzz run found that line breaks and the unused bits of the last character gave other strings for one token. The MAC never let them reach another position or query. | `TestPageToken`, `FuzzAfterPage` | Holds |
| Escalate: token scopes within the creator's permissions | `internal/accounts/tokens.go` `Tokens.Create` (`ErrScope`, line 75); a token acts with its scopes as far as its owner's role allows | `TestTokenScopesBoundedByCreator` | Holds |
| Escalate: roles only grantable by higher roles | Only an Owner makes, changes or removes an Owner (`internal/accounts/members.go` `Members.Invite`, line 85; `Members.SetRole`, line 193); granting Admin or Owner needs a step-up | `TestMembers_Rules`, `TestInvitations` | Holds as the roles table of [04](../04-security.md#roles) says. An Admin may grant Admin, which the threat model's wording "higher roles" does not allow ([G3](#gaps-and-follow-ups)) |
| Open a shell or log stream on another org's connector | No shell (Phase 3) and no live log stream (Phase 2) exists | `TestShellRequiresOwnershipGrantAndOptIn` (registered, Phase 3) | Later phase |
| Take another org's domain | As "Claim a hostname" above | `TestDomains` (another org's claim on a taken name) | Holds |

### Malicious user in the same org

| Cannot (control) | Code | Tests | Status |
|---|---|---|---|
| Act beyond their role (permission matrix) | `internal/authz/permissions.go` `Grants` (line 65), applied by the interceptor; Operators enroll only with the org's setting | `TestGrants`, `TestServer_Authorization`, the role cases of the `internal/apisvc` tests | Holds |

### Compromised connector

| Cannot (control) | Code | Tests | Status |
|---|---|---|---|
| Serve other routes | A gateway admits data sessions only from connectors its snapshot knows (`internal/gateway/sessions.go` `Sessions.identify`). It opens a route's streams only to that route's connectors (`Sessions.candidates`). The route table is signed (`internal/controller/push.go` `pusher.push`, line 159). | `TestSessions_Admission`, `TestSessions_ReadinessGatesStreams`, `TestVerify_Refused`, `TestBadSnapshotKeepsLastKnownGood` | Holds |
| Read other agents' configuration | Snapshots are compiled per agent (`internal/snapshot/snapshot.go` `Compiler.Compile`, line 54). Large items are served only when one of the caller's own snapshots names them (`internal/controller/fetch.go` `Sessions.FetchResource`). | `TestCompile`, `internal/controller` fetch tests, `TestCrossTenantLeaks` | Holds |
| Reach private services without a grant | No private services exist in Phase 1 | `TestRelaySeesCiphertextOnly` (registered, Phase 2) | Later phase |
| Survive revocation | The controller revokes, sends the deny-list to every session and ends the revoked agent's session with `Goodbye{revoked}` (`internal/controller/deny.go` `Sessions.applyDeny`, line 129). Gateways close the data sessions of a denied connector (`internal/gateway/sessions.go`). Renewal checks the database (`internal/pki/store.go` `CheckRenewable`, line 381). Agents keep the deny-list across restarts and epochs. An agent revokes itself with `rpmgr leave`; `Control.Leave` takes only a valid certificate (`internal/controller/leave.go` `Sessions.Leave`, line 26). | `TestRevoke_Certificate`, `TestRevoke_Identity`, `TestDenyList_AppliedDespiteRejectedSnapshot`, `TestDenyList_PersistedAcrossGatewayRestart`, `TestReauth_ExpiredWithinGrace`, `TestRestore_RevocationsReapplied`, `TestLeave` | Holds |
| … a race between two deny-list refreshes | A revision check's refresh that read the database before a revocation's commit could store its older list after the newer one. Until the next revision check, a certificate revoked a moment before would then have passed the controller's TLS check. `Sessions.refreshDeny` is now serialised by `denyMu` (`internal/controller/deny.go`; #397). | `TestDenyList_ConcurrentRefreshes`, `TestDenyList_HelloDigest` | Fixed (#397) |
| Exhaust a gateway: a stream limit per data session and a cap on one connector's data sessions | Each data session has a stream limit: `MaxIncomingStreams` (`internal/tunnel/quic.go`, line 134) and HTTP/2's limit (`internal/tunnel/h2.go`, line 26). The gateway opens streams without waiting. Since #393 a gateway also caps the data sessions of one connector identity before the handshake ([03](../03-connections.md#establishment); `internal/gateway/sessions.go` `Sessions.admits`, `MaxConnectorSessions`). Bandwidth limits are Phase 2 ([05](../05-features.md#edge-access-control-and-limits)), as 04 now says. | `TestH2_AdmissionUnderBudget`, `TestFlowControl_StalledStreamsDoNotFreezeSession`, `TestH2_IdleStreamMemoryBounded`, `TestSessions_ConnectorCap` | Fixed (#393, [G2](#gaps-and-follow-ups)) |

### Compromised gateway

| Cannot (control) | Code | Tests | Status |
|---|---|---|---|
| Read private-service traffic | No private services exist in Phase 1 | `TestRelaySeesCiphertextOnly`, `TestPrivateUDP_GatewaySeesCiphertextOnly` (registered, Phase 2) | Later phase |
| Obtain routes or keys of other gateway groups | Per-agent snapshots and per-snapshot item fetches, as above; a gateway's snapshot holds only its group's routes and their certificates | `TestCompile`, `TestCrossTenantLeaks` | Holds |
| Make a connector dial an arbitrary address, or a target of another gateway group's route | `StreamOpen` names a route; the connector dials only that route's targets (`internal/connector/targets.go` `Targets.open`, line 326), through the local policy at dial time (`internal/policy/policy.go` `Control`, line 235). Since #393 the connector serves a stream only for a route its snapshot lists for the opening gateway (`internal/connector/sessions.go` `Sessions.accept`, `Sessions.serves`; [03](../03-connections.md#one-stream-per-user-connection)). A route a newer snapshot takes from the gateway is accepted for the route drain period. | `TestTargets_Codes`, `TestTargets_BlockedNeverDialled`, `TestOpenRequest_Semantics`, `TestH2_ConnectorInitiatedStreams`, `TestSessions_StreamsOnlyForTheGatewaysRoutes` | Fixed (#393, [G1](#gaps-and-follow-ups)) |
| Impersonate a connector or another gateway | Role and ID are part of the SPIFFE identity, and every peer is checked against the expected one (`Expect.VerifyConnection`; `Sessions.identify` on the gateway) | `TestTLS_WrongGatewayIDRejected`, `TestGateway_PerGatewayTunnelEndpoints`, `TestSPIFFE_TrustDomainExact` | Holds |
| Open shells | No shell exists in Phase 1 | `TestShellRequiresOwnershipGrantAndOptIn` (registered, Phase 3) | Later phase |

### Compromised controller

| Cannot (control) | Code | Tests | Status |
|---|---|---|---|
| Make a connector exceed its local policy (`allow_targets`) | The connector checks every dial, on the resolved address, against its own policy file (`internal/policy/policy.go` `Control`). A blocked route is reported as not ready, never dialled. Since #388, a reloaded policy also resets every relayed connection to a target it no longer allows (`internal/connector/targets.go` `Targets.Recheck`, line 161). That includes an upstream's pooled HTTP/2 connection opened before. | `TestPolicy_MetadataAlwaysDenied`, `TestTargets_BlockedNeverDialled`, `TestTargets_PolicyReloadResetsBlocked`, the e2e cell `TestLocalPolicy` | Holds |
| Enable shell, functions, virtual-network routes, P2P or listeners | None of these exists in Phase 1 | — | Later phase |
| Install an unsigned or older binary | Agents do not update themselves in Phase 1; the OTA tests are registered for Phase 2. The release chain is verified against compiled-in root keys (`internal/release/release.go` `Verify`, line 67), by the controller's mirror and by `/install.sh`. An older controller refuses a database that holds a migration it does not know (`internal/store/migrate.go`, `ErrUnknownMigration`, slice 12.5). The root keys are still empty (`internal/release/roots.go`) until the maintainer makes them (D48). | `internal/release` tests, `test/installsh` `TestInstall`, `TestMigrate_UnknownMigrationRefused`; `TestOTA_*` (Phase 2) | Later phase for OTA; the release keys are a maintainer action before v0.1.0 (#170) |
| Read agent private keys | Keys are generated on the agent and never leave it (goal 1) | `TestCSR_BoundToConnection`, enrollment tests | Holds |

### Database dump without the KEK

| Cannot (control) | Code | Tests | Status |
|---|---|---|---|
| Use passwords | argon2id in PHC format (`internal/password/password.go` `Hash`, line 84) | `internal/password` tests | Holds |
| Use session, API, enrollment, reset or invitation tokens | Only SHA-256 hashes of 256-bit tokens are stored (`token.Hash`) | `internal/token` tests | Holds |
| Use CA, ACME, TOTP and other secrets | AES-256-GCM envelopes under the KEK, bound to table, row, column and KEK version (`internal/secret/envelope.go`). CA keys: `internal/pki/store.go`, line 107. ACME storage: `internal/acme/storage.go`, line 78. TOTP seeds, uploaded keys and SMTP password: `seed_enc`, `key_enc` and `value_enc` in the schema. OIDC comes in Phase 2. | `internal/secret` tests, `TestSecretsNeverLogged` | Holds. Hygiene: `ca_keys.key_enc` is not marked `Sensitive()` in the Ent schema; it holds ciphertext only ([G6](#gaps-and-follow-ups)) |
| Keep using a KEK after its rotation | `rpmgr kek rotate` re-wraps the data key of every sealed column, with every controller stopped (`internal/controller/localadmin.go` `RotateKEK`, which takes the controller lock). `rpmgr kek status` lists the rows still under an older KEK, by `secrets_meta` (`StatusKEK`). `rpmgr ca rotate-intermediate` replaces the issuing intermediate (`RotateIntermediate`). | `TestKEK_StatusAndRotate`, `TestKEK_StatusWithoutKEK`, `TestSealedColumnsCovered`, `TestCA_StatusAndRotate` | Holds |

### Holder of a stolen DNS-provider token

DNS automation is Phase 2 ([15](../15-dns.md)); its tests are registered as `TestDNS_*`. Later
phase.

### Malicious insider with Admin role

| Cannot (control) | Code | Tests | Status |
|---|---|---|---|
| Use the shell on hosts that did not opt in | No shell exists in Phase 1 | — | Later phase |
| Read secrets back | Secret fields are write-only: requests mark them `sensitive`, and answers carry at most a flag such as `smtp_password_set`. Uploaded certificate keys and basic-auth hashes are never returned. | `TestSecretsNeverLogged`, `internal/apisvc` settings and certificate tests | Holds |
| Act unnoticed | Hash-chained audit log per org and instance. Signed checkpoints go to the database and to `audit-checkpoints.log` (`internal/controller/checkpoints.go`). Phase 1 has no external sink, as [04](../04-security.md#audit-log) states. | `TestVerify_DetectsTampering`, `TestVerifyChain_Checkpoints`, `TestCheckpointJob`, `TestCheckpointLog` | Partial, as documented: an attacker with the controller host can rewrite the database and the file together until the external sink of Phase 2 |
| Get revoked access back through a restore | A restore re-applies every revocation logged after the backup. One that may be incomplete fails closed into restore review (`internal/controller/restore.go`). During the review, no API call ends the instance-wide review; `rpmgr restore confirm` on the controller host does (`internal/controller/review.go` `ConfirmRestore`). An org's Owner confirms only their own org. The web UI shows the review and an Owner's checklist (`web/src/components/restore-review.tsx`, `web/src/pages/org.tsx`). | `TestRestore_RevocationsReapplied`, `TestRestore_IncompleteLogFailsClosed`, `TestRestore_OrgOwnerCannotEndInstanceReview`, `TestServer_RestoreReview`, `web/src/components/restore-review.test.tsx` | Holds |
| Grant Owner | Owner-only (row "Escalate" above) | `TestMembers_Rules` | Holds |
| Skip step-up for dangerous actions | Methods with `step_up` in their authorization option need one within 10 min (`internal/api/interceptor.go` `stepUp`); a few requests need one only for some values (`api.RequireStepUp`) | `TestServer_Authorization`, `TestAuth_MFA`, the step-up tests of `internal/apisvc` | Holds |

### Supply-chain attacker

| Cannot (control) | Code | Tests | Status |
|---|---|---|---|
| Ship an update agents install: signing keys offline, apart from CI | No signing key enters CI. The release workflow builds a draft release with the unsigned manifest, and the signer signs it offline (`.github/workflows/release.yml`; `tools/releasemanifest`; the interim key ceremony in RELEASING.md, D48). Release builds ignore the `rpmgrtest` tag, and an artifact with test roots is refused (`.github/scripts/build-release.sh`, `check-release-artifacts.sh`, D60). | `internal/release` tests, `tools/releasemanifest` tests, `test-checks.sh` cases of the release scripts | Holds; agents' OTA in a later phase; the keys themselves are a maintainer action (#170) |
| Redirect downloads usefully | The signature is trusted, not the URL: the mirror and `/install.sh` check root → statement → manifest → SHA-256 | `internal/release` tests, `test/installsh` `TestInstall` | Holds |
| Go unnoticed: `go.sum`, govulncheck, SBOM, SLSA provenance, reproducible build, actions pinned by SHA | `go.sum` is committed. `check-govulncheck.sh` runs in CI's go job. `check-workflows.sh` requires full commit SHAs. On a tag, two builds on runners of two architectures must be equal byte for byte, also nightly (`check-reproducible.sh`). `check-release-tag.sh` checks the tag and the changelog. The SBOM comes from syft (`release-sbom.sh`), the SLSA provenance from `actions/attest-build-provenance`, whose attestations sign every artifact, the SBOM and `SHA256SUMS` keylessly (since D72, in place of separate cosign signatures). | `test-checks.sh` cases of the checks; the nightly reproducibility run | Holds. See [G5](#gaps-and-follow-ups) for what blocks a merge |
| Tamper with the container images | Distroless static base pinned by digest, as a non-root user (`Dockerfile`). Multi-arch images get keyless cosign signatures and SLSA provenance (`.github/workflows/images.yml`). Dependabot watches the base image. | `test/images` `TestImage` (every role starts as the non-root user; an all-in-one serves on 80 and 443 as that user) | Holds |

## What the design does not protect against

Each statement of [04](../04-security.md#threat-model) still holds and is stated there plainly:

- **Gateway plaintext:** a compromised gateway sees the plaintext of the HTTP routes it terminates.
  Passthrough routes exist (`internal/gateway/passthrough.go`).
- **Re-routing by the controller:** a compromised controller can re-route a public hostname and
  obtain certificates for it. DNS providers come in Phase 2.
- **Cloudflare proxying:** it is Phase 2; nothing in Phase 1 proxies through Cloudflare.
- **Connector hosts:** a compromised connector host is out of scope beyond its own identity and
  routes.
- **Denial of service** against public gateways is limited, not solved. #393 adds the cap on one
  connector's data sessions. The nightly chaos test checks that no byte changes and that routes
  answer again after restarts, kills, clock jumps, latency and loss (`test/e2e`
  `TestChaos`, `TestMatrix`, slice 12.1). Upgrades between releases under live traffic are
  tested by `TestUpgrade` (slice 12.7).

## Gaps and follow-ups

The finding text is kept as found at `09b260a`, so the record shows what the review found.

| ID | Severity | Gap | Proposal | Status |
|---|---|---|---|---|
| G1 | Medium | A connector serves a `StreamOpen` for any of its routes from any gateway it has a data session with. A compromised gateway can reach the targets of the connector's routes in other gateway groups (`internal/connector/sessions.go` `Sessions.accept`; `internal/connector/targets.go` `Targets.open`). | Issue draft 1 | Fixed in #393: `Sessions.accept` refuses a stream for a route the opening gateway does not serve, with a grace of the route drain period |
| G2 | Medium | 04 claims per-identity stream and bandwidth quotas. Phase 1 limits streams per data session only. A connector the gateway knows can open any number of data sessions. Bandwidth limits are Phase 2. | Issue draft 2; decision proposal 1 | Fixed in #393: a per-connector cap on data sessions, its value in 03; 04 reworded with bandwidth limits in Phase 2 |
| G3 | Low | The threat model says roles are grantable only by higher roles. The roles table and the code let an Admin grant Admin. | Decision proposal 2 | Fixed: 04 reworded ([D66](../14-open-decisions.md#security-defaults)) |
| G4 | Low | The threat model says the admin listener is bound to localhost; the code and 10 also allow a private address. | Decision proposal 3 | Fixed: 04 reworded ([D67](../14-open-decisions.md#security-defaults)) |
| G5 | Low | The required status checks are only `pr-rules`, `lint`, `docs` and `secrets`. A failing go, govulncheck, store or e2e job does not block a merge mechanically; only the merge process does (D64). | Decision proposal 4 | Decided: advisory until v1.0.0, required from then on ([D68](../14-open-decisions.md#project-and-process)) |
| G6 | Low | `ca_keys.key_enc` is not marked `Sensitive()` in the Ent schema, unlike the other sealed columns. It holds ciphertext, so a printed row leaks no key. | Issue draft 3 | Fixed: `key_enc` and also `api_requests.response_enc` are `Sensitive()`, and `TestSecretColumnsAreSensitive` requires it of every sealed column |
| G7 | Low | The API's authenticator (`internal/apisvc/credentials.go`, now `callers.go`) was not reviewed. Unchecked were limits and uniform errors for bearer tokens, and how sessions and tokens become a caller. | Issue draft 4 | Fixed: reviewed after the rename. Failed API tokens had no per-address limit, which `Credentials.Failures` now adds (`TestTokens_FailedAddressesWait`). The rest holds: a token counts only as `Authorization: Bearer` (`callers.go`, line 40) and acts with its owner's current role in its org and its scopes (`internal/accounts/tokens.go`, line 162; `TestTokenScopesBoundedByCreator`); a suspended token is refused (line 148; `TestRestore_OrgOwnerCannotEndInstanceReview`); a cookie becomes the user's live session with their current memberships, refused for a disabled user (`internal/websession/authenticator.go` `Sessions.Authenticate`; `TestAuthenticate`, `TestSessions_Revoke`), and cross-site requests are refused (`internal/api/csrf.go`; `TestCSRF`) |

### Issue drafts

1. **`fix(connector): accept a stream only from a gateway that serves its route`** (G1; done in
   #393). The connector's snapshot names, per gateway, the routes it serves, and a `StreamOpen` for
   any other route gets `ROUTE_UNKNOWN`. Test: a gateway of group A opens a stream for a route of
   group B on a connector that serves both, and is refused. Docs: 03 and 04.
2. **`fix(gateway): cap the data sessions of one connector`** (G2; done in #393). A gateway admits
   at most a fixed number of data sessions per connector identity and refuses more before the
   handshake. The value lives only in 03. Test: a connector above the cap is refused, and its
   existing sessions keep working.
3. **`refactor(store): mark sealed CA keys sensitive`** (G6; done). `CAKey.key_enc` gets
   `Sensitive()`, as `seed_enc`, `key_enc` and `value_enc` have. Generated code only; no migration.
4. **`refactor(apisvc): rename credentials.go`** (G7; done, to `callers.go`). Rename it, for example
   to `callers.go`, so that review tools that refuse files named `credentials*` can read the API's
   authenticator. Then review it against the "Internet attacker" row: per-IP limits and uniform
   errors for bearer tokens.

### Decision proposals

1. **Quotas in the threat model** (G2; accepted). Reword the compromised-connector row of 04 to
   "per-session stream limits and a per-connector session cap (Phase 1); bandwidth quotas (Phase
   2)". #393 did so together with the cap. [R] Accept #393's wording.
2. **Role grants** (G3; accepted as D66). Reword "roles only grantable by higher roles" to "Owner
   only grantable by an Owner; Admin and lower by Owners and Admins, Admin and Owner with step-up".
   This matches the roles table and the code. [R] Reword.
3. **Admin listener** (G4; accepted as D67). Reword "admin listener bound to localhost" to "admin
   listener never on a public address (loopback by default)", as 10 states. [R] Reword.
4. **Required checks** (G5; accepted as D68). Add `go`, `store` and `e2e` to the required status
   checks of `main`, or record that D64's selective CI keeps them advisory until v1.0.0 and the
   merge process guards them. [R] Record it under D64, and require them again from v1.0.0.

## Open items

- **Maintainer actions before v0.1.0** (#170):
  - ~~the offline release root and signing keys, compiled into `internal/release/roots.go`~~
    **Done** (2026-10-12, `eda22a1`): the interim release root keys;
  - ~~VB-19 against Let's Encrypt staging~~ **Moved by D98** to the first release with DNS-01.
