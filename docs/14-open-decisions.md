# 14 — Open decisions

> Status: design, not implemented. **No decision is open as of 2026-10-06.** Each row records a
> decision that was open, the options, the outcome and where the outcome is written down. A new
> open question gets the next free number and a recommended default, which the other
> documents then assume; it is closed by recording its outcome here
> ([CONTRIBUTING](../CONTRIBUTING.md#feature-documentation-checklist)).
>
> Decisions that depend on a measurement (D17–D20) are closed by a **pre-agreed rule**: the
> spike's result applies the rule and leaves nothing to decide
> ([13](13-roadmap.md#phase-0--spikes)).

## Product and project

| # | Decision | Options | Outcome | Recorded in |
|---|---|---|---|---|
| D1 | **License** | AGPL-3.0, Apache-2.0, MPL-2.0, proprietary | **Apache-2.0** for code and documentation. Contributions under the same license with a Developer Certificate of Origin sign-off; no CLA; SPDX headers in source files. This is not legal advice | [LICENSE](../LICENSE), [README](../README.md#license), [CONTRIBUTING](../CONTRIBUTING.md#license-sign-off-and-third-party-code) |
| D2 | Project, binary and package name | `rpmgr`, other | **`rpmgr` everywhere**; `rpm` collides with the RPM package manager | [ADR-0001](adr/0001-name-rpmgr.md) |
| D3 | Repository hosting | GitHub `felix-homelab`, a self-hosted GitLab, both | **GitHub `felix-homelab/rpmgr`**, renamed from `rpmgr-dev`; no mirror. Go module path `github.com/felix-homelab/rpmgr`; CI on GitHub Actions; Dependabot | [CONTRIBUTING](../CONTRIBUTING.md#repository-settings), [08](08-software-stack.md#build-packaging-delivery) |
| D4 | Telemetry and update checks | on, opt-in, off | **No telemetry, ever.** The controller's **release check is on by default**: once a day it fetches the signed release manifest from GitHub Releases with a plain request that sends no data; it can be switched off in Settings → Updates; air-gapped installations upload the manifest. Only controllers fetch releases; agents download from their controller's mirror. Changed from the earlier default "off", which contradicted D6 | [10](10-operations.md#ports), [04](04-security.md#over-the-air-updates) |

## Security defaults

| # | Decision | Options | Outcome | Recorded in |
|---|---|---|---|---|
| D5 | Connector-local policy after a non-interactive install | nothing allowed; loopback only; allow private ranges | **Nothing allowed** (`allow_targets: []`); targets are added with installer `--allow-target` flags, the interactive prompt, or `rpmgr policy allow-target`. Loopback is not a safe default: loopback-only services are often the least protected | [04](04-security.md#connector-local-policy) |
| D6 | Default `auto_update` when the policy file does not set it | `auto`, `notify`, `off` | **`auto`**, with `update_channel: stable`. The installer always writes both keys explicitly, so the built-in default applies only to a missing file | [04](04-security.md#connector-local-policy) |
| D7 | Root CA key storage | online, encrypted under the KEK; offline | **Online, KEK-encrypted**, with `rpmgr ca offline-root` for high-assurance installs | [04](04-security.md#ca-hierarchy) |
| D8 | Leaf certificate lifetime and expired-certificate grace | 1–30 days; grace 0–90 days | **7 days**, renewal at 50 %; **30-day** grace with the same key. Both are instance settings in Settings → PKI (lifetime 1–30 days, grace 0–90 days, 0 disables) | [04](04-security.md#leaf-certificates) |
| D9 | Shell model | built-in PTY over the control session; SSH over a private service; both | **SSH over a private service** as the documented way in v1; a built-in shell only in Phase 3, behind host opt-in, per-user grant and step-up | [04](04-security.md#connector-local-policy), [05](05-features.md#advanced-phase-3) |
| D10 | Release-signing key custody | one maintainer; two people with hardware tokens; HSM/KMS | **One maintainer** (D27): two offline Ed25519 root keys on **two hardware tokens**, either of which can sign a signing-key statement alone (1-of-2); one token is kept off-site. The routine signing key is on a third token; signing-key statements are valid for **12 months**. Signatures are minisign-compatible if VB-13 confirms the token can produce them, otherwise rpmgr's own documented Ed25519 format | [04](04-security.md#release-signing), [RELEASING](../RELEASING.md#roles), [ADR-0013](adr/0013-signed-ota.md) |
| D11 | External audit sink | required; optional | **Optional**; no separate "compliance" profile. Phase 1 keeps signed checkpoints locally, so tamper evidence is limited until an external sink (Phase 2) is configured; the hardening checklist recommends one | [04](04-security.md#audit-log) |
| D12 | End-to-end encryption for public HTTP routes | not offered; `tls_passthrough` route type | **`tls_passthrough`** (Phase 1); HTTP routes terminate on the gateway by design | [05](05-features.md#publishing-services-routes) |

## Tenancy and data

| # | Decision | Options | Outcome | Recorded in |
|---|---|---|---|---|
| D13 | Domain verification in single-org installs | always verify; instance admin can mark domains trusted | **Global uniqueness always; the Instance Admin can mark a domain `trusted`** (no DNS/HTTP proof, step-up, audited), Phase 1 | [04](04-security.md#route-and-hostname-ownership), [06](06-data-model.md#routing), [07](07-api.md#services) |
| D14 | Shared gateways across orgs | per-org gateways only; system-org gateways with grants | **The system org owns shared gateway groups; orgs get explicit grants** (Phase 2, with the multi-org UI) | [06](06-data-model.md#tenancy-enforcement), [07](07-api.md#services) |
| D15 | PostgreSQL row-level security | v1; later | **Not in v1**; the schema keeps it possible | [04](04-security.md#one-enforcement-point-with-defence-in-depth) |
| D16 | MySQL support | keep; drop | **Dropped**; the importer still reads MySQL source databases ([11](11-migration.md)) | [ADR-0011](adr/0011-sqlite-postgres-ent-atlas.md) |
| D17 | Where ACME runs | each gateway; controller with gateways answering challenges | **The controller**; gateways answer HTTP-01/TLS-ALPN-01, and certificates are pushed to the gateways that serve the hostnames. Rule for S6: if certmagic cannot work with gateway-answered challenges, the controller uses acmez (certmagic's ACME library) with rpmgr's own solvers and storage | [04](04-security.md#controller-certificates), [13](13-roadmap.md#phase-0--spikes) |
| D22 | Where managed DNS records point | CNAME to a group name; the group's A/AAAA addresses; each gateway's addresses | **Group-level `dns_target`**: a CNAME (preferred) or a list of addresses. Per-gateway addresses with health-aware records in Phase 3 | [15](15-dns.md#publication-rules), [06](06-data-model.md#fleet) |
| D23 | How names under the instance base domain reach orgs | not at all; flat names through approved nested claims; a delegated label per org | **The Instance Admin delegates `<org-slug>.<base>`** to an org (domain method `delegated`); the org's routes under it are published by the DNS job in the system org's zone. Flat names directly under the base domain need a nested claim the Instance Admin approves (`pending_approval`). Both Phase 2 | [15](15-dns.md#publication-rules), [04](04-security.md#route-and-hostname-ownership), [07](07-api.md#services) |
| D24 | Defaults of a managed zone's gates | everything on; everything off; route hostnames on, the rest off | **Publish route hostnames on; proxied names off; wildcards off; `delete_threshold` 10** | [15](15-dns.md#publication-rules) |
| D25 | DNS providers after Cloudflare | none; a generic libdns-based provider; native providers by demand | **Native providers by demand**, each with its capability flags; a libdns-based generic provider only if it can be made safe without comment markers | [15](15-dns.md#provider-interface) |

## Engineering

| # | Decision | Options | Outcome | Recorded in |
|---|---|---|---|---|
| D18 | Data-access layer | Ent + Atlas; sqlc + goose; bun | **Ent + Atlas**, using only Apache-2.0 parts. Rule for S5: if Atlas CLI features rpmgr needs are not in the Apache-2.0 build, migrations are generated through Ent's Go API (`ariga.io/atlas` library); if Ent fails the S5 criteria (privacy rules, composite foreign keys), **bun** | [ADR-0011](adr/0011-sqlite-postgres-ent-atlas.md), [13](13-roadmap.md#phase-0--spikes) |
| D19 | Default transport policy | QUIC first; TCP/h2 first; per-host benchmark | **QUIC first with happy eyeballs.** Rule for S1: QUIC and TCP + h2 are compared head-to-head on the reference testbed (D30) on four metrics — single-stream throughput, 32-stream goodput at 1 % loss, connection-setup latency p99, CPU per Gbit/s; the default is the transport that wins more of the four; a tie keeps QUIC (D34). **Replaced by D45 (2026-10-07)** before the rule was applied | [ADR-0004](adr/0004-quic-default-transport-policy.md), [13](13-roadmap.md#phase-0--spikes) |
| D20 | Agent RPC framework | ConnectRPC; grpc-go | **ConnectRPC.** Rule for S4: if any S4 check fails, grpc-go for the agent protocol only; browsers and the CLI stay on ConnectRPC. **S4 applied the rule (2026-10-06): connect-go failed cancellation, deadlines and message limits on idle streams, so grpc-go carries the agent protocol at both ends; the product owner confirmed it on 2026-10-07** | [ADR-0016](adr/0016-connectrpc-public-api-grpc-go-agents.md) (supersedes [ADR-0010](adr/0010-connectrpc.md)), [S4](spikes/S4.md), [13](13-roadmap.md#phase-0--spikes) |
| D21 | Connector-only build | ship; don't ship | **Ship** in Phase 2: artifact `rpmgr-connector_<version>_<os>_<arch>`, installed as `rpmgr`, listed with `variant: connector` in the signed manifest | [02](02-architecture.md#roles), [04](04-security.md#release-signing), [13](13-roadmap.md#phase-2--production) |
| D40 | S2 outcome: TCP transport when reverse HTTP/2 as designed fails one criterion (a connector-first half-close resets the request, [S2](spikes/S2.md)) | the pre-agreed rule: a patched yamux; reverse HTTP/2 with the connector's FIN sent in-band | **Reverse HTTP/2 with an in-band connector FIN** (decided 2026-10-07): after `StreamResult` the connector's bytes are length-prefixed chunks and a zero-length chunk is its FIN; net/http's HTTP/2 instead of `golang.org/x/net/http2`. The rule did not foresee this variant, which passes every S2 criterion with the standard library; the yamux fallback was never prototyped | [ADR-0005](adr/0005-reverse-http2-fallback.md), [03](03-connections.md#transports-and-fallback), [08](08-software-stack.md#networking) |
| D41 | How a gateway learns the ACME challenges it answers (D17), which the agent protocol did not cover ([S6](spikes/S6.md)) | a new control-session message; challenges inside the snapshot; gateways read the database | **A control-session message** (decided 2026-10-07): `ControllerMessage.AcmeChallenge{op_id, add \| remove, type, identifier, token, key_authorization}` to every gateway serving the name, acknowledged with `OpResult`; the CA validates only after all acknowledged within 10 s; gateways keep challenges in memory only | [03](03-connections.md#service-sketch), [07](07-api.md#agent-protocol-catalogue), [04](04-security.md#controller-certificates) |
| D42 | Certificates of a gateway | a leaf for its control session (clientAuth) and a server certificate for data sessions (serverAuth); one leaf with both EKUs | **One leaf certificate with clientAuth and serverAuth** (decided 2026-10-07), like connectors: both certificates carried the same identity and key holder, so the second added no separation, only a second renewal ([S7](spikes/S7.md)) | [04](04-security.md#leaf-certificates) |
| D45 | Default transport when the S1 testbed cannot run ([S1](spikes/S1.md)) | apply the S1 rule on a reference testbed; make the transport a setting | **A setting** (decided 2026-10-07): both transports stay first-class; the instance default `default_transport` is `auto` (QUIC first with happy eyeballs), `quic` or `h2`, shipped as `auto`, overridable per connector and per route (route over connector over instance). A pinned transport never falls back; changes apply to new connections only. Replaces the S1 rule of D19 | [ADR-0004](adr/0004-quic-default-transport-policy.md), [03](03-connections.md#transport-selection), [06](06-data-model.md), [07](07-api.md#services), [10](10-operations.md#runtime-settings-ui--settings) |

## Project and process

Decided on 2026-10-06, when the remaining questions were cleared.

| # | Decision | Options | Outcome | Recorded in |
|---|---|---|---|---|
| D26 | Ownership | personal project; organisation-owned project | **A personal open-source project** of the maintainer. CONTRIBUTING and RELEASING define its rules | [CONTRIBUTING](../CONTRIBUTING.md), [RELEASING](../RELEASING.md) |
| D27 | Maintainers and merge gate | solo; two people; team of 3+ — and for solo: CI + AI review with a next-day merge for security-sensitive changes (recommended); CI + AI review; CI only | **One maintainer** (with AI assistance) who holds every role: maintainer, release manager, signer, spike owner. **Merge gate: pull request plus green CI, no required approval**; additional review tools are optional. No CODEOWNERS and no dates in the roadmap. If maintainers join, the review rules change by PR | [CONTRIBUTING](../CONTRIBUTING.md#reviews), [RELEASING](../RELEASING.md#roles), [13](13-roadmap.md#approach) |
| D28 | External security review before v1.0.0 | hard gate; sought but not a gate; dropped | **Sought, not a gate.** Before 1.0 a documented self-review: the threat model checked against the code, every security-sensitive package reviewed, a fuzzing campaign. An external review (paid or sponsored) is sought; the v1.0.0 release notes state whether one took place | [12](12-testing-and-quality.md#security-testing), [13](13-roadmap.md#phase-2--production), [RELEASING](../RELEASING.md#release-process) |
| D29 | Platform scope | Windows in Phase 1; Windows/macOS in Phase 2; Linux only until 1.0 | **Phase 1 is Linux only.** Windows service and macOS launchd connectors in Phase 2, installed and updated through winget/MSI and Homebrew; OTA for them in Phase 3. `/install.ps1` is dropped | [05](05-features.md#platform-support), [10](10-operations.md#install), [13](13-roadmap.md) |
| D30 | Benchmark reference testbed | cloud VMs plus a Raspberry Pi; homelab machines; local VMs | **Three short-lived 2-vCPU cloud VMs** (client, gateway, connector) with `tc netem`, run on x86-64 and on arm64, plus a **Raspberry Pi 5** connector for the CPU-constrained case. Used before every release (S1 no longer needs it, D45) (a regression of more than 10 % blocks the release); nightly CI checks correctness only | [12](12-testing-and-quality.md#benchmarks), [13](13-roadmap.md#phase-0--spikes) |
| D31 | Scope cuts | keep and design each; drop | **Dropped:** (a) policy hooks (synchronous per-connection callouts; Phase 2 webhooks remain); (b) TLS termination for raw TCP, on the gateway or on the connector (`tls_passthrough` routes never terminate TLS); (c) a configurable fallback for unknown or missing SNI; (d) the optional signed CRL | [03](03-connections.md#port-443-multiplexing), [04](04-security.md#revocation), [05](05-features.md#feature-catalogue), [11](11-migration.md) |
| D32 | UI languages in Phase 1 | English only; English and German | **English only.** Strings are i18next keys from day one; further languages are translation files | [09](09-web-ui.md#ux-principles) |
| D33 | References to other projects | keep comparisons with other tunnel products; remove them except where a feature needs them; remove every project name | **The documents name no other tunnel products.** The one exception is the importer ([11](11-migration.md)), which has to name the formats it reads. Libraries, standards and design references that rpmgr uses or evaluated (quic-go, yamux, Envoy xDS, TUF, Next.js, …) stay. The former document 01 and its defect IDs were removed; the security controls they motivated stay, with their regression tests | [README](../README.md), [12](12-testing-and-quality.md#security-testing) |
| D34 | Baseline of the performance targets | another tunnel product; a direct connection; no comparative targets | **A direct connection on the same path**: single-stream throughput ≥ 80 % of direct TCP for each transport; 32-stream goodput at 1 % loss: QUIC ≥ 1.5 × TCP + h2; CPU per Gbit/s recorded as a baseline under the release regression gate. S1 compares QUIC and TCP + h2 head-to-head (D19) | [03](03-connections.md#targets-t), [12](12-testing-and-quality.md#benchmarks), [ADR-0004](adr/0004-quic-default-transport-policy.md) |
| D35 | Merge method for pull requests | squash merge only; merge commit; rebase merge | **Merge commit**, with GitHub's default merge settings kept (squash and rebase stay enabled but are not used), so that no commit is lost. Every commit of a PR therefore follows the commit rules and is signed off; CI checks every commit header and refuses `fixup!` commits; fix-ups are folded in before merging. No linear-history rule. Replaces the squash-only rule of the first set of contribution rules | [CONTRIBUTING](../CONTRIBUTING.md#pull-requests), [RELEASING](../RELEASING.md#release-process), [12](12-testing-and-quality.md#continuous-integration) |
| D36 | Spike workflow and what is kept of spike code | delete `tmp/` branches after the result; keep them until v1.0.0; archive tag per spike | **One issue per spike; code in `spikes/sx/` on a `tmp/` branch that is never merged; the result, the ADR and the affected documents in one `feature/` PR; then the branch's last commit is tagged `spike/sx` (immutable, protected by a ruleset) and the branch deleted.** The S1 harness becomes `bench/` through a normal PR in Phase 1 | [CONTRIBUTING](../CONTRIBUTING.md#spikes), [13](13-roadmap.md#phase-0--spikes) |
| D37 | Spike parts that need external resources (S1 reference testbed; S6 Let's Encrypt staging and a real test zone) | run them before Phase 0 starts; local results decide; harness first, maintainer runs them later | **Harness and local dry runs first; the maintainer runs the external parts later.** A dry run never decides a rule: until the external run, the spike stays *Running* and its ADR *Proposed*, and Phase 0 is not complete. S1 is resolved by D45 instead | [13](13-roadmap.md#phase-0--spikes) |
| D38 | Platforms and clients the spikes may use | real hardware and branded browsers only; emulation and engine-equivalent clients | **S8 under QEMU user-mode emulation** for arm64, armv7 and riscv64 where no hardware is at hand, arm64 again on the Raspberry Pi 5; **S3 with headless Chromium and Firefox**, curl and Go as the real clients | [13](13-roadmap.md#phase-0--spikes) |
| D39 | Library versions in spikes | the versions reviewed during the design; the current releases | **The current releases**, pinned, with the `[F]` facts the decision rests on re-checked at those versions and cited with the new version inline | [CONTRIBUTING](../CONTRIBUTING.md#spikes), [README](../README.md#citations) |
| D43 | How S1's rule computes its four metrics (D19 names the metrics, not the cells or the aggregation) | as proposed with the S1 harness; another aggregation | **As proposed, confirmed on 2026-10-07 before the testbed run:** cells per metric, medians of the repetitions, a geometric mean of the QUIC ÷ h2 ratios per metric over all cells and testbeds, a win needs at least 5 %, more wins decide and a tie keeps QUIC. **Moot since D45**: the harness's summary still computes it, as information | [S1](spikes/S1.md), [13](13-roadmap.md#phase-0--spikes) |
| D44 | Who force-pushes and deletes remote branches | anyone for their own branches; the maintainer only | **The maintainer deletes branches, including archived `tmp/` branches; AI assistants never force-push and never delete a remote branch**, and bring a pushed branch up to date by merging `main` into it (decided 2026-10-07) | [CONTRIBUTING](../CONTRIBUTING.md#branches), [CLAUDE.md](../CLAUDE.md) |

## Resolved inconsistencies and gaps

A review on 2026-10-06 found gaps and contradictions between the documents. Each was resolved as
follows; the documents named hold the details.

| Topic | Resolution | Recorded in |
|---|---|---|
| ADR status | Accepted by the product owner: ADR-0002, 0003, 0004 (D45), 0006, 0007, 0009, 0012, 0013, 0014, 0015. Accepted by their spikes: ADR-0005 (S2 with D40), 0008 (S7), 0011 (S5, S8), 0016 (S4; it supersedes ADR-0010). S3 passed for ADR-0004; tunnels share UDP/443. No ADR is *Proposed* | [adr](adr/) |
| Update channels and build variants | The signed manifest carries `channel` (`stable`, `prerelease`) and a `variant` per artifact (`full`, `connector`); the policy file's `update_channel` (default `stable`) and the recorded install variant are enforced by the root updater | [04](04-security.md#release-signing) |
| Install script | `/install.sh` (Linux) verifies root key → signing-key statement → manifest → SHA-256 with OpenSSL ≥ 3.0 and refuses without it | [04](04-security.md#install-scripts) |
| Revocation-log sink | S3-compatible object storage or a filesystem path; optional on a single node (standing warning), required with more than one controller replica | [04](04-security.md#revocation-log), [10](10-operations.md#backup-and-restore) |
| Settings and UI areas | D8 values and the password-hash profile in Settings → PKI; release check, channel and rollouts in Settings → Updates; org settings are Owner-only | [09](09-web-ui.md#information-architecture), [10](10-operations.md#runtime-settings-ui--settings) |
| Local administration | Admin commands on the controller host are authorised by host access and audited as `local-cli`; the same actions in the UI or API need Instance Admin and step-up | [04](04-security.md#roles) |
| API tokens, e-mail | Personal API tokens in Phase 1 (the CLI needs them), service accounts in Phase 2. SMTP is optional: invitations and password resets work as one-time links | [04](04-security.md#human-authentication-and-sessions), [07](07-api.md#services) |
| API versioning | Adding `rpmgr.v2` is a minor release; removing `rpmgr.v1` is a major release, at least two minor releases later | [07](07-api.md#versioning-and-compatibility), [RELEASING](../RELEASING.md#versioning) |
| Phases and quotas | Shared-group grants Phase 2; port quotas per org and gateway group, Phase 1; connector-only build Phase 2; SQLite → PostgreSQL with `rpmgr migrate-db`, Phase 2 | [05](05-features.md), [06](06-data-model.md) |
| Data model | New: `ca_keys`, `acme_storage`, `ca_bundles`, `port_quotas`, `password_resets`; Phase 2: webhook and rollout tables. `route_http.port80` replaces `redirect_http`; `route_targets.tls_spki_sha256` | [06](06-data-model.md) |
| Gateways and hosts | At most 4 gateways per group; happy-eyeballs results cached per gateway and local source address; one instance per role per host; admin listeners `127.0.0.1:7381` (controller, all-in-one), `7382` (gateway), `7383` (connector) | [03](03-connections.md), [10](10-operations.md#ports) |
| Supported platforms | Linux kernel ≥ 5.10 and systemd ≥ 249 (Debian 12+, Ubuntu 22.04+, RHEL-compatible 9+, Raspberry Pi OS); Windows and macOS connector specifics for Phase 2 | [10](10-operations.md#install) |
| Libraries and formats | WebSocket: `coder/websocket`; charts: Recharts via shadcn/ui; SBOM: SPDX JSON (syft); secret scanning: gitleaks; forms: protovalidate-es (fallback zod); Go: latest stable at the first commit, pinned with `toolchain`; KEK: file and systemd credential (P1), Vault/OpenBao Transit (P2) | [08](08-software-stack.md), [04](04-security.md#secrets-at-rest-and-in-logs) |
| Packaging | `.deb`/`.rpm` from a signed repository on GitHub Pages (Phase 2); Homebrew and winget (Phase 2); Helm chart (Phase 3); no `.apk` | [10](10-operations.md#install) |
| Single sources of truth | Session-ticket rotation, webhook signature age and tombstone periods moved to 04; webhook delivery timeout and `request_id` deduplication to 03 | [03](03-connections.md#timeouts-keepalive-and-backoff), [04](04-security.md) |
| Phase 3 sketches | Every Phase 3 item gets its detailed design before it is implemented; a sketch is not an open question | [13](13-roadmap.md#phase-3--advanced) |
| Verification | New backlog items VB-13 to VB-16 (hardware-token signatures, package name, install-script verification, protovalidate-es) | [13](13-roadmap.md#verification-backlog) |
| Spike definitions | S2 in 13 now also covers stall detection and the first chunk in `OpenRequest` (as ADR-0005 did); S4 in 13 also covers a TLS-passthrough route, and ADR-0010 also covers 10 000 idle sessions | [13](13-roadmap.md#phase-0--spikes), [ADR-0010](adr/0010-connectrpc.md) |

## Decided during this design

Recorded so they are not re-opened by accident:

- rpmgr defines its own versioned protocol; compatibility with other tunnel tools is a non-goal,
  and an importer converts existing configurations ([ADR-0003](adr/0003-clean-slate-protocol.md),
  [11](11-migration.md)).
- Self-hosted, single-org default, every record org-scoped ([ADR-0012](adr/0012-org-scoped-tenancy.md)).
- One binary with three roles ([ADR-0002](adr/0002-one-binary-three-roles.md)).
- The project is named `rpmgr` everywhere, including the repository and all identifiers
  ([ADR-0001](adr/0001-name-rpmgr.md)).
- Design documentation first, implementation after review of these documents. The review closed
  every open question on 2026-10-06; Phase 0 can start.
- DNS automation ([ADR-0015](adr/0015-dns-provider-integration.md), [15](15-dns.md)): Cloudflare
  first, in Phase 2 together with ACME DNS-01; rpmgr manages only records it owns (route hostnames,
  DNS names, challenge TXTs) and touches others only after an explicit adopt; Cloudflare's proxy is
  an opt-in per `http` route; Org Owners and Admins connect their own accounts, and the Instance
  Admin connects accounts for instance-level domains in the system org.
- How the project works ([CONTRIBUTING](../CONTRIBUTING.md), [RELEASING](../RELEASING.md)):
  branch names carry GitHub issue numbers (`feature/42-…`), with `release/<major>.<minor>`
  maintenance branches; commit messages
  and PR titles follow Conventional Commits and are signed off (DCO); pull requests are merged
  with a merge commit on green CI (D35); releases use Semantic Versioning with signed, immutable
  `v` tags; the changelog follows Keep a Changelog and is written in the same PR as the change.
