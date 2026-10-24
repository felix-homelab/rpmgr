# Changelog

All notable changes for people who run rpmgr or use its API are recorded in this file. The format
follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html), and the rules for entries are in
[RELEASING.md](RELEASING.md#changelog).

Changes to the design documents are not recorded here: see the git history and the
[ADRs](docs/adr/).

## [Unreleased]

### Added

- Updates: **Check now** on Settings → Updates, `rpmgr check release` and
  `ReleaseService.CheckReleases` check for new releases at once instead of at the next daily
  check, for an Instance Admin, audited. The page and `ListReleases` show when the last check ended
  and how: ok, failed with its error, or off. A check is refused while the release check is off,
  and shortly after the last one or while the release source limits requests, with the time to
  wait. (#890)

## [0.2.0] - 2026-10-24

### Added

- Install: both install scripts and `rpmgr setup` install the root updater and its state on every
  Linux host: `/var/lib/rpmgr-update/install.json` with the binary's path, variant and roles,
  `state.json` with the version floor and the highest manifest `seq`, and the
  `rpmgr-update.path`/`rpmgr-update.service` units, which they enable. The updater installs a
  staged release after verifying it, restarts the roles, and rolls back when one does not become
  ready. A host installed before the updater gets them from `install.sh --upgrade`; `rpmgr setup
  --no-unit` leaves the units out. Both scripts also keep the variant a host runs. (#850)

- Controller: the release mirror keeps the controller's own version, the version it ran before and
  the target of each running or paused rollout, with both variants; `ReleaseService.UploadRelease`
  and `rpmgr upload release` record a release for air-gapped installations or a signed downgrade,
  and `rpmgr release import` still fills the mirror from a directory. A rollout may target a
  recorded release the mirror does not hold yet: the mirror fetches it at once, also while the
  release check is off, and agents are offered it once the mirror holds it. (#839, #854, #610)

- CLI: `rpmgr list release`, `rpmgr upload release <dir>`, and the `rollout` commands (`create`,
  `get`, `list`, `list rollout-target`, `advance`, `pause`, `resume`, `cancel`) run a staged
  rollout from the command line, each change but a pause after a step-up. (#610)

- Updates: the Instance Admin runs a staged rollout from **Settings → Updates**: the releases the
  controller verified, an upload of a release's signed files for air-gapped installations, and a
  rollout that starts with test agents the page suggests, then continues to 25 % and to all agents
  with one button once a stage is done, showing the stages, the agents updated and the agents that
  need attention, update now or wait; a rollback or a stalled agent pauses the rollout. Agents
  download and stage the release for their root updater, honouring `auto_update: off` or `notify`
  in their local policy; connector and gateway lists show each agent's update state and warn when
  it is below the oldest version the controller accepts. (#611, #877)

- CLI: `rpmgr policy set-auto-update auto|notify|off` and `rpmgr policy set-update-channel
  stable|prerelease` set whether a connector or gateway host takes over-the-air updates and which
  releases, `prerelease` taking betas and release candidates too, without a restart. They refuse a
  policy file the root updater would not trust. (#897)

- Releases: a connector-only build of rpmgr, `rpmgr-<version>-<os>-<arch>-connector`, for every
  Linux architecture and, as the only build there, for Windows (amd64, `.exe`) and macOS (amd64,
  arm64). It runs the connector role and the commands of a connector host, links nothing of the
  controller, the gateway or the importer, and is less than a third of the full build's size.
  Both install scripts take `--variant connector`; the controller's mirror serves it for Linux.
  (#837)

- CLI: `rpmgr status`, `rpmgr diag transport` and `rpmgr diag clock` work on an all-in-one host.
  `status` reports its built-in gateway and connector, each marked built in, and the readiness of
  `rpmgr-all-in-one.service`; `diag` runs as the built-in connector. `rpmgr leave` is refused there
  with the reason, and the controller refuses a leave of the built-in agents in any case, as the
  API refuses to decommission them. (#810)

### Changed

- Tunnels: QUIC data sessions use quic-go v0.64.1, whose loss recovery no longer shrinks the
  congestion window for packets that were only reordered. On the benchmark runners a single QUIC
  stream without loss carried two to four times as much at 20 and 80 ms RTT as with v0.1.0. (#828)
- Connectors keep four QUIC data sessions to each gateway instead of one, each with its own
  congestion window, so that a loss slows a quarter of the streams; TCP + h2 stays at two
  connections. A gateway of v0.1.0 accepts them. A single connection is carried as before. (#825)

### Fixed

- Gateway: a gateway admits about eighty data sessions over TCP + HTTP/2 instead of nine. Each
  session's flow-control window now takes at most a sixteenth of the free window budget, down to a
  small floor, instead of half of it, so connectors beyond the fourth on TCP + h2 are no longer
  refused; later sessions get smaller windows. (#819)
- Gateway: a connector that restarts after it was killed gets its data sessions at once. The
  gateway kept the sessions of the killed process until their transport noticed, opened new
  connections on them, which were reset, and counted them against the connector's limit of
  sessions, so the restarted connector's sessions could be refused. A session that names a new
  start of the connector now closes those of its earlier start. (#849)
- All-in-one: a built-in gateway or connector whose identity is revoked as a whole, as a restore
  that applies a later revocation leaves it, no longer stops the start. The all-in-one replaces it
  with a new built-in gateway or connector, which keeps the old one's name and, for a gateway, its
  group and tunnel endpoints, for a connector, its route targets; the revocation stays, and the
  audit log records the replacement. (#805)
- All-in-one: the built-in connector follows the gateway group's public hostnames while it runs.
  It read them only at start, so after a hostname was added, its addresses were not refused as the
  host's own until the service restarted, and a removed one stayed refused. (#808)

### Security

- Controller: a password reset or a password change now ends the user's other unused reset links,
  so a link issued before the change can no longer set the password; a reset link of a disabled
  user sets no password. Severity low to medium; affects 0.1.0. (#812)
- Controller: a gateway's reports count only for what it serves: traffic counters of routes in its
  own gateway group, and data sessions of connectors with a target on such a route. A gateway
  could write traffic statistics for routes of other groups, and show data sessions for any
  connector of its org. (#821)
- Gateway: a request path with an empty, `.` or `..` segment, such as `//admin` or
  `/%2e%2e/admin`, also with `;` parameters (`/..;/admin`, `/;/admin`), or with a `\` or a
  control character, is refused with 400 before a route is chosen, also on port 80; so is an
  absolute-form request with an empty path (`GET http://host HTTP/1.1`). Before, such a path was
  routed by a broader route of the host, and a backend that resolves it served the path of a
  narrower route without that route's access policy. A path with `;` parameters, such as
  `/admin;jsessionid=1`, now belongs to the route its form without them matches. `CONNECT`
  requests are refused with 501. Medium severity; affects v0.1.0. (#813)
- Controller: an HTTP domain proof connects only to public addresses, so an HTTP claim whose name
  resolves to a loopback, private, link-local or other internal address fails with "the name
  resolves to an address that is not public"; through a proxy nothing changes. The last error of
  an HTTP claim names only the kind of failure, no longer the addresses, the resolver or the
  server's own text. A domain that resolves only on the local network is proved with a TXT record
  or marked trusted by the Instance Admin. (#822)
- Controller: a TXT domain proof asks the claimed zone's nameservers only at public addresses, so
  a zone whose NS records point at a loopback, private, link-local or metadata address gets no
  query there, and the claim's last error names only the kind of failure, no longer the addresses
  of the nameservers, the resolver or the controller. A zone whose nameservers are reachable only
  on the local network is marked trusted by the Instance Admin. Low severity; affects 0.1.0. (#823)

## [0.1.0] - 2026-10-19

### Added

- All roles: `rpmgr setup` sets a host up for its role: the user and directories, the boot file,
  the controller's init or the agent's enrollment, a connector's local policy and proxy, and the
  systemd unit, started and checked for readiness. It asks in full-screen forms, or in plain
  prompts without a terminal, and shows the plan before it changes anything; with `--yes` it takes
  every value from its flags. A connector's proxy is an `http://`, `socks5://` or `socks5h://` URL
  that the enrollment takes too, kept in a file only root reads; one with credentials comes from
  `--proxy-file` or the form, never the command line. Release candidates up to rc.8 wrote the
  proxy into a drop-in every user reads: run setup again and change the proxy's password. (#446,
  #448, #449, #569)
- All roles: one `rpmgr` binary for Linux on amd64, arm64, armv7 and riscv64 runs every role:
  `rpmgr controller`, `gateway`, `connector` and `all-in-one`, each from a strictly checked YAML
  boot file. `rpmgr version` names the build. (#174, #196, #260, #266, #267, #384)
- Controller: `rpmgr controller init` creates the boot file, the SQLite database, the
  key-encryption key (KEK, from a systemd credential or a file) and the internal CA, and prints a
  one-time link that creates the first user. Secrets in the database are encrypted under the KEK,
  and logs redact them. (#183, #184, #186, #187, #189, #199, #313, #375)
- Controller: all-in-one, the homelab default, runs a controller, a gateway and a connector in one
  process. `rpmgr all-in-one init` also creates the gateway group `default`, its public hostname
  the public URL's host if that is a valid one, with the enrolled gateway `local`, and the
  connector `local`, which publishes services on the same host as its local policy allows, never
  rpmgr's own ports, over in-memory data sessions. An all-in-one initialised before gets its
  connector at the next start. Its own gateway and connector cannot be decommissioned; after a
  restore on a new host, or from a backup older than their certificates, it enrolls them again at
  start. `rpmgr setup` asks for the connector's allowed and denied targets, and `rpmgr policy`
  reloads the all-in-one on a host without a separate connector. (#268, #269, #490, #494, #535,
  #537, #538, #540, #579)
- Controller: a controller without a public address can stay on a private network, published
  through a gateway that passes its hostnames through to it. (#285)
- Controller: serves `/install.sh`. The script downloads the controller's own release from the
  controller, verifies its signatures with OpenSSL 3, installs the binary, the boot file, the
  connector-local policy and a hardened systemd unit, and enrolls the host. It reads the
  enrollment token from a file, the environment or the terminal. The command the web UI shows
  downloads the script and runs it with `sudo`, so that a token typed at the prompt also arrives
  under sudo-rs, Ubuntu's `sudo` since 25.10. It is tested on Debian 12 and 13, Ubuntu 22.04, 24.04
  and 26.04, and Rocky Linux 9. (#328, #374, #376, #477)
- All roles: `rpmgr systemd-unit <role>` prints a hardened systemd unit for each role. (#375)
- All roles: an internal CA gives every controller, gateway and connector a short-lived certificate
  with a SPIFFE identity in the instance's trust domain. Agents renew it in time; an agent that
  missed its renewal re-authenticates within the grace period. (#195, #197, #198, #222, #223, #232)
- Gateway and connector: `rpmgr enroll --controller <url> --ca-pin <pin>` enrolls a host with an
  enrollment token. A token carries a checksum, so a mistyped one fails before any connection, and
  each certificate request is bound to the TLS connection it arrives on. (#200, #208, #209, #210)
- Controller: a revoked certificate or identity reaches every agent through a signed deny-list,
  which agents keep across restarts. A re-enrollment revokes the certificates it replaces. (#220,
  #224, #229, #326)
- Controller: the intermediate CA and the signing keys rotate on their schedule; agents then
  receive their configuration signed by the new key. (#230, #231)
- Controller: agents keep a control session to the controller on its port 443 and receive a signed
  configuration snapshot for each revision. They reject an invalid snapshot and run their
  last-known-good copy, also while the controller is unreachable. (#202, #207, #214, #217, #218,
  #219, #221, #261, #262)
- Gateway and connector: data sessions run over QUIC, or over TLS with reverse HTTP/2 where UDP is
  blocked. A connector keeps a session to every gateway of its routes and chooses each route's
  transport, `auto`, `quic` or `h2`, with happy eyeballs. (#236, #237, #238, #239, #240, #243,
  #244, #251)
- Gateway: data sessions, `tls_passthrough` routes and `http` routes share TCP and UDP port 443. A
  stalled stream is reset before it can freeze its session. (#205, #241, #242)
- Connector: reaches its gateways through an HTTP CONNECT or SOCKS5 proxy (`HTTPS_PROXY`,
  `ALL_PROXY`) where only a proxy leads out, and carries its control session inside a data session
  when no controller endpoint is reachable. (#245, #267, #286)
- Controller: its requests to the ACME CA, to GitHub and to a domain's HTTP token follow the proxy
  variables as the connector reads them, `ALL_PROXY` included; a proxy variable that is no proxy
  URL stops the start with a message that names the variable without its value. (#578)
- Connector: the connector-local policy, `/etc/rpmgr/policy.yaml`, limits the targets a connector
  dials, even for a compromised controller. A target is an address or a subnet, such as
  `10.0.0.1/16` (stored as `10.0.0.0/16`), with an optional port or port range such as
  `127.0.0.1:200-500`; without a port it means all ports. `deny_targets` refuses what it matches,
  whatever allows it. `rpmgr policy show`, `allow-target`, `deny-target` and their `remove-` forms
  edit it and reload the connector; a reload ends relayed connections the policy no longer allows.
  `rpmgr setup` and the install command take `--allow-target` and `--deny-target`. YAML anchors,
  aliases and merge keys make the file invalid. A connector of an earlier build reads a file that
  uses `deny_targets`, a target string, an entry without ports or a subnet with host bits as invalid
  and dials nothing, also after an automatic update rolls it back. (#247, #248, #249, #388, #524)
- Gateway: `tcp` routes take a public port from their gateway group's port pools, within the org's
  port quota, and carry each connection as one stream to a connector. (#234, #235, #254, #326)
- Gateway: `udp` routes carry each client flow as QUIC datagrams, or as frames on the `h2`
  transport. (#279, #281, #283, #284)
- Gateway: `tcp_udp` routes publish one port number with TCP and UDP, for services such as DNS:
  one route with one list of targets, its port taken from the gateway group's TCP and UDP pools
  and counted against both quotas; a target's PROXY protocol header goes on its TCP connections
  only. (#513, #534)
- Gateway: `tls_passthrough` routes pass TLS connections by server name to a connector, still
  encrypted. (#276, #278, #332)
- Gateway: `http` routes terminate TLS for their hostnames and proxy HTTP/1.1, HTTP/2, WebSocket
  and gRPC by hostname and path prefix, to HTTP, h2c or verified HTTPS upstreams (server name, CA
  bundle, optional SPKI pin). A target whose certificate nothing can verify, such as a
  self-signed one, may be checked by its pinned key alone, which "Trust the certificate it shows
  now" reads through the connector, or be marked unverified: the gateway then checks no
  certificate, and the web UI warns about it and marks the target. Stricter TLS settings end the
  target's open connections at once. (#292, #294, #296, #333, #516, #518, #521)
- Gateway: a route's targets may be on several connectors, and their priority and weight hold
  across connectors: a target of a higher priority is a failover that takes connections only while
  no connector has a ready target of a lower one, another connector's better target comes before a
  connector's own worse one, and one priority is shared by weight. A target that refuses or does
  not answer passes the connection to the next one, so the route still works, and HTTP connections
  the gateway keeps alive move back once a better target's connector is ready again. (#547)
- Gateway: `http` routes set `Forwarded` and `X-Forwarded-*` and keep a client's own only from the
  gateway group's trusted proxies. They can replace the `Host` header, set request and response
  headers, redirect or serve port 80, and send HSTS. (#297, #298)
- Gateway: a browser gets a page instead of bare text or a closed connection. A name no route
  serves shows "Site not available" (404) on port 80, and on port 443 with a certificate the
  gateway holds that covers the name, such as a route's wildcard one, or else after the browser's
  certificate warning. A route without a live target, or whose target refuses or does not answer,
  shows "Service unavailable" (503, 502, 504). Other clients keep getting text, and an upstream's
  own errors pass unchanged. On all-in-one, port 80 redirects only the controller's own name to
  its public URL. (#536)
- Gateway: an `http` route can be put in maintenance, with an optional plain-text message. Its
  gateways then answer every request its access policies admit with a "Down for maintenance" page
  (503) and send nothing to its targets; its certificate, HSTS and port 80 stay as they are. The
  route's status says `maintenance`, and the web UI has a "Maintenance" switch on the route's page,
  the CLI `--maintenance` and `--maintenance-message`. (#539)
- Connector: a route target is a host and port or a Unix socket, with a weight, a priority and
  optionally the PROXY protocol. (#249, #262, #334)
- Controller: route hostnames must lie under a domain the org has verified, by a DNS TXT record or
  by an HTTP token its gateways serve. An Instance Admin can mark a domain trusted without a proof.
  (#273, #276, #331, #332)
- Gateway: access policies hold IP allow and deny rules for every route type, and basic auth with
  argon2id-hashed passwords for `http` routes. A deny rule wins over every allow rule, whatever the
  order of the rules and of a route's policies; a gateway of a release candidate still lets the
  first matching rule decide until it is upgraded. A tightened policy also ends the open
  connections it now denies. (#299, #300, #338, #522)
- Controller: `http` routes get certificates through ACME, by HTTP-01 or TLS-ALPN-01 answered by
  every gateway that serves the name, from Let's Encrypt or another ACME directory. Renewal is
  automatic and can also be started on demand. A name that fails is tried again after waits
  growing from 1 min to 6 h, and each retry rehearses at Let's Encrypt's staging directory first,
  so a name the CA cannot validate yet does not use up the account's limits. (#303, #304, #305,
  #339, #479)
- Controller: obtains its own certificate through ACME when its public URL has a public DNS name;
  otherwise it uses the configured certificate or a self-signed one. (#306)
- Controller: `http` routes can use uploaded certificates instead, whose keys are encrypted under
  the KEK; gateways fetch them by hash and choose one by server name. CA bundles verify HTTPS
  upstreams. (#287, #288, #289, #339, #340)
- API: the controller serves a public ConnectRPC API over HTTP/2 and HTTP/1.1, to Connect, gRPC
  and gRPC-Web clients. Each method checks a named permission of the org roles Owner, Admin,
  Operator and Viewer, or of the Instance Admin. Lists are paged, updates take field masks and
  etags, and creates are idempotent by `request_id`. (#310, #311, #322, #333, #575)
- API: local accounts with argon2id passwords, cookie sessions, TOTP and recovery codes, and step-up
  for sensitive actions. Users change their own password, and one-time links reset it. (#312,
  #313, #314, #316, #321)
- API: orgs with members and roles. Invitations and password resets are one-time links, also sent
  by e-mail when an SMTP relay is configured. (#318, #319, #349)
- All roles: administrators recover other users' accounts after a step-up, in the web UI, with
  `rpmgr` and through the API: a password-reset link, by an Owner or Admin for their members and by
  the Instance Admin for anyone, and the removal of a lost second factor, by an Owner or the
  Instance Admin, which ends the user's sessions. An Owner or Admin recovers only users all of whose
  organisations they hold, and no Instance Admin. The Instance Admin grants and revokes the Instance
  Admin role on the new Users page or with `rpmgr update user`; the last one keeps it. (#583, #585)
- API: personal API tokens for the CLI and scripts, each bound to one org and limited to
  permissions its owner holds; a token can step up. (#320, #346)
- API: services for gateway groups, gateways, port pools and quotas, enrollment tokens and install
  commands, connectors (status, data sessions, decommissioning, purging ephemeral ones), domains,
  routes and their targets, access policies, certificates, CA bundles, settings and the PKI status.
  (#322, #323, #326, #328, #329, #330, #331, #332, #333, #334, #338, #339, #340, #341)
- Controller: decommissioning a connector, `rpmgr leave` and the purge delete its route targets
  and each route left with no target, so its ports and hostnames are free again; the UI names
  those routes before, the API and the CLI after. Gateways listen only on the ports of routes a
  connector serves, and a refused port names the route that holds it. (#492)
- API: every write returns its revision, and the apply status says how far the agents are with it.
  A route can be previewed before it is saved, routes report their observed status, and
  configuration and status changes stream to clients. (#335, #336, #337)
- API: an org's resources export as YAML manifests. (#341, #342)
- API: a request message holds at most 4 MiB, also once decompressed; a larger one is refused
  before it is handled. (#582)
- CLI: `rpmgr login` signs in with a personal API token. Verb-first commands (`get`, `list`,
  `create`, `update`, `delete`, `enable`, `disable`, `preview` and more) cover every resource of the
  API, with table, YAML or JSON output. Flags may stand before or after a command's arguments, as
  in `rpmgr get route web -o yaml`; `--` ends them. (#342, #344, #345, #346, #347, #348, #349,
  #574)
- Gateway: a drained or disabled gateway lets its open connections finish within the drain period;
  `rpmgr drain gateway` starts a drain. (#347, #349)
- UI: the controller serves an embedded web UI under a strict Content Security Policy, with
  first-run setup, sign-in with a second factor, password resets, step-up in place, and an account
  page for profile, theme, password, authenticator, recovery codes, sessions and API tokens. (#356,
  #359, #360, #362, #363)
- UI: routes can be listed, created with a preview, edited with conflict resolution, switched on
  and off while the apply status follows live, given targets, and deleted after a confirmation.
  TCP and UDP routes are shown at their gateway group's public hostnames, such as
  `eu.example.net:25432`. (#363, #364, #365, #366, #472, #490, #494)
- UI: pages for connectors with an enrollment dialog, gateway groups, gateways and port pools,
  domains, certificates and CA bundles, access policies, and members and invitations. A connector
  is switched on and off on its page; the overview counts neither disabled connectors nor drained
  gateways as offline. (#366, #367, #368, #369, #508)
- UI: an overview with traffic and what needs attention, traffic per route, the audit log with
  chain verification, org and instance settings, the PKI page, read-only YAML views with export,
  and a command palette. (#370, #371, #372)
- UI: a sidebar groups the pages, and is a menu on narrow screens. The top bar holds "Go to…", a
  switch for the light, dark or system theme, which saves it to the profile, and the user menu.
  Both themes keep text contrast at WCAG 2.2 AA. The overview leads with a figure per area, the
  traffic of the last 24 hours and what needs attention. Every page uses the same page header,
  cards, tables, status badges and empty states, and fills the window's width, with long forms in
  columns on wide screens. The foot of the sidebar names the version the controller runs.
  (#460, #461, #462, #463, #464, #465, #482, #507)
- UI: a field a form needs has a red asterisk after its label, also while it is needed only
  because of another field, such as the sender address once a mail relay is set. Screen readers
  announce the field as required. (#491, #494)
- Controller: every change, sign-in and token use is recorded once in a hash-chained audit log per
  org and one for the instance, with signed checkpoints and retention. The API and the UI list and
  verify the chains. (#194, #311, #350, #351, #352)
- All roles: an admin listener serves `/healthz`, `/readyz` and Prometheus metrics for sessions,
  streams, routes, ACME certificates, audit checkpoints and refusals. (#233, #352, #353)
- Controller: gateways report each route's traffic, which the controller rolls up hourly and daily
  for the API and the UI. (#353, #354)
- All roles: OpenTelemetry traces over OTLP/HTTP, off by default; public requests are traced
  through the tunnel. (#355)
- Controller: `rpmgr backup` writes the database, the revocation log and the audit checkpoints into
  one archive while the controller runs. The revocation log can also be shipped to a filesystem
  sink. (#377)
- Controller: `rpmgr restore` restores a backup with a new database epoch and re-applies every
  revocation made since it. When those may be incomplete, it fails closed into a read-only restore
  review: Owners confirm their orgs, the UI shows a checklist, and `rpmgr restore confirm` ends the
  review. (#378, #379, #381)
- Controller: local administration on the controller host with `rpmgr migrate`, `ca status`,
  `ca rotate-intermediate`, `kek status`, `kek rotate` and `user reset-password`. (#313, #382)
- Gateway and connector: `rpmgr status`, `rpmgr leave`, `rpmgr diag transport` and
  `rpmgr diag clock` on agent hosts. (#383)
- Controller: checks GitHub Releases daily for its own version (setting `release_check`, on by
  default), verifies the signed release and mirrors it under `/dl/` for installs.
  `rpmgr release import` fills the mirror from a directory for air-gapped installations. (#373,
  #374)
- Install: a global install script, attached to every release as `install.sh`, downloads the
  release from GitHub, verifies it with the release root keys it embeds, installs the binary, the
  user `rpmgr` and its directories, and offers to run `rpmgr setup`. On a host that has rpmgr,
  `--upgrade` replaces only the binary and then names what is left to do, and `--restart`
  restarts the rpmgr services that run and checks that they stay up. (#445, #554)
- Releases: reproducible builds with an SPDX SBOM, SLSA provenance attestations and a signed
  release manifest; distroless, nonroot multi-arch images at `ghcr.io/felix-homelab/rpmgr`, signed
  with cosign. (#384, #385, #434)
- Docs: a user guide in `docs/guide/` covers concepts, a quick start, every task in the web UI
  and on the command line, a page per web UI screen with its screenshot, and references for the
  command line (generated from the binary), the boot files, the local policy file, the environment
  and the API. (#565)

[Unreleased]: https://github.com/felix-homelab/rpmgr/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/felix-homelab/rpmgr/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/felix-homelab/rpmgr/releases/tag/v0.1.0
