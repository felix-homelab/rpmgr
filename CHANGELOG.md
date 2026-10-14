# Changelog

All notable changes for people who run rpmgr or use its API are recorded in this file. The format
follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html), and the rules for entries are in
[RELEASING.md](RELEASING.md#changelog).

Nothing has been released yet. Changes to the design documents are not recorded here: see the git
history and the [ADRs](docs/adr/).

## [Unreleased]

### Added

- All roles: `rpmgr setup` sets a host up for its role: the user and directories, the boot file,
  the controller's init or the agent's enrollment, a connector's local policy and proxy, and the
  systemd unit, started and checked for readiness. It asks in full-screen forms, or in plain
  prompts without a terminal, and shows the plan before it changes anything; with `--yes` it takes
  every value from its flags. (#435)
- All roles: one `rpmgr` binary for Linux on amd64, arm64, armv7 and riscv64 runs every role:
  `rpmgr controller`, `gateway`, `connector` and `all-in-one`, each from a strictly checked YAML
  boot file. `rpmgr version` names the build. (#174, #196, #260, #266, #267, #384)
- Controller: `rpmgr controller init` creates the boot file, the SQLite database, the
  key-encryption key (KEK, from a systemd credential or a file) and the internal CA, and prints a
  one-time link that creates the first user. Secrets in the database are encrypted under the KEK,
  and logs redact them. (#183, #184, #186, #187, #189, #199, #313, #375)
- Controller: all-in-one, the homelab default, runs a controller and a gateway in one process.
  `rpmgr all-in-one init` also creates the gateway group `default`, its public hostname the public
  URL's host if that is a valid one, with the enrolled gateway `local`. (#268, #269, #484, #493)
- Controller: a controller without a public address can stay on a private network, published
  through a gateway that passes its hostnames through to it. (#285)
- Controller: serves `/install.sh`. The script downloads the controller's own release from the
  controller, verifies its signatures with OpenSSL 3, installs the binary, the boot file, the
  connector-local policy and a hardened systemd unit, and enrolls the host. It reads the
  enrollment token from a file, the environment or the terminal. The command the web UI shows
  downloads the script and runs it with `sudo`, so that a token typed at the prompt also arrives
  under sudo-rs, Ubuntu's `sudo` since 25.10. It is tested on Debian 12 and 13, Ubuntu 22.04, 24.04
  and 26.04, and Rocky Linux 9. (#328, #374, #376, #476)
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
- Connector: the connector-local policy, `/etc/rpmgr/policy.yaml`, limits the targets a connector
  dials, even for a compromised controller. `rpmgr policy show` and `rpmgr policy allow-target`
  edit it and reload the connector; a reload ends relayed connections the policy no longer allows.
  (#247, #248, #249, #388)
- Gateway: `tcp` routes take a public port from their gateway group's port pools, within the org's
  port quota, and carry each connection as one stream to a connector. (#234, #235, #254, #326)
- Gateway: `udp` routes carry each client flow as QUIC datagrams, or as frames on the `h2`
  transport. (#279, #281, #283, #284)
- Gateway: `tcp_udp` routes publish one port number with TCP and UDP, for services such as DNS:
  one route with one list of targets, its port taken from the gateway group's TCP and UDP pools
  and counted against both quotas. (#506)
- Gateway: `tls_passthrough` routes pass TLS connections by server name to a connector, still
  encrypted. (#276, #278, #332)
- Gateway: `http` routes terminate TLS for their hostnames and proxy HTTP/1.1, HTTP/2, WebSocket
  and gRPC by hostname and path prefix, to HTTP, h2c or verified HTTPS upstreams (server name, CA
  bundle, optional SPKI pin). A target whose certificate nothing can verify, such as a
  self-signed one, may be marked unverified: the gateway then checks no certificate, and the web
  UI warns about it and marks the target. (#292, #294, #296, #333, #504)
- Gateway: `http` routes set `Forwarded` and `X-Forwarded-*` and keep a client's own only from the
  gateway group's trusted proxies. They can replace the `Host` header, set request and response
  headers, redirect or serve port 80, and send HSTS. (#297, #298)
- Connector: a route target is a host and port or a Unix socket, with a weight, a priority and
  optionally the PROXY protocol. (#249, #262, #334)
- Controller: route hostnames must lie under a domain the org has verified, by a DNS TXT record or
  by an HTTP token its gateways serve. An Instance Admin can mark a domain trusted without a proof.
  (#273, #276, #331, #332)
- Gateway: access policies hold IP allow and deny rules for every route type, and basic auth with
  argon2id-hashed passwords for `http` routes. A tightened policy also ends the open connections it
  now denies. (#299, #300, #338)
- Controller: `http` routes get certificates through ACME, by HTTP-01 or TLS-ALPN-01 answered by
  every gateway that serves the name, from Let's Encrypt or another ACME directory. Renewal is
  automatic and can also be started on demand. A name that fails is tried again after waits
  growing from 1 min to 6 h, and each retry rehearses at Let's Encrypt's staging directory first,
  so a name the CA cannot validate yet does not use up the account's limits. (#303, #304, #305,
  #339, #478)
- Controller: obtains its own certificate through ACME when its public URL has a public DNS name;
  otherwise it uses the configured certificate or a self-signed one. (#306)
- Controller: `http` routes can use uploaded certificates instead, whose keys are encrypted under
  the KEK; gateways fetch them by hash and choose one by server name. CA bundles verify HTTPS
  upstreams. (#287, #288, #289, #339, #340)
- API: the controller serves a public ConnectRPC API. Each method checks a named permission of the
  org roles Owner, Admin, Operator and Viewer, or of the Instance Admin. Lists are paged, updates
  take field masks and etags, and creates are idempotent by `request_id`. (#310, #311, #322, #333)
- API: local accounts with argon2id passwords, cookie sessions, TOTP and recovery codes, and step-up
  for sensitive actions. Users change their own password, and one-time links reset it. (#312,
  #313, #314, #316, #321)
- API: orgs with members and roles. Invitations and password resets are one-time links, also sent
  by e-mail when an SMTP relay is configured. (#318, #319, #349)
- API: personal API tokens for the CLI and scripts, each bound to one org and limited to
  permissions its owner holds; a token can step up. (#320, #346)
- API: services for gateway groups, gateways, port pools and quotas, enrollment tokens and install
  commands, connectors (status, data sessions, decommissioning, purging ephemeral ones), domains,
  routes and their targets, access policies, certificates, CA bundles, settings and the PKI status.
  (#322, #323, #326, #328, #329, #330, #331, #332, #333, #334, #338, #339, #340, #341)
- Controller: decommissioning a connector, `rpmgr leave` and the purge delete its route targets
  and each route left with no target, so its ports and hostnames are free again; the UI names
  those routes before, the API and the CLI after. Gateways listen only on the ports of routes a
  connector serves, and a refused port names the route that holds it. (#485)
- API: every write returns its revision, and the apply status says how far the agents are with it.
  A route can be previewed before it is saved, routes report their observed status, and
  configuration and status changes stream to clients. (#335, #336, #337)
- API: an org's resources export as YAML manifests. (#341, #342)
- CLI: `rpmgr login` signs in with a personal API token. Verb-first commands (`get`, `list`,
  `create`, `update`, `delete`, `enable`, `disable`, `preview` and more) cover every resource of the
  API, with table, YAML or JSON output. (#342, #344, #345, #346, #347, #348, #349)
- Gateway: a drained or disabled gateway lets its open connections finish within the drain period;
  `rpmgr drain gateway` starts a drain. (#347, #349)
- UI: the controller serves an embedded web UI under a strict Content Security Policy, with
  first-run setup, sign-in with a second factor, password resets, step-up in place, and an account
  page for profile, theme, password, authenticator, recovery codes, sessions and API tokens. (#356,
  #359, #360, #362, #363)
- UI: routes can be listed, created with a preview, edited with conflict resolution, switched on
  and off while the apply status follows live, given targets, and deleted after a confirmation.
  TCP and UDP routes are shown at their gateway group's public hostnames, such as
  `eu.example.net:25432`. (#363, #364, #365, #366, #471, #484, #493)
- UI: pages for connectors with an enrollment dialog, gateway groups, gateways and port pools,
  domains, certificates and CA bundles, access policies, and members and invitations. A connector
  is switched on and off on its page; the overview counts neither disabled connectors nor drained
  gateways as offline. (#366, #367, #368, #369, #503)
- UI: an overview with traffic and what needs attention, traffic per route, the audit log with
  chain verification, org and instance settings, the PKI page, read-only YAML views with export,
  and a command palette. (#370, #371, #372)
- UI: a sidebar groups the pages, and is a menu on narrow screens. The top bar holds "Go to…", a
  switch for the light, dark or system theme, which saves it to the profile, and the user menu.
  Both themes keep text contrast at WCAG 2.2 AA. The overview leads with a figure per area, the
  traffic of the last 24 hours and what needs attention. Every page uses the same page header,
  cards, tables, status badges and empty states, and fills the window's width, with long forms in
  columns on wide screens. The foot of the sidebar names the version the controller runs.
  (#459, #481, #502)
- UI: a field a form needs has a red asterisk after its label, also while it is needed only
  because of another field, such as the sender address once a mail relay is set. Screen readers
  announce the field as required. (#483, #493)
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
  user `rpmgr` and its directories, and offers to run `rpmgr setup`. (#436)
- Releases: reproducible builds with an SPDX SBOM, SLSA provenance attestations and a signed
  release manifest; distroless, nonroot multi-arch images at `ghcr.io/felix-homelab/rpmgr`, signed
  with cosign. (#384, #385)

[Unreleased]: https://github.com/felix-homelab/rpmgr/commits/main
