# 10 — Operations

> Status: Phase 1, being implemented. Tags: [F] fact · [R] recommendation · [T] target · [V] verify
> at implementation ([README](../README.md#how-to-read-these-documents)). Timeouts, sizes and limits
> are defined in [03-connections.md](03-connections.md); identities, lifetimes and cryptographic
> parameters in [04-security.md](04-security.md). This document links to them instead of restating
> them.

## Install

### Install paths

| Path | For | Notes |
|---|---|---|
| **Controller-hosted install script** | Gateways and connectors on Linux (`/install.sh`) | Served by the controller from embedded templates; downloads from the controller's `/dl/` mirror and verifies root key → signing-key statement → manifest signature → artifact SHA-256 with OpenSSL ≥ 3.0, and refuses to install without it [V VB-15] ([04](04-security.md#install-scripts)). The UI generates the full command with `--controller` and `--ca-pin` ([04](04-security.md#join-command)). There is no `/install.ps1`: Windows and macOS connectors are installed from packages (Phase 2) |
| **Distribution packages** (`.deb`, `.rpm`; Phase 2) | High-assurance installs | [R] Package name `rpmgr` (never `rpm`, [ADR-0001](adr/0001-name-rpmgr.md)); availability checked as VB-14. Built with nfpm and served from a signed apt/yum repository on GitHub Pages, signed with a key on the release signing token. The package installs the binary and the hardened units; enrollment is a separate step. Package installs are **updated by the package manager from the signed repository, not by OTA**: the updater refuses to replace a package-owned binary, because the next package run would silently revert it ([04](04-security.md#over-the-air-updates)). `.apk` packages are not planned |
| **Homebrew tap** (Phase 2) | Connectors on macOS | Updated with `brew upgrade`; no OTA on macOS before Phase 3 ([Windows and macOS connectors](#windows-and-macos-connectors-phase-2)) |
| **winget / MSI** (Phase 2) | Connectors on Windows | Updated through winget or a new MSI; no OTA on Windows before Phase 3 ([Windows and macOS connectors](#windows-and-macos-connectors-phase-2)) |
| **OCI image** `ghcr.io/felix-homelab/rpmgr` | Containers, Kubernetes | Distroless, nonroot; same binary; signed with cosign. Gateways need host networking or explicit port publishing for UDP/443. |
| **Release download** | Air-gapped or manual installs | Signed release manifest + artifacts; verify before use ([04](04-security.md#release-signing)). |

A Helm chart is Phase 3 ([13](13-roadmap.md#phase-3--advanced)).

### Supported platforms

| Requirement | Value |
|---|---|
| Linux kernel | ≥ 5.10 (the updater needs `openat2`, available since 5.6) |
| systemd | ≥ 249; the KEK source `systemd-credential` needs ≥ 250, otherwise the installer configures `file` [V VB-03] |
| Distributions | Debian 12+, Ubuntu 22.04+, RHEL, Rocky and Alma Linux 9+, Raspberry Pi OS (Debian 12 based) |
| `/install.sh` | OpenSSL ≥ 3.0 for signature verification [V VB-15] |
| Windows, macOS | Connectors only, from Phase 2 ([Windows and macOS connectors](#windows-and-macos-connectors-phase-2)) |

Architectures per role are in [05](05-features.md#platform-support).

**One instance per role per host.** Paths, unit names and the admin port are fixed per role, so a
host runs at most one controller (or all-in-one), one gateway and one connector.

A first installation of the controller:

```sh
rpmgr controller init --public-url https://panel.example.com   # creates DB, trust domain, root CA, first-user link
systemctl enable --now rpmgr-controller
```

`init` writes the boot file if it does not exist (from `--public-url` and, for a KEK file,
`--kek-source file --kek-path`), creates the KEK, the database and its migrations, and in one
transaction the trust domain, the database epoch, the CA with its signing keys, and the audit
entry. It never overwrites a boot file or a KEK: an existing one is read and used, so `init` can run
again after a failure, and it refuses a database that is already initialised or in use by a running
controller. A new systemd credential is encrypted with `systemd-creds encrypt` into
`/etc/rpmgr/credstore/<name>`; an existing one is readable only where systemd loads it, so `init`
then has to run under `systemd-run --pipe --wait --property=LoadCredentialEncrypted=…`.

`init` prints the trust domain and the CA pin for `--ca-pin`, and a one-time link for creating the
first user (Owner and Instance Admin), which arrives with local accounts in Phase 1. There is no
default password ([04](04-security.md#security-goals)).

### Filesystem layout

| Path | Owner / mode | Contents |
|---|---|---|
| `/usr/bin/rpmgr` (packages) or `/usr/local/bin/rpmgr` (script installs) | root, 0755 | The binary; `.prev` kept next to it during OTA. **Never writable by the service user**: for script installs and standalone binaries only the root-owned updater replaces it, at the path recorded in `install.json`; package installs are updated by the package manager ([04](04-security.md#over-the-air-updates)) |
| `/etc/rpmgr/<role>.yaml` | root, 0644 | Boot configuration ([Configuration](#configuration)) |
| `/etc/rpmgr/policy.yaml` | root, 0644 | Connector-local policy, read-only for the service user; the root updater also reads `auto_update` from it ([04](04-security.md#connector-local-policy)) |
| `/var/lib/rpmgr/identity/` | rpmgr, 0700 | Agent identity, written by `rpmgr enroll`: `key.pem` (private key, 0600), `chain.pem` (certificate and intermediates), `roots.pem` (the pinned root and roots it cross-signed), `signing.pem` (the config-signing certificates, replaced by those of every `Welcome`), `agent.json` (agent ID, trust domain, controller endpoints). Enrollment refuses a directory open to the group or other users, and an existing identity without `--replace` |
| `/var/lib/rpmgr/` | rpmgr, 0750 | Last-known-good snapshot (`snapshot.signed`, 0600) and **deny-list** (both signed; the deny-list is loaded before any session is accepted), stateless reset key (gateways), SQLite database and its lock file `controller.db.lock`, held by the running controller (controller) |
| `/var/lib/rpmgr/update/` | rpmgr, 0750 | OTA download area: artifact and signed manifest written by the agent. **Untrusted input** to the updater, which never verifies or installs files in place here |
| `/var/lib/rpmgr-update/` | root, 0700 | Updater state, out of the service user's reach: version floor and highest manifest `seq` (initialised at install time from the running version and its release `seq`), `install.json` (binary path, role service and install method recorded by the installer), and `staging/`, where the updater copies and verifies the files |
| `/var/lib/rpmgr/audit-checkpoints.log` (controller) | rpmgr, 0640 | Signed audit checkpoints, appended locally and included in every backup; the external sink (Phase 2) is what makes tampering evident ([04](04-security.md#audit-log)) |
| `/var/lib/rpmgr/revocations.log` (controller) | rpmgr, 0640 | This replica's durable, fsync'd **revocation log**: every revocation and credential supersession is appended here first, then shipped asynchronously to the shared readable sink ([Backup and restore](#backup-and-restore)) |

### Hardened systemd units

One unit per role: `rpmgr-controller.service`, `rpmgr-gateway.service`, `rpmgr-connector.service`
and `rpmgr-all-in-one.service`, plus the root-owned updater pair `rpmgr-update.path` and
`rpmgr-update.service` (below). Excerpt for a gateway:

```ini
[Service]
User=rpmgr
Group=rpmgr
ExecStart=/usr/bin/rpmgr gateway --config /etc/rpmgr/gateway.yaml
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
StateDirectory=rpmgr
ReadOnlyPaths=/etc/rpmgr
LimitNOFILE=1048576
Restart=on-failure
RestartSec=2s
```

- **Controller**: the same, without `CAP_NET_BIND_SERVICE` if it listens on high ports behind a
  gateway, plus `LoadCredentialEncrypted=rpmgr-kek:/etc/rpmgr/credstore/rpmgr-kek` for the KEK
  ([04](04-security.md#secrets-at-rest-and-in-logs)) [V VB-03].
- **Connector**: no capabilities at all; `ReadOnlyPaths=/etc/rpmgr` keeps `policy.yaml` out of the
  service's reach. `ExecReload=/bin/kill -HUP $MAINPID`: `rpmgr policy …` edits the policy file and
  runs `systemctl reload`; the connector also watches the file and re-evaluates its current snapshot
  on change ([04](04-security.md#connector-local-policy)). Phase 3 features that need privileges (virtual networks with a kernel TUN device,
  shell) are documented with the exact additional unit settings when they ship; the userspace
  netstack variant needs none.
- **Updater** (every role): a root-owned pair `rpmgr-update.path` (watches `/var/lib/rpmgr/update/`)
  and oneshot `rpmgr-update.service` ([04](04-security.md#over-the-air-updates)). It:
  1. reads `auto_update` from `/etc/rpmgr/policy.yaml` **itself** and stops if updates are not
     allowed (it does not trust the agent's decision);
  2. refuses to act on a **package-owned** binary (`install.json` records the install method):
     package installs are updated by the package manager from the signed repository, never by OTA,
     because the next package run would silently revert an OTA swap;
  3. opens the staging directory through a directory fd with
     `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`, requires regular files (`fstat` → `S_ISREG`;
     no symlinked directory, FIFO or device), and checks that each file's size is ≤ the manifest's
     size and ≤ a hard cap of 256 MiB, before and while copying;
  4. **copies** the files into the root-only `/var/lib/rpmgr-update/staging/` and verifies **the
     copy**: signature, manifest `seq`, version floor, OS/arch, size and SHA-256. The service user can
     no longer swap a file or plant a symlink between check and install;
  5. refuses anything below the persisted floor. Floor and `seq` are initialised at install time from
     the running version and its release `seq`; after that the running version plays no role. A
     manifest with a higher `seq` may lower the floor, which makes **signed downgrades** possible,
     while replaying an old manifest (lower `seq`) is refused — also on a fresh host;
  6. copies the verified file into the target directory as `.rpmgr.new` (same filesystem, so no
     cross-filesystem `rename`), fsyncs it, re-hashes it, and `rename`s it over the binary at the path
     recorded in `/var/lib/rpmgr-update/install.json` (`/usr/local/bin/rpmgr` for script installs),
     keeping `.prev`, then restarts the role service;
  7. polls the agent's admin `/readyz` (ready only with an established control session and an
     applied snapshot, see [Health](#health)) for up to 5 min, otherwise rolls back to `.prev`. The
     automatic rollback is exempt from the floor, because floor and `seq` are only raised after a
     successful health check.

  The role service's `NoNewPrivileges=yes` and `ProtectSystem=strict` stay intact; the service user
  can never write the binary or the updater state.

  ```ini
  # rpmgr-update.path
  [Path]
  PathChanged=/var/lib/rpmgr/update/manifest.json

  # rpmgr-update.service (runs as root; the installer writes the binary path from install.json)
  [Service]
  Type=oneshot
  ExecStart=/usr/bin/rpmgr update apply --staged /var/lib/rpmgr/update --state /var/lib/rpmgr-update
  ```

- No secret appears in `ExecStart` or `Environment=` ([04](04-security.md#secrets-at-rest-and-in-logs)).
- The installer applies the host tuning from [03](03-connections.md#host-tuning-applied-by-the-installer).

### Windows and macOS connectors (Phase 2)

Only the connector role runs on Windows and macOS. Both follow the Linux rules: the policy file is
writable only by administrators, the service account can read it but not change it, and the
connector reloads it on a service signal and when the file changes
([04](04-security.md#connector-local-policy)).

| | Windows | macOS |
|---|---|---|
| Install and update | winget or MSI | Homebrew tap |
| Service | Windows service `rpmgr-connector`, running under its virtual service account | launchd daemon `com.felix-homelab.rpmgr.connector`, running as user `_rpmgr` |
| Local policy | `%ProgramData%\rpmgr\policy.yaml`; writable only by SYSTEM and Administrators, read-only for the service account | `/etc/rpmgr/policy.yaml`; owner root, mode 0644 |
| Policy reload | Service control request and file watch | SIGHUP and file watch |
| OTA | Not before Phase 3; updated by the package manager | Not before Phase 3; updated by the package manager |

In Phase 1, CI only builds these targets; end-to-end tests on Windows and macOS start in Phase 2
([12](12-testing-and-quality.md#continuous-integration)).

## Ports

| Role | Port | Protocol | Purpose | Exposure |
|---|---|---|---|---|
| Gateway | 443 | TCP | Public HTTPS (terminated), TLS-passthrough routes, data-session fallback (`rpmgr-tunnel-h2/1`, SNI `<gateway-id>.gateway.<td>`), WSS transport on the **gateway's own** WSS hostname at `/.rpmgr/tunnel` (Phase 2), controller passthrough ([03](03-connections.md#port-443-multiplexing)). Connectors dial each gateway at its own `tunnel_endpoints`; group-level DNS or anycast names are for public traffic only | Public |
| Gateway | 443 | UDP | QUIC data sessions (`rpmgr-tunnel/1`); HTTP/3 in Phase 3. Optionally, tunnels move to a separate UDP port (`listen.tunnel_udp`) when their QUIC tuning must differ from public HTTP/3 ([03](03-connections.md#port-443-multiplexing)) | Public |
| Gateway | 80 | TCP | ACME HTTP-01 challenges; per `http` route a redirect to HTTPS (default), plain HTTP, or nothing (`port80`, [06](06-data-model.md#routing)) | Public |
| Gateway | port pools (e.g. 20000–20999) | TCP and/or UDP | `tcp`/`udp` routes; ranges are gateway-group settings, allocated per [04](04-security.md#route-and-hostname-ownership) | Public, only the configured ranges |
| Controller | 443 | TCP | UI, public API, enrollment, agent control sessions (SNI `controller.<td>`), `Reauth` for expired agent certificates (SNI `reauth.controller.<td>`), `/install.sh`, `/dl/` mirror | Reachable by browsers and agents (directly or via a gateway passthrough route for both agent names, [03](03-connections.md#reaching-a-private-controller)) |
| Controller | 80 | TCP | Optional: ACME HTTP-01 and redirect, if the controller obtains its own UI certificate | Public, optional |
| Every role | 127.0.0.1:7381 (controller, all-in-one), 127.0.0.1:7382 (gateway), 127.0.0.1:7383 (connector) | TCP | Admin listener: `/metrics`, `/healthz`, `/readyz`, pprof (off unless enabled). One port per role, so roles on the same host never collide, and none is 9090, Prometheus's own port. If the default is taken, the installer picks the next free port and writes it to the boot file. The ports are registered in Prometheus's port registry once public code exists | Localhost by default; may be bound to a private interface for scrapers and load-balancer checks, **never** public |
| Connector | — | — | No inbound ports. Outbound: 443/TCP+UDP to gateways, 443/TCP to the controller | — |
| Connector | per `allow_listen` | TCP/UDP | Visitor listeners for private services | Local or LAN, as the policy allows |
| All-in-one | 80, 443/TCP, 443/UDP, port pools, admin | | Gateway ports; the controller is reached through the gateway's SNI router in-process | Public (except admin) |

**Controller outbound connections.** The controller dials out only for these, all through
`HTTPS_PROXY`/`ALL_PROXY` when set:

| Destination | Port | Purpose | When |
|---|---|---|---|
| The ACME CA (e.g. Let's Encrypt) | 443/TCP | Certificate orders | ACME in use |
| GitHub Releases of `felix-homelab/rpmgr` | 443/TCP | Daily release check: fetches the signed release manifest (a plain GET, no data sent); artifacts are mirrored to `/dl/` once a rollout is approved ([04](04-security.md#over-the-air-updates)); in Phase 1, the artifacts of the controller's own version ([D59](14-open-decisions.md#security-defaults)). Only controllers fetch releases; agents download from the controller's mirror | On by default ([D4](14-open-decisions.md#product-and-project)); off in Settings → Updates; air-gapped installs upload the manifest instead |
| `api.cloudflare.com` | 443/TCP | DNS provider API, and Cloudflare's IP ranges for proxied routes ([15](15-dns.md#cloudflare-specifics)) | A Cloudflare provider is connected (Phase 2) |
| The authoritative nameservers of claimed domains | 53/UDP and TCP | Reading `_rpmgr-challenge` TXT records ([04](04-security.md#route-and-hostname-ownership)) | Domains pending verification |
| Webhook receivers, the external audit sink, the revocation-log sink, OIDC providers, SMTP, KMS | as configured | Integrations configured by an admin | As configured |

## Configuration

Configuration has two layers (the commands and their flags are listed in
[16](16-cli.md)):

1. A **small boot file** per role, read at start: only what is needed before the database or the
   control session is available. Strict YAML: unknown keys are rejected and the process refuses to
   start. Containers mount the boot file (and secrets as files). The only environment variables
   read are `RPMGR_CONFIG` (config path), the proxy variables (`HTTPS_PROXY`, `ALL_PROXY`,
   `NO_PROXY`) and, by the install script and `rpmgr enroll` only, `RPMGR_ENROLL_TOKEN`. There is no
   KEK from an environment variable ([04](04-security.md#secrets-at-rest-and-in-logs)).
2. **Runtime settings in the database**, typed and validated, edited in the UI or API, audited, and
   distributed to agents through snapshots. No restart needed.

### Boot files

```yaml
# /etc/rpmgr/controller.yaml
version: 1
public_url: https://panel.example.com
listen:
  https: ":443"
  http: ":80"                 # ACME HTTP-01 + redirect; "" disables
  admin: "127.0.0.1:7381"
database:
  driver: sqlite              # sqlite; postgres from Phase 2 (D57)
  dsn: /var/lib/rpmgr/controller.db
kek:
  source: systemd-credential  # systemd-credential | file; kms (Vault/OpenBao Transit) from Phase 2; never env
  name: rpmgr-kek             # systemd-credential: the credential name
  # path: /etc/rpmgr/kek      # file: base64 of 32 random bytes, mode 0600 or 0400
log:
  level: info                 # debug | info | warn | error
  format: json
```

```yaml
# /etc/rpmgr/gateway.yaml
version: 1
controller:
  endpoints: [https://panel.example.com]   # replaced by the list from snapshots after first connect
identity_dir: /var/lib/rpmgr/identity       # key, certificate chain, trust bundle (written by enroll)
state_dir: /var/lib/rpmgr                   # last-known-good snapshot, stateless reset key
listen:
  tcp: ":443"
  udp: ":443"
  tunnel_udp: ""                            # optional separate UDP port for tunnels; empty = share 443
  http: ":80"
  admin: "127.0.0.1:7382"
log: { level: info, format: json }
```

```yaml
# /etc/rpmgr/connector.yaml
version: 1
controller:
  endpoints: [https://panel.example.com]
identity_dir: /var/lib/rpmgr/identity
state_dir: /var/lib/rpmgr
policy_file: /etc/rpmgr/policy.yaml         # see 04-security.md#connector-local-policy
listen:
  admin: "127.0.0.1:7383"
log: { level: info, format: json }
# HTTPS_PROXY / ALL_PROXY / NO_PROXY are honoured for the TCP transports (03-connections.md#transports-and-fallback)
```

Rules for every boot file:

- One YAML document of at most 64 KiB with `version: 1`; another version, an unknown key or a value
  of the wrong type stops the process with the line at fault.
- An omitted key takes the value shown above, except `public_url` (controller) and
  `controller.endpoints` (agents), which are required. `listen.http: ""` disables port 80; the
  other listeners cannot be disabled.
- URLs are `https://<host>[:<port>]` without user, path, query or fragment; listen addresses are
  `[host]:port`; paths are absolute. `database.driver: postgres` and `kek.source: kms` are refused
  until Phase 2.

Port pools, routes, gateway groups and everything else an agent runs come from snapshots, not from
the boot file.

### Runtime settings (UI → Settings)

| Scope | Examples |
|---|---|
| Instance (Instance Admin) | Default data-session transport (`auto`, `quic`, `h2`; shipped `auto`, [03](03-connections.md#transport-selection)), public URL aliases (each alias is also accepted as `Origin` by the CSRF check, [04](04-security.md#human-authentication-and-sessions)), ACME account, Cloudflare IP ranges (refreshed automatically), SMTP (optional), retention (audit, metric rollups), external audit sink (Phase 2), revocation-log sink ([Backup and restore](#backup-and-restore)), controller endpoints advertised to agents. **PKI** page: leaf-certificate lifetime and grace period ([D8](14-open-decisions.md#security-defaults), values and ranges in [04](04-security.md#leaf-certificates)), password-hash profile. **Updates** page: release check (on by default, [D4](14-open-decisions.md#product-and-project)), update channel (`stable` or `prerelease`), manifest upload for air-gapped installs, rollout policy (Phase 2) |
| Org (Owner) | MFA requirement, OIDC providers and group→role mapping, default gateway group, Operator may enroll connectors, branding ([04](04-security.md#roles)) |
| Gateway group (Admin) | Port pools, trusted-proxy CIDRs, DNS target for managed records, default TLS options, per-route limit defaults |
| DNS (Owner/Admin; Instance Admin for the system org) | DNS providers and their tokens, managed zones and their gates. These are resources with their own pages, not settings ([15](15-dns.md)) |
| Install command generator | Install prefix, gateway group, labels, ephemeral flag, `--allow-target` entries — the install location lives here, because it is a property of the install command, not of a running agent. There is no service-name suffix: one instance per role per host ([Supported platforms](#supported-platforms)) |

Secret fields are write-only ([04](04-security.md#secrets-at-rest-and-in-logs)). Settings that
affect agents take effect through reconciliation and show apply status like any other change
([03](03-connections.md#configuration-reconciliation)).

## Upgrades and version skew

[R] Policy:

- **Semantic versioning** of the release (`v<major>.<minor>.<patch>`). The **protocol major
  version is in the ALPN** (`rpmgr-tunnel/1`, …) and changes only with a release major version
  ([03](03-connections.md#versioning-and-capabilities)).
- **A controller at minor N supports agents at N and N−1** of the same major. Agents newer than the
  controller are not supported: they connect, the UI shows a warning, and features the controller
  does not know are not used.
- The controller refuses agents older than `min_agent_version` with `Goodbye{upgrade_required}`
  ([03](03-connections.md#versioning-and-capabilities)), so skew beyond N−1 is visible, not silent.
- A protocol change that would break N−1 ships behind a capability flag first; the old behaviour is
  removed one minor release later.

**Upgrade order**: controller(s) → gateways → connectors.

1. **Controller.** Back up first ([Backup and restore](#backup-and-restore)). Migrations run at
   start under a database lock (single node) or with `rpmgr migrate` before rolling the replicas
   (HA). Agents keep running their last-known-good snapshot while the controller restarts
   ([03](03-connections.md#failure-modes)).
2. **Gateways.** One at a time per gateway group: the gateway drains, connectors re-home to the
   other gateways of the group, then it restarts ([03](03-connections.md#multiple-gateways)).
3. **Connectors.** Through the staged OTA rollout: canary → percentage → all, with automatic
   rollback on failure ([04](04-security.md#over-the-air-updates)). Hosts with
   `auto_update: notify` or `off` are listed in the UI and updated by their operators. Package
   installs are updated by the package manager from the signed repository, not by OTA. Windows and
   macOS connectors (Phase 2) are updated through winget or Homebrew; they get no OTA before
   Phase 3.

## Backup and restore

- `rpmgr backup --out <file>` writes a **consistent** copy of the controller database: `VACUUM INTO`
  on SQLite, which runs while the controller keeps reading and writing
  ([S8](spikes/S8.md)), `pg_dump` on PostgreSQL (or the operator's own PostgreSQL backups).
  Secrets in the backup stay envelope-encrypted.
- **The KEK is backed up separately** and stored apart from database backups. A database backup
  without its KEK cannot be used to recover CA keys, ACME keys or other secrets; a KEK stored next
  to the backup defeats the encryption.
- `rpmgr restore --in <file>` restores the database and **assigns a new `db_epoch`** — a fresh
  random UUIDv7, as at init, so restoring the same backup twice never reuses an epoch. Agents accept
  the restored, lower revisions only together with the new epoch
  ([03](03-connections.md#revisions-and-ordering)).
- **Relying parties never shrink their deny-list across epochs**: agents merge deny-list updates by
  union and drop an entry only after its own expiry, never because of a version number or a new
  `db_epoch`, so certificates revoked after the backup stay denied on every gateway, connector and
  controller ([04](04-security.md#revocation)).
- **Revocation log.** An append-only log outside the database records certificate revocations,
  API-token revocations, member removals and role downgrades, session revocations, superseded
  certificate serials, and **credential supersessions** (password, MFA and recovery-code changes,
  removed shell grants and visitor grants).
  - A revocation or supersession is **committed and enforced immediately**, even when the shared sink
    is unavailable: security actions are never refused because of the log.
  - Each replica first appends the entry to its durable, fsync'd local log
    (`/var/lib/rpmgr/revocations.log`), then ships it to the shared, readable sink asynchronously
    with retries. While a replica has an unshipped backlog, the UI raises an alert ("revocation log
    not yet off-host").
  - **Sink types**: S3-compatible object storage, where the sequence number is allocated by a
    conditional create (`If-None-Match: *`) of the object named `<seq>`, or a filesystem path (for
    example a file share), where it is allocated by an exclusive create of the file `<seq>`. Either
    way the allocation is the write, so the sink has no gaps. Entries form a **hash chain**. Phase 1
    offers the filesystem sink; the S3-compatible sink comes with HA in Phase 2
    ([D58](14-open-decisions.md#project-and-process)).
  - A syslog or webhook sink cannot be read back and does not count.
  - **Single node**: the sink is optional. Without one, the local `revocations.log`, which every
    backup includes, is the only copy; the restore reads it with `--revocation-log <file>`. The UI
    then shows a standing hardening warning ("revocation log has no off-host copy") instead of the
    backlog alert. **More than one controller replica**: a sink is required; a second replica
    refuses to start without one ([High availability](#high-availability)).
- **Restore side effects**, applied automatically:
  - the restore merges the sink with every reachable replica's local log, checks the sink's hash
    chain, then re-applies every entry newer than the backup;
  - all sessions and all **unused enrollment tokens** from the backup are invalidated (a token
    consumed after the backup would otherwise become usable again);
  - agents enrolled after the backup are unknown and must re-enroll;
  - every managed DNS zone starts **held**: nothing is written at a DNS provider until an Owner or
    Admin approves the zone's plan, which shows records created or deleted since the backup
    ([15](15-dns.md#held-zones-and-plan-approval)). `rpmgr restore --dns-disabled` disables DNS
    automation entirely, for a copy restored into a test environment that must never touch
    production DNS.
- **Fail closed** only when the sink's hash chain is broken, or a replica that reported an unshipped
  backlog has an unreachable local log: all API tokens and service accounts are suspended, all
  sessions invalidated, every user must reset their password and re-verify MFA, and the instance
  enters **restore review** mode (read-only):
  - each org's **Owner** re-confirms only their own org's memberships and roles; an org stays
    read-only until its Owner (or the Instance Admin) confirms it;
  - the instance-wide review is ended by the **Instance Admin** with a local CLI command on the
    controller host, `rpmgr restore confirm`. An org Owner cannot end it, because restored Owner
    memberships are exactly what is in doubt.
- [R] Back up daily and before every controller upgrade; test a restore at least quarterly.

## High availability

- **Two or more controllers on PostgreSQL** ([02](02-architecture.md#high-availability)). SQLite is
  single-node only. Making PostgreSQL itself highly available is the operator's responsibility.
- **Moving from SQLite to PostgreSQL** (Phase 2): stop the controller, then run
  `rpmgr migrate-db --from <sqlite path> --to <postgres DSN>`, which copies every table offline
  into a PostgreSQL database migrated to the same schema version. Secrets stay envelope-encrypted
  under the same KEK. Then point the boot file at PostgreSQL and start the controllers.
- **Any replica serves any request.** Revisions come from the database, compilation is
  deterministic, and each agent has one control session tracked by `session_epoch`
  ([03](03-connections.md#revisions-and-ordering)).
- **Session registry.** A row per control session records which replica holds it. Pushes for an
  agent are signalled to that replica via PostgreSQL `LISTEN/NOTIFY`; no replica polls.
  `LISTEN/NOTIFY` carries only small signals (payload limit 8000 bytes), never operation data.
- **Imperative operations** (live logs, diagnostics, later the shell): the replica holding the
  agent's control session serves the operation; the replica serving the user's stream proxies to it
  over an internal controller-to-controller mutual-TLS connection (controller SPIFFE IDs) [V S9].
  Controller node certificates therefore carry **clientAuth as well as serverAuth**, and a
  `controller_nodes` table records each replica's `node_id`, `internal_address` and `last_seen`
  ([04](04-security.md#leaf-certificates)).
- **Revocation log**: every replica appends each entry to its durable local log first and enforces
  it immediately, then ships it asynchronously to the shared sink, where sequence numbers are
  allocated by conditional create of the object `<seq>` (no gaps) and entries form a hash chain
  ([Backup and restore](#backup-and-restore)). With more than one replica the sink is required. A
  sink outage never blocks a revocation; it raises an alert until the backlog is shipped.
- **Singleton jobs** (ACME orders, CA rotation, ephemeral purge, metric rollups, audit
  checkpoints, the DNS job) run under a database **lease with a fencing token**: a replica that lost
  its lease cannot commit work started under it. Each time a replica takes a job's lease it is
  granted the job's system scope, which the audit log records; lease timing is in
  [03](03-connections.md#timeouts-keepalive-and-backoff).
- **DNS job** (Phase 2): configuration transactions that touch DNS sources send `dns_dirty` with the
  zone ID over `LISTEN/NOTIFY` to the replica holding the `dns` lease; a replica that takes over the
  lease starts with a full pass. The fencing token cannot stop a call to the provider, so the job
  checks its lease before every batch. DNS-01 writes come from the ACME lease holder and share the
  provider's rate budget ([15](15-dns.md#the-dns-job)).
- **Load balancer**: layer-4 TLS passthrough for at least the agent hostnames `controller.<td>`
  and `reauth.controller.<td>`, because mutual TLS terminates at the controller. [R] Pass all of 443 through at
  layer 4 and let the controller terminate the UI as well; health checks use `/readyz` on a private
  admin interface.
- Per-replica admission limits from [03](03-connections.md#timeouts-keepalive-and-backoff) prevent
  reconnect storms after a replica fails.

## Observability

### Logs

- Structured JSON via `log/slog`, one line per event, with `trace_id` where available.
- Secrets are redacted by type and by field annotation; whole requests are never logged
  ([04](04-security.md#secrets-at-rest-and-in-logs)).
- Live logs of an agent can be streamed to the UI (an imperative operation with a deadline,
  [03](03-connections.md#service-sketch)).

### Metrics

Prometheus exposition on the admin listener of every role. Labels use stable IDs (`route` = route
ID); there are never per-connection or per-client-IP labels.

| Metric | Type | Role | Meaning |
|---|---|---|---|
| `rpmgr_gateway_sessions{transport}` | gauge | gateway | Data sessions from connectors, by transport (`quic`, `h2`, `wss`) |
| `rpmgr_gateway_streams_open{route,transport}` | gauge | gateway | Open user streams |
| `rpmgr_route_connections_total{route,result}` | counter | gateway | User connections by `StreamResult` code name ([03](03-connections.md#framing)) |
| `rpmgr_route_bytes_total{route,direction}` | counter | gateway | Bytes, `direction` = `in` (public → service) or `out` |
| `rpmgr_route_connection_setup_seconds{route}` | histogram | gateway | Accept → `StreamResult` |
| `rpmgr_http_requests_total{route,code}` | counter | gateway | HTTP routes |
| `rpmgr_udp_oversize_total{route}` | counter | gateway, connector | UDP payloads too large for a datagram, sent on the flow stream ([03](03-connections.md#udp-routes)) |
| `rpmgr_udp_datagrams_dropped_total{route,reason}` | counter | gateway, connector | Drops: queue full, unknown flow, policy |
| `rpmgr_connector_session_rtt_seconds{gateway,transport}` | gauge | connector | Smoothed RTT per data session |
| `rpmgr_connector_target_dial_seconds{route}` | histogram | connector | Upstream dial time |
| `rpmgr_connector_policy_denied_total{route}` | counter | connector | Dials refused by local policy |
| `rpmgr_agent_applied_revision` | gauge | agent | Last applied revision `seq` |
| `rpmgr_agent_apply_status{agent,status}` | gauge | controller | 1 for the current status (`pending`, `applied`, `rejected`, `apply_timeout`) |
| `rpmgr_agent_cert_expiry_timestamp_seconds` | gauge | agent | Own certificate `NotAfter` |
| `rpmgr_controller_control_sessions` | gauge | controller | Connected agents |
| `rpmgr_acme_cert_expiry_timestamp_seconds{hostname}` | gauge | controller | Public certificates |
| `rpmgr_quic_gso_enabled`, `rpmgr_quic_udp_buffer_warning` | gauge | gateway, connector | Host tuning status ([03](03-connections.md#host-tuning-applied-by-the-installer)) |
| `rpmgr_audit_checkpoint_age_seconds` | gauge | controller | Time since the last checkpoint reached the external sink |
| `rpmgr_dns_sync_runs_total{zone,result}` | counter | controller | DNS passes per managed zone: `ok`, `held`, `failed`, `rate_limited` |
| `rpmgr_dns_names{zone,status}` | gauge | controller | Names per `dns_status` ([15](15-dns.md#publication-rules)) |
| `rpmgr_dns_records{zone,state}` | gauge | controller | Owned records per ledger state |
| `rpmgr_dns_provider_requests_total{provider,code}` | counter | controller | Provider API calls by HTTP status |
| `rpmgr_dns_provider_token_expiry_timestamp_seconds{provider}` | gauge | controller | Expiry of the provider's token, if it has one |

### Traces

OpenTelemetry (OTLP export, off by default). The W3C trace context travels in `StreamOpen`
([03](03-connections.md#framing)) and in HTTP `traceparent` headers, so one public request can be
followed gateway → connector → service. [R] Head sampling at 1 % by default, always-on for errors.

### Health

- `/healthz`: process is alive.
- `/readyz`: controller — database reachable and migrations current; gateway — control session
  established, snapshot applied and listeners bound; connector — control session established and a
  snapshot applied (data-session state is reported separately and does not affect readiness). The
  root updater uses the agents' `/readyz` as its health check after an update
  ([Hardened systemd units](#hardened-systemd-units)).
- UI status pages: per agent (version, session, transport, RTT, applied revision, apply status and
  reasons, certificate expiry, clock offset) and per route (desired vs observed, ready connectors,
  recent errors).

### Suggested alerts

| Alert | Condition |
|---|---|
| Agent offline | No control session for 5 min |
| Configuration not applied | `apply_status` is `rejected` or `apply_timeout` |
| Certificate renewal failing | Agent certificate expires in < 2 days (renewal normally happens at half-life) |
| Public certificate expiring | ACME certificate expires in < 14 days |
| Route has no ready connector | A route's ready-connector count is 0 for 2 min |
| UDP payloads too large | `rpmgr_udp_oversize_total` rate > 0 sustained |
| Clock skew | Agent clock offset > 30 s |
| Audit sink behind | `rpmgr_audit_checkpoint_age_seconds` > 1 h |
| Revocation log not yet off-host | A revocation-log sink is configured and a controller replica has entries not yet shipped to it for > 5 min (without a sink, the UI shows a standing hardening warning instead) |
| DNS conflict | A name in a managed zone is `conflict` or `ambiguous` for > 15 min |
| DNS zone held | A managed zone is `held` (after import, restore or the deletion guard) |
| DNS sync failing | No successful pass of a managed zone for > 30 min, or the provider status is not `ok` |
| DNS-provider token invalid or expiring | The provider rejects the token, or it expires within the warning period ([15](15-dns.md#timers-and-limits)) |
| Cloudflare IP ranges stale | The daily refresh was rejected by the sanity bounds or failed for > 3 days, while proxied routes exist |

## Hardening checklist

- [ ] Controller UI on HTTPS with a valid certificate; HSTS on.
- [ ] KEK in a KMS, a systemd encrypted credential or a mounted secret file (environment variables
      are not accepted); KEK backup stored separately from database backups.
- [ ] Admin listener bound to localhost or a private interface only.
- [ ] MFA required for the org; WebAuthn for Owners and Instance Admins.
- [ ] SSO configured with a break-glass local Owner whose credentials are stored offline.
- [ ] External audit sink configured (Phase 2); revocation-log sink configured (required for more
      than one controller replica).
- [ ] Every connector's `policy.yaml` reviewed: `allow_targets` as narrow as possible (the default
      is `[]`, nothing; loopback is not allowed unless listed); shell, functions, egress proxy and
      virtual-network routes off unless needed.
- [ ] `auto_update` chosen deliberately per host; staged rollout policy set.
- [ ] Gateway groups expose only the port pools they need; trusted-proxy CIDRs set if gateways sit
      behind another proxy.
- [ ] DNS-provider tokens: API tokens (never a Global API Key) with only Zone Read and DNS Write,
      limited to the managed zones and to the controller's egress addresses, with an expiry;
      mail and corporate records kept in a zone rpmgr does not manage ([15](15-dns.md)).
- [ ] Proxied routes: the zone's SSL/TLS mode set to Full (strict).
- [ ] Route access policies set for every route that is not meant to be public.
- [ ] Host tuning applied ([03](03-connections.md#host-tuning-applied-by-the-installer)); time
      synchronisation (NTP/chrony) on every host.
- [ ] Backups scheduled (with the revocation log) and a restore tested.
- [ ] Enrollment tokens: no long-lived multi-use tokens except for ephemeral connectors.
- [ ] Release signatures verified for manual installs; packages from the signed repository.

## Runbooks

Each runbook: **symptoms → steps → done when**.

### Controller down

- **Symptoms**: UI unreachable; `rpmgr_controller_control_sessions` absent; traffic still flows.
- **Steps**: check `/healthz` and `/readyz` on the admin listener; check the database (`readyz`
  reports it); check the KEK source is available; read the last log lines. Restart the service.
  If the database is lost, restore ([Restore from backup](#restore-from-backup)).
- **Done when**: agents reconnect (backoff per [03](03-connections.md#timeouts-keepalive-and-backoff))
  and report `applied` for the current revision.

### Replace a gateway

- **Steps**: in the UI, add the new gateway to the group with its own `tunnel_endpoints` (address,
  and its WSS hostname if WSS is used) and create an enrollment token; install and enroll the new
  host; wait until connectors show a session to it; update public DNS/load balancer — for
  managed zones, change the group's DNS target instead and wait until its names are `published`;
  set the old gateway to draining; after the gateway drain period, revoke and decommission it.
- **Done when**: the old gateway has no sessions and is revoked; route readiness unchanged.

### Re-enroll a connector

- **When**: identity files lost, certificate expired beyond the grace period
  ([04](04-security.md#leaf-certificates)), or after a root compromise.
- **Steps**: in the UI, mint a **re-enrollment token bound to this one connector** (step-up
  required); the host cannot choose the ID, so a token cannot be used to take over another
  connector. On the host run `rpmgr enroll --replace` with the token from `--token-file`,
  `RPMGR_ENROLL_TOKEN` or the terminal prompt. When the new certificate connects, every certificate
  issued to this connector before the replacement is revoked **by serial** — not by identity, because
  the connector ID and SPIFFE ID are reused and an identity-level entry would deny the new
  certificate too.
- **Done when**: the connector reports `applied`; the old serials appear on the deny-list.

### Revoke a compromised connector

- **Steps**: UI → Connectors → Revoke (step-up required). The deny-list is pushed to all relying
  parties and live sessions close immediately ([04](04-security.md#revocation)). Review the audit
  log and route metrics for the connector; rotate any credentials the host's services held; rebuild
  the host before re-enrolling.
- **Done when**: no session from the identity anywhere; routes served by other connectors healthy.

### Rotate the issuing intermediate

- **Steps**: normally automatic at half-life. Manual: `rpmgr ca rotate-intermediate` on the
  controller host (authorised by host access, audited as `local-cli`), or Settings → PKI in the UI
  (Instance Admin, step-up). Agents receive the new chain at their next renewal
  ([04](04-security.md#ca-rotation)).
- **Done when**: every agent's certificate is issued by the new intermediate (Settings → PKI).

### Root compromise

- **Steps**: treat every certificate as untrusted. Generate a new trust bundle with a new root
  (`rpmgr ca new-root --compromised`, Phase 2; in Phase 1, initialise a new controller), which
  publishes a new pin. Re-enroll **every** agent with the
  new `--ca-pin` (in-band rotation is not possible, [04](04-security.md#ca-rotation)). Investigate
  how the KEK and database were exposed; rotate the KEK.
- **Done when**: no agent presents a certificate from the old root.

### Rotate the KEK

- **Steps**: provision the new KEK in its source; `rpmgr kek rotate` re-wraps every data key
  ([04](04-security.md#secrets-at-rest-and-in-logs)); back up the new KEK separately; retire the old
  one after a successful backup and test restore.
- **Done when**: no data key is wrapped with the old KEK version (`rpmgr kek status`).

### Restore from backup

- **Steps**: stop all controllers; `rpmgr restore --in <file> --revocation-log <sink-url or file>
  [--revocation-log <replica-local-log> …]` (new random `db_epoch`); the restore merges the sink with
  every reachable replica's local log. Without a sink (single node), pass the local
  `revocations.log` from the old host or from the backup. Provide the KEK that matches the backup;
  start one controller, check `/readyz`, then the others.
- **After**: check that the sink's hash chain was intact and that entries newer than the backup were
  re-applied. If the restore failed closed (broken chain, or an unreachable local log of a replica
  that reported an unshipped backlog), the instance is in **restore review** mode: each org's Owner
  re-confirms their own org's memberships and roles and re-enables API tokens and service accounts
  one by one; users reset passwords and re-verify MFA; the **Instance Admin** ends the instance-wide
  review on the controller host with `rpmgr restore confirm`. Re-enroll agents enrolled after the
  backup; tell users that sessions were invalidated ([Backup and restore](#backup-and-restore)).
- **Done when**: agents report `applied` under the new epoch and restore review (if entered) is
  closed by the Instance Admin.

### Rotate a DNS-provider token

- **Steps**: create the new token at Cloudflare (Zone Read and DNS Write, the same zones,
  restricted to the controller's egress addresses, with an expiry); UI → Domains & certificates →
  DNS providers → Rotate token (step-up); check that every zone of the provider shows provider
  status `ok`; then revoke the old token at Cloudflare.
- **Done when**: no zone of the provider reports `permission_denied` and the expiry alert is clear.

### Resolve a DNS conflict

- **Symptoms**: a hostname shows `dns_status = conflict` or `ambiguous`.
- **Steps**: open the zone. For `conflict`, look at the foreign record: if it is the old address of
  this service (e.g. a migrated server), **Adopt** it; if it serves something else, rename the route
  hostname or remove the record at the provider. For a `conflict` with reason `delegated`, the name
  lies in a delegated subzone that rpmgr cannot write. For `ambiguous`, create a DNS name that
  picks the gateway group.
- **Done when**: the name is `published`.

### Cloudflare outage or rate limit

- **Symptoms**: zones show `unreachable` or `rate_limited`; the "DNS sync failing" alert fires.
- **Steps**: nothing breaks: published records keep serving and nothing is deleted
  ([15](15-dns.md#fail-static)). Check Cloudflare's status page; for `rate_limited`, look for
  other users of the same Cloudflare user's API budget, and move rpmgr to an account-owned token or
  a dedicated user.
- **Done when**: the next pass succeeds and pending names are `published`.

### Zone held after a restore or the deletion guard

- **Symptoms**: the "DNS zone held" alert; names stay `pending` or `held`.
- **Steps**: open the zone's plan. After a restore, decide for each orphaned record whether to
  delete or re-link it. After the deletion guard, check that the removals are intended (e.g. many
  routes deleted on purpose), not a mistake. Approve the plan (step-up), or fix the configuration
  and let a new plan be computed.
- **Done when**: the zone is `active` again.

### Certificate expiry or clock skew

- **Symptoms**: TLS handshake errors mentioning expiry or "not yet valid"; the agent reports
  "clock skew".
- **Steps**: compare host time with the controller's (`rpmgr diag clock`); fix NTP. If the agent's
  certificate expired while offline, it re-authenticates within the grace period automatically;
  otherwise re-enroll.
- **Done when**: clock offset < 30 s and the agent renews.

### UDP blocked or degraded

- **Symptoms**: connectors on `auto` use `h2` instead of `quic`; UDP routes flagged as served over
  TCP; routes pinned to `quic` are `not_ready(transport_unavailable: quic)`.
- **Steps**: `rpmgr diag transport --gateway <id>` reports the QUIC handshake result, UDP buffer
  sizes, GSO status and MTU estimate; check firewalls for UDP/443 in both directions; check NAT
  timeouts against the QUIC keepalive ([03](03-connections.md#quic-parameters)). If UDP is known to
  be unreliable on that network, set the connector's transport to `h2`, or the instance default
  if it holds for every connector ([03](03-connections.md#transport-selection)).
- **Done when**: the intended transport is in use, or the TCP transport is pinned deliberately.
