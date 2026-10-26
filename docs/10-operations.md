# 10 — Operations

> Status: Phase 1 is implemented. Tags: [F] fact · [R] recommendation · [T] target · [V] verify
> at implementation ([README](README.md#how-to-read-these-documents)). Timeouts, sizes and limits
> are defined in [03-connections.md](03-connections.md); identities, lifetimes and cryptographic
> parameters in [04-security.md](04-security.md). This document links to them instead of restating
> them.

## Install

### Install paths

| Path | For | Notes |
|---|---|---|
| **Global install script** | The first host on Linux: a controller or all-in-one, or any role without a controller to install from | `deploy/install.sh` in the repository, attached to every release as `install.sh` and pinned to it ([D74](14-open-decisions.md#project-and-process)): `curl -fsSLO https://github.com/felix-homelab/rpmgr/releases/latest/download/install.sh && sudo sh install.sh`. It downloads the release from GitHub, verifies it as the controller-hosted script does, and installs the binary, the user `rpmgr`, `/etc/rpmgr` and `/var/lib/rpmgr`; then it offers `rpmgr setup` ([D75](14-open-decisions.md#project-and-process), [04](04-security.md#install-scripts)) |
| **Controller-hosted install script** | Gateways and connectors on Linux (`/install.sh`) | Served by the controller from embedded templates; downloads from the controller's `/dl/` mirror and verifies root key → signing-key statement → manifest signature → artifact SHA-256 with OpenSSL ≥ 3.0, and refuses to install without it (VB-15, resolved in [13](13-roadmap.md#verification-backlog)) ([04](04-security.md#install-scripts)). The UI generates the full command with `--controller` and `--ca-pin` ([04](04-security.md#join-command)). `--variant connector` installs the connector-only build ([D119](14-open-decisions.md#engineering)), which the mirror keeps for every Linux architecture. There is no `/install.ps1`: Windows and macOS connectors are installed by hand from the release download (D99, [D122](14-open-decisions.md#project-and-process)) |
| **OCI image** `ghcr.io/felix-homelab/rpmgr` | Containers, Kubernetes | The release binary on distroless static (Debian 13), for every released Linux architecture, run as the nonroot user (UID 65532) without a shell. `rpmgr` is the entrypoint, so the role is the command: `docker run … ghcr.io/felix-homelab/rpmgr gateway`. Signed keylessly with cosign, with SLSA provenance. Tags: `X.Y.Z`, and for a stable release also `X.Y`, `X` and `latest` ([RELEASING](../RELEASING.md#release-process)). The boot file is mounted at `/etc/rpmgr/<role>.yaml`, and the state is a volume at `/var/lib/rpmgr`, which the image gives to the nonroot user. A gateway publishes 80/tcp, 443/tcp and 443/udp: Docker lets the nonroot user bind ports below 1024 in the container's own network namespace, as `test/images` checks. [R] With host networking, the host's `net.ipv4.ip_unprivileged_port_start` must be 80 or lower; on Kubernetes, the pod sets that sysctl in its security context. |
| **Release download** | Air-gapped or manual installs; Windows and macOS connectors (Phase 2) | Signed release manifest + artifacts; verify before use ([04](04-security.md#release-signing)). Every release has the full build for Linux and the connector-only build for Linux, Windows and macOS ([D119](14-open-decisions.md#engineering)) |

A Helm chart is Phase 3 ([13](13-roadmap.md#phase-3--advanced)).

### Supported platforms

| Requirement | Value |
|---|---|
| Linux kernel | ≥ 5.10 (the updater needs `openat2`, available since 5.6) |
| systemd | ≥ 249; the KEK source `systemd-credential` needs ≥ 250, otherwise `rpmgr controller init` chooses `file`. The units verify on systemd 249 (Ubuntu 22.04) and 257 (Debian 13) (`check-units.sh`, VB-03) |
| Distributions | Debian 12+, Ubuntu 22.04+, RHEL, Rocky and Alma Linux 9+, Raspberry Pi OS (Debian 12 based) |
| `/install.sh` | OpenSSL ≥ 3.0 for signature verification; checked on the distributions above by `check-install.sh` (VB-15, resolved) |
| Windows, macOS | Connectors only, from Phase 2 ([Windows and macOS connectors](#windows-and-macos-connectors-phase-2)) |

Architectures per role are in [05](05-features.md#platform-support).

**One instance per role per host.** Paths, unit names and the admin port are fixed per role, so a
host runs at most one controller (or all-in-one), one gateway and one connector. An all-in-one runs
a connector of its own, so a separate connector on its host is rarely needed; both would read
`/etc/rpmgr/policy.yaml` unless the all-in-one's `policy_file` names another file.

A first installation sets the host up with `rpmgr setup` ([16](16-cli.md)), as root, once the
global install script has installed the binary, the user and the directories:

```sh
curl -fsSLO https://github.com/felix-homelab/rpmgr/releases/latest/download/install.sh
sh install.sh                   # verifies and installs, then offers to run rpmgr setup
```

`rpmgr setup` asks for the role and its values in forms, pre-filled with any flags, shows its plan
and asks before it changes anything ([D73](14-open-decisions.md#engineering)); with `--yes` it asks
nothing, as in `rpmgr setup --role all-in-one --public-url https://panel.example.com --yes`. It
writes the boot file, runs `init` (or `rpmgr enroll` for a gateway or connector), installs and
starts the unit, waits until the role is ready, and prints the trust domain, the CA pin and the
first-user link. A public name orders its certificate from Let's Encrypt production at the first
start; `--acme-directory staging` tries a setup first with certificates no browser trusts. The
same, step by step, for a controller:

```sh
sh install.sh --no-setup
rpmgr controller init --public-url https://panel.example.com   # creates DB, trust domain, root CA, first-user link
rpmgr systemd-unit controller > /etc/systemd/system/rpmgr-controller.service
systemctl daemon-reload
systemctl enable --now rpmgr-controller
```

By hand, with the binary verified as in [04](04-security.md#release-signing), `sh install.sh`
stands for the following; `rpmgr setup` also creates the user and the directories when they are
missing, each with the mode of [Filesystem layout](#filesystem-layout) whatever the umask, and
leaves the mode of a directory that exists:

```sh
install -m 0755 rpmgr /usr/local/bin/rpmgr
useradd --system --user-group --home-dir /var/lib/rpmgr --shell /usr/sbin/nologin rpmgr
install -d -m 0755 /etc/rpmgr
install -d -m 0750 -o rpmgr -g rpmgr /var/lib/rpmgr
```

- **KEK source:** for a new boot file without `--kek-source`, `init` chooses the systemd credential
  from systemd 250, which has encrypted credentials. Below that, or without systemd, it chooses
  the file `/etc/rpmgr/kek`, which it gives to the user `rpmgr` when that user exists, because
  the service reads it.
- **Unit:** `rpmgr systemd-unit <role>` prints the role's hardened unit. For a controller or
  all-in-one it reads the boot file: it loads the KEK credential when the KEK is one, and makes
  the revocation-log sink writable when the file names one
  ([Hardened systemd units](#hardened-systemd-units)).
- **State directory:** `init` runs as root. It gives what it creates in the state directory to the
  directory's owner, the user `rpmgr` the installer gave it to, also when it fails: the database
  and the files beside it, and on an all-in-one the gateway's and the connector's identities. So
  the service, which runs as `rpmgr`, starts without a `chown`.

`init` writes the boot file if it does not exist (from `--public-url` and, for a KEK file,
`--kek-source file --kek-path`), creates the KEK, the database and its migrations, and in one
transaction the trust domain, the database epoch, the CA with its signing keys, and the audit
entry. It never overwrites a boot file or a KEK: an existing one is read and used, so `init` can run
again after a failure, and it refuses a database that is already initialised or in use by a running
controller. When the agents' part of `all-in-one init` fails, the gateway's or the connector's, it
removes the database and what it created beside it, so the same `init` can run again once the
cause is fixed. `rpmgr all-in-one` enrolls its built-in gateway and connector again at start,
through the in-process controller and before the gateway runs, when an identity is missing, as on
a new host after a restore, or for the connector on an all-in-one initialised before
[ADR-0019](adr/0019-all-in-one-runs-a-connector.md); when its certificate names another agent
than the database's built-in one; and when the controller cannot renew its certificate: one the
database does not know, as after the restore of a backup older than the certificate, a revoked or
superseded one, or one expired longer than the grace period
([D97](14-open-decisions.md#engineering)). Each keeps its ID and routes; the enrollment revokes
the certificates the database records for the identity it replaces, and the audit log has each
token with its reason. A certificate the database does not record stays valid until it expires.
An agent whose identity is revoked as a whole, as a restore that replays the revocation log can
leave it, is replaced, since enrolling again under the same ID cannot lift a revocation: in one
configuration change, audited, the old gateway or connector is decommissioned, its identity staying
revoked, and a new built-in one takes its place, the gateway with the old one's group, name, tunnel
endpoints and switch, the connector with its name, labels, transport, switch and route targets, so
no route changes; then the new one is enrolled as above. Only the database's built-in agents are
replaced, never another gateway or connector: on a database from before ADR-0019, which marks no
gateway built in, the gateway's identity names the built-in gateway only if its certificate
chains to the database's root and names its trust domain. An identity that cannot be read stops the start; it
is replaced by deleting `<state_dir>/gateway/identity` or `<state_dir>/connector/identity` and
restarting the service. Without a database, `rpmgr all-in-one` refuses to start, as on a host
never initialised. A new systemd credential is encrypted with `systemd-creds encrypt` into
`/etc/rpmgr/credstore/<name>`; an existing one is readable only where systemd loads it, so `init`
then has to run under `systemd-run --pipe --wait --property=LoadCredentialEncrypted=…`.

`init` prints the trust domain and the CA pin for `--ca-pin`, and a one-time link for creating the
first user (Owner and Instance Admin), `<public URL>/setup#<token>`, valid for 7 days; the token
sits in the fragment, which browsers never send, so it stays out of logs. A lost link is replaced
with `rpmgr user reset-password` while no user exists. There is no default password
([04](04-security.md#security-goals)).

### Filesystem layout

| Path | Owner / mode | Contents |
|---|---|---|
| `/usr/local/bin/rpmgr` (script installs) | root, 0755 | The binary; `.prev` kept next to it during OTA. **Never writable by the service user**: for script installs and standalone binaries only the root-owned updater replaces it, at the path recorded in `install.json` ([04](04-security.md#over-the-air-updates)) |
| `/etc/rpmgr/` | root, 0755 | Boot files and the connector-local policy; the service user reads them |
| `/etc/rpmgr/<role>.yaml` | root, 0644 | Boot configuration ([Configuration](#configuration)) |
| `/etc/rpmgr/tls/` | root, 0755 | The certificate `rpmgr setup --tls self-signed` makes for the UI: `<host>.crt` (root, 0644) and `<host>.key` (rpmgr, 0600) |
| `/etc/rpmgr/policy.yaml` | root, 0644 | Connector-local policy, read-only for the service user; the root updater, and a gateway's agent when it is offered a release, also read `auto_update` and `update_channel` from it ([04](04-security.md#connector-local-policy)) |
| `/var/lib/rpmgr/identity/` | rpmgr, 0700 | Agent identity, written by `rpmgr enroll`: `key.pem` (private key, 0600) and `chain.pem` (certificate and intermediates), both replaced at every renewal (`*.new` files are a renewal in progress, finished at the next start), `roots.pem` (the pinned root and roots it cross-signed), `signing.pem` (the config-signing certificates, replaced by those of every `Welcome`), `agent.json` (agent ID, trust domain, the controller endpoints of the enrollment; those of the stored snapshot take their place, [03](03-connections.md#transport)). Enrollment refuses a directory open to the group or other users, and an existing identity without `--replace` |
| `/var/lib/rpmgr/` | rpmgr, 0750 | Last-known-good snapshot (`snapshot.signed`, 0600) and **deny-list** (`denylist.signed`, 0600) (both signed; the deny-list is loaded before any session is accepted), stateless reset key (gateways: `quic-reset.key`, 0600, created at the first start), route certificates with their keys that the gateway fetched (gateways: `resources/`, 0700, one 0600 file per item, named by its SHA-256, removed when no route needs it), SQLite database and its lock file `controller.db.lock`, held by the running controller (controller) |
| `/var/lib/rpmgr/update/` | rpmgr, 0750 | OTA download area: artifact and signed manifest written by the agent. **Untrusted input** to the updater, which never verifies or installs files in place here |
| `/etc/sysctl.d/60-rpmgr.conf` | root, 0644 | Host tuning, written by `/install.sh` on every run: the UDP buffers, whatever the host has now, and BBR with `--tcp-bbr` or while the file sets it ([03](03-connections.md#host-tuning-applied-by-the-installer)) |
| `/var/lib/rpmgr-update/` | root, 0700 | Updater state, out of the service user's reach: version floor and highest manifest `seq` in `state.json` (`{"seq": 87, "floor": "1.4.2"}`, initialised at install time from the running version and its release `seq`), `install.json` (`{"method": "script", "path": "/usr/local/bin/rpmgr", "variant": "full", "roles": ["connector"]}`, written by `rpmgr setup` and both install scripts through `rpmgr updater install`, [Hardened systemd units](#hardened-systemd-units); the single `role` that v0.1.0 wrote is read as a list of one), `pending.json` while an install's outcome is not known yet, and `staging/`, where the updater copies and verifies the files. **A host keeps its variant** ([D119](14-open-decisions.md#engineering)): both install scripts take the one `install.json` records, else the one the installed binary reports with `rpmgr version --verbose`, `full` for a binary that reports none (0.1.0); an explicit other `--variant` is refused, and the global script's `--upgrade` refuses to guess when it cannot tell. `RPMGR_INSTALL_BIN` and `RPMGR_INSTALL_STATE` move the binary and this directory for the scripts' tests only |
| `/run/rpmgr-update/status.json` | root, 0644 | The updater's last outcome (`updated`, `rolled_back`, `rollback_failed`, `refused`), which the agent reports ([04](04-security.md#over-the-air-updates)) |
| `/run/rpmgr/<role>/handoff.json` | rpmgr, 0644 | The outcome of the role's last restart with socket hand-off (`running`, `ok`, `failed`, `refused`, with the reason and both process IDs), which `rpmgr handoff` waits for; read without following a link and only as a small regular file ([03](03-connections.md#restarts-with-socket-hand-off-phase-2)) |
| `/var/lib/rpmgr/dl/<version>/` (controller) | rpmgr, 0750; files 0640 | The release mirror, served under `/dl/`: the controller's own version, the targets of its rollouts and its previous version, verified release files only; `dl/.own.json` records the own and the previous version ([04](04-security.md#over-the-air-updates)) |
| `/var/lib/rpmgr/audit-checkpoints.log` (controller) | rpmgr, 0640 | Signed audit checkpoints, appended locally and included in every backup; the external sink (Phase 2) is what makes tampering evident ([04](04-security.md#audit-log)) |
| `/var/lib/rpmgr/revocations.log` (controller) | rpmgr, 0640 | This replica's durable, fsync'd **revocation log**: every revocation and credential supersession is appended here first, then shipped asynchronously to the shared readable sink ([Backup and restore](#backup-and-restore)) |

### Hardened systemd units

One unit per role: `rpmgr-controller.service`, `rpmgr-gateway.service`, `rpmgr-connector.service`
and `rpmgr-all-in-one.service`, plus the root-owned updater pair `rpmgr-update.path` and
`rpmgr-update.service` (below; Phase 2). `rpmgr systemd-unit <role>` prints the role units,
which `check-units.sh` verifies with `systemd-analyze verify` on Debian 13 and Ubuntu 22.04.
Excerpt for a gateway:

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
  - **Revocation-log sink:** when the boot file sets `revocation_log.sink`, the unit adds
    `ReadWritePaths=-<sink>`, which keeps the sink writable under `ProtectSystem=strict`
    [F systemd v257 `man/systemd.exec.xml:1691-1693`] ([Backup and restore](#backup-and-restore)).
    With `-`, a missing directory is ignored [F systemd v257 `man/systemd.exec.xml:1715-1718`], so
    a sink outage, such as a share not mounted yet, never keeps the controller from starting; the
    backlog alert covers the entries that wait. A share mounted after the start is writable as on
    the host [F systemd v257 `man/systemd.exec.xml:1726-1731`]; [R] after creating a plain
    directory, restart the controller. `rpmgr systemd-unit` refuses a sink with whitespace, a
    control character, `%`, `\`, a quote, or a `.` or `..` part, which systemd would split,
    expand or read differently, and the root, which would leave nothing read-only.
  - [R] A boot file that gains or changes its sink needs its unit written again with
    `rpmgr systemd-unit`, then `systemctl daemon-reload` and a restart.
- **Connector**: no capabilities at all (`CapabilityBoundingSet=` is empty);
  `ReadOnlyPaths=/etc/rpmgr` keeps `policy.yaml` out of the service's reach. `ExecReload=/bin/kill -HUP $MAINPID`, with `kill`
  from procps, which standard installations have: `rpmgr policy …` edits the policy file and runs
  `systemctl reload`; the connector also watches the file and re-evaluates its current snapshot
  on change ([04](04-security.md#connector-local-policy)). Phase 3 features that need privileges (virtual networks with a kernel TUN device,
  shell) are documented with the exact additional unit settings when they ship; the userspace
  netstack variant needs none.
- **All-in-one**: the controller's settings, its sink included, with `CAP_NET_BIND_SERVICE`, and
  the connector's `ExecReload`: its own connector reads `policy.yaml`, and `rpmgr policy …`
  reloads `rpmgr-all-in-one.service` on a host with an all-in-one boot file and no connector's
  ([ADR-0019](adr/0019-all-in-one-runs-a-connector.md)).
- **Restarts with socket hand-off** (Phase 2;
  [03](03-connections.md#restarts-with-socket-hand-off-phase-2),
  [D148](14-open-decisions.md#engineering)): the gateway, all-in-one and connector units are
  `Type=notify` with `NotifyAccess=all`, so that the new process of a hand-off can tell systemd it
  is the main one, and `RuntimeDirectory=rpmgr/<role>` holds the outcome of the last hand-off: one
  directory per role, as systemd removes a unit's runtime directory when the unit stops.
  - **Gateway and all-in-one:** `ExecReload=<bin> handoff <role>`, so that `systemctl reload`
    restarts with a hand-off and fails, with the reason, if the new process does not become
    ready; the old one then keeps serving. `systemctl restart` stays the restart without one.
  - **All-in-one policy reload:** `rpmgr policy …` signals the running all-in-one with `SIGHUP`
    itself (`systemctl kill --kill-whom=main --signal=SIGHUP`), since its reload is now the
    hand-off.
  - **Connector:** its `ExecReload` stays the policy reload; `rpmgr handoff connector` restarts it
    with a hand-off.
  - **Containers:** no hand-off; the image's process is the container's first one, and an
    orchestrator replaces containers instead ([D149](14-open-decisions.md#engineering)).
- **Updater** (every role): a root-owned pair `rpmgr-update.path` (watches `/var/lib/rpmgr/update/`)
  and oneshot `rpmgr-update.service` ([04](04-security.md#over-the-air-updates)). It:
  1. reads `auto_update` and `update_channel` from `/etc/rpmgr/policy.yaml` **itself** and stops
     if updates are not allowed (it does not trust the agent's decision); a file that does not
     parse, that its group or other users may write, that root does not own, or that is a
     symbolic link counts as `off` ([D120](14-open-decisions.md#security-defaults)), and
     `install.json` and `state.json` must pass the same test. The connector itself still reads
     the policy as [04](04-security.md#connector-local-policy) says;
  2. opens the staging directory through a directory fd with
     `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`, requires regular files (`fstat` → `S_ISREG`;
     no symlinked directory, FIFO or device), and checks that each file's size is ≤ the manifest's
     size and ≤ the hard cap of [03](03-connections.md#timeouts-keepalive-and-backoff), before and
     while copying;
  3. **copies** the files into the root-only `/var/lib/rpmgr-update/staging/` and verifies **the
     copy**: signature, manifest `seq`, version floor, channel, OS/arch, variant, size and SHA-256,
     and refuses a version rolled back on this host until a manifest with a higher `seq` offers it.
     The service user can no longer swap a file or plant a symlink between check and install;
  4. refuses anything below the persisted floor. Floor and `seq` are initialised at install time
     from the running version and its release `seq` (by `rpmgr setup`, which knows no manifest,
     with `seq` 0: then no manifest below the floor is taken, whatever its `seq`, until an update
     records one); after that the running version plays no role.
     A manifest with a higher `seq` may lower the floor, which makes **signed downgrades** possible,
     while replaying an old manifest (lower `seq`) is refused — also on a fresh host;
  5. copies the verified file into the target directory as `.rpmgr.new` (same filesystem, so no
     cross-filesystem `rename`), fsyncs it, re-hashes it, and `rename`s it over the binary at the path
     recorded in `/var/lib/rpmgr-update/install.json` (`/usr/local/bin/rpmgr` for script installs),
     keeping the installed binary as `<path>.prev` (a hard link, put in place by a rename), then
     restarts each role service that `install.json` lists, which may name only `gateway` and
     `connector`. Just before the rename it writes `pending.json` to `/var/lib/rpmgr-update/`. A
     failure before the rename leaves the installed binary untouched; after it the install goes on
     to the readiness check, and a directory that cannot be synced is only a warning in the
     status. A binary path that is a symbolic link is refused, and links planted at
     `.rpmgr.new` or `.prev` are replaced, never followed;
  6. polls each role's admin `/readyz`, at the address of the role's boot file and never through a
     proxy (ready only with an established control session and an applied snapshot, see
     [Health](#health)), within the readiness window of
     [03](03-connections.md#timeouts-keepalive-and-backoff); a role counts as ready only while its
     unit is `active`. It rolls back to `.prev` when a role is not ready by then, or its service
     fails (`ActiveState=failed`) or systemd restarts it too often (`NRestarts`) before or right
     after it was ready; the rollback restarts the roles again and records the version in
     `state.json` as failed, so that only a manifest with a higher `seq` offers it again. The
     automatic rollback is exempt from the floor, because floor and `seq` are only raised after a
     successful health check. A connector's local policy is not rolled back with the binary: a
     `deny_targets` list, a target string, an entry without ports or a subnet with host bits set
     ([D84](14-open-decisions.md#engineering)), written while the new binary ran, makes a binary
     from before D84 read the file as invalid and dial nothing until the file is changed back or
     the binary updated again ([04](04-security.md#connector-local-policy));
  7. writes the outcome to `/run/rpmgr-update/status.json` (root, 0644): `updated`, `rolled_back`,
     `rollback_failed` or `refused`, the version, the previous one and a reason, which the agent
     reports at its next start, and removes `pending.json`. `rollback_failed` means `.prev` could
     not be put back: the host needs an operator, who installs a release with
     `install.sh --upgrade`;
  8. at every start, and once at boot after the roles, finishes an install that `pending.json`
     records: if the new binary is in place, it restarts and checks the roles as in step 6 and
     rolls back if one is not ready; if the run ended before the rename, nothing changed and the
     record goes. A staged release that is the installed binary already is not installed again.
     Without a staged `manifest.json`, which the agent writes last, nothing is staged: the run
     ends there and writes no status, so it neither reports `refused` at every boot nor replaces
     an earlier outcome; a staged set that does not verify is still `refused`.

  The role service's `NoNewPrivileges=yes` and `ProtectSystem=strict` stay intact; the service user
  can never write the binary or the updater state.

  Excerpt of `rpmgr systemd-unit update`:

  ```ini
  # /etc/systemd/system/rpmgr-update.path
  [Path]
  PathChanged=/var/lib/rpmgr/update/manifest.json
  Unit=rpmgr-update.service

  # /etc/systemd/system/rpmgr-update.service (runs as root; ExecStart names install.json's path)
  [Service]
  Type=oneshot
  ExecStart=/usr/local/bin/rpmgr updater apply --staged /var/lib/rpmgr/update --state /var/lib/rpmgr-update
  RuntimeDirectory=rpmgr-update
  RuntimeDirectoryPreserve=yes
  ProtectSystem=strict
  ReadWritePaths=/usr/local/bin /var/lib/rpmgr-update

  [Install]
  WantedBy=multi-user.target
  ```

  `RuntimeDirectoryPreserve=yes` keeps `/run/rpmgr-update/status.json` after the oneshot run
  ends, so the agent reads it when its service starts again. The service is also enabled
  (`WantedBy=multi-user.target`, after the role units), so that it runs once at boot and finishes
  an install a crash or reboot interrupted (step 8).

- **Who installs the updater** ([04](04-security.md#over-the-air-updates)): `rpmgr setup`, the
  controller-hosted `/install.sh` and the global install script write the updater units,
  `install.json` and `state.json` on every Linux host with systemd, whatever its role. On a host
  whose roles include a controller or an all-in-one the updater refuses every release, because the
  roles share one binary and such hosts are upgraded by hand
  ([D102](14-open-decisions.md#engineering)).
  - **What is recorded:** `install.json` records the method (`script`, or `setup` for a binary
    that no script installed), the binary's path, the variant and a `roles` list, so that a host
    with a gateway and a connector restarts both; `rpmgr systemd-unit update` prints the units
    with that path in `ExecStart`.
  - **How the scripts do it:** both run `rpmgr updater install` with the binary they installed and
    the `seq` and version of the release they verified ([16](16-cli.md)). It records the binary's
    own variant, refusing another than recorded; it keeps the roles recorded, the single `role` of
    v0.1.0 included, and adds the script's role and those whose boot file `/etc/rpmgr/<role>.yaml`
    exists; it initialises the floor and `seq` in `state.json`, or raises them, never lowering
    either; and it writes the units, which the script enables (`systemctl enable
    rpmgr-update.service`, `systemctl enable --now rpmgr-update.path`). A refusal writes nothing,
    and a record or state it cannot read, which may hide a higher `seq`, is never replaced.
    `install.sh --upgrade` runs it too, so a host installed with v0.1.0 gets the units and files;
    the global script installing a release from before the updater writes only a missing
    `install.json`, without roles.
  - **What setup does:** `rpmgr setup` adds its role to `install.json` and installs and enables
    the units, unless `--no-unit`. It knows no manifest, so it leaves a `state.json` a script
    wrote, and starts a missing one at the binary's own version with `seq` 0 (as does
    `rpmgr updater install` without `--seq`). With `seq` 0 the updater takes no manifest below
    the floor, whatever its `seq`; the first update records the `seq`. A development build has no
    release version and gets no `state.json`, so the updater refuses every release, which setup
    says.
- No secret appears in `ExecStart` or `Environment=` ([04](04-security.md#secrets-at-rest-and-in-logs)).
- The installer applies the host tuning from [03](03-connections.md#host-tuning-applied-by-the-installer).

### Windows and macOS connectors (Phase 2)

Only the connector role runs on Windows and macOS. Both follow the Linux rules: the policy file is
writable only by administrators, the service account can read it but not change it, and the
connector reloads it on a service signal and when the file changes
([04](04-security.md#connector-local-policy)).

| | Windows | macOS |
|---|---|---|
| Platforms | windows/amd64, connector variant only | darwin/amd64 and darwin/arm64, connector variant only |
| Install and update | By hand, from the verified release download (`rpmgr-<version>-windows-amd64-connector.exe`, installed as `rpmgr.exe`); not code-signed, so the download mark is cleared with `Unblock-File` after the verification ([D103](14-open-decisions.md#security-defaults)). `rpmgr setup` installs the service, the policy file and the identity, as on Linux; `rpmgr setup --remove` stops and removes the service and the program's files, and keeps the identity and the policy file unless `--purge` | By hand, likewise (`rpmgr-<version>-darwin-<arch>-connector`, installed as `/usr/local/bin/rpmgr`); not notarized, so the quarantine attribute is cleared with `xattr -d com.apple.quarantine` after the verification. `rpmgr setup` and `rpmgr setup --remove` as on Windows |
| Service | Windows service `rpmgr-connector`, running under its virtual service account | launchd daemon `com.felix-homelab.rpmgr.connector`, running as user `_rpmgr` |
| Local policy | `%ProgramData%\rpmgr\policy.yaml`; writable only by SYSTEM and Administrators, read-only for the service account | `/etc/rpmgr/policy.yaml`; owner root, mode 0644 |
| Policy reload | Service control request and file watch | SIGHUP and file watch |
| OTA | Not before Phase 3; updated by hand | Not before Phase 3; updated by hand |

In Phase 1, CI only builds these targets; end-to-end tests on Windows and macOS start in Phase 2
([12](12-testing-and-quality.md#continuous-integration)).

## Ports

| Role | Port | Protocol | Purpose | Exposure |
|---|---|---|---|---|
| Gateway | 443 | TCP | Public HTTPS (terminated), TLS-passthrough routes, data-session fallback (`rpmgr-tunnel-h2/1`, SNI `<gateway-id>.gateway.<td>`), WSS transport on the **gateway's own** WSS hostname at `/.rpmgr/tunnel` (Phase 2), controller passthrough ([03](03-connections.md#port-443-multiplexing)). Connectors dial each gateway at its own `tunnel_endpoints`; group-level DNS or anycast names are for public traffic only | Public |
| Gateway | 443 | UDP | QUIC data sessions (`rpmgr-tunnel/1`); HTTP/3 in Phase 3. Optionally, tunnels move to a separate UDP port (`listen.tunnel_udp`) when their QUIC tuning must differ from public HTTP/3 ([03](03-connections.md#port-443-multiplexing)) | Public |
| Gateway | 80 | TCP | ACME HTTP-01 challenges; per `http` route a redirect to HTTPS (default), plain HTTP, or nothing (`port80`, [06](06-data-model.md#routing)) | Public |
| Gateway | port pools (e.g. 20000–20999) | TCP and/or UDP | `tcp`, `udp` and `tcp_udp` routes (a `tcp_udp` route holds its port number in both); ranges are gateway-group settings, allocated per [04](04-security.md#route-and-hostname-ownership) | Public, only the configured ranges |
| Controller | 443 | TCP | UI, public API, enrollment, agent control sessions (SNI `controller.<td>`), `Reauth` for expired agent certificates (SNI `reauth.controller.<td>`), `/install.sh`, `/dl/` mirror | Reachable by browsers and agents (directly or through a gateway's controller passthrough, [03](03-connections.md#reaching-a-private-controller)) |
| Controller | 80 | TCP | Optional: ACME HTTP-01 and redirect, if the controller obtains its own UI certificate | Public, optional |
| Every role | 127.0.0.1:7381 (controller, all-in-one), 127.0.0.1:7382 (gateway), 127.0.0.1:7383 (connector) | TCP | Admin listener: `/metrics`, `/healthz`, `/readyz`, pprof (off unless enabled). One port per role, so roles on the same host never collide, and none is 9090, Prometheus's own port. If the default is taken, the installer picks the next free port and writes it to the boot file. The ports are registered in Prometheus's port registry once public code exists | Localhost by default; may be bound to a private interface for scrapers and load-balancer checks, **never** public: a boot file that binds it to all interfaces, a public address or a host name is refused |
| Connector | — | — | No inbound ports. Outbound: 443/TCP+UDP to gateways, 443/TCP to the controller | — |
| Connector | per `allow_listen` | TCP/UDP | Visitor listeners for private services | Local or LAN, as the policy allows |
| All-in-one | 80, 443/TCP, 443/UDP, port pools, admin | | Gateway ports; the controller is reached through the gateway's SNI router in-process; its connector opens no port and never dials the ports rpmgr listens on: admin, 80, 443, tunnel UDP and every route port the gateway has bound ([04](04-security.md#connector-local-policy)) | Public (except admin) |

**Controller outbound connections.** The controller dials out only for these. Its HTTPS requests
go through `HTTPS_PROXY`, else `ALL_PROXY`, its plain HTTP requests through `HTTP_PROXY`, else
`ALL_PROXY`, and SMTP through a SOCKS5 `ALL_PROXY`, unless `NO_PROXY` exempts the host; DNS
queries go direct. A proxy variable that is no proxy URL stops the controller at start, with a
message that names the variable, not its value ([D93](14-open-decisions.md#engineering)):

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
   read are `RPMGR_CONFIG` (config path), the proxy variables (`HTTPS_PROXY`, `HTTP_PROXY`,
   `ALL_PROXY`, `NO_PROXY`) and, by the install script and `rpmgr enroll` only, `RPMGR_ENROLL_TOKEN`. There is no
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
tls:                          # the certificate of public_url from files; without them, ACME
  cert_file: /etc/rpmgr/tls/panel.crt   # PEM chain; re-read within a minute after a change
  key_file: /etc/rpmgr/tls/panel.key
log:
  level: info                 # debug | info | warn | error
  format: json
tracing:                      # every role's boot file takes this section
  otlp_endpoint: ""           # OTLP/HTTP traces URL, e.g. https://collector:4318/v1/traces; "" = off
  sample_ratio: 0.01          # share of new traces sampled; failed spans are exported regardless
revocation_log:
  sink: ""                    # a directory, usually a share, for a copy off the host; "" = none
```

```yaml
# /etc/rpmgr/gateway.yaml
version: 1
controller:
  endpoints: [https://panel.example.com]   # only checked: agents dial the endpoints of enrollment
  passthrough:                              # optional: publish a private controller (03, R23)
    address: ""                             # its host:port for 443, reached from here; "" = none
    hostnames: []                           # its UI hostnames; the agent names always go there
identity_dir: /var/lib/rpmgr/identity       # key, certificate chain, trust bundle (written by enroll)
state_dir: /var/lib/rpmgr                   # last-known-good snapshot, stateless reset key
listen:
  tcp: ":443"
  udp: ":443"
  tunnel_udp: ""                            # optional separate UDP port for tunnels; empty = share 443
  http: ":80"
  admin: "127.0.0.1:7382"
# handoff: { drain: 10m }                   # Phase 2, with 17.x: an old process's drain (03)
log: { level: info, format: json }
tracing: { otlp_endpoint: "", sample_ratio: 0.01 }
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

`rpmgr setup --role connector --proxy <url>` takes an `http://`, `socks5://` or `socks5h://` URL,
the schemes the connector reads, enrolls through it, and gives it to the service as `HTTPS_PROXY`
in `/etc/rpmgr/connector-proxy.env` (mode 0600, root's), which the drop-in
`rpmgr-connector.service.d/proxy.conf` names: a proxy password never shows in the unit or in
`systemctl show`. A URL with credentials comes from `--proxy-file <file>` or the form; `--proxy`
refuses it, as a command line shows it to every user of the host.

```yaml
# /etc/rpmgr/all-in-one.yaml
version: 1
public_url: https://panel.example.com
listen:
  tcp: ":443"                 # the gateway's; the controller is reached through it
  udp: ":443"
  tunnel_udp: ""
  http: ":80"                 # the gateway's: http routes; the controller's redirect for its name
  admin: "127.0.0.1:7381"     # reports the controller, the gateway and the connector
database: { driver: sqlite, dsn: /var/lib/rpmgr/controller.db }
kek: { source: systemd-credential, name: rpmgr-kek }
tls: { cert_file: /etc/rpmgr/tls/panel.crt, key_file: /etc/rpmgr/tls/panel.key }   # optional
state_dir: /var/lib/rpmgr     # the gateway's identity in gateway/identity, its state in gateway/;
                              # the connector's in connector/identity and connector/
policy_file: /etc/rpmgr/policy.yaml   # the connector's local policy (04)
log: { level: info, format: json }
```

Rules for every boot file:

- One YAML document of at most 64 KiB with `version: 1`; another version, an unknown key or a value
  of the wrong type stops the process with the line at fault.
- An omitted key takes the value shown above, except `public_url` (controller) and
  `controller.endpoints` (agents), which are required. `listen.http: ""` disables port 80; the
  other listeners cannot be disabled. `tls.cert_file` and `tls.key_file` go together; a pair that
  does not load at a re-read keeps the certificate in use. Without them, the controller obtains
  the certificate of the public URL's host with ACME if the host is a public DNS name, which needs
  port 80 or 443 reachable from the CA, and serves a self-signed certificate until then; for any
  other host it keeps the self-signed certificate and warns
  ([04](04-security.md#controller-certificates)). A change of the ACME settings reaches the
  controller's own certificate at its next start. `rpmgr enroll` downloads the trust bundle from
  the public URL, so enrollment needs a certificate the agent host trusts
  ([04](04-security.md#join-command)).
- `controller.passthrough` is for gateways only and absent from all-in-one: `address` is
  `host:port`; `hostnames` are lower-case DNS names (internationalised ones in their `xn--` form)
  and need an address ([03](03-connections.md#reaching-a-private-controller)).
- URLs are `https://<host>[:<port>]` without user, path, query or fragment; listen addresses are
  `[host]:port`; paths are absolute. `database.driver: postgres` and `kek.source: kms` are refused
  until Phase 2.

Port pools, routes, gateway groups and everything else an agent runs come from snapshots, not from
the boot file.

### Runtime settings (UI → Settings)

| Scope | Examples |
|---|---|
| Instance (Instance Admin) | Default data-session transport (`auto`, `quic`, `h2`, `wss`; shipped `auto`, [03](03-connections.md#transport-selection); [R] pin `h2` on routes or connectors that carry bulk transfers over high-delay paths, where it carried single streams faster in the Phase 1 measurements, [ADR-0004](adr/0004-quic-default-transport-policy.md#phase-1-measurements)), public URL aliases (each alias is also accepted as `Origin` by the CSRF check, [04](04-security.md#human-authentication-and-sessions)), ACME account, Cloudflare IP ranges (refreshed automatically), SMTP (optional: the relay's `host:port`, sender address, user name, and STARTTLS or TLS from the start, as the controller sends no mail in plain text; the password is write-only and kept under the KEK), retention (audit entries: 365 days by default, 30 to 3650 days; metric rollups), external audit sink (Phase 2), revocation-log sink ([Backup and restore](#backup-and-restore)), controller endpoints advertised to agents (each `https://<host>[:<port>]`, tried in order; agents get them at enrollment and in every snapshot, and the public URL alone while none are listed, [03](03-connections.md#reaching-a-private-controller)). **PKI** page: leaf-certificate lifetime and grace period ([D8](14-open-decisions.md#security-defaults), values and ranges in [04](04-security.md#leaf-certificates)), password-hash profile. **Updates** page: release check (on by default, [D4](14-open-decisions.md#product-and-project)), update channel (`stable` or `prerelease`), manifest upload for air-gapped installs, rollout policy (Phase 2); Phase 2: the audit sinks ([04](04-security.md#audit-log)) and the private ranges webhook receivers may use (`webhook_private_ranges`, none; [04](04-security.md#webhooks-and-the-egress-guard-phase-2)) |
| Org (Owner) | MFA requirement, OIDC providers and group→role mapping, default gateway group, Operator may enroll connectors, branding ([04](04-security.md#roles)); Phase 2: alert e-mails on or off (`alert_email`, on) and the alert types the org gets (`alert_types`, all) ([D139](14-open-decisions.md#engineering)) |
| Gateway group (Admin) | Port pools, trusted-proxy CIDRs, DNS target for managed records, default TLS options, per-route limit defaults |
| DNS (Owner/Admin; Instance Admin for the system org) | DNS providers and their tokens, managed zones and their gates. These are resources with their own pages, not settings ([15](15-dns.md)) |
| Install command generator | Install prefix, gateway group, labels, ephemeral flag, `--allow-target` and `--deny-target` entries — the install location lives here, because it is a property of the install command, not of a running agent. There is no service-name suffix: one instance per role per host ([Supported platforms](#supported-platforms)) |

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
- **Across a major release** the window is the same: a controller at the first minor of a major
  supports the agents of the last minor release of the major before. A 1.0 controller supports the
  agents of the last 0.y release, v0.7.0 as planned
  ([D100](14-open-decisions.md#project-and-process),
  [D115](14-open-decisions.md#engineering)), so a fleet of 0.y agents keeps running while it is
  upgraded in the order below. The binary records the last minor release of each earlier major,
  and the release of a new major checks that record ([RELEASING](../RELEASING.md#release-process)).
  v1.0.0 keeps the protocol major `rpmgr-tunnel/1`.
- The controller refuses agents older than `min_agent_version` with `Goodbye{upgrade_required}`
  ([03](03-connections.md#versioning-and-capabilities)), so skew beyond N−1 is visible, not silent.
- **Upgrades go from one minor release to the next.** Skipping a minor release, for example from
  1.2 to 1.4, is unsupported: the agent window above and the database migrations assume that each
  minor release ran. Patch releases may be skipped. A controller that finds a database it does not
  know refuses to start ([06](06-data-model.md#migrations)).
- A protocol change that would break N−1 ships behind a capability flag first; the old behaviour is
  removed one minor release later.
- **Gated route features** fail closed on older agents
  ([03](03-connections.md#versioning-and-capabilities), [D113](14-open-decisions.md#engineering)):
  a route that uses a feature an agent's release lacks, such as a require-header rule on a gateway
  of the previous minor, is left out of that agent's snapshot, and the route status shows the agent
  with `CAPABILITY_MISSING` until it is upgraded. With mixed gateways in a group, only the upgraded
  ones serve such a route; upgrade the gateways before using a new route feature.
  Weakness: the gate only withholds the route. A gateway of the previous minor that served the
  route before the feature was added lets its requests in flight and upgraded connections, such as
  WebSockets, finish as for any removed route, so a connection admitted without a require-header
  value stays open on such a gateway until it ends or the gateway is upgraded.
- A route with header matches is a special case: on a gateway without `http.header-match`, its
  requests reach the route of the same hostname and path prefix without matches, if there is one,
  which the gated route's status says.
- **Controller replicas during a rolling upgrade to v0.3.0** (HA): the release stores a route's
  header matches in a new form. A replica of the previous release that reads a route with header
  matches fails on it, so its snapshots and API answers that need the route fail closed until it
  is upgraded too; upgrade all replicas before setting header matches.
- Before the first release, one change of meaning shipped without a capability: access policies'
  deny rules win ([D85](14-open-decisions.md#engineering)). A gateway of a release candidate
  (v0.1.0-rc.1 to rc.6) applies the first matching rule to the same snapshot, so a deny placed
  after an allow is ignored there until that gateway is upgraded; upgrade gateways with the
  controller.

**Upgrade order**: controller(s) → gateways → connectors.

1. **Controller.** Back up first ([Backup and restore](#backup-and-restore)). Migrations run at
   start under a database lock (single node) or with `rpmgr migrate` before rolling the replicas
   (HA). Agents keep running their last-known-good snapshot while the controller restarts
   ([03](03-connections.md#failure-modes)).
2. **Gateways.** One at a time per gateway group: the gateway drains, connectors re-home to the
   other gateways of the group, then it restarts ([03](03-connections.md#multiple-gateways)). From
   Phase 2 a rollout does this for gateways installed with the install scripts
   ([D102](14-open-decisions.md#engineering)). [T] A gateway, an all-in-one and a Linux connector
   that run v0.3.0 or later restart with a socket hand-off, so that a lone gateway refuses no
   visitor connection either: the new process takes the listening sockets over and the old one
   drains its open connections for the hand-off drain
   ([03](03-connections.md#restarts-with-socket-hand-off-phase-2),
   [D127](14-open-decisions.md#project-and-process)). An upgrade from an earlier release, a plain
   `systemctl restart` and a container restart drain and stop as before; an all-in-one's web UI
   and API answer 503 for the seconds its controller moves.
3. **Connectors.** Through the staged OTA rollout: canary → percentage → all, with automatic
   rollback on failure, each stage approved by the Instance Admin; a rollback pauses the rollout
   ([04](04-security.md#over-the-air-updates)). A rollout's target is the controller's own
   version, so agents never run ahead of their controller. Hosts with
   `auto_update: notify` or `off` are listed in the UI and updated by their operators. Windows and
   macOS connectors (Phase 2) are updated by hand from the release download; they get no OTA
   before Phase 3.

Until OTA (Phase 2), every host is upgraded by hand in this order, with the new release's global
install script: `sudo sh install.sh --upgrade --restart`. `--upgrade` refuses a host without an
installed `rpmgr`, replaces the binary in one rename, changes nothing else and offers no setup;
after the version and the release root keys it prints only what is left to do. `--restart`
restarts every rpmgr service that runs and fails, naming `journalctl -u <unit>`, if one does not
stay active for 5 s without systemd restarting it. Without `--restart`, the script names each
service that still runs the previous binary, with the command that restarts it.

## Backup and restore

- `rpmgr backup --out <file>` writes a **consistent** copy of the controller database: `VACUUM INTO`
  on SQLite, which runs while the controller keeps reading and writing
  ([S8](spikes/S8.md)), `pg_dump` on PostgreSQL (or the operator's own PostgreSQL backups).
  Secrets in the backup stay envelope-encrypted.
  - **The archive:** one tar file, mode 0600, with `controller.db`, `revocations.log`,
    `audit-checkpoints.log` (both without a line still being written) and `backup.json` (format,
    version, time, trust domain, `db_epoch`).
  - **Writing it:** it never overwrites a file, leaves nothing behind when it fails, and is
    audited as `local-cli`.
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
  - **The filesystem sink** is the boot setting `revocation_log.sink`, a directory, which the unit
    of `rpmgr systemd-unit` makes writable ([Hardened systemd units](#hardened-systemd-units)).
    - **Publishing:** each entry is written to a temporary file, synced, then hard-linked to its
      number; the link fails when the number exists, so a crash leaves no empty number.
    - **Contents:** an entry holds the replica, its local entry and the sink's own hash chain.
    - **Shipping:** every 10 s; a replica finds what it has shipped in the sink itself, by the
      entries' hashes, so nothing is shipped twice, and the entries a restore appends to a restored
      log are shipped although their numbers were used before.
    - **State:** `GetInstanceSettings` reports it as `revocation_log`, and the metrics below
      ([Metrics](#metrics)).
    - [R] A boot setting, not a runtime setting as the settings table lists. The share has to be
      mounted on every controller host, and a runtime setting could not check that per host when it
      is saved.
  - A syslog or webhook sink cannot be read back and does not count.
  - **Single node**: the sink is optional. Without one, the local `revocations.log`, which every
    backup includes, is the only copy; the restore reads it with `--revocation-log <file>`. The UI
    then shows a standing hardening warning ("revocation log has no off-host copy") instead of the
    backlog alert. **More than one controller replica**: a sink is required; a second replica
    refuses to start without one ([High availability](#high-availability)).
- **Restore side effects**, applied automatically:
  - the restore merges the sink with every reachable replica's local log, checks the sink's hash
    chain, then re-applies every entry newer than the backup, with its original time and reason;
    without `--revocation-log` it reads the local `revocations.log` of the host it runs on. The
    re-applied entries are appended to the restored local log, so a later restore finds them
    without the sink.
  - **Re-applying:** a revoked certificate the backup does not hold, because it was issued after
    the backup, stays on the deny-list until it expires; so does a revoked identity of an org created
    after the backup. A role downgrade never raises a role. A password changed after the backup is
    cleared and must be reset; an authenticator or recovery codes changed after it must be set up
    again, because the backup's may be the very ones that were compromised.
  - all sessions and every **enrollment token** from the backup that can still be used are
    invalidated (a token consumed after the backup would otherwise become usable again). [R] So are
    unused password-reset links and open invitations, which are one-time credentials too.
  - agents enrolled after the backup are unknown and must re-enroll. An agent that renewed its
    certificate after the backup keeps its control session, but `Renew` and `Reauth` refuse a
    certificate the restored database does not record
    ([04](04-security.md#leaf-certificates)): re-enroll it before its certificate expires;
  - every managed DNS zone starts **held**: nothing is written at a DNS provider until an Owner or
    Admin approves the zone's plan, which shows records created or deleted since the backup
    ([15](15-dns.md#held-zones-and-plan-approval)). `rpmgr restore --dns-disabled` disables DNS
    automation entirely, for a copy restored into a test environment that must never touch
    production DNS.
- **Fail closed** only when the sink's hash chain is broken, or a replica that reported an unshipped
  backlog has an unreachable local log. Without a sink, a single node's whole log is not off the
  host, so a restore without that log fails closed too; so does a log entry of a kind the restoring
  version does not know. The entries of every reachable log are merged and re-applied all the
  same. Then all API tokens and service accounts are suspended, all sessions invalidated, every
  user must reset their password and set up their second factor again (re-verify MFA), and the
  instance enters **restore review** mode (read-only):
  - **Read-only:** every API method that changes something is refused with `RESTORE_REVIEW`
    ([07](07-api.md#errors)) while its org, or for an instance setting the instance, is in review.
    Revocations stay available (revoking API and enrollment tokens, member changes and removals),
    and so do the review itself and each user's own account: password, second factor, sessions.
    Another user's account is not recovered through the API
    ([04](04-security.md#account-recovery)). A revocation of the Instance Admin role that would
    leave the restored instance without an active Instance Admin is not applied again; the restore
    names it, and the audit entry of the restore too.
  - **Passwords:** a user resets theirs with a link from `rpmgr user reset-password --email
    <address>` on the controller host, or with the self-service reset when SMTP is set up.
  - each org's **Owner** re-confirms only their own org's memberships and roles, and resumes its
    suspended API tokens one by one; an org stays read-only until its Owner confirms it, or the
    Instance Admin with `rpmgr restore confirm --org <org>` on the controller host;
  - the instance-wide review is ended by the **Instance Admin** with a local CLI command on the
    controller host, `rpmgr restore confirm`. An org Owner cannot end it, because restored Owner
    memberships are exactly what is in doubt, and no API method ends it.
- **Running the restore:** every controller must be stopped; the restore takes the controller lock
  and refuses while a controller holds it. It prepares the restored database and logs next to the
  live ones (`*.restoring`) and renames them into place only when every step succeeded, so a failed
  restore changes nothing. The replaced database and logs stay in the state directory with the
  suffix `.before-restore-<time>`; delete them once the restored controller runs.
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
- **Session registry.** A row per control session records which replica holds it. Registration
  takes the agent's next `session_epoch` under the row's lock and, in the same transaction, signals
  the replica that held the agent before, which ends that session; a replica that gets the signal
  before it has added the session ends it as it adds it. Pushes for an agent are signalled to the
  replica that holds it via PostgreSQL `LISTEN/NOTIFY`, a revision to every replica at once; a
  signal for one agent reads its registry row `FOR SHARE`, so it reaches the replica that is
  registering the agent at that moment. `LISTEN/NOTIFY` carries only small signals, never
  operation data: a payload must be shorter than 8000 bytes
  [F PostgreSQL 18.6 `src/backend/commands/async.c:163,619-622`]
  ([S9](spikes/S9.md)).
- **Lost notifications.** PostgreSQL delivers a notification only to sessions that were listening
  when it committed [F PostgreSQL 18.6 `async.c:1066-1121`]. Each replica therefore listens on a
  dedicated connection that never runs a transaction, and after every (re)connect it first
  `LISTEN`s, then resyncs every session it holds: the revision, each agent's snapshot and the
  registry's epochs. The revision check of 03 stays as the safety net
  ([03](03-connections.md#timeouts-keepalive-and-backoff)); it also ends a session whose registry
  epoch has moved on ([D112](14-open-decisions.md#project-and-process)).
- **Notifying transactions commit one at a time** across the database: PostgreSQL holds a lock from
  queueing the notifications to the end of the commit [F PostgreSQL 18.6 `async.c:907-922`]. A
  transaction sends its signals as its last statements and stays short, and one configuration
  change sends one revision signal, not one per agent.
- **Connection poolers.** PgBouncer in transaction mode is unsupported: `LISTEN` never works
  there [F PgBouncer 1.26 docs, features, retrieved 2026-10-19]. Session pooling or direct
  connections work ([D112](14-open-decisions.md#project-and-process)).
- **Imperative operations** (live logs, diagnostics, later the shell): the replica holding the
  agent's control session serves the operation; the replica serving the user's stream proxies to it
  over an internal controller-to-controller mutual-TLS connection: HTTP/2 over TLS 1.3, where each
  side accepts only a controller SPIFFE ID, and the caller only the node the registry names. In S9
  this added about 1.5 ms to a forwarded `ProbeTarget` at p99 ([S9](spikes/S9.md)).
  Controller node certificates therefore carry **clientAuth as well as serverAuth**, and a
  `controller_nodes` table records each replica's `node_id`, `internal_address` and `last_seen`
  ([04](04-security.md#leaf-certificates)).
- **Revocation log**: every replica appends each entry to its durable local log first and enforces
  it immediately, then ships it asynchronously to the shared sink, where sequence numbers are
  allocated by conditional create of the object `<seq>` (no gaps) and entries form a hash chain
  ([Backup and restore](#backup-and-restore)). With more than one replica the sink is required. A
  sink outage never blocks a revocation; it raises an alert until the backlog is shipped. A
  filesystem sink allocates a number by a hard link, which fails when the name exists; an
  S3-compatible sink by a PUT with `If-None-Match: *`, which fails with 412. Both kept two racing
  shippers free of gaps and duplicates in S9, the S3 sink on MinIO ([S9](spikes/S9.md)).
- **Singleton jobs** (ACME orders, CA rotation, ephemeral purge, metric rollups, audit
  checkpoints, the DNS job, rollouts) run under a database **lease with a fencing token**: a replica that lost
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
- Live logs of a connector or gateway can be streamed to the UI and the CLI (Phase 2: an
  imperative operation with a deadline and limits, redacted on the agent, for `agents.logs`;
  [03](03-connections.md#control-session), [04](04-security.md#secrets-at-rest-and-in-logs)).

### Metrics

Prometheus exposition on the admin listener of every role. Labels use stable IDs (`route` = route
ID); there are never per-connection or per-client-IP labels. An all-in-one serves the metrics of
all three roles on its one listener, and adds a `role` label (`gateway` or `connector`) to every
series its gateway and its connector register: every metric of the table whose role is gateway,
connector or agent, the Go runtime and process collectors excepted, which it registers once. The
controller's series have no `role` label. The connector's in-memory data session to its own
gateway counts as `transport="h2"` ([03](03-connections.md#transport-selection)).

| Metric | Type | Role | Phase | Meaning |
|---|---|---|---|---|
| `rpmgr_gateway_sessions{transport}` | gauge | gateway | 1 | Data sessions from connectors, by transport (`quic`, `h2`, `wss`) |
| `rpmgr_gateway_streams_open{route,transport}` | gauge | gateway | 1 | Open user streams |
| `rpmgr_route_connections_total{route,result}` | counter | gateway | 1 | User connections, and streams of HTTP routes, by `StreamResult` code name in lower case ([03](03-connections.md#framing)), or `no_session`, `draining`, `timeout` or `error` without one |
| `rpmgr_route_bytes_total{route,direction}` | counter | gateway | 1 | Bytes, `direction` = `in` (public → service) or `out` |
| `rpmgr_route_connection_setup_seconds{route}` | histogram | gateway | 1 | Asking a connector for a stream → its `StreamResult` |
| `rpmgr_http_requests_total{route,code}` | counter | gateway | 1 | Requests of HTTP routes by status, the route's refusals included |
| `rpmgr_gateway_page_log_lines_dropped_total` | counter | gateway | 2 | Log lines of custom pages' request IDs not written over their bound ([03](03-connections.md#timeouts-keepalive-and-backoff), [D136](14-open-decisions.md#engineering)) |
| `rpmgr_udp_oversize_total{route}` | counter | gateway, connector | 1 | UDP payloads too large for a datagram, sent on the flow stream ([03](03-connections.md#udp-routes)) |
| `rpmgr_udp_datagrams_dropped_total{route,reason}` | counter | gateway, connector | 1 | Drops: queue full, flow limit, unknown flow, policy; from Phase 2 also a route limit (`limit`) and a per-client rate limit (`rate_limit`), [03](03-connections.md#route-limits-phase-2) |
| `rpmgr_connector_session_rtt_seconds{gateway,transport}` | gauge | connector | 1 | Smoothed RTT, the lowest of the data sessions to a gateway over a transport: QUIC's own estimate, or for h2 from the session `Ping` and `Pong` ([03](03-connections.md#timeouts-keepalive-and-backoff)) |
| `rpmgr_connector_target_dial_seconds{route}` | histogram | connector | 1 | Upstream dial time; dials the local policy refuses are not timed |
| `rpmgr_connector_policy_denied_total{route}` | counter | connector | 1 | Dials refused by local policy |
| `rpmgr_agent_applied_revision` | gauge | agent | 1 | Last applied revision `seq` |
| `rpmgr_agent_apply_status{agent,status}` | gauge | controller | 1 | 1 for the current status (`pending`, `applied`, `rejected`, `apply_timeout`) |
| `rpmgr_agent_cert_expiry_timestamp_seconds` | gauge | agent | 1 | Own certificate `NotAfter` |
| `rpmgr_controller_control_sessions` | gauge | controller | 1 | Connected agents |
| `rpmgr_acme_cert_expiry_timestamp_seconds{hostname}` | gauge | controller | 1 | Public certificates |
| `rpmgr_quic_gso_enabled`, `rpmgr_quic_udp_buffer_warning` | gauge | gateway, connector | 1 | Host tuning status, read from the QUIC socket at each scrape: 1 if quic-go sends with GSO; 1 if its receive or send buffer is below the 7 MiB quic-go asks for ([03](03-connections.md#host-tuning-applied-by-the-installer)) |
| `rpmgr_audit_checkpoint_age_seconds` | gauge | controller | 1 | Age of the oldest audit entry no checkpoint covers yet, 0 when every entry is covered ([04](04-security.md#audit-log)); with the external sink (Phase 2), no checkpoint that reached the sink |
| `rpmgr_revocation_log_sink` | gauge | controller | 1 | 1 if a sink keeps the revocation log off the host, 0 for a single node without one ([Backup and restore](#backup-and-restore)) |
| `rpmgr_revocation_log_unshipped` | gauge | controller | 1 | Revocation log entries the sink does not hold yet |
| `rpmgr_revocation_log_oldest_unshipped_timestamp_seconds` | gauge | controller | 1 | When the oldest unshipped entry was logged, 0 when none; the alert "revocation log not yet off-host" fires 5 min after it |
| `rpmgr_audit_sink_backlog{sink}` | gauge | controller | 2 | Audit entries and checkpoints a sink has not acknowledged ([04](04-security.md#audit-log)) |
| `rpmgr_audit_sink_oldest_unshipped_timestamp_seconds{sink}` | gauge | controller | 2 | When the oldest of them was appended, 0 when none |
| `rpmgr_webhook_deliveries_total{result}` | counter | controller | 2 | Delivery attempts: `ok`, `failed`, `refused` (the egress guard), `given_up` |
| `rpmgr_webhooks_disabled` | gauge | controller | 2 | Endpoints disabled for failing ([D143](14-open-decisions.md#engineering)) |
| `rpmgr_events_pending` | gauge | controller | 2 | Events not yet delivered to every endpoint that wants them |
| `rpmgr_live_log_operations` | gauge | controller | 2 | Open live-log operations |
| `rpmgr_alerts_firing{kind}` | gauge | controller | 2 | Alerts the controller evaluates that fire now || `rpmgr_ratelimit_refused_total{limit}` | counter | controller | 1 | [R] Requests a rate limit refused: `login` and `password_reset` per address, `account` per account, `enrollment` per address; the audit log leaves them out ([04](04-security.md#audit-log)) |
| `rpmgr_dns_sync_runs_total{zone,result}` | counter | controller | 2 | DNS passes per managed zone: `ok`, `held`, `failed`, `rate_limited` |
| `rpmgr_dns_names{zone,status}` | gauge | controller | 2 | Names per `dns_status` ([15](15-dns.md#publication-rules)) |
| `rpmgr_dns_records{zone,state}` | gauge | controller | 2 | Owned records per ledger state |
| `rpmgr_dns_provider_requests_total{provider,code}` | counter | controller | 2 | Provider API calls by HTTP status |
| `rpmgr_dns_provider_token_expiry_timestamp_seconds{provider}` | gauge | controller | 2 | Expiry of the provider's token, if it has one |

### Traces

OpenTelemetry (OTLP export, off by default). The W3C trace context travels in `StreamOpen`
([03](03-connections.md#framing)) and in HTTP `traceparent` headers, so one public request can be
followed gateway → connector → service. [R] Head sampling at 1 % by default, always-on for errors.

- The `tracing` section of each role's boot file turns it on: `otlp_endpoint` is the collector's
  OTLP/HTTP traces URL, and `sample_ratio` the share of new traces sampled at their start. A
  connector continues the gateway's decision, which `StreamOpen` carries; a gateway does not take a
  public client's decision from its `traceparent`, so that clients cannot have every request
  exported, and applies its own share. Every span is recorded, so that one that fails is exported
  even when its trace was not sampled; such spans go out in the background and are dropped when
  the collector falls behind. When a process stops, it exports what is left within 5 s.
- The exporter honours `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` [F otlptracehttp v1.47.0
  client.go:50-51].

### Health

- `/healthz`: process is alive.
- `/readyz`: controller — database reachable and migrations current (checked at most once a
  minute); gateway — control session established (welcomed), snapshot applied and listeners bound;
  connector — control session established and a snapshot applied (data-session state is reported
  separately and does not affect readiness). A check answers within 5 s or counts as not ready;
  a 503 names the reason. The
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
| Audit checkpoints behind | `rpmgr_audit_checkpoint_age_seconds` > 1 h |
| Audit sink backlog (Phase 2) | A sink's oldest unshipped item has waited longer than the period in [03](03-connections.md#timeouts-keepalive-and-backoff) |
| Webhook endpoint failing (Phase 2) | An endpoint had no successful delivery for 1 h while deliveries were due; it is disabled after the period in 03 ([D143](14-open-decisions.md#engineering)) |
| Revocation log not yet off-host | A revocation-log sink is configured and a controller replica has entries not yet shipped to it for > 5 min: `rpmgr_revocation_log_unshipped > 0` and `time() - rpmgr_revocation_log_oldest_unshipped_timestamp_seconds > 300` (without a sink, the UI shows a standing hardening warning instead) |
| DNS conflict | A name in a managed zone is `conflict` or `ambiguous` for > 15 min |
| DNS zone held | A managed zone is `held` (after import, restore or the deletion guard) |
| DNS sync failing | No successful pass of a managed zone for > 30 min, or the provider status is not `ok` |
| DNS-provider token invalid or expiring | The provider rejects the token, or it expires within the warning period ([15](15-dns.md#timers-and-limits)) |
| Cloudflare IP ranges stale | The daily refresh was rejected by the sanity bounds or failed for > 3 days, while proxied routes exist |

[R] **Alerts the controller evaluates** (Phase 2, [D142](14-open-decisions.md#engineering)): the
conditions above stay fixed; they are not configured per org. The controller evaluates, from its
own state: agent offline, configuration not applied, certificate renewal failing, public
certificate expiring, route has no ready connector, clock skew and webhook endpoint failing for
each org; audit checkpoints behind, revocation log not yet off-host and audit sink backlog for the
instance; and, with DNS automation, the DNS alerts. "UDP payloads too large" stays a Prometheus
alert. A firing or resolved alert is an event (`alert.fire`, `alert.resolve`) for the webhooks
that want it, and an e-mail to the org's Owners and Admins, or the Instance Admins for an instance
alert, when SMTP is configured; an org chooses the alert types it gets and can turn the e-mails off
([D139](14-open-decisions.md#engineering), [07](07-api.md#webhooks-phase-2)). The Overview shows
the alerts that fire.

## Hardening checklist

- [ ] Controller UI on HTTPS with a valid certificate; HSTS on.
- [ ] KEK in a KMS, a systemd encrypted credential or a mounted secret file (environment variables
      are not accepted); KEK backup stored separately from database backups.
- [ ] Admin listener bound to localhost or a private interface only.
- [ ] MFA required for the org; WebAuthn for Owners and Instance Admins.
- [ ] SSO configured with a break-glass local Owner whose credentials are stored offline.
- [ ] External audit sink configured (Phase 2: object storage with Object Lock resists tampering
      best); revocation-log sink configured (required for more than one controller replica).
- [ ] Webhook receivers on private networks: only the ranges they need listed in
      `webhook_private_ranges` (Phase 2).
- [ ] Every connector's `policy.yaml` reviewed: `allow_targets` as narrow as possible (the default
      is `[]`, nothing; loopback is not allowed unless listed; a subnet without ports allows all of
      them), `deny_targets` for what a broad entry must not reach; shell, functions, egress proxy
      and virtual-network routes off unless needed.
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
- [ ] Release signatures verified for manual installs.

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

- **Steps**: UI → Connectors → the connector → **Decommission…**, or
  `rpmgr decommission connector <name>`. The deny-list is pushed to all relying parties and live
  sessions close immediately ([04](04-security.md#revocation)); its route targets are deleted
  ([D78](14-open-decisions.md#engineering)). Review the audit
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

- **Steps**: keep the old KEK in a file of the `file` format, mode 0600 (for a systemd credential,
  `systemd-creds decrypt --name=rpmgr-kek /etc/rpmgr/credstore/rpmgr-kek <file>`); stop every
  controller; provision the new KEK in its source; `rpmgr kek rotate --previous-file <file>`
  re-wraps every data key in one transaction ([04](04-security.md#secrets-at-rest-and-in-logs));
  start the controllers; back up the new KEK separately; delete the old KEK's file and retire it
  after a successful backup and test restore.
- **A systemd credential** is loaded only inside a unit: run a command that needs the KEK, such as
  `kek rotate` or `ca rotate-intermediate`, under `systemd-run --pipe --wait
  --property=LoadCredentialEncrypted=rpmgr-kek:/etc/rpmgr/credstore/rpmgr-kek`.
- **Done when**: no data key is wrapped with the old KEK version (`rpmgr kek status`).

### Restore from backup

- **Steps**: stop all controllers; `rpmgr restore --in <file> --revocation-log <sink-url or file>
  [--revocation-log <replica-local-log> …]` (new random `db_epoch`); the restore merges the sink with
  every reachable replica's local log. Without a sink (single node), pass the old host's local
  `revocations.log`; without it, the restore fails closed. Provide the KEK that matches the backup;
  start one controller, check `/readyz`, then the others.
- **After**: check that the sink's hash chain was intact and that entries newer than the backup were
  re-applied. If the restore failed closed (broken chain, or an unreachable local log of a replica
  that reported an unshipped backlog), the instance is in **restore review** mode: each org's Owner
  re-confirms their own org's memberships and roles and re-enables API tokens and service accounts
  one by one; users reset passwords and set up their second factor again; the **Instance Admin**
  confirms orgs without an Owner (`rpmgr restore confirm --org <org>`) and ends the instance-wide
  review on the controller host with `rpmgr restore confirm`. Re-enroll agents enrolled after the
  backup, and agents that renewed their certificate after it, before that certificate expires; tell
  users that sessions were invalidated ([Backup and restore](#backup-and-restore)).
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

### Webhook endpoint failing or disabled

- **Symptoms**: the "webhook endpoint failing" alert; deliveries of the endpoint show errors; the
  endpoint shows **disabled: failing** after the period in
  [03](03-connections.md#timeouts-keepalive-and-backoff).
- **Steps**: read the last deliveries' status codes and errors. `refused` names a private range
  the instance does not list: an Instance Admin adds it to `webhook_private_ranges` if the receiver
  belongs there. A TLS error means the receiver's certificate does not verify against the system
  roots. Fix the receiver, send a test event, then enable the endpoint again; events of the time it
  was disabled are not resent.
- **Done when**: a test event and the next real event are delivered with a 2xx answer.

### Audit sink backlog

- **Symptoms**: the "audit sink backlog" alert; the sink's status in Settings shows its last
  error and a growing backlog.
- **Steps**: check the sink's reachability and credentials from the controller host (syslog: the
  server's TLS certificate against the sink's CA bundle; object storage: the bucket, Object Lock
  and the credentials). Appends go on meanwhile; nothing is lost, as the sink's cursor holds its
  place. Fix the sink; it catches up by itself.
- **Done when**: the backlog is 0 and the alert resolved.

### A restart with hand-off failed

- **Symptoms**: `systemctl reload rpmgr-<role>`, `rpmgr handoff <role>`, the install script or
  the updater reports that the hand-off failed; the role still runs its previous process.
- **Steps**: read the reason it printed (also in `/run/rpmgr/` and the journal of the unit): a
  binary that fails the ownership check ([04](04-security.md#socket-hand-off-phase-2)) is fixed
  with `chown root:root` and `chmod go-w` on it and its directories; a new process that did not
  become ready is diagnosed like a failed start (`journalctl -u rpmgr-<role>`), as visitors were
  served by the old process throughout. When a hand-off is not possible, `systemctl restart`
  restarts the role with the drain of a planned restart.
- **Done when**: `rpmgr handoff <role>` succeeds, or the role runs the new release after a plain
  restart.

### Certificate expiry or clock skew

- **Symptoms**: TLS handshake errors mentioning expiry or "not yet valid"; the agent reports
  "clock skew".
- **Steps**: compare host time with the controller's (`rpmgr diag clock`); fix NTP. If the agent's
  certificate expired while offline, it re-authenticates within the grace period automatically;
  otherwise re-enroll.
- **Done when**: clock offset < 30 s and the agent renews.

### A route certificate is not obtained

- **Symptoms**: under Security → Domains & certificates, the hostname's certificate is `failed`
  with the CA's error; HTTPS to the hostname fails.
- **Steps**: the name's A and AAAA records must point at the gateway group's public addresses, and
  80/tcp or 443/tcp must be reachable from the internet. Every enabled gateway of the route's group
  must be online and answer the challenge: one that is offline or not yet enrolled blocks the
  certificate, so drain or disable it. A name of a private address, such as a
  `nip.io` name of `172.18.0.5`, can never be validated: give its route an uploaded certificate
  instead. Meanwhile the job retries with growing waits and rehearses each retry at the CA's test
  directory, so the failures cost the account nothing at the CA
  ([04](04-security.md#controller-certificates)); the waits are in
  [03](03-connections.md#timeouts-keepalive-and-backoff). Once DNS is fixed, "Renew now" tries at
  once (`rpmgr renew certificate <id>`).
- **Done when**: the certificate is `active`.

### Many hostnames under one domain

- **When**: many routes under one domain, or a CA limit on new certificates per domain is near
  (Let's Encrypt: 50 in 7 days for a registered domain [F le:docs/rate-limits]). Every hostname
  of a route in `acme` mode has a certificate of its own, so each new hostname orders one; ACME
  wildcard certificates need DNS-01, which comes with DNS automation in Phase 2
  ([15](15-dns.md#acme-dns-01)).
- **Steps**:
  1. Obtain one certificate for `example.com` and `*.example.com` outside rpmgr, for example with
     certbot and the DNS plugin of the domain's DNS host.
  2. Upload it: Security → Domains & certificates → "Upload a certificate", or
     `rpmgr upload certificate --chain fullchain.pem --key privkey.pem`.
  3. Give each route under the domain that certificate: in the route's form, "TLS certificate",
     or `rpmgr update route --tls-mode certificate --certificate <id> <route>`. These routes ask
     the CA nothing.
  4. Before the certificate expires, upload the renewed one, move the routes to it as in step 3,
     and delete the old one; rpmgr does not renew an uploaded certificate.
- **Done when**: the routes serve the uploaded certificate, and new hostnames under the domain
  order nothing.

### UDP blocked or degraded

- **Symptoms**: connectors on `auto` use `h2` instead of `quic`; UDP routes flagged as served over
  TCP; routes pinned to `quic` are `not_ready(transport_unavailable: quic)`.
- **Steps**: `rpmgr diag transport --gateway <id>` reports the QUIC handshake result, UDP buffer
  sizes, GSO status and MTU estimate; check firewalls for UDP/443 in both directions; check NAT
  timeouts against the QUIC keepalive ([03](03-connections.md#quic-parameters)). If UDP is known to
  be unreliable on that network, set the connector's transport to `h2`, or the instance default
  if it holds for every connector ([03](03-connections.md#transport-selection)).
- **Done when**: the intended transport is in use, or the TCP transport is pinned deliberately.
