# The real-world run

`run.sh` installs and operates real `rpmgr` binaries on hosts that run systemd, the way
[10](../../docs/10-operations.md) and [16](../../docs/16-cli.md) tell an operator to: from the
verification of a release to a backup and its restore. Unit, integration and end-to-end tests run
the roles in one process or as plain processes; this run is the one that meets systemd, its
credentials and units, the installer on several distributions, and the order of an operator's
steps. It found the faults #437 to #444 in `v0.1.0-rc.1`.

## Running it

```sh
test/realworld/run.sh                       # v0.1.0-rc.1, downloaded with gh, on every host
test/realworld/run.sh --binary <rpmgr>      # that binary on the all-in-one, the release elsewhere
test/realworld/run.sh --keep                # leave the containers running afterwards
test/realworld/run.sh --from policies       # with the containers kept, from that flow on
```

- **Needs:** Docker with cgroup v2, Go (for Pebble and the test service) and `gh` for the download.
  With the host images built, a run took 250 to 390 s on a WSL2 host.
- **The binary under test** with `--binary` must name the release's version, so that `rpmgr
  release import` takes the release: build it as the release does, with
  `CGO_ENABLED=0 go build -trimpath -ldflags "-X github.com/felix-homelab/rpmgr/internal/version.Version=0.1.0-rc.1" ./cmd/rpmgr`.
  The agents always get the release's binary, through the controller's `/install.sh` and `/dl/`
  mirror; where a check needs the binary under test on an agent host, it runs `/rw/bin/rpmgr`.
- **Output:** each step with its time; on a failure, the last lines of each host's journal. The
  run directory (`$RW_RUN`, a temporary directory by default) keeps the downloaded release, the
  built tools and `out/`.

## Hosts

| Host | Image | Networks | Role |
|---|---|---|---|
| `aio` | Debian 12 | public 172.40.0.10 | all-in-one, the default systemd-credential KEK; `panel.rw.test` and the default group's hostnames |
| `gw2` | Ubuntu 24.04 | public 172.40.0.11 | gateway of the group `edge`, installed with `/install.sh`; `gw2.rw.test`, `app2.rw.test` |
| `con1` | Ubuntu 24.04 | public, private | connector, installed with `/install.sh` |
| `con2` | Rocky Linux 9 | public, private | connector, installed with `/install.sh` |
| `svc` | Debian 13 slim | private 172.41.0.30 | the services: TCP echo, UDP echo, HTTP, TLS |
| `client` | Debian 13 slim | public 172.40.0.40 | the public client |
| `ca` | Debian 13 slim | public, alias `pebble` | Pebble with `pebble-challtestsrv` as DNS, at the version in `go.mod` |

Both networks are `internal`: no host reaches the internet, so nothing contacts Let's Encrypt or
GitHub. Base images are pinned by digest through `mirror.gcr.io`.

**systemd as PID 1.** The host containers run `/sbin/init` with:

- `privileged: true` and `cgroup: private` (`--privileged --cgroupns=private`): systemd needs to
  manage its own cgroup tree, which Docker's cgroup v2 driver gives a container only in a private
  namespace;
- `container=docker`, `STOPSIGNAL SIGRTMIN+3` (systemd's shutdown signal) and a tmpfs on `/tmp`;
- the getty units masked, as a container has no console;
- `shared-root.service`, which runs `mount --make-rshared /` before `sysinit.target`. Docker mounts
  a container's root privately, and then systemd's service credentials (`LoadCredentialEncrypted=`,
  the default KEK source) reach the service empty. A real host's root is shared from boot.

A container restart stands in for a reboot.

## Flows

| Flow | What an operator does, and what is checked | Docs |
|---|---|---|
| `aio` | Verify the release with minisign against root key 1 and the manifest's SHA-256; create the user and directories; `rpmgr all-in-one init` with the default KEK; a self-signed panel certificate; `rpmgr systemd-unit all-in-one`, `systemctl enable --now`; `/readyz` | 10 "Install", VB-19 run sheet |
| `login` | The first user and an API token with the calls the web UI makes; `rpmgr login`; the instance's ACME CA, the panel certificate from it; `rpmgr release import` into the `/dl/` mirror | 10, 16 |
| `gateway` | Group `edge`, gateway `gw2`, port pools, `create gateway-token`; the controller's install command run on `gw2` | 16 |
| `connectors` | The install command with `--allow-target`; an enrollment token per connector; the command run on `con1` and `con2`; `/install.sh` writes `60-rpmgr.conf` with mode 0644 | 16, 10 "Filesystem layout" |
| `routes` | Domain `rw.test` proved over HTTP; a route of every Phase 1 type with targets on both connectors: tcp, udp, http with ACME on both groups, http with an uploaded certificate, tls_passthrough | 16 |
| `traffic` | Every route from the client, through both gateways | 03 |
| `policies` | An access policy that denies the client, taken off again with `--policy ''` and deleted; the connector-local policy of each connector, by `rpmgr policy`, until neither serves the target, then allowed again | 16, 04 |
| `restarts` | `systemctl restart` of each service; `con1` and `aio` rebooted; `rpmgr status`, `rpmgr diag transport`, `rpmgr diag clock` | 10 |
| `backup` | `rpmgr backup` while it runs, a change, `rpmgr restore` with the service stopped; traffic again; no error and no warning in the all-in-one's journal but the release check | 10 "Backup and restore" |

**Where the run differs from a real host.**

- The release check logs a warning, as GitHub is out of reach; the mirror comes from `rpmgr
  release import`, as on an air-gapped host.
- A step-up asks for the factor on a terminal only, and the run has none: before each command that
  needs one, it steps the token up with the API call the CLI makes.
- `/install.sh` cannot raise `net.core.rmem_max` inside a container, as the kernel keeps it for the
  initial network namespace; it says so, and `rpmgr diag transport` reports the smaller buffers.
- Pebble stands in for Let's Encrypt; its root is added to each host's trust store, as a public
  CA's root is there already.

## What an operator does by hand

The steps the documents make an operator take for an all-in-one with one more gateway and two
connectors, as the run takes them; input for a global install script and an interactive setup:

1. Download the release files and verify them: `signing-key.json` against a root key with
   minisign, then `manifest.json` against the signer, then the binary's SHA-256 in the manifest.
2. Install the binary to `/usr/local/bin`, create the system user `rpmgr`, `/etc/rpmgr` (0755) and
   `/var/lib/rpmgr` (0750, the user's).
3. `rpmgr all-in-one init --public-url https://<name>`, and keep the first-user link it prints.
4. Until the instance has an ACME CA or the boot file names certificate files: a certificate for
   the panel, its key readable by the group `rpmgr`, in the boot file's `tls:` section.
5. `rpmgr systemd-unit all-in-one` into `/etc/systemd/system/`, `systemctl daemon-reload` and
   `systemctl enable --now`.
6. DNS: the panel's name and each route's hostname to the gateway of its group.
7. The first-user link in a browser: the password, and a second factor; then an API token.
8. `rpmgr login --controller <url> --token-file <file>`, with `--ca-file` while the panel's
   certificate is not from a public CA.
9. The ACME account (`acme_email`, and the directory when it is not Let's Encrypt), then the `tls:`
   section out of the boot file and a restart.
10. Without internet access: `rpmgr release import <dir>`, so that `/install.sh` finds the release
    in the mirror.
11. Per extra gateway: a group with its public hostnames, the gateway with its tunnel endpoint, the
    port pools, a gateway token (with a step-up), and the install command run on the host with the
    token in a file.
12. Per connector: an enrollment token (with a step-up; one per connector unless ephemeral), the
    install command with the targets the connector may reach, run on the host with the token in a
    file.
13. The domain claim and its proof, then the routes and their targets.
14. Backups: `rpmgr backup --out <file>` on a schedule, and the KEK kept apart from them.

## Results

| Run | Binary on the all-in-one | Outcome |
|---|---|---|
| 2026-10-12 | `v0.1.0-rc.1` | `aio` fails: with the default KEK, init fails (#432, fixed by #433); with `--kek-source file`, the service cannot open its root-owned database (#437) |
| 2026-10-12 | `v0.1.0-rc.1`, `--kek-source file`, the state directory given to `rpmgr` by hand | Every route serves through both gateways; then #438 to #444 |
| 2026-10-12 | `origin/main` with the fixes of #437 to #444 merged, version 0.1.0-rc.1 | Every flow passes, in 250 s |
