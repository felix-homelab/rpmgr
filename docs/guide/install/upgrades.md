# Upgrades

rpmgr updates **connectors and gateways** itself, in a staged rollout you approve, and the
**controller or all-in-one** when you ask for it, on SQLite
([Updates](../operations/updates.md)); a controller on PostgreSQL is upgraded by hand, with the
new release's install script. This page gives the order of the hosts, the steps for each, what
the install script's `--upgrade` and `--restart` do, which versions work together, and how to go
back. Read it before every upgrade.

## Before you start

- **Read the release notes** of every version between yours and the new one, in the
  [CHANGELOG](../../../CHANGELOG.md) and on the
  [Releases page](https://github.com/felix-homelab/rpmgr/releases).
- **Back up the controller** and check that you have its KEK
  ([Backup and restore](../operations/backup-and-restore.md)). The new controller migrates the
  database when it starts, and the way back is a restore of that backup.
- **Know your hosts:** `rpmgr version` on each, or the **Version** column of the gateways and the
  connectors in the web UI.

## The order

Upgrade the **controller first, then the gateways, then the connectors**. A controller works with
agents of its own minor version and of the one before, so agents may lag behind the controller by
one minor version. Agents newer than the controller are not supported: they connect, and the
controller does not use what it does not know
([10](../../10-operations.md#upgrades-and-version-skew)).

The controller refuses an agent too old for it before the agent's session starts, so the web UI
shows that agent offline. The agent's log says why: `controller said goodbye` with
`reason=GOODBYE_REASON_UPGRADE_REQUIRED`
([03](../../03-connections.md#versioning-and-capabilities)).

While the controller restarts, every gateway and connector keeps running its last configuration,
and visitor traffic flows on ([03](../../03-connections.md#failure-modes)).

## Upgrade a host

On each host, download the new release's global install script and run it with `--upgrade` and
`--restart`:

```sh
curl -fsSLO https://github.com/felix-homelab/rpmgr/releases/latest/download/install.sh
sudo sh install.sh --upgrade --restart
```

For a pre-release, take `install.sh` from that release instead:
`https://github.com/felix-homelab/rpmgr/releases/download/v<version>/install.sh`.

What you see (abbreviated):

```text
rpmgr install: downloading rpmgr 0.1.1 for linux/amd64 from https://github.com/felix-homelab/rpmgr
rpmgr install: verified rpmgr 0.1.1 (manifest …)
rpmgr 0.1.1 (commit …, go…, linux/amd64)
release root keys:
  …
rpmgr install: restarted rpmgr-connector with rpmgr 0.1.1
```

### 1. The controller

**Over the air (SQLite, v0.3.0 and later).** Choose **Update controller to …** on **Settings →
Updates**, or run `rpmgr upgrade controller --release <version>`. The host's updater backs the
database up itself, installs the release, restarts the controller (an all-in-one is handed over),
and restores the backup and starts the previous version when the new one fails after its
migration ([Update the controller](../operations/updates.md#update-the-controller)). The steps
below are for a controller on PostgreSQL, a host without the root updater, and releases before
v0.3.0.

1. Back up: `sudo rpmgr backup --out /root/rpmgr-before-0.1.1.tar`.
2. Run the install script with `--upgrade --restart` on the controller's or all-in-one's host.
3. Check that it is ready: `curl -fsS http://127.0.0.1:7381/readyz` prints `ok`. Sign in to the
   web UI; the foot of the sidebar shows the new version.

The controller applies the database migrations of the new version when it starts, under a lock.
To apply them yourself first, run the install script with `--upgrade` but without `--restart`, so
that the controller keeps running the old binary. Then stop the controller, run
`sudo rpmgr migrate`, which keeps a copy of the database beside it,
`<database>.before-migrate-<time>`, before it migrates, and start the controller again.

If the controller has no access to GitHub, import the new release into its mirror after the
upgrade, so that new agents install the new version ([Air-gapped installations](air-gapped.md)).

### 2. The gateways

From Phase 2, a rollout drains each gateway, updates it and enables it again, one gateway at a
time per group ([Updates](../operations/updates.md)). A host whose policy says `auto_update: off`
or `notify`, or that has no root updater, is listed as skipped and is upgraded by hand.

Upgrade the gateways one at a time. With several gateways in a group, drain each first, so that
its visitors move to the others:

1. **Drain** the gateway: in the web UI under **Network → Gateways**, open its group and choose
   **Drain** on the gateway, or run `rpmgr drain gateway <gateway>`. It takes no new connections
   and ends the open ones after its drain period ([Gateways](../gateways.md)).
2. Run the install script with `--upgrade --restart` on the gateway's host.
3. Check it: the last line of `sudo rpmgr status`, `Service:`, says `running and ready`.
4. **Resume** it in the web UI, or run `rpmgr enable gateway <gateway>`.

A gateway alone in its group drains by itself when it stops, but its routes cannot be reached
until it is back.

### 3. The connectors

Through the rollout: offer the release to the test agents you choose, then to a percentage, then
to all, and approve each stage ([Updates](../operations/updates.md)). A connector whose updater
rolls back pauses the rollout, and the page says which one and why. A connector on
`auto_update: off` or `notify` is skipped and is upgraded by hand:

Run the install script with `--upgrade --restart` on each connector's host, and check it with
`sudo rpmgr status`. A route whose targets are on several connectors keeps serving through the
others while one restarts.

## What --upgrade and --restart do

**`--upgrade`** upgrades a host that has rpmgr:

- It refuses a host without `/usr/local/bin/rpmgr` before it downloads anything:
  `nothing to upgrade: /usr/local/bin/rpmgr is not installed; install it without --upgrade`.
- It verifies the release as every install does and replaces the binary in one rename. It leaves
  the boot files, the policy, the identity and the database as they are. Only for a gateway,
  all-in-one or connector that has a unit, and a release from v0.3.0 on, it writes the unit again
  and its drop-in `handoff.conf`, so that the role restarts without refusing connections (below).
- It offers no setup. After the version and the release root keys, it prints only what is left to
  do.

**`--restart`** restarts every rpmgr service that runs, in the upgrade order: `rpmgr-controller`,
`rpmgr-all-in-one`, `rpmgr-gateway`, `rpmgr-connector`.

- After each restart it checks that the service stays active for 5 s without systemd restarting
  it, and reports `restarted <unit> with rpmgr <version>`.
- A service that does not stay up stops the script with exit code 1:
  `<unit> does not stay up with rpmgr <version>; see: journalctl -u <unit> -n 50`.
- With no service running, it says `no rpmgr service runs; nothing to restart`.
- It also works without `--upgrade`, for example after a first installation.

Without `--restart`, the script names each service that still runs the previous binary:

```text
rpmgr install: rpmgr-controller runs the previous binary until you restart it: sudo systemctl restart rpmgr-controller
```

### Restart without refusing connections

From v0.3.0 on, a gateway, an all-in-one and a connector restart with a **hand-off**: the new
process takes over the listening sockets and the sessions, and the old one serves until the new
one is ready. With `--restart` the script hands such a service over instead of restarting it:

```text
rpmgr install: handed rpmgr-gateway over to rpmgr 0.3.0 without a restart
```

- **When it hands over.** The running process is of v0.3.0 or later and its unit runs as
  `Type=notify`, which the drop-in `rpmgr-<role>.service.d/handoff.conf` sets. A host set up
  before the drop-in has none: the script writes it, restarts the service as before and says
  `restarting rpmgr-gateway without a hand-off`. The next upgrade hands over. The same goes for
  an upgrade from a release before v0.3.0.
- **Without `--restart`,** the script names how to hand over later:
  `sudo systemctl reload rpmgr-gateway`, which does the same for a gateway and an all-in-one, and
  `sudo rpmgr handoff connector` for a connector.
- **A failed hand-off** (the new process was not ready) ends the script with exit code 1 and the
  message `cannot hand <unit> over to rpmgr <version>; the old process serves on`; nothing has
  stopped. Read `journalctl -u <unit>`, then restart by hand if you must.
- **The controller restarts as before.** An all-in-one hands its gateway over without refusing a
  connection, but its controller is unavailable for a few seconds: the API and the web UI answer
  `503` until the new process serves.
- **Limits.** QUIC and `udp` routes move after the old process exits, so a UDP flow may lose
  packets for a moment. The limits are in
  [03](../../03-connections.md#restarts-with-socket-hand-off-phase-2). A container restarts
  without a hand-off.

To take the unit of a newer release on a host the script does not write it for, such as a
controller's, print it again with `rpmgr systemd-unit <role>`, as in
[Manual installation and containers](manual.md#3-the-unit), then `sudo systemctl daemon-reload`
and restart the service.

### With an older install script

The install script of v0.1.0-rc.7 and earlier has neither `--upgrade` nor `--restart`. With it,
replace the binary with `--no-setup` and restart the service yourself:

```sh
sudo sh install.sh --no-setup
sudo systemctl restart rpmgr-all-in-one   # or rpmgr-controller, rpmgr-gateway, rpmgr-connector
```

### Agent hosts without access to GitHub

A gateway or connector host that reaches only the controller can take the new version from the
controller, once the controller runs it and its mirror holds it. Run the controller's install
command again, then restart the service: the script replaces the binary and keeps the boot file,
the policy and the identity
([The install scripts](install-script.md#the-controllers-install-script)).

- **Get the command** with `rpmgr get install-command` for a connector, or
  `rpmgr get --role gateway install-command` for a gateway; neither makes a token. The web UI shows
  a gateway's command only before the gateway enrolls, and a connector's only with a new
  enrollment token. Revoke a token you made only to see the command
  ([Enrolling connectors](../connectors/enroll.md)).
- **On a gateway,** the command must carry `--role gateway`. Without it, the script installs and
  starts a connector's unit beside the gateway, which fails on the gateway's identity.

```sh
# a connector
curl -fsSLO 'https://panel.example.com/install.sh' && sudo sh install.sh \
  --controller 'https://panel.example.com' --ca-pin 'sha256:…'
sudo systemctl restart rpmgr-connector

# a gateway
curl -fsSLO 'https://panel.example.com/install.sh' && sudo sh install.sh \
  --controller 'https://panel.example.com' --ca-pin 'sha256:…' \
  --role gateway
sudo systemctl restart rpmgr-gateway
```

## Release candidates

Release candidates are pre-releases, such as `0.1.0-rc.7`. Install one with the `install.sh`
attached to it, or with `--version 0.1.0-rc.7`; the container image has the tag of the version.

Before v0.1.0, two changes of behaviour shipped without a way for old agents to take part, so
upgrade the agents soon after the controller:

- **Access policies:** a gateway of v0.1.0-rc.1 to rc.6 applies the first matching rule, so a deny
  rule after an allow rule is ignored there until that gateway is upgraded; current versions let a
  deny rule win ([D85](../../14-open-decisions.md#engineering)).
- **Target priority and weight across connectors:** a gateway or connector of v0.1.0-rc.1 to rc.7
  does not follow the priorities across connectors that current versions use
  ([D90](../../14-open-decisions.md#engineering), [03](../../03-connections.md#multiple-gateways)).

## Going back

An agent can go back to the version before with the same script and `--version`:

```sh
sudo sh install.sh --upgrade --restart --version 0.1.0
```

A connector's local policy does not go back with the binary. An older binary may read a policy file
that uses newer forms, such as `deny_targets`, as invalid, and then reaches no target until the file
is changed back ([10](../../10-operations.md#hardened-systemd-units)).

A controller cannot simply go back once it has migrated the database to the new version. Go back
with the backup you made before the upgrade: install the old version with `--upgrade --version`,
stop the controller, restore the backup and start it again
([Backup and restore](../operations/backup-and-restore.md#restore)). The restore takes the
instance back to the time of the backup, with the effects that page describes.
