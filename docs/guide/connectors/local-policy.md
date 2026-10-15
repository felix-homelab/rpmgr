# The local policy

The local policy is a file on each connector's host that decides which targets the connector may
dial, whatever the controller says. This page is for the administrators of connector hosts, and of
all-in-one hosts, whose built-in connector reads one too. It shows how to read and change the
policy with `rpmgr policy`, what a change does, and what routes show when the policy blocks a
target. Every key of the file is in [Local policy file](../reference/policy-file.md).

## Why it exists

Routes and their targets are configured on the controller, but a target is dialled on the
connector's host. The local policy keeps that host's administrator in charge: the controller never
writes the file, and a connector never dials an address the file does not allow, even if the
controller, or someone who took it over, says so. It is the one control that survives a compromised
controller ([04](../../04-security.md#connector-local-policy),
[ADR-0009](../../adr/0009-connector-local-policy.md)). On an all-in-one it does not, as the
controller runs in the same process ([On an all-in-one](#on-an-all-in-one)).

- **Nothing is allowed by default.** Without the file, the connector dials no target at all.
  Loopback is not allowed either: databases, admin interfaces and the Docker API often listen there
  with the least protection.
- **The install script and `rpmgr setup` write the first targets**, from their `--allow-target` and
  `--deny-target` flags or by asking ([Install script](../install/install-script.md),
  [rpmgr setup](../install/setup.md)).
- **The file is root's:** `/etc/rpmgr/policy.yaml`, owned by root with mode `0644`, so the `rpmgr`
  service user can read it but not change it. A file that its group or other users may write counts
  as invalid.

## Before you start

- A shell on the connector's host, or the all-in-one's, with `sudo`: the editing commands run as
  root. `rpmgr policy show` needs no root.
- The addresses and ports of the services the connector should reach, as that host reaches them.

## How the policy decides

The connector checks each connection when it dials it, on the address a target's name resolves to,
so a name that later resolves elsewhere is checked again:

1. If an entry of `deny_targets` matches the address and port, the dial is refused, whatever
   allows it.
2. Otherwise, if an entry of `allow_targets` matches, the dial goes ahead.
3. Otherwise it is refused.

A Unix socket is allowed only when an entry names exactly its path. Link-local and cloud metadata
addresses, such as `169.254.169.254`, are allowed only by an entry no broader than their protected
range: `0.0.0.0/0` never lets them through ([04](../../04-security.md#connector-local-policy)).

## Targets

The commands, the file's string entries, the install script and `rpmgr setup` all write a target
the same way ([D84](../../14-open-decisions.md#engineering)):

| Target | Means |
|---|---|
| `127.0.0.1:8080` | One address, one port |
| `127.0.0.1:200-500` | One address, a port range |
| `127.0.0.1` | One address, every port |
| `10.0.0.0/16` | A subnet, every port; `10.0.0.1/16` is stored and shown as `10.0.0.0/16` |
| `10.0.0.0/16:443` | A subnet, one port |
| `[fd00::7]:8080`, `[fd00::/64]:8000-8099` | IPv6, always in brackets |
| `/run/app/app.sock` | A Unix socket, an absolute path |

A target without a port allows, or denies, every port; `rpmgr policy show` says "all ports". Host
names are not targets: the policy names addresses, which the connector compares with what a name
resolves to. In a shell, quote IPv6 targets, as brackets are special there: `'[fd00::7]:8080'`.

## Show the policy

```sh
rpmgr policy show
```

```text
/etc/rpmgr/policy.yaml:
allowed targets:
  127.0.0.1/32 ports 8080
  192.168.10.0/24 ports 80, 443, 8000-8099
  10.0.0.0/16 all ports
  unix /run/app/app.sock
denied targets, which win over allowed ones:
  10.0.9.0/24 all ports
auto_update: auto
update_channel: stable
```

Without a file it says `no file, the defaults apply`; for a file with an error it says `invalid,
nothing is allowed` and prints the error, with exit status 1. `--file <path>` reads another file.

## Change the policy

The editing commands run as root. They change one target in the file, keep its comments and other
keys, write it atomically under a lock, and then reload the connector.

**Allow a target:**

```sh
sudo rpmgr policy allow-target 10.0.0.5:5432
```

```text
/etc/rpmgr/policy.yaml: updated
```

A target that an entry covers already is not added twice (`nothing to change`). A port is added to
the `ports` of its subnet's entry when that entry is written as a mapping (`cidr:` and `ports:`);
beside an entry written as a target string, the command appends a new entry. Without a file, the
command creates one.

**Deny a target,** so that no allow entry can let it through, for example the SSH port in an
allowed subnet:

```sh
sudo rpmgr policy deny-target 10.0.0.0/16:22
```

**Stop allowing or stop denying a target:**

```sh
sudo rpmgr policy remove-target 10.0.0.5:5432
sudo rpmgr policy remove-deny-target 10.0.0.0/16:22
```

A target without a port removes every entry of its address or subnet. A command cannot split an
entry: removing one port that only a broader entry or a port range covers is refused. For an allow
entry, the advice is to deny the target with `rpmgr policy deny-target` instead, or to edit the
file; for a deny entry, to remove that deny entry, or to edit the file to split it.

| Flag | Meaning |
|---|---|
| `--file <path>` | The policy file; `/etc/rpmgr/policy.yaml` if not given |
| `--no-reload` | Change the file, but do not ask the running connector to reload it |

### Reload

After a change, the command runs `systemctl reload rpmgr-connector.service`, or on a host with an
all-in-one's boot file and no connector's, `systemctl reload rpmgr-all-in-one.service`. The reload
sends the process `SIGHUP`, and it reads the file at once. If the reload fails, the command warns:
"could not reload the connector (…); it picks the change up within a few seconds". The connector
also watches the file and reloads it on its own after any change, a hand edit included
([03](../../03-connections.md#timeouts-keepalive-and-backoff)).

### Edit the file by hand

You may edit `/etc/rpmgr/policy.yaml` as root with any editor, for example to add comments, to write
several ports in one entry, or to split a range. Keep `version: 1`, and do not use YAML anchors,
aliases or merge keys (`<<`), which make the file invalid. Then check it, and reload:

```sh
sudo rpmgr policy show
sudo systemctl reload rpmgr-connector.service
```

## What a change does

- **No new revision is needed.** The connector evaluates its current routes against the new policy
  at once and reports their readiness, so the web UI shows the effect within moments.
- **Removed targets are cut off at once.** Open connections to a target that the policy no longer
  allows are reset, a target that a new deny entry matches included, and so are pooled HTTP/2
  connections to it. A connection being set up is checked against the policy in force when it is
  recorded.
- **A file with an error allows nothing.** If the file does not parse, or its group or other users
  may write it, every target is refused, and the routes show "the connector's local policy does not
  load". The connector still applies its configuration from the controller. The editing commands
  refuse a file that does not parse: fix it first, by hand. A file with a bad mode they rewrite
  with mode 0644 when they change it.

## In the web UI

A connector reports one readiness per route, not per target. When none of a route's targets on a
connector is allowed, the route's page shows each of them as **blocked by the connector's local
policy**, and the routes list counts them ("1 blocked by local policy"). The route's page then
shows, under "Run on the host of *connector*:", the command that lets the first blocked target
through, with a **Copy** button; each of that connector's targets shows the same command:

- `sudo rpmgr policy allow-target 10.0.0.5:5432` for a target that no entry allows;
- `sudo rpmgr policy remove-deny-target 10.0.0.0/16:22` for a target that a deny entry refuses; the
  readiness detail names the entry, as in `10.0.0.5:22 denied by 10.0.0.0/16:22`.

A blocked target blocks only itself. While another target of the route on the same connector is
allowed, the connector reports the route ready and its connections go there. The route's page then
shows the blocked target as **ready** too, with no command: check that connector's policy with
`rpmgr policy show` on its host ([Targets](../routes/targets.md#the-local-policy-and-targets)).

## On an all-in-one

An all-in-one runs a built-in connector named `local`, so that services on its own host need no
second installation ([Topologies](../install/topologies.md),
[ADR-0019](../../adr/0019-all-in-one-runs-a-connector.md)). It reads the policy file that the
all-in-one boot file's `policy_file` names, `/etc/rpmgr/policy.yaml` by default, and allows nothing
until you allow targets, as any connector does. `rpmgr policy` reloads `rpmgr-all-in-one.service`
on such a host.

- **rpmgr's own ports are always refused.** The built-in connector never dials one of the ports
  rpmgr listens on, on an address of its own host, whatever the policy allows: the admin listener,
  80, 443 over TCP and UDP, the tunnel UDP port, and every route port the gateway has bound. The
  host's addresses are loopback, the unspecified addresses, its interfaces' addresses, and those the
  public URL's host and the gateway group's public hostnames resolve to. Such a target shows "is
  one of rpmgr's own ports, which the all-in-one's connector never dials, whatever its policy
  allows. Point the target at the service itself." and no command. This keeps the metrics out of
  reach and routes from looping through the gateway.
- **Other paths to these ports are not detected.** A router or container that forwards an address
  of its own to rpmgr's ports is not recognised: never allow such a target.
- **It does not survive a compromised controller.** The controller runs in the same process and
  could dial anything the `rpmgr` user can. On an all-in-one, the policy limits the routes made
  through the API, not an attacker inside the process.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `the local policy is root's; run this as root (sudo)` | The editing commands need root |
| `… has mode 0666; only its owner may write it` | Run `sudo chmod 644 /etc/rpmgr/policy.yaml`, or change the file with an editing command, which writes it with mode 0644; the file is invalid until then |
| `anchors, aliases and merge keys are not allowed in the policy file` | Write the entries out in full |
| `… (fix the file first)` | The file has an error; `rpmgr policy show` prints it |
| `the target is part of a broader entry or port range` | Deny the target instead, or edit the file to split the entry |
| `write an IPv6 address or subnet in brackets` | Write `[fd00::1]:443`, not `fd00::1:443` |
