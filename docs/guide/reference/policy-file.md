# Local policy file

This page describes every key of the connector-local policy file, `/etc/rpmgr/policy.yaml`, and the
rules by which a connector reads it. It is for administrators who edit the file by hand or check
what it allows. How to change the policy with `rpmgr policy`, and what a change does, is in
[The local policy](../connectors/local-policy.md). The design document describes the policy as well
([04](../../04-security.md#connector-local-policy)).

## Where it is

| Host | File |
|---|---|
| Connector | The connector boot file's `policy_file`, `/etc/rpmgr/policy.yaml` by default |
| All-in-one | The all-in-one boot file's `policy_file`, `/etc/rpmgr/policy.yaml` by default, read by the built-in connector `local` |

The file is owned by root with mode `0644`. The controller never writes it. A missing file means the
defaults: no target allowed, `auto_update: auto`, `update_channel: stable`
([Boot files](boot-files.md)).

## Example

```yaml
# /etc/rpmgr/policy.yaml: owner root, mode 0644
version: 1
allow_targets:
  - 127.0.0.1:8080                # one address, one port
  - 127.0.0.1:200-500             # a port range
  - 10.0.0.0/16                   # a subnet, every port
  - "[fd00::/64]:443"             # IPv6 in brackets, quoted in YAML
  - cidr: 192.168.10.0/24         # the mapping form: several ports and ranges
    ports: [80, 443, 8000-8099]
  - unix: /run/app/app.sock       # a Unix socket
deny_targets:                     # wins over allow_targets; the same forms
  - 127.0.0.1:345
  - 10.0.9.0/24
  - 10.0.0.0/16:22
auto_update: auto
update_channel: stable
```

`rpmgr policy show` prints this file as:

```text
allowed targets:
  127.0.0.1/32 ports 8080
  127.0.0.1/32 ports 200-500
  10.0.0.0/16 all ports
  fd00::/64 ports 443
  192.168.10.0/24 ports 80, 443, 8000-8099
  unix /run/app/app.sock
denied targets, which win over allowed ones:
  127.0.0.1/32 ports 345
  10.0.9.0/24 all ports
  10.0.0.0/16 ports 22
auto_update: auto
update_channel: stable
```

## Keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | integer | required | The file's format; must be `1` |
| `allow_targets` | list of entries | `[]` | The targets the connector may dial for routes |
| `deny_targets` | list of entries | `[]` | Targets the connector never dials, whatever `allow_targets` allows |
| `auto_update` | `auto`, `notify` or `off` | `auto` | Whether this host takes automatic updates; read and checked, but without effect until over-the-air updates come in Phase 2 |
| `update_channel` | `stable` or `prerelease` | `stable` | The release channel for automatic updates; without effect until Phase 2 as well |
| `allow_listen` | list of strings | `[]` | Where visitor listeners of private services may bind; private services come in Phase 2 |
| `allow_remote_shell` | boolean | `false` | A remote shell on this host; Phase 3 |
| `allow_functions` | boolean | `false` | Functions on this host; Phase 3 |
| `allow_vnet_routes` | list of strings | `[]` | CIDRs this host may route for virtual networks; Phase 3 |
| `allow_p2p` | boolean | `false` | Direct connections between connectors; Phase 3 |
| `allow_egress_proxy` | boolean | `false` | SOCKS5 and HTTP proxy targets; Phase 3 |

The keys of later phases are accepted so that a file stays valid across upgrades; they change
nothing yet ([13](../../13-roadmap.md)). The install script and `rpmgr policy` write
`auto_update` and `update_channel` explicitly when they create the file.

## Entries of `allow_targets` and `deny_targets`

An entry is a target string or a mapping.

### Target strings

| Form | Example | Means |
|---|---|---|
| Address | `127.0.0.1` | Every port of the address |
| Address and port | `127.0.0.1:8080` | One port |
| Address and port range | `127.0.0.1:200-500` | Ports 200 to 500 |
| Subnet | `10.0.0.0/16` | Every port of every address in it |
| Subnet and port or range | `10.0.0.0/16:443`, `10.0.0.0/16:8000-8099` | Those ports in the subnet |
| IPv6, always in brackets | `[fd00::7]`, `[fd00::7]:8080`, `[fd00::/64]:8000-8099` | As for IPv4 |
| Unix socket | `/run/app/app.sock` | That socket |

Quote an IPv6 target in YAML, as a bracket would start a list: `- "[fd00::7]:8080"`.

### Mappings

| Key | Meaning |
|---|---|
| `cidr` | An address or a subnet |
| `ports` | Optional: a list of ports and port ranges, such as `[80, 443, 8000-8099]`; without the key, every port |
| `unix` | Instead of `cidr` and `ports`: a Unix socket's path |

### Rules for entries

- Ports are 1 to 65535; a range runs from its first to its last port, never backwards.
- A subnet's host bits are cleared: `10.0.0.1/16` means, and is shown as, `10.0.0.0/16`. An
  IPv4-mapped IPv6 address or subnet counts as its IPv4 form.
- A host name is not a target: entries name addresses, which the connector compares with what a
  target's name resolves to at each dial.
- A socket path is absolute and clean: no `.` or `..` parts, no doubled or trailing slash.
- In a mapping, an unknown key, a key given twice, an empty `ports` list, and `unix` together with
  `cidr` or `ports` are errors.

## How a dial is decided

1. An entry of `deny_targets` that matches the address and port refuses the dial.
2. Otherwise an entry of `allow_targets` that matches allows it.
3. Otherwise the dial is refused.

A Unix socket matches only an entry with exactly its path. The checks run at dial time, on the
address a target's name resolves to.

**Protected ranges.** The link-local and cloud metadata ranges `169.254.0.0/16`, `fe80::/10`,
`fd00:ec2::254/128` and `100.100.100.200/32` are allowed only by an allow entry that lies within
the range, such as `169.254.169.254:80`. A broader entry, even `0.0.0.0/0`, does not let them
through.

**On an all-in-one,** the built-in connector also refuses rpmgr's own ports on its host's
addresses, whatever the file allows
([The local policy](../connectors/local-policy.md#on-an-all-in-one)).

## When the file is invalid

These make the whole file invalid:

- YAML that does not parse, or a key the format does not have;
- `version` missing or other than `1`;
- an entry that breaks the rules above;
- an `auto_update` or `update_channel` value not listed above;
- YAML anchors, aliases or merge keys (`<<`) anywhere in the file;
- a file mode that lets its group or other users write it.

An invalid file allows **nothing**: every target of the connector is refused and its routes show
"the connector's local policy does not load". The connector still applies its configuration from
the controller, and reports the routes again once the file is fixed. `rpmgr policy show` prints the
error, such as `policy: allow_targets[0]: ports is empty; leave the key out for all ports`, and the
editing commands refuse to change the file until it is fixed by hand.

A connector from before `deny_targets` and the target strings existed
([D84](../../14-open-decisions.md#engineering)) reads `deny_targets`, a target string, an entry
without ports and a subnet with host bits set as errors, and so dials nothing. Upgrade the
connectors before you use these forms ([Upgrades](../install/upgrades.md)).
