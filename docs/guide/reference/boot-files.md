# Boot files

Every rpmgr role reads a small YAML file when it starts: its boot file. This page lists every key
of the boot files of the controller, the gateway, the connector and the all-in-one, with its type,
its default and what it does, and shows an example for each role. Read it when you write or change
a boot file by hand, or when a role refuses to start because of one.

Everything else, such as routes, gateway groups, port pools and the instance settings, lives in the
controller's database and reaches the agents with their configuration. You change it in the web UI,
with the command line or through the API, never in a boot file
([10](../../10-operations.md#configuration)).

## Where the files live

| Role | Boot file | Command that reads it | Unit |
|---|---|---|---|
| Controller | `/etc/rpmgr/controller.yaml` | `rpmgr controller` | `rpmgr-controller.service` |
| Gateway | `/etc/rpmgr/gateway.yaml` | `rpmgr gateway` | `rpmgr-gateway.service` |
| Connector | `/etc/rpmgr/connector.yaml` | `rpmgr connector` | `rpmgr-connector.service` |
| All-in-one | `/etc/rpmgr/all-in-one.yaml` | `rpmgr all-in-one` | `rpmgr-all-in-one.service` |

- **Which file a command reads.** A role command reads the file its `--config` flag names, else the
  file `RPMGR_CONFIG` names, else the role's file above ([Environment variables](environment.md)).
  The systemd units always pass `--config /etc/rpmgr/<role>.yaml`.
- **Commands on an agent host,** such as `rpmgr status`, `rpmgr diag` and `rpmgr leave`, read the
  connector's boot file, else the gateway's. **Commands on the controller host,** such as
  `rpmgr backup`, read the controller's boot file, else the all-in-one's.
- **Owner and mode.** The files belong to root with mode 0644. The service user `rpmgr` reads them
  and cannot change them. They hold no secret: the key-encryption key (KEK) and certificate keys
  are separate files that a boot file only names.
- **Who writes them.** `rpmgr setup` writes the boot file of the role it sets up
  ([Set up a host with rpmgr setup](../install/setup.md)). `rpmgr controller init` and
  `rpmgr all-in-one init` write one from their flags when it does not exist. The controller's
  `/install.sh` writes the boot file of a gateway or connector when it does not exist
  ([The install scripts](../install/install-script.md)). None of them overwrites a file you
  changed, except `rpmgr setup --force`, which keeps the old file as `<file>.before-setup`.
- **Containers** mount the boot file at `/etc/rpmgr/<role>.yaml`
  ([Manual installation and containers](../install/manual.md#container-images)).

A role reads its boot file once, when it starts. After you change one, restart the role, for
example with `sudo systemctl restart rpmgr-gateway`. The certificate files that `tls.cert_file` and
`tls.key_file` name are the exception: the controller reads them again after a change, without a
restart ([10](../../10-operations.md#boot-files)).

## Rules for every boot file

- **Strict parsing.** A boot file is one YAML document of at most 64 KiB. A key the role does not
  know, a value of the wrong type, a second document or an empty file stops the role at start, with
  the line at fault. So does a key of another role: a connector refuses `listen.tcp`, for example.
- **Version.** `version: 1` is required. A file of another version is refused.
- **Defaults.** A key you leave out takes the default in the tables below. Only `version`, a
  controller's or all-in-one's `public_url` and an agent's `controller.endpoints` have none.
- **URLs** are `https://<host>[:<port>]`: no user, path, query or fragment. A final `/` is
  accepted.
- **Listen addresses** are `[host]:port` with a port from 1 to 65535, such as `:443`,
  `0.0.0.0:443` or `[2001:db8::1]:443`. Where the tables say so, the empty string `""` turns a
  listener off; the other listeners cannot be turned off.
- **The admin listener** (`listen.admin`) serves `/healthz`, `/readyz` and `/metrics`. Its address
  must be a loopback, private or link-local IP address, or `localhost`. An address on all
  interfaces, such as `:7381` or `0.0.0.0:7381`, a public address and any other host name are
  refused, because the listener is never public ([10](../../10-operations.md#ports)).
- **Paths** are absolute.
- **Phase 2 values** are refused for now: `database.driver: postgres` and `kek.source: kms`
  ([13](../../13-roadmap.md#phase-2--production)).

## Sections every role has

| Key | Type | Default | Meaning |
|---|---|---|---|
| `log.level` | string | `info` | `debug`, `info`, `warn` or `error` |
| `log.format` | string | `json` | `json`, one JSON object per line, or `text` |
| `tracing.otlp_endpoint` | URL | `""` | The OTLP/HTTP traces URL of a collector, `http://` or `https://`, such as `https://collector:4318/v1/traces`. Empty turns tracing off |
| `tracing.sample_ratio` | number | `0.01` | The share of new traces that are sampled, from 0 to 1. A span that fails is exported whatever the sampling |

Logs go to standard output, which the systemd journal keeps: `journalctl -u rpmgr-<role>`. The
tracing section is described in [Monitoring](../operations/monitoring.md).

## Controller

`/etc/rpmgr/controller.yaml` configures a controller that runs on its own
([Topologies](../install/topologies.md)).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | integer | required | The format version: `1` |
| `public_url` | URL | required | The URL of the web UI, the API and the agents. Agents get it as their controller endpoint when they enroll and with every configuration. Its host decides the controller's own certificate (`tls` below) |
| `listen.https` | address | `:443` | The listener for the web UI, the API, enrollment, the agents' control sessions, `/install.sh` and the `/dl/` mirror |
| `listen.http` | address or `""` | `:80` | ACME HTTP-01 challenges and the redirect to HTTPS. `""` turns port 80 off |
| `listen.admin` | address | `127.0.0.1:7381` | The admin listener (rules above) |
| `database.driver` | string | `sqlite` | Only `sqlite` for now |
| `database.dsn` | path | `/var/lib/rpmgr/controller.db` | The SQLite database file: an absolute path without `?`, `#` or `%`. The revocation log, the audit checkpoints and the `/dl/` mirror live in the same directory |
| `kek.source` | string | `systemd-credential` | Where the KEK comes from: `systemd-credential` or `file`. A KEK is never read from an environment variable |
| `kek.name` | string | `rpmgr-kek` with `systemd-credential` | The name of the systemd credential: 1 to 64 letters, digits, `_`, `.` or `-`. Only with `systemd-credential` |
| `kek.path` | path | none | The KEK file. Only with `file`, and then required. The file must be a regular file that neither its group nor other users can read or write |
| `tls.cert_file` | path | none | The certificate chain of the public URL's host, PEM, the certificate first. Goes with `tls.key_file` |
| `tls.key_file` | path | none | Its private key, PEM |
| `revocation_log.sink` | path | `""` | A directory, usually on a share, that keeps a copy of the revocation log off the host. Empty keeps only the local log ([Backup and restore](../operations/backup-and-restore.md#the-revocation-log-sink)) |
| `log`, `tracing` | | | As above |

**The KEK.** With `systemd-credential`, systemd decrypts the credential
`/etc/rpmgr/credstore/<kek.name>` for the service, which the unit loads with
`LoadCredentialEncrypted=`. This needs systemd 250 or later. With `file`, the controller reads the
file itself. `rpmgr controller init` and `rpmgr setup` create the KEK and choose the source by the
host's systemd version when you do not; the key and its format are described in
[04](../../04-security.md#secrets-at-rest-and-in-logs).

**The controller's certificate.** With `tls.cert_file` and `tls.key_file`, the controller serves
that certificate. If a pair does not load after a change, it keeps the one in use. Without them, a
controller whose public URL has a public DNS name obtains a certificate from the instance's ACME CA
at its first start, which needs port 80 or 443 reachable from the CA, and serves a self-signed
certificate until then. For any other host, such as an IP address, `localhost` or a name under
`.internal`, it keeps the self-signed certificate
([04](../../04-security.md#controller-certificates)).

Example:

```yaml
# /etc/rpmgr/controller.yaml
version: 1
public_url: https://panel.example.com
listen:
  https: ":443"
  http: ":80"                 # "" turns port 80 off
  admin: "127.0.0.1:7381"
database:
  driver: sqlite
  dsn: /var/lib/rpmgr/controller.db
kek:
  source: systemd-credential
  name: rpmgr-kek
log:
  level: info
  format: json
```

## Gateway

`/etc/rpmgr/gateway.yaml` configures a gateway. Its routes, port pools and certificates come from
the controller, not from this file.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | integer | required | The format version: `1` |
| `controller.endpoints` | list of URLs | required | At least one controller URL. The installers write the URL the gateway enrolled with. The running gateway does not read this list: it dials the controller endpoints it received when it enrolled, which it keeps with its identity, and those of each configuration it receives, which are the controller's public URL |
| `controller.passthrough.address` | `host:port` | `""` | A private controller's port 443, as this gateway reaches it directly. The gateway then forwards the controller's names to it, still encrypted ([Topologies](../install/topologies.md#a-private-controller-behind-a-gateway)). Empty forwards nothing |
| `controller.passthrough.hostnames` | list of names | `[]` | The controller's web UI hostnames to forward as well, in lower case, at least two labels, an internationalised name in its `xn--` form. Needs `address`. The agents' own controller names are always forwarded |
| `identity_dir` | path | `/var/lib/rpmgr/identity` | The gateway's key, certificate chain and pinned root, which `rpmgr enroll` writes |
| `state_dir` | path | `/var/lib/rpmgr` | The last good configuration, the deny-list, the route certificates it fetched and the stateless reset key |
| `listen.tcp` | address | `:443` | Public TCP: HTTPS for `http` routes, `tls_passthrough` routes, and the TCP data sessions of connectors |
| `listen.udp` | address | `:443` | QUIC data sessions of connectors |
| `listen.tunnel_udp` | address or `""` | `""` | A separate UDP port for the QUIC data sessions. Empty shares `listen.udp` |
| `listen.http` | address or `""` | `:80` | ACME HTTP-01 challenges and port 80 of `http` routes. `""` turns port 80 off |
| `listen.admin` | address | `127.0.0.1:7382` | The admin listener (rules above) |
| `log`, `tracing` | | | As above |

The ports of `tcp`, `udp` and `tcp_udp` routes are not in the boot file: they come from the port
pools of the gateway's group ([Gateways](../gateways.md)). The connectors reach the gateway at the
tunnel endpoints you give the gateway in the web UI, so those must lead to `listen.tcp` and
`listen.udp` (or `listen.tunnel_udp`).

Example, as the controller's `/install.sh` writes it, with a private controller added:

```yaml
# /etc/rpmgr/gateway.yaml
version: 1
controller:
  endpoints: ['https://panel.example.com']
  passthrough:                    # only for a private controller
    address: "10.0.0.5:443"
    hostnames: [panel.example.com]
listen:
  admin: '127.0.0.1:7382'
```

## Connector

`/etc/rpmgr/connector.yaml` configures a connector. What it may reach is not in this file but in
its local policy, which `policy_file` names
([The local policy](../connectors/local-policy.md)).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | integer | required | The format version: `1` |
| `controller.endpoints` | list of URLs | required | As for a gateway: written by the installers, not read by the running connector |
| `identity_dir` | path | `/var/lib/rpmgr/identity` | The connector's key, certificate chain and pinned root |
| `state_dir` | path | `/var/lib/rpmgr` | The last good configuration and the deny-list |
| `policy_file` | path | `/etc/rpmgr/policy.yaml` | The connector-local policy ([Local policy file](policy-file.md)) |
| `listen.admin` | address | `127.0.0.1:7383` | The admin listener (rules above) |
| `log`, `tracing` | | | As above |

A connector opens no other listener. `controller.passthrough` is refused: only a gateway forwards to
a private controller. A proxy for the connector's TCP connections is not a boot-file key but the
environment variable `HTTPS_PROXY` or `ALL_PROXY` of its service
([Environment variables](environment.md#proxies)).

Example, as the controller's `/install.sh` writes it:

```yaml
# /etc/rpmgr/connector.yaml
version: 1
controller:
  endpoints: ['https://panel.example.com']
listen:
  admin: '127.0.0.1:7383'
```

## All-in-one

`/etc/rpmgr/all-in-one.yaml` configures a controller, a gateway and a connector in one process
([Concepts](../concepts.md#the-all-in-one)). It has the controller's keys, the gateway's listeners
and the connector's policy file, but no `controller` section and no `identity_dir`: the gateway and
the connector reach the controller inside the process.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | integer | required | The format version: `1` |
| `public_url` | URL | required | As for a controller. `rpmgr all-in-one init` also makes the public URL's host the tunnel endpoint of the built-in gateway `local`, on the port of `listen.tcp`, and the public hostname of the gateway group `default` |
| `listen.tcp` | address | `:443` | The gateway's public TCP listener. The controller is reached through it: the gateway hands the controller's names to the controller in the process |
| `listen.udp` | address | `:443` | The gateway's QUIC listener |
| `listen.tunnel_udp` | address or `""` | `""` | As for a gateway |
| `listen.http` | address or `""` | `:80` | The gateway's port 80: ACME HTTP-01, port 80 of `http` routes, and the redirect to HTTPS for the controller's name. `""` turns port 80 off |
| `listen.admin` | address | `127.0.0.1:7381` | One admin listener that reports the controller, the gateway and the connector |
| `database.driver`, `database.dsn` | | as for a controller | As for a controller |
| `kek.source`, `kek.name`, `kek.path` | | as for a controller | As for a controller |
| `tls.cert_file`, `tls.key_file` | | none | As for a controller |
| `state_dir` | path | `/var/lib/rpmgr` | The gateway's identity and state go to `<state_dir>/gateway/identity` and `<state_dir>/gateway`, the connector's to `<state_dir>/connector/identity` and `<state_dir>/connector` |
| `policy_file` | path | `/etc/rpmgr/policy.yaml` | The local policy of the built-in connector `local` |
| `revocation_log.sink` | path | `""` | As for a controller |
| `log`, `tracing` | | | As above |

An all-in-one has no `listen.https`, because the gateway owns port 443, and no
`controller.passthrough`. Its connector never dials one of rpmgr's own ports on the host, whatever
its policy allows ([ADR-0019](../../adr/0019-all-in-one-runs-a-connector.md)).

If you run a separate connector on an all-in-one's host as well, both read
`/etc/rpmgr/policy.yaml` unless the all-in-one's `policy_file` names another file
([10](../../10-operations.md#supported-platforms)).

Example, with the KEK in a file and the controller's certificate from files:

```yaml
# /etc/rpmgr/all-in-one.yaml
version: 1
public_url: https://panel.example.com
listen:
  tcp: ":443"
  udp: ":443"
  http: ":80"
  admin: "127.0.0.1:7381"
kek:
  source: file
  path: /etc/rpmgr/kek
tls:
  cert_file: /etc/rpmgr/tls/panel.crt
  key_file: /etc/rpmgr/tls/panel.key
state_dir: /var/lib/rpmgr
policy_file: /etc/rpmgr/policy.yaml
```

## A state directory elsewhere

The systemd units that `rpmgr systemd-unit` prints let the service write only to
`/var/lib/rpmgr` (`ProtectSystem=strict` with `StateDirectory=rpmgr`). If you move `state_dir`,
`identity_dir` or `database.dsn` elsewhere, add a drop-in that makes the new directory writable,
such as `ReadWritePaths=/srv/rpmgr`, and give the directory to the user `rpmgr`.

## When a boot file is refused

The role stops at start and the journal names the file, the key and what is wrong:

```sh
sudo journalctl -u rpmgr-gateway -n 20
```

Typical messages:

| Message | Cause |
|---|---|
| `config: yaml: unmarshal errors: line 5: field tcp not found in type …` | A key this role does not know, or a typing error in a key |
| `version: 2 is not supported; this binary reads version 1` | The wrong `version` |
| `listen.admin: admin address "0.0.0.0:7382": all interfaces include public ones; …` | The admin listener on all interfaces |
| `listen.admin: admin address ":7382": want a loopback or private IP address` | The admin listener without an address |
| `public_url "https://panel.example.com/ui": want https://<host>[:<port>]` | A URL with a path, user, query or fragment |
| `kek: file needs an absolute path and no name` | `kek.source: file` without `kek.path`, or with `kek.name` |
| `tls: cert_file and key_file go together` | Only one of the two certificate keys |
| `controller.passthrough: only a gateway forwards to a private controller` | `controller.passthrough` in a connector's file |
| `database.driver: postgres comes with Phase 2 (D57); use sqlite` | A Phase 2 value |
