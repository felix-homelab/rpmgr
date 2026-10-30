# Set up a host with rpmgr setup

`rpmgr setup` turns a host with the `rpmgr` binary into an all-in-one, a controller, a gateway or a
connector. It writes the boot file, initialises the controller or enrolls the agent, writes the
local policy, installs the systemd unit, starts it and waits until the role is ready. This page
describes what setup asks, the flag for each answer, and what it does. Read it when you set up a
host, or when you script a setup with `--yes`.

## Before you start

- **The binary** is installed at `/usr/local/bin/rpmgr`, usually by the global install script,
  which offers to run setup when it finishes ([The install scripts](install-script.md)).
- **Root:** run `sudo rpmgr setup`. Setup refuses to start otherwise.
- **systemd,** unless you start the role yourself with `--no-unit`.
- **For an all-in-one or a controller:** the public URL, `https://<host>[:<port>]`, whose name
  points at the host, and for a certificate from Let's Encrypt the ports 80 and 443 open to the
  internet.
- **For a gateway or a connector:** the controller's URL, its CA pin and a token: a gateway token
  from the gateway's **Enrollment token…** action, or an enrollment token from
  **Enroll a connector** ([Enrolling connectors](../connectors/enroll.md),
  [Gateways](../gateways.md)). The controller's `setup` or `init` printed the CA pin; the web UI
  shows it under **Settings → PKI** as **Root pin, for rpmgr enroll --ca-pin**.

## How setup works

1. **It asks.** Without `--yes`, setup asks for the role and its values in forms. On a terminal at
   least 40 columns wide the forms take the full screen; otherwise setup asks plain questions on
   standard input and output, which a pipe or a screen reader can answer. Each flag you give
   pre-fills its answer.
2. **It checks.** Every value is checked as the role will read it, and the host too: setup refuses,
   before it changes anything, a boot file that exists (unless `--force`), a host that holds a
   controller database already, a KEK credential on a systemd older than 250, certificate files
   that do not load, an agent that is enrolled already (unless `--force`), a missing systemd or
   binary (unless `--no-unit`), and an admin address that is in use.
3. **It shows the plan.** A summary of your choices, then the numbered steps it will take. The
   token is listed as `given (not shown)`.
4. **It asks once more:** **Run it?** with **Run** and **Cancel**. Nothing changes before you
   choose **Run**. Cancelled, setup says `nothing was changed`.
5. **It runs the steps,** printing each as it starts (`→ write the boot file …`), and ends with what
   you need next.

With `--yes`, setup asks nothing: it needs `--role`, takes every value from the flags and runs the
plan at once. The token then comes from `--token-file`, `RPMGR_ENROLL_TOKEN` or the terminal
prompt.

## Flags of every role

| Form field | Flag | Default | Meaning |
|---|---|---|---|
| **Role of this host** | `--role` | `all-in-one` in the form | `all-in-one`, `controller`, `gateway` or `connector`. Required with `--yes` |
| **listen.admin** | `--listen-admin` | the role's port on 127.0.0.1 | The admin listener: 127.0.0.1:7381 for an all-in-one or controller, 7382 for a gateway, 7383 for a connector |
| (none) | `--firewall ufw` | off | A gateway or all-in-one only: hand the host's `ufw` to rpmgr, which opens the gateway's listeners and the port pools' ranges. Setup writes the `firewall` key of the boot file, the root-owned bounds file and the units of the root helper ([Gateways](../gateways.md#the-hosts-firewall)). Without `ufw` on the host, setup still finishes and warns |
| (none) | `--firewall-max-range` | none | With `--firewall`: the largest range of port pools rpmgr may open, `<from>-<to>`, such as `20000-29999`. Without it rpmgr opens only the listeners |
| **Install the unit rpmgr-&lt;role&gt;, start it and wait until it is ready?** | `--no-unit` | install it | Without the unit, setup writes the files, initialises or enrolls, and starts nothing |
| (none) | `--force` | off | Replace an existing boot file, keeping the old one as `<file>.before-setup`; on a gateway or connector, also enroll again with a new token. A host with a controller database is refused all the same |
| (none) | `--yes` | off | Ask nothing |

The listen addresses are asked in a form of their own, **Listen addresses**; an empty field keeps
the default. They become the boot file's `listen` keys ([Boot files](../reference/boot-files.md)).

## All-in-one

An all-in-one runs a controller, a gateway and a connector in one process
([Concepts](../concepts.md#the-all-in-one)). Setup initialises it as `rpmgr all-in-one init` does:
it creates the KEK, the database, the trust domain and the CA, the gateway group `default` with the
built-in gateway `local`, and the built-in connector `local`, and enrolls both.

| Form field | Flag | Default | Meaning |
|---|---|---|---|
| **Public URL: https://&lt;host&gt;[:&lt;port&gt;] of the web UI, the API and the agents** | `--public-url` | none, required | The address of the web UI and of the agents. Its host also becomes the gateway group's public hostname, where `tcp` and `udp` routes are reached |
| **Where the KEK is kept** | `--kek-source` | by the systemd version | `systemd-credential` (systemd 250 or later) or `file`. Below systemd 250 the form only says that the KEK is a file |
| **KEK file** | `--kek-path` | `/etc/rpmgr/kek` | The KEK file, with `--kek-source file` |
| **Certificate of &lt;host&gt;** | `--tls` | `acme` for a public name, else `self-signed` | `acme`: from the instance's ACME CA at the first start. `files`: your certificate chain and key. `self-signed`: no browser trusts it until you switch |
| **Certificate chain file** | `--cert-file` | none | With `--tls files`: the PEM chain, the certificate first |
| **Key file** | `--key-file` | none | With `--tls files`: its private key |
| **ACME CA of the instance, for the public URL and the routes** | `--acme-directory` | `production` | `production` (Let's Encrypt), `staging` (Let's Encrypt's staging CA, whose certificates no browser trusts), or the `https://` directory URL of another ACME CA |
| **ACME account e-mail address (optional)** | `--acme-email` | none | The e-mail address of the instance's ACME account |
| **Allowed targets, separated by spaces (optional)** | `--allow-target`, repeated | none | Targets on this host that the built-in connector may reach, such as `127.0.0.1:8080` |
| **Denied targets, which win over allowed ones (optional)** | `--deny-target`, repeated | none | Targets it must not reach, whatever allows them |
| **listen.tcp** | `--listen-tcp` | `:443` | The gateway's public TCP listener, which also serves the web UI |
| **listen.udp** | `--listen-udp` | `:443` | The gateway's QUIC listener |
| **listen.http, or off** | `--listen-http` | `:80` | Port 80, or `off` |

The built-in connector reaches services on the host itself, such as containers next to rpmgr, but
only the targets its local policy allows, and never rpmgr's own ports. You can allow targets later
with `sudo rpmgr policy allow-target <target>`
([The local policy](../connectors/local-policy.md)).

```sh
sudo rpmgr setup --role all-in-one --public-url https://panel.example.com \
  --acme-email you@example.com --allow-target 127.0.0.1:8080 --yes
```

## Controller

A controller alone serves the web UI, the API and the CA, with gateways on other hosts
([Topologies](topologies.md)). Setup initialises it as `rpmgr controller init` does.

| Form field | Flag | Default | Meaning |
|---|---|---|---|
| **Public URL: …** | `--public-url` | none, required | The address of the web UI, the API and the agents |
| **Where the KEK is kept**, **KEK file** | `--kek-source`, `--kek-path` | as for an all-in-one | As for an all-in-one |
| **Certificate of &lt;host&gt;**, **Certificate chain file**, **Key file** | `--tls`, `--cert-file`, `--key-file` | as for an all-in-one | As for an all-in-one |
| **ACME CA of the instance, …**, **ACME account e-mail address (optional)** | `--acme-directory`, `--acme-email` | as for an all-in-one | As for an all-in-one |
| **listen.https** | `--listen-https` | `:443` | The controller's HTTPS listener |
| **listen.http, or off** | `--listen-http` | `:80` | ACME HTTP-01 and the redirect to HTTPS, or `off` |

A controller has no connector of its own, so it takes no targets.

```sh
sudo rpmgr setup --role controller --public-url https://panel.example.com --yes
```

## Gateway

A gateway takes the public traffic of its group's routes. You create it in the web UI first, with
its tunnel endpoints, and make its gateway token there ([Gateways](../gateways.md)).

| Form field | Flag | Default | Meaning |
|---|---|---|---|
| **Controller URL** | `--controller` | none, required | The controller's `https://<host>[:<port>]` |
| **CA pin, as the controller's init printed it** | `--ca-pin` | none, required | `sha256:<base64>` |
| **Token: the gateway or enrollment token** | `--token-file`, or `RPMGR_ENROLL_TOKEN` | asked | The gateway token, in a hidden field. Never a flag value |
| **listen.tcp**, **listen.udp** | `--listen-tcp`, `--listen-udp` | `:443` | The public listeners |
| **listen.http, or off** | `--listen-http` | `:80` | Port 80, or `off` |

```sh
sudo rpmgr setup --role gateway --controller https://panel.example.com --ca-pin 'sha256:…' --yes
```

With `--yes` and no `--token-file`, setup asks for the token on the terminal.

## Connector

A connector reaches the services of its network ([Concepts](../concepts.md#connector)).

| Form field | Flag | Default | Meaning |
|---|---|---|---|
| **Controller URL** | `--controller` | none, required | The controller's `https://<host>[:<port>]` |
| **CA pin, as the controller's init printed it** | `--ca-pin` | none, required | `sha256:<base64>` |
| **Allowed targets, separated by spaces (optional)** | `--allow-target`, repeated | none | Targets the connector may reach, written to `/etc/rpmgr/policy.yaml` |
| **Denied targets, which win over allowed ones (optional)** | `--deny-target`, repeated | none | Targets it must not reach |
| **Proxy for the connection to the controller (optional)** | `--proxy`, or `--proxy-file` for one with credentials | none | A proxy for the enrollment and the connector's service: `http://`, `socks5://` or `socks5h://`, such as `http://proxy.lan:3128` |
| **Token: the gateway or enrollment token** | `--token-file`, or `RPMGR_ENROLL_TOKEN` | asked | The enrollment token, in a hidden field |

A target is an address or a subnet with an optional port or port range, an IPv6 address in
brackets, or a socket path: `10.0.0.5:5432`, `10.0.0.0/16` (all ports), `127.0.0.1:200-500`,
`[fd00::1]:443` or `/run/app.sock`.

**The proxy.** Give an `http://`, `socks5://` or `socks5h://` URL, the kinds the connector reads;
setup refuses any other. Setup enrolls through the proxy, so a host whose only way out is the proxy
can be set up with it. The connector's service then reads it as `HTTPS_PROXY` from
`/etc/rpmgr/connector-proxy.env`, a file only root reads, which the drop-in
`/etc/systemd/system/rpmgr-connector.service.d/proxy.conf` names: a proxy password never shows in
the unit or in `systemctl show`, and the plan shows the URL without its user name and password. The
connector sends its TLS data sessions through the proxy, and through an `http://` proxy its control
session too; QUIC goes direct, or the connector falls back to TLS
([Connector networking](../connectors/network.md)).

```sh
sudo rpmgr setup --role connector --controller https://panel.example.com --ca-pin 'sha256:…' \
  --allow-target 192.168.1.20:8080 --proxy http://proxy.lan:3128
```

A proxy URL with a user name or password is a secret, which a command line shows to every user of
the host. `--proxy` refuses it: type it in the form, or put it in a file only you read and give
`--proxy-file`, which warns of a file other users may read:

```sh
sudo install -m 0600 /dev/null /root/proxy-url
sudoedit /root/proxy-url      # one line: http://user:password@proxy.lan:3128
sudo rpmgr setup --role connector --controller https://panel.example.com --ca-pin 'sha256:…' \
  --proxy-file /root/proxy-url --yes
```

Characters the environment file would read differently, such as a space, a quote, a backslash or
a letter outside ASCII, must be percent-encoded (`%20`, `%22`, `%5C`); setup refuses them as they
are. Without a proxy, setup enrolls through the `HTTPS_PROXY` of its own environment, as
`rpmgr enroll` does, and gives the service no proxy; a proxy an earlier run gave stays until you
remove `/etc/rpmgr/connector-proxy.env` and its drop-in.

## What setup does

The plan's steps, in order; setup leaves out those it does not need:

1. **Creates the system user `rpmgr`,** `/etc/rpmgr` (root, 0755) and `/var/lib/rpmgr` (`rpmgr`,
   0750), if they are missing, whatever the umask.
2. **Makes a self-signed certificate** in `/etc/rpmgr/tls/<host>.crt` and `<host>.key`, for
   `--tls self-signed` on a public name, unless an earlier run made one.
3. **Writes the boot file and initialises,** on an all-in-one or controller. The boot file is
   `/etc/rpmgr/<role>.yaml`; with `--force`, setup replaces it and keeps the old one as
   `<file>.before-setup`. Initialising makes the KEK, the database, the trust domain and the CA,
   and for an all-in-one its built-in gateway and connector.
   **Or enrolls, then writes the boot file,** on a gateway or connector. Setup gives the identity to
   the user `rpmgr`, then writes the boot file as above.
4. **Writes the local policy** of a connector or all-in-one: the denied targets, then the allowed
   ones.
5. **Writes the proxy** of a connector with `--proxy` or `--proxy-file`:
   `/etc/rpmgr/connector-proxy.env` (root, 0600), replacing an earlier one, and the drop-in that
   names it.
6. **Sets the instance's ACME directory and e-mail address,** if you gave either, before the first
   start, so that the first certificate comes from that CA.
7. **Installs the updater:** records the role for the updater in `/var/lib/rpmgr-update/`, beside
   the roles recorded already, and, unless `--no-unit`, writes and enables its units
   `rpmgr-update.path` and `rpmgr-update.service`
   ([10](../../10-operations.md#hardened-systemd-units)). The updater's floor and release number
   stay as an install script wrote them; on a host without them, setup starts them at the
   binary's own version, so that no older release is ever installed. A controller or all-in-one
   is always upgraded by hand ([Upgrades](upgrades.md)).
8. **Installs the unit** `/etc/systemd/system/rpmgr-<role>.service` and runs
   `systemctl daemon-reload` and `systemctl enable --now rpmgr-<role>`; on a second run with
   `--force` also `systemctl restart`, so the role reads its new boot file.
9. **Waits until** the admin listener's `/readyz` reports ready. If it does not, setup names
   `journalctl -u rpmgr-<role>`, which says why.

## What setup prints

An all-in-one or controller (abbreviated; `…` marks values that differ on your host):

```text
rpmgr all-in-one is set up and runs as rpmgr-all-in-one.

  trust domain: rpmgr-…
  CA pin:       sha256:…
  gateway:      gw_…
  connector:    con_…
  KEK:          new systemd credential /etc/rpmgr/credstore/rpmgr-kek
Back up the KEK separately: without it the database cannot be read.

Create the first user, Instance Admin and Owner, with this one-time link (valid …):
  https://panel.example.com/setup#…

Next: create the first user with the link, then set up each connector on another network with its enrollment token:
  rpmgr setup --role connector --controller https://panel.example.com --ca-pin sha256:…
Services on this host go through the all-in-one's own connector: allow them with rpmgr policy allow-target <target>.
```

- **The CA pin** goes into every gateway's and connector's install command. You can look it up
  again under **Settings → PKI**.
- **The KEK** line says where the key-encryption key is. Back it up now, apart from the database
  backups ([Backup and restore](../operations/backup-and-restore.md#back-up-the-kek)).
- **The link** creates the first account. It works once and expires
  ([04](../../04-security.md#human-authentication-and-sessions)). While no account exists,
  `sudo rpmgr user reset-password` prints a new one.

A gateway or connector:

```text
rpmgr connector is set up and runs as rpmgr-connector: enrolled as connector con_….
Next: check it with rpmgr status; allow more targets with rpmgr policy allow-target <target>.
```

## Run setup again

- **To change a value,** edit the boot file and restart the role
  ([Boot files](../reference/boot-files.md)).
- **On a gateway or connector,** `--force` enrolls the host again with a new token. It replaces the
  boot file, keeps the old one as `<file>.before-setup` and restarts the role
  ([Enrolling connectors](../connectors/enroll.md)).
- **On a controller or all-in-one,** setup refuses, with `--force` or without: it never initialises
  a host whose `/var/lib/rpmgr/controller.db` exists.

## If setup fails

Setup stops at the first step that fails, names it, and lists what it had created:

```text
setup stopped. It had created: /var/lib/rpmgr/identity, /etc/rpmgr/connector.yaml
Remove them, or fix the cause and run setup again with --force where it applies.
```

- **The initialisation or enrollment failed:** fix the cause, remove what setup lists, and run it
  again. Setup never initialises a host that has a controller database, so
  `/var/lib/rpmgr/controller.db` must go if setup lists it.
- **Only the last step failed,** `wait until … /readyz reports ready`: the role is installed and
  runs, but is not ready. The journal says why; fix the cause and restart the service, without
  running setup again:

  ```sh
  sudo journalctl -u rpmgr-all-in-one -n 50
  sudo systemctl restart rpmgr-all-in-one
  ```

The [Troubleshooting](../operations/troubleshooting.md) page covers the common causes.
