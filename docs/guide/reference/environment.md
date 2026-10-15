# Environment variables

rpmgr is configured by its boot files and by the settings in the controller's database, not by
the environment. A few environment variables still matter: the path of a boot file, tokens that
must not appear on a command line, proxies, the KEK that systemd passes to the controller, and the
download source of the install script. This page lists every variable that rpmgr and its install
scripts read, and what each one does. Read it when you script an installation, run rpmgr behind a
proxy or debug why a variable seems to have no effect.

No variable ever holds the KEK: a KEK comes from a systemd credential or a file
([04](../../04-security.md#secrets-at-rest-and-in-logs)). Secrets that a variable may hold, such
as an enrollment token, are never written to a log.

## Overview

| Variable | Read by | What it does |
|---|---|---|
| [`RPMGR_CONFIG`](#rpmgr_config) | Role commands and administration commands | The boot file, when `--config` is not given |
| [`RPMGR_ENROLL_TOKEN`](#rpmgr_enroll_token) | `rpmgr enroll`, `rpmgr setup`, the controller's `/install.sh` | The enrollment or gateway token, when `--token-file` is not given |
| [`RPMGR_TOKEN`](#rpmgr_token) | `rpmgr login` | The personal API token, when `--token-file` is not given |
| [`RPMGR_CREDENTIALS`](#rpmgr_credentials) | `rpmgr login`, `logout` and every API command | Where the command line keeps its stored token |
| [`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`](#proxies) | Connector, gateway, controller, `rpmgr enroll`, `rpmgr setup`, the command line | Outbound connections through a proxy |
| [`CREDENTIALS_DIRECTORY`](#credentials_directory) | Controller, all-in-one | Where systemd put the KEK credential |
| [`RPMGR_INSTALL_GITHUB`, `RPMGR_INSTALL_API`](#rpmgr_install_github-and-rpmgr_install_api) | The global install script | Where the script downloads releases from |
| [`QUIC_GO_DISABLE_GSO`, `QUIC_GO_DISABLE_ECN`, `QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING`](#quic-library-variables) | Gateway, connector | Switches of the QUIC library, for diagnosis |
| [`XDG_CONFIG_HOME`, `HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`](#variables-of-the-go-standard-library) | The command line, `rpmgr enroll`, the controller | Standard paths and trusted CAs |

**Under sudo.** `sudo` resets the environment by default, so a variable you set in your shell does
not reach a command you run with `sudo`. Pass it explicitly, for example
`sudo --preserve-env=RPMGR_ENROLL_TOKEN rpmgr enroll …`, or
`sudo env HTTPS_PROXY=http://proxy.lan:3128 rpmgr setup …`.

**For a service.** A service started by systemd sees only the variables of its unit. Set one with
a drop-in, for example `sudo systemctl edit rpmgr-connector`:

```ini
[Service]
Environment="HTTPS_PROXY=http://proxy.lan:3128"
```

Then `sudo systemctl restart rpmgr-connector`. Never put a secret in `Environment=`: the units take
none.

## RPMGR_CONFIG

The path of the boot file. Every command that reads a boot file takes it from its `--config` flag,
else from `RPMGR_CONFIG`, else from its default path:

- **Role commands:** `rpmgr controller`, `gateway`, `connector` and `all-in-one`, and
  `rpmgr controller init` and `rpmgr all-in-one init`, read `/etc/rpmgr/<role>.yaml`.
- **Agent-host commands:** `rpmgr status`, `rpmgr diag` and `rpmgr leave` read
  `/etc/rpmgr/connector.yaml`, else `/etc/rpmgr/gateway.yaml`.
- **Controller-host commands:** `rpmgr backup`, `restore`, `migrate`, `release import`,
  `user reset-password`, `ca …` and `kek …` read `/etc/rpmgr/controller.yaml`, else
  `/etc/rpmgr/all-in-one.yaml`.
- **`rpmgr systemd-unit controller` and `all-in-one`** read the boot file to find the KEK
  credential the unit loads.

`rpmgr setup` does not read it: it always writes `/etc/rpmgr/<role>.yaml`. The systemd units pass
`--config /etc/rpmgr/<role>.yaml`, so `RPMGR_CONFIG` has no effect on them. Because one variable
serves every role, do not set it for a whole host that runs more than one role
([Boot files](boot-files.md)).

## RPMGR_ENROLL_TOKEN

The single-use token that enrolls a gateway or a connector. A token is never accepted as a
command-line argument, which other users of the host could read. `rpmgr enroll` and
`rpmgr setup --role gateway|connector` take it, in this order, from:

1. the file that `--token-file` names (mode 0600, delete it afterwards; a file other users can read
   is used with a warning);
2. `RPMGR_ENROLL_TOKEN`;
3. a prompt on the terminal, with echo off.

The controller's `/install.sh` passes its environment on to `rpmgr enroll`, so the variable works
there too:

```sh
read -rs RPMGR_ENROLL_TOKEN && export RPMGR_ENROLL_TOKEN   # paste the token, then Enter
curl -fsSLO 'https://panel.example.com/install.sh'
sudo --preserve-env=RPMGR_ENROLL_TOKEN sh install.sh \
  --controller 'https://panel.example.com' --ca-pin 'sha256:…'
```

See [Enrolling connectors](../connectors/enroll.md) for the tokens themselves.

## RPMGR_TOKEN

A personal API token for `rpmgr login`, which checks it and stores it for the commands of the
public API. `rpmgr login` takes the token from `--token-file`, else from `RPMGR_TOKEN`, else from a
prompt. Only `rpmgr login` reads the variable; the other commands use the stored token
([API tokens and the command line](../accounts/api-tokens-and-cli.md)).

## RPMGR_CREDENTIALS

The file in which `rpmgr login` stores the controller URL, the organisation, the token and the CA
file, and which `rpmgr logout` and every API command read. The default is
`rpmgr/credentials.yaml` in your configuration directory: `$XDG_CONFIG_HOME/rpmgr/credentials.yaml`,
or `~/.config/rpmgr/credentials.yaml` when `XDG_CONFIG_HOME` is not set. The file holds the token,
so it is written readable by you only, and a file that other users can read or write is refused.

Set `RPMGR_CREDENTIALS` to keep several logins apart, for example one per organisation:

```sh
RPMGR_CREDENTIALS=~/.config/rpmgr/lab.yaml rpmgr list route
```

## Proxies

rpmgr reads the usual proxy variables. Each is also read in lower case (`https_proxy`), and the
upper-case one wins. Which variable applies depends on the connection:

| Connection | Variables | Proxy kinds |
|---|---|---|
| A connector's TCP data sessions to its gateways (TLS and HTTP/2) | `HTTPS_PROXY`, else `ALL_PROXY`; `NO_PROXY` | `http://` (HTTP CONNECT), `socks5://`, `socks5h://`, with optional `user:password@` |
| A gateway's or connector's control session to the controller, and `rpmgr enroll` (also within `rpmgr setup`) | `HTTPS_PROXY`; `NO_PROXY` | `http://` (HTTP CONNECT) |
| The controller's requests to the ACME CA and to GitHub for the release check | `HTTPS_PROXY`; `NO_PROXY` | `http://`, `https://`, `socks5://` |
| The controller's check of a domain's HTTP token, which is an `http://` URL | `HTTP_PROXY`; `NO_PROXY` | `http://`, `https://`, `socks5://` |
| The controller's connection to the mail relay (SMTP) | `ALL_PROXY`; `NO_PROXY` | `socks5://`, `socks5h://` |
| The command line's requests to the controller | `HTTPS_PROXY`; `NO_PROXY` | `http://`, `https://`, `socks5://` |

- **QUIC is never proxied.** A connector's QUIC data sessions go straight to the gateways over UDP.
  Where only a proxy leads out, the connector falls back to TLS and HTTP/2 through the proxy, and
  when no controller endpoint answers, it carries its control session through a data session
  ([Connector networking](../connectors/network.md)).
- **A connector refuses a proxy URL it cannot use.** If `HTTPS_PROXY` or `ALL_PROXY` is not an
  `http://`, `socks5://` or `socks5h://` URL with a host, the connector does not start, and says
  which variable is wrong without repeating its value.
- **`rpmgr setup --role connector --proxy <url>`** writes the proxy into the drop-in
  `/etc/systemd/system/rpmgr-connector.service.d/proxy.conf` as `HTTPS_PROXY`. The enrollment that
  setup runs uses setup's own environment, so on a network where only the proxy leads out, run
  setup with the variable as well
  ([Set up a host with rpmgr setup](../install/setup.md#connector)):

  ```sh
  sudo env HTTPS_PROXY=http://proxy.lan:3128 rpmgr setup --role connector \
    --proxy http://proxy.lan:3128 …
  ```
- **`ALL_PROXY` does not reach the controller's HTTPS requests.** The controller's requests to the
  ACME CA, to GitHub and to a domain's HTTP token follow `HTTPS_PROXY` and `HTTP_PROXY` only.
- **The install scripts** download with `curl` (or `wget`, for the global script), which read
  their own proxy variables.

## CREDENTIALS_DIRECTORY

Set by systemd for a service whose unit loads a credential with `LoadCredentialEncrypted=`. A
controller or all-in-one whose boot file has `kek.source: systemd-credential` reads its KEK from
the file `<kek.name>` in that directory. You do not set it yourself.

A command run outside the unit has no such directory, so a command that needs the KEK, such as
`rpmgr kek rotate` or `rpmgr ca rotate-intermediate`, runs under `systemd-run`, which loads the
credential for it ([10](../../10-operations.md#rotate-the-kek)):

```sh
sudo systemd-run --pipe --wait \
  --property=LoadCredentialEncrypted=rpmgr-kek:/etc/rpmgr/credstore/rpmgr-kek \
  /usr/local/bin/rpmgr ca rotate-intermediate
```

## RPMGR_INSTALL_GITHUB and RPMGR_INSTALL_API

Read by the global install script only ([The install scripts](../install/install-script.md)). They
replace the sources it downloads from, for a mirror of the GitHub releases inside your network:

| Variable | Default | Used for |
|---|---|---|
| `RPMGR_INSTALL_GITHUB` | `https://github.com` | The release files, from `<value>/felix-homelab/rpmgr/releases/download/v<version>/<file>` |
| `RPMGR_INSTALL_API` | `https://api.github.com` | Finding the latest release, from `<value>/repos/felix-homelab/rpmgr/releases/latest`, or with `--prerelease` from `<value>/repos/felix-homelab/rpmgr/releases?per_page=20` |

Both must be `https://` URLs. A mirror changes nothing in the verification: the script still
checks every file against the release root keys it embeds. With `--version`, the script asks the
API nothing, so a mirror of the release files alone is enough:

```sh
sudo env RPMGR_INSTALL_GITHUB=https://mirror.lan sh install.sh --version 0.1.0
```

## QUIC library variables

The gateways and connectors use the QUIC library quic-go, which reads these variables. rpmgr sets
none of them. They help to rule out a problem of the host's network stack.

| Variable | Effect |
|---|---|
| `QUIC_GO_DISABLE_GSO=true` | Sends without UDP generic segmentation offload (GSO). rpmgr reads it too, so the metric `rpmgr_quic_gso_enabled` and `rpmgr diag transport` report GSO as off |
| `QUIC_GO_DISABLE_ECN=true` | Turns off explicit congestion notification (ECN) on the QUIC sockets |
| `QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING=true` | Silences the library's warning about a UDP buffer below what it asks for. The metric `rpmgr_quic_udp_buffer_warning` still reports it |

Set them for a service with a drop-in, as above. A UDP buffer that is too small is fixed with the
host tuning, not by silencing the warning
([03](../../03-connections.md#host-tuning-applied-by-the-installer)).

## Variables of the Go standard library

rpmgr is a Go program, so the Go standard library reads a few variables on its behalf:

- **`XDG_CONFIG_HOME`, `HOME`:** the configuration directory of the command line's stored token
  ([`RPMGR_CREDENTIALS`](#rpmgr_credentials)).
- **`SSL_CERT_FILE`, `SSL_CERT_DIR`:** the CAs the system trusts. They apply where rpmgr verifies a
  certificate against the system's CAs: the controller's certificate when `rpmgr enroll` downloads
  the trust bundle and when the command line talks to the controller without `--ca-file`, and the
  certificates of the ACME CA and GitHub that the controller reaches. They never apply to the
  connections between controller, gateways and connectors, which trust only the installation's
  pinned root ([04](../../04-security.md#join-command)).

## Variables of the test suite

Variables whose names start with `RPMGR_TEST_` belong to rpmgr's tests and to `rpmgrtest` builds,
which release builds refuse ([D60](../../14-open-decisions.md#security-defaults)). A release binary
does not read them.
