# Command-line reference

This page lists every command of the `rpmgr` binary with its synopsis and its flags. It is
for you when you need the exact name of a command or a flag; the task pages of this guide explain
when and why to use them.

<!-- Generated from the command tree in cmd/rpmgr by TestCLIReference. Do not edit by hand. -->

## How to read this page

- Each section below is one command, in the order of the command tree. A command that only
  groups others lists them and has no flags of its own.
- The synopsis shows the command path, `<command>` where a sub-command follows,
  `[flags]` when the command has flags, and the positional arguments.
- Flags may stand before or after the name, the ID or the kind:
  `rpmgr get -o yaml route web` and `rpmgr get route web -o yaml` do the same.
  After `--` every argument is positional, also one that begins with `-`, such
  as a directory named `-new`: `rpmgr release import -- -new`.
- A flag is written `--name`, or `-o` for a one-letter flag, followed by the kind
  of value it takes. A flag without a kind is a switch: `--all` turns it on. A flag that
  may be repeated says so in its description.
- The default column is empty where the default is empty, zero or `false`.
- A command marked *not available in this build* exists in the tree but exits with code 2.
- On a host, `rpmgr <command> --help` and `rpmgr help <command>` print a
  command's summary, sub-commands and flags as well.

Exit codes, the conventions every command follows and the design notes are in
[16](../../16-cli.md). The task pages show the commands in use, for example
[API tokens and the command line](../accounts/api-tokens-and-cli.md),
[rpmgr setup](../install/setup.md), [Enrolling connectors](../connectors/enroll.md),
[The local policy](../connectors/local-policy.md) and
[Status and diagnostics](../connectors/status-and-diagnostics.md).

## How this page is generated

This page is generated from the command tree in `cmd/rpmgr`. The test
`TestCLIReference` fails when the page and the tree differ. After changing a command,
regenerate the page from the repository root and commit it with the change:

```sh
go test ./cmd/rpmgr -run TestCLIReference -update
```

## rpmgr

Publish services on private networks through public gateways.

```text
rpmgr <command>
```

| Command | What it does |
|---|---|
| [`rpmgr controller`](#rpmgr-controller) | Run the controller: web UI, API, CA and configuration |
| [`rpmgr gateway`](#rpmgr-gateway) | Run a gateway: public listeners and data sessions from connectors |
| [`rpmgr connector`](#rpmgr-connector) | Run a connector: data sessions to gateways and the local targets |
| [`rpmgr all-in-one`](#rpmgr-all-in-one) | Run a controller, a gateway and a connector in one process |
| [`rpmgr setup`](#rpmgr-setup) | Set this host up for a role: boot file, init or enrollment, systemd unit |
| [`rpmgr enroll`](#rpmgr-enroll) | Enroll this host as an agent with a single-use token |
| [`rpmgr login`](#rpmgr-login) | Store a personal API token for the commands of the public API |
| [`rpmgr logout`](#rpmgr-logout) | Remove the stored API token from this machine |
| [`rpmgr leave`](#rpmgr-leave) | Revoke this agent's identity and remove it from the host |
| [`rpmgr status`](#rpmgr-status) | Show the state of the agents on this host |
| [`rpmgr diag`](#rpmgr-diag) | Diagnose this host |
| [`rpmgr policy`](#rpmgr-policy) | Show or change the connector-local policy of this host |
| [`rpmgr updater`](#rpmgr-updater) | The root-owned updater of a Linux host |
| [`rpmgr backup`](#rpmgr-backup) | Write a consistent backup of the controller |
| [`rpmgr restore`](#rpmgr-restore) | Restore the controller from a backup |
| [`rpmgr migrate`](#rpmgr-migrate) | Apply database migrations |
| [`rpmgr ca`](#rpmgr-ca) | Administer the internal CA on the controller host |
| [`rpmgr kek`](#rpmgr-kek) | Administer the key-encryption key on the controller host |
| [`rpmgr user`](#rpmgr-user) | Administer users on the controller host |
| [`rpmgr release`](#rpmgr-release) | Administer release artifacts on the controller host |
| [`rpmgr systemd-unit`](#rpmgr-systemd-unit) | Print the hardened systemd unit of a role |
| [`rpmgr version`](#rpmgr-version) | Print the version of this binary |
| [`rpmgr get`](#rpmgr-get) | Show a resource of the public API, the settings, or the install command of an agent |
| [`rpmgr list`](#rpmgr-list) | List the resources of a kind in the org, or of the instance |
| [`rpmgr delete`](#rpmgr-delete) | Delete a resource of the public API |
| [`rpmgr create`](#rpmgr-create) | Create a resource of the public API |
| [`rpmgr update`](#rpmgr-update) | Change a resource of the public API |
| [`rpmgr enable`](#rpmgr-enable) | Serve a resource again |
| [`rpmgr disable`](#rpmgr-disable) | Stop serving a resource, keeping its configuration |
| [`rpmgr drain`](#rpmgr-drain) | Stop a gateway taking new connections |
| [`rpmgr decommission`](#rpmgr-decommission) | Take an agent out of service for good |
| [`rpmgr revoke`](#rpmgr-revoke) | Revoke a credential |
| [`rpmgr set`](#rpmgr-set) | Set an org's limit |
| [`rpmgr preview`](#rpmgr-preview) | Show what a change would do, saving nothing |
| [`rpmgr verify`](#rpmgr-verify) | Check a proof now |
| [`rpmgr check`](#rpmgr-check) | Check for new releases now |
| [`rpmgr trust`](#rpmgr-trust) | Trust something without a proof |
| [`rpmgr upload`](#rpmgr-upload) | Upload a file to the controller |
| [`rpmgr renew`](#rpmgr-renew) | Renew a certificate now |
| [`rpmgr remove`](#rpmgr-remove) | Remove a member from the org, or a user's second factor |
| [`rpmgr advance`](#rpmgr-advance) | Move a rollout to its next stage |
| [`rpmgr pause`](#rpmgr-pause) | Pause a rollout |
| [`rpmgr resume`](#rpmgr-resume) | Let a paused rollout run again |
| [`rpmgr cancel`](#rpmgr-cancel) | End a rollout for good |
| [`rpmgr upgrade`](#rpmgr-upgrade) | Update agents to the controller's version |

## rpmgr controller

Run the controller: web UI, API, CA and configuration.

```text
rpmgr controller [flags]
rpmgr controller <command>
```

| Command | What it does |
|---|---|
| [`rpmgr controller init`](#rpmgr-controller-init) | Initialise a controller: boot file, KEK, database, trust domain and CA |

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | boot file (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml) |

## rpmgr controller init

Initialise a controller: boot file, KEK, database, trust domain and CA.

```text
rpmgr controller init [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | boot file, written if it does not exist (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml) |
| `--kek-path string` |  | KEK file of a new boot file with --kek-source file (default /etc/rpmgr/kek) |
| `--kek-source string` |  | KEK source of a new boot file: systemd-credential or file (default systemd-credential from systemd 250, else file) |
| `--public-url string` |  | https URL of the web UI and API; needed when the boot file does not exist |

## rpmgr gateway

Run a gateway: public listeners and data sessions from connectors.

```text
rpmgr gateway [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | boot file (default $RPMGR_CONFIG, else /etc/rpmgr/gateway.yaml) |

## rpmgr connector

Run a connector: data sessions to gateways and the local targets.

```text
rpmgr connector [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | boot file (default $RPMGR_CONFIG, else /etc/rpmgr/connector.yaml) |

## rpmgr all-in-one

Run a controller, a gateway and a connector in one process.

```text
rpmgr all-in-one [flags]
rpmgr all-in-one <command>
```

| Command | What it does |
|---|---|
| [`rpmgr all-in-one init`](#rpmgr-all-in-one-init) | Initialise an all-in-one installation: controller, CA and its enrolled gateway and connector |

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | boot file (default $RPMGR_CONFIG, else /etc/rpmgr/all-in-one.yaml) |

## rpmgr all-in-one init

Initialise an all-in-one installation: controller, CA and its enrolled gateway and connector.

```text
rpmgr all-in-one init [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | boot file, written if it does not exist (default $RPMGR_CONFIG, else /etc/rpmgr/all-in-one.yaml) |
| `--kek-path string` |  | KEK file of a new boot file with --kek-source file (default /etc/rpmgr/kek) |
| `--kek-source string` |  | KEK source of a new boot file: systemd-credential or file (default systemd-credential from systemd 250, else file) |
| `--public-url string` |  | https URL of the web UI, the API and the agents; needed when the boot file does not exist |

## rpmgr setup

Set this host up for a role: boot file, init or enrollment, systemd unit.

```text
rpmgr setup [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--acme-directory string` |  | controller, all-in-one: the instance's ACME CA for the public URL and the routes: production, staging or a directory URL (default production) |
| `--acme-email string` |  | controller, all-in-one: the instance's ACME account e-mail address |
| `--allow-target value` |  | connector: a target the connector-local policy allows: an address or subnet, optionally :port or :port-port, IPv6 in brackets, or a socket path; repeat for more |
| `--ca-pin string` |  | gateway, connector: the controller's CA pin, sha256:\<base64> |
| `--cert-file string` |  | controller, all-in-one: the certificate chain with --tls files |
| `--controller string` |  | gateway, connector: the controller URL, https://\<host>[:\<port>] |
| `--deny-target value` |  | connector: a target the connector-local policy denies, whatever allows it; the same form |
| `--force` |  | replace an existing boot file (kept beside it) or an agent's identity |
| `--kek-path string` |  | controller, all-in-one: the KEK file with --kek-source file (default /etc/rpmgr/kek) |
| `--kek-source string` |  | controller, all-in-one: systemd-credential or file (default by the systemd version) |
| `--key-file string` |  | controller, all-in-one: its key with --tls files |
| `--listen-admin string` |  | listen.admin (default the role's 127.0.0.1 port) |
| `--listen-http string` |  | controller, all-in-one, gateway: listen.http, or off (default :80) |
| `--listen-https string` |  | controller: listen.https (default :443) |
| `--listen-tcp string` |  | all-in-one, gateway: listen.tcp (default :443) |
| `--listen-udp string` |  | all-in-one, gateway: listen.udp (default :443) |
| `--no-unit` |  | install no systemd unit and start nothing |
| `--proxy string` |  | connector: the proxy of its enrollment and its service, http://, socks5:// or socks5h://, without credentials |
| `--proxy-file string` |  | connector: file with the proxy URL instead of --proxy, for one with a user name or password |
| `--public-url string` |  | controller, all-in-one: https URL of the web UI, the API and the agents |
| `--role string` |  | all-in-one, controller, gateway or connector (required with --yes) |
| `--tls string` |  | controller, all-in-one: the public URL's certificate: acme, files or self-signed (default acme for a public name, else self-signed) |
| `--token-file string` |  | gateway, connector: file with the gateway or enrollment token (default $RPMGR_ENROLL_TOKEN, else a prompt) |
| `--yes` |  | ask nothing: take every value from the flags and run the plan |

## rpmgr enroll

Enroll this host as an agent with a single-use token.

```text
rpmgr enroll [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--ca-pin string` |  | pin of the controller's root CA, sha256:\<base64> (required) |
| `--controller string` |  | controller URL, https://\<host>[:\<port>] (required) |
| `--identity-dir string` | `/var/lib/rpmgr/identity` | where the identity is written |
| `--replace` |  | replace an existing identity on this host |
| `--token-file string` |  | file with the enrollment token (default $RPMGR_ENROLL_TOKEN, else a prompt) |
| `--trust-bundle string` |  | PEM trust bundle to use instead of downloading it |

## rpmgr login

Store a personal API token for the commands of the public API.

```text
rpmgr login [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--ca-file string` |  | PEM certificates that verify the controller instead of the system's roots |
| `--controller string` |  | the controller's URL, e.g. https://panel.example.com |
| `--org string` |  | the ID of the token's org |
| `--token-file string` |  | file holding the token (default $RPMGR_TOKEN, else a prompt) |

## rpmgr logout

Remove the stored API token from this machine.

```text
rpmgr logout
```

## rpmgr leave

Revoke this agent's identity and remove it from the host.

```text
rpmgr leave [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the connector's, gateway's or all-in-one's boot file (default $RPMGR_CONFIG, else /etc/rpmgr/connector.yaml, else /etc/rpmgr/gateway.yaml, else /etc/rpmgr/all-in-one.yaml) |

## rpmgr status

Show the state of the agents on this host.

```text
rpmgr status [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the connector's, gateway's or all-in-one's boot file (default $RPMGR_CONFIG, else /etc/rpmgr/connector.yaml, else /etc/rpmgr/gateway.yaml, else /etc/rpmgr/all-in-one.yaml) |

## rpmgr diag

Diagnose this host.

```text
rpmgr diag <command>
```

| Command | What it does |
|---|---|
| [`rpmgr diag transport`](#rpmgr-diag-transport) | Test the data-session transports to a gateway |
| [`rpmgr diag clock`](#rpmgr-diag-clock) | Compare this host's clock with the controller's |

## rpmgr diag transport

Test the data-session transports to a gateway.

```text
rpmgr diag transport [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the connector's, gateway's or all-in-one's boot file (default $RPMGR_CONFIG, else /etc/rpmgr/connector.yaml, else /etc/rpmgr/gateway.yaml, else /etc/rpmgr/all-in-one.yaml) |
| `--gateway string` |  | the gateway's ID (default every gateway of the connector's configuration) |

## rpmgr diag clock

Compare this host's clock with the controller's.

```text
rpmgr diag clock [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the connector's, gateway's or all-in-one's boot file (default $RPMGR_CONFIG, else /etc/rpmgr/connector.yaml, else /etc/rpmgr/gateway.yaml, else /etc/rpmgr/all-in-one.yaml) |

## rpmgr policy

Show or change the connector-local policy of this host.

```text
rpmgr policy <command>
```

| Command | What it does |
|---|---|
| [`rpmgr policy show`](#rpmgr-policy-show) | Print the effective local policy |
| [`rpmgr policy allow-target`](#rpmgr-policy-allow-target) | Allow the connector to dial a target; without a port, all its ports |
| [`rpmgr policy remove-target`](#rpmgr-policy-remove-target) | Stop allowing a target |
| [`rpmgr policy deny-target`](#rpmgr-policy-deny-target) | Deny a target, whatever allows it |
| [`rpmgr policy remove-deny-target`](#rpmgr-policy-remove-deny-target) | Stop denying a target |
| [`rpmgr policy set-auto-update`](#rpmgr-policy-set-auto-update) | Set whether this host takes over-the-air updates: auto, notify (only report them) or off |
| [`rpmgr policy set-update-channel`](#rpmgr-policy-set-update-channel) | Set which releases this host takes: stable, or prerelease for betas and release candidates too |

## rpmgr policy show

Print the effective local policy.

```text
rpmgr policy show [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--file string` | `/etc/rpmgr/policy.yaml` | the policy file |

## rpmgr policy allow-target

Allow the connector to dial a target; without a port, all its ports.

```text
rpmgr policy allow-target [flags] <ip or subnet>[:<port or range>] | [<ipv6 or subnet>][:<port or range>] | <socket path>
```

| Flag | Default | Description |
|---|---|---|
| `--file string` | `/etc/rpmgr/policy.yaml` | the policy file |
| `--no-reload` |  | do not ask the running connector to reload the policy |

## rpmgr policy remove-target

Stop allowing a target.

```text
rpmgr policy remove-target [flags] <ip or subnet>[:<port or range>] | [<ipv6 or subnet>][:<port or range>] | <socket path>
```

| Flag | Default | Description |
|---|---|---|
| `--file string` | `/etc/rpmgr/policy.yaml` | the policy file |
| `--no-reload` |  | do not ask the running connector to reload the policy |

## rpmgr policy deny-target

Deny a target, whatever allows it.

```text
rpmgr policy deny-target [flags] <ip or subnet>[:<port or range>] | [<ipv6 or subnet>][:<port or range>] | <socket path>
```

| Flag | Default | Description |
|---|---|---|
| `--file string` | `/etc/rpmgr/policy.yaml` | the policy file |
| `--no-reload` |  | do not ask the running connector to reload the policy |

## rpmgr policy remove-deny-target

Stop denying a target.

```text
rpmgr policy remove-deny-target [flags] <ip or subnet>[:<port or range>] | [<ipv6 or subnet>][:<port or range>] | <socket path>
```

| Flag | Default | Description |
|---|---|---|
| `--file string` | `/etc/rpmgr/policy.yaml` | the policy file |
| `--no-reload` |  | do not ask the running connector to reload the policy |

## rpmgr policy set-auto-update

Set whether this host takes over-the-air updates: auto, notify (only report them) or off.

```text
rpmgr policy set-auto-update [flags] auto | notify | off
```

| Flag | Default | Description |
|---|---|---|
| `--file string` | `/etc/rpmgr/policy.yaml` | the policy file |

## rpmgr policy set-update-channel

Set which releases this host takes: stable, or prerelease for betas and release candidates too.

```text
rpmgr policy set-update-channel [flags] stable | prerelease
```

| Flag | Default | Description |
|---|---|---|
| `--file string` | `/etc/rpmgr/policy.yaml` | the policy file |

## rpmgr updater

The root-owned updater of a Linux host.

```text
rpmgr updater <command>
```

| Command | What it does |
|---|---|
| [`rpmgr updater apply`](#rpmgr-updater-apply) | Install the release the agent staged, as root, and roll back if a role is not ready |
| [`rpmgr updater install`](#rpmgr-updater-install) | Record this installation for the updater, raise its floor and seq, and write its units, as root |

## rpmgr updater apply

Install the release the agent staged, as root, and roll back if a role is not ready.

```text
rpmgr updater apply [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--policy string` | `/etc/rpmgr/policy.yaml` | the local policy file |
| `--staged string` | `/var/lib/rpmgr/update` | the directory the agent stages a release in |
| `--state string` | `/var/lib/rpmgr-update` | the updater's own directory: install.json, state.json, staging/ |
| `--status string` | `/run/rpmgr-update/status.json` | where the outcome is written for the agent |

## rpmgr updater install

Record this installation for the updater, raise its floor and seq, and write its units, as root.

```text
rpmgr updater install [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--etc string` | `/etc/rpmgr` | the boot files, whose roles are recorded |
| `--floor string` |  | the installed release's version, the floor, with --seq |
| `--method string` | `script` | how rpmgr was installed |
| `--no-units` |  | write no units, as on a host without systemd |
| `--path string` | `/usr/local/bin/rpmgr` | the installed binary |
| `--role value` |  | a role of this host, besides those recorded and those with a boot file; repeat for more |
| `--seq uint` |  | the seq of the installed release's verified manifest (default: none; a missing state starts at this binary's version) |
| `--state string` | `/var/lib/rpmgr-update` | the updater's own directory: install.json, state.json |
| `--units string` | `/etc/systemd/system` | where the units rpmgr-update.path and rpmgr-update.service go |

## rpmgr backup

Write a consistent backup of the controller.

```text
rpmgr backup [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else /etc/rpmgr/all-in-one.yaml) |
| `--out string` |  | the archive to write; it must not exist (required) |

## rpmgr restore

Restore the controller from a backup.

```text
rpmgr restore [flags]
rpmgr restore <command>
```

| Command | What it does |
|---|---|
| [`rpmgr restore confirm`](#rpmgr-restore-confirm) | End the instance-wide restore review |

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else /etc/rpmgr/all-in-one.yaml) |
| `--in string` |  | the archive of rpmgr backup (required) |
| `--revocation-log value` |  | the revocation-log sink directory, or a replica's revocations.log; repeat for each (default the state directory's revocations.log) |

## rpmgr restore confirm

End the instance-wide restore review.

```text
rpmgr restore confirm [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else /etc/rpmgr/all-in-one.yaml) |
| `--org string` |  | confirm this org's members and roles instead, by ID or slug |

## rpmgr migrate

Apply database migrations.

```text
rpmgr migrate [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else /etc/rpmgr/all-in-one.yaml) |

## rpmgr ca

Administer the internal CA on the controller host.

```text
rpmgr ca <command>
```

| Command | What it does |
|---|---|
| [`rpmgr ca status`](#rpmgr-ca-status) | Show the CA keys and their validity |
| [`rpmgr ca rotate-intermediate`](#rpmgr-ca-rotate-intermediate) | Rotate the issuing intermediate now |

## rpmgr ca status

Show the CA keys and their validity.

```text
rpmgr ca status [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else /etc/rpmgr/all-in-one.yaml) |

## rpmgr ca rotate-intermediate

Rotate the issuing intermediate now.

```text
rpmgr ca rotate-intermediate [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else /etc/rpmgr/all-in-one.yaml) |

## rpmgr kek

Administer the key-encryption key on the controller host.

```text
rpmgr kek <command>
```

| Command | What it does |
|---|---|
| [`rpmgr kek status`](#rpmgr-kek-status) | Show which KEK version wraps the stored secrets |
| [`rpmgr kek rotate`](#rpmgr-kek-rotate) | Re-wrap every stored secret under a new KEK |

## rpmgr kek status

Show which KEK version wraps the stored secrets.

```text
rpmgr kek status [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else /etc/rpmgr/all-in-one.yaml) |

## rpmgr kek rotate

Re-wrap every stored secret under a new KEK.

```text
rpmgr kek rotate [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else /etc/rpmgr/all-in-one.yaml) |
| `--previous-file string` |  | the KEK before, in a file of the format of kek.source file, mode 0600 (required) |

## rpmgr user

Administer users on the controller host.

```text
rpmgr user <command>
```

| Command | What it does |
|---|---|
| [`rpmgr user reset-password`](#rpmgr-user-reset-password) | Create a one-time password-reset link; before the first user exists, a first-user link |

## rpmgr user reset-password

Create a one-time password-reset link; before the first user exists, a first-user link.

```text
rpmgr user reset-password [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else /etc/rpmgr/all-in-one.yaml) |
| `--email string` |  | the user's e-mail address; leave it out to create the first user |

## rpmgr release

Administer release artifacts on the controller host.

```text
rpmgr release <command>
```

| Command | What it does |
|---|---|
| [`rpmgr release import`](#rpmgr-release-import) | Import a signed release for air-gapped installations |

## rpmgr release import

Import a signed release for air-gapped installations.

```text
rpmgr release import [flags] <dir>
```

| Flag | Default | Description |
|---|---|---|
| `--config string` |  | the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else /etc/rpmgr/all-in-one.yaml) |

## rpmgr systemd-unit

Print the hardened systemd unit of a role.

```text
rpmgr systemd-unit [flags] controller | gateway | connector | all-in-one | update
```

| Flag | Default | Description |
|---|---|---|
| `--bin string` |  | the installed binary (default /usr/local/bin/rpmgr; for update, the path install.json records) |
| `--config string` |  | the controller's or all-in-one's boot file, for its KEK credential and revocation-log sink (default $RPMGR_CONFIG, else /etc/rpmgr/\<role>.yaml) |

## rpmgr version

Print the version of this binary.

```text
rpmgr version [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--verbose` |  | also print the variant of this build and the release root keys compiled into it |

## rpmgr get

Show a resource of the public API, the settings, or the install command of an agent.

```text
rpmgr get [flags] install-command | settings | <route|connector|gateway|gateway-group|port-pool|domain|certificate|ca-bundle|route-target|access-policy|rollout> <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--allow-target value` |  | install-command: a target the connector may reach: an address or subnet, optionally :port or :port-port, IPv6 in brackets, or a socket path; repeat for more |
| `--deny-target value` |  | install-command: a target the connector must not reach, whatever allows it; the same form |
| `--instance` |  | settings: the instance's settings, for an Instance Admin, instead of the org's |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--role string` | `connector` | install-command: the role to install, connector or gateway |

## rpmgr list

List the resources of a kind in the org, or of the instance.

```text
rpmgr list [flags] <route|connector|gateway|gateway-group|port-pool|port-quota|domain|certificate|ca-bundle|enrollment-token|access-policy|member|token|release|rollout|rollout-target> [<what they belong to>]
```

| Flag | Default | Description |
|---|---|---|
| `--all` |  | also the decommissioned agents, and the used-up, expired and revoked enrollment tokens |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |

## rpmgr delete

Delete a resource of the public API.

```text
rpmgr delete [flags] <route|gateway-group|port-pool|port-quota|domain|certificate|ca-bundle|route-target|access-policy> <id>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | delete without checking that the resource is unchanged since this command read it |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr create

Create a resource of the public API.

```text
rpmgr create <command>
```

| Command | What it does |
|---|---|
| [`rpmgr create route`](#rpmgr-create-route) | Create a route |
| [`rpmgr create route-target`](#rpmgr-create-route-target) | Add a target to a route |
| [`rpmgr create enrollment-token`](#rpmgr-create-enrollment-token) | Make a token that enrolls connectors; it is shown once |
| [`rpmgr create gateway-group`](#rpmgr-create-gateway-group) | Create a gateway group |
| [`rpmgr create gateway`](#rpmgr-create-gateway) | Create a gateway |
| [`rpmgr create port-pool`](#rpmgr-create-port-pool) | Create a port pool |
| [`rpmgr create gateway-token`](#rpmgr-create-gateway-token) | Make the token that enrolls a gateway; it is shown once |
| [`rpmgr create domain`](#rpmgr-create-domain) | Create a domain |
| [`rpmgr create ca-bundle`](#rpmgr-create-ca-bundle) | Create a ca bundle |
| [`rpmgr create access-policy`](#rpmgr-create-access-policy) | Create an access policy of IP rules, where a deny wins, and basic auth |
| [`rpmgr create invitation`](#rpmgr-create-invitation) | Invite someone to the org and print the one-time link; as Admin or Owner it takes a step-up |
| [`rpmgr create token`](#rpmgr-create-token) | Personal API tokens are made in the web UI |
| [`rpmgr create reset-link`](#rpmgr-create-reset-link) | Print a one-time link that sets a member's password, for one who forgot it; takes a step-up |
| [`rpmgr create rollout`](#rpmgr-create-rollout) | Roll a release out to the connectors and gateways: staged, its canary agents first, or easy, one agent after another |

## rpmgr create route

Create a route.

```text
rpmgr create route [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--bandwidth uint` |  | the route's bytes a second in each direction, shared by the group's gateways; 0 is no limit |
| `--certificate string` |  | http: the uploaded certificate's ID, with --tls-mode certificate |
| `--description string` |  | a description for people |
| `--disabled` |  | the route is not served |
| `--flow-idle-timeout duration` |  | tcp-udp: forget a UDP flow idle this long |
| `--group string` |  | the gateway group, by name or ID |
| `--host-header string` |  | http: the Host header towards the upstream; empty keeps the client's |
| `--hostname value` |  | a hostname of an http or tls-passthrough route; repeat for more |
| `--hsts duration` |  | http: the Strict-Transport-Security max-age; 0 sends none |
| `--http` |  | an http route: TLS ends at the gateway |
| `--idle-timeout duration` |  | tcp, tcp-udp: close a connection idle this long; udp: forget a flow idle this long |
| `--label value` |  | a label key=value; repeat for more |
| `--maintenance` |  | http: answer every request with the maintenance page, 503 |
| `--maintenance-message string` |  | http: plain text the maintenance page shows, at most 500 characters |
| `--max-body uint` |  | http: the largest request body in bytes; 0 is no limit |
| `--max-connections uint` |  | the route's open connections, flows or requests in flight, shared by the group's gateways; 0 is no limit |
| `--name string` |  | the route's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--path-prefix string` |  | http: the path prefix it serves |
| `--policy value` |  | an access policy, by name or ID; repeat for more |
| `--port uint` |  | tcp, udp, tcp-udp: the public port; 0 on create picks a free one |
| `--port80 string` |  | http: what port 80 does: redirect, serve or off |
| `--requests-per-second uint` |  | the route's requests, new connections or new flows a second, shared by the group's gateways; 0 is no limit |
| `--set-request-header value` |  | http: a header Name=value set towards the upstream; repeat for more |
| `--set-response-header value` |  | http: a header Name=value set towards the client; repeat for more |
| `--tcp` |  | a tcp route on a public port |
| `--tcp-udp` |  | a route on one public port number with both TCP and UDP |
| `--tls-mode string` |  | http: acme or certificate |
| `--tls-passthrough` |  | a TLS route the gateway passes through by its SNI |
| `--transport string` |  | the data-session transport: auto, quic or h2; empty is the connector's |
| `--udp` |  | a udp route on a public port |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |
| `--websocket` | `true` | http: whether WebSocket upgrades pass |

## rpmgr create route-target

Add a target to a route.

```text
rpmgr create route-target [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--address string` |  | the target's host:port, as the connector dials it |
| `--ca-bundle string` |  | https: the CA bundle that verifies it, by name or ID; empty is the gateway's roots |
| `--connector string` |  | the connector that dials the target, by name or ID |
| `--disabled` |  | the target gets no streams |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--priority uint` |  | lower first; a higher one gets streams only when no lower one is ready |
| `--proxy-protocol string` |  | tcp, tls_passthrough and tcp_udp: the PROXY header sent first: none, v1 or v2; on a tcp_udp route, on TCP connections only |
| `--route string` |  | the route, by name or ID |
| `--server-name string` |  | https: the name its certificate must carry |
| `--spki string` |  | https: the SHA-256 of its public key, 64 hex digits, checked as well |
| `--unix string` |  | the target's Unix socket on the connector host, instead of --address |
| `--upstream string` |  | what the target speaks: tcp, http, https or h2c |
| `--verification string` |  | https: how its certificate is checked: verified; pinned-key, its --spki only; or unverified, which lets anyone between the connector and the target read and change the traffic |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |
| `--weight uint` |  | its share of the streams among targets of the same priority |

## rpmgr create enrollment-token

Make a token that enrolls connectors; it is shown once.

```text
rpmgr create enrollment-token [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--connector string` |  | re-enroll this connector, by name or ID, with a new key: a single-use token |
| `--ephemeral` |  | the connectors it enrolls are purged 30 minutes after their last disconnect |
| `--gateway-group string` |  | the gateway group it is scoped to, by name or ID |
| `--label value` |  | a label key=value each connector it enrolls gets; repeat for more |
| `--max-uses int` | `1` | how many connectors it enrolls; more than 1, or 0 for unlimited, only with --ephemeral |
| `--ttl duration` | `1h0m0s` | how long it lasts, at most 720h |

## rpmgr create gateway-group

Create a gateway group.

```text
rpmgr create gateway-group [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--name string` |  | the group's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--public-hostname value` |  | a name under which its gateways are reached; repeat for more |
| `--region string` |  | where its gateways are, for people |
| `--trusted-proxy value` |  | a CIDR of a proxy in front of its gateways whose X-Forwarded-For counts; repeat for more |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr create gateway

Create a gateway.

```text
rpmgr create gateway [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--group string` |  | its gateway group, by name or ID |
| `--name string` |  | the gateway's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--tunnel-endpoint value` |  | a host:port at which connectors reach it; repeat for more |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr create port-pool

Create a port pool.

```text
rpmgr create port-pool [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--from string` |  | its first port |
| `--group string` |  | its gateway group, by name or ID |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--protocol string` |  | tcp or udp |
| `--to string` |  | its last port |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr create gateway-token

Make the token that enrolls a gateway; it is shown once.

```text
rpmgr create gateway-token [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--gateway string` |  | the gateway, by name or ID |
| `--ttl duration` | `1h0m0s` | how long it lasts |

## rpmgr create domain

Create a domain.

```text
rpmgr create domain [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--fqdn string` |  | the name to claim, e.g. example.com |
| `--method string` |  | how to prove it: txt (a DNS TXT record, the default) or http (a token the org's gateways serve) |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |
| `--wildcard` |  | claim the names under it as well |

## rpmgr create ca-bundle

Create a ca bundle.

```text
rpmgr create ca-bundle [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--name string` |  | the bundle's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--pem-file string` |  | a file of 1 to 100 PEM certificates, each a trust anchor |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr create access-policy

Create an access policy of IP rules, where a deny wins, and basic auth.

```text
rpmgr create access-policy [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--description string` |  | a description for people |
| `--name string` |  | the policy's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--passwords-file string` |  | a file of user:password lines for the basic-auth users; the others are asked for |
| `--rule value` |  | a rule: allow:\<cidr>,…, deny:\<cidr>,… or basic-auth:\<user>,…; repeat for more; a deny wins over every allow |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr create invitation

Invite someone to the org and print the one-time link; as Admin or Owner it takes a step-up.

```text
rpmgr create invitation [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--email string` |  | the invitee's e-mail address |
| `--role string` | `viewer` | the role: owner, admin, operator or viewer |

## rpmgr create token

Personal API tokens are made in the web UI.

```text
rpmgr create token
```

## rpmgr create reset-link

Print a one-time link that sets a member's password, for one who forgot it; takes a step-up.

```text
rpmgr create reset-link <user ID or e-mail address>
```

## rpmgr create rollout

Roll a release out to the connectors and gateways: staged, its canary agents first, or easy, one agent after another.

```text
rpmgr create rollout [flags] --release <version> (--canary <agent>… | --easy --agent <agent>…)
```

| Flag | Default | Description |
|---|---|---|
| `--agent value` |  | an easy rollout's agent, in the order they update: a connector or gateway of the org by name, or of any org by ID; repeat for more |
| `--canary value` |  | a staged rollout's canary agent: a connector or gateway of the org by name, or of any org by ID; repeat for more |
| `--easy` |  | an easy rollout: the --agent agents update one after another, and a failed one is skipped |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--release string` |  | the release, by version or ID; no newer than the controller |

## rpmgr update

Change a resource of the public API.

```text
rpmgr update <command>
```

| Command | What it does |
|---|---|
| [`rpmgr update route`](#rpmgr-update-route) | Change the fields of a route that the flags name |
| [`rpmgr update route-target`](#rpmgr-update-route-target) | Change the fields of a route target that the flags name |
| [`rpmgr update connector`](#rpmgr-update-connector) | Change a connector's name, labels or transport |
| [`rpmgr update gateway-group`](#rpmgr-update-gateway-group) | Change the fields of a gateway group that the flags name |
| [`rpmgr update gateway`](#rpmgr-update-gateway) | Change the fields of a gateway that the flags name |
| [`rpmgr update port-pool`](#rpmgr-update-port-pool) | Change the fields of a port pool that the flags name |
| [`rpmgr update ca-bundle`](#rpmgr-update-ca-bundle) | Change the fields of a ca bundle that the flags name |
| [`rpmgr update access-policy`](#rpmgr-update-access-policy) | Change an access policy's name, description or rules |
| [`rpmgr update member`](#rpmgr-update-member) | Change a member's role; granting Admin or Owner takes a step-up |
| [`rpmgr update user`](#rpmgr-update-user) | Grant or revoke the Instance Admin role; as Instance Admin, with a step-up |
| [`rpmgr update settings`](#rpmgr-update-settings) | Change the org's settings, or with --instance the instance's |

## rpmgr update route

Change the fields of a route that the flags name.

```text
rpmgr update route [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--bandwidth uint` |  | the route's bytes a second in each direction, shared by the group's gateways; 0 is no limit |
| `--certificate string` |  | http: the uploaded certificate's ID, with --tls-mode certificate |
| `--description string` |  | a description for people |
| `--disabled` |  | the route is not served |
| `--flow-idle-timeout duration` |  | tcp-udp: forget a UDP flow idle this long |
| `--force` |  | update without checking that the route is unchanged since this command read it |
| `--host-header string` |  | http: the Host header towards the upstream; empty keeps the client's |
| `--hostname value` |  | a hostname of an http or tls-passthrough route; repeat for more |
| `--hsts duration` |  | http: the Strict-Transport-Security max-age; 0 sends none |
| `--idle-timeout duration` |  | tcp, tcp-udp: close a connection idle this long; udp: forget a flow idle this long |
| `--label value` |  | a label key=value; repeat for more |
| `--maintenance` |  | http: answer every request with the maintenance page, 503 |
| `--maintenance-message string` |  | http: plain text the maintenance page shows, at most 500 characters |
| `--max-body uint` |  | http: the largest request body in bytes; 0 is no limit |
| `--max-connections uint` |  | the route's open connections, flows or requests in flight, shared by the group's gateways; 0 is no limit |
| `--name string` |  | the route's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--path-prefix string` |  | http: the path prefix it serves |
| `--policy value` |  | an access policy, by name or ID; repeat for more |
| `--port uint` |  | tcp, udp, tcp-udp: the public port; 0 on create picks a free one |
| `--port80 string` |  | http: what port 80 does: redirect, serve or off |
| `--requests-per-second uint` |  | the route's requests, new connections or new flows a second, shared by the group's gateways; 0 is no limit |
| `--set-request-header value` |  | http: a header Name=value set towards the upstream; repeat for more |
| `--set-response-header value` |  | http: a header Name=value set towards the client; repeat for more |
| `--tls-mode string` |  | http: acme or certificate |
| `--transport string` |  | the data-session transport: auto, quic or h2; empty is the connector's |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |
| `--websocket` | `true` | http: whether WebSocket upgrades pass |

## rpmgr update route-target

Change the fields of a route target that the flags name.

```text
rpmgr update route-target [flags] <id>
```

| Flag | Default | Description |
|---|---|---|
| `--address string` |  | the target's host:port, as the connector dials it |
| `--ca-bundle string` |  | https: the CA bundle that verifies it, by name or ID; empty is the gateway's roots |
| `--disabled` |  | the target gets no streams |
| `--force` |  | update without checking that the target is unchanged since this command read it |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--priority uint` |  | lower first; a higher one gets streams only when no lower one is ready |
| `--proxy-protocol string` |  | tcp, tls_passthrough and tcp_udp: the PROXY header sent first: none, v1 or v2; on a tcp_udp route, on TCP connections only |
| `--server-name string` |  | https: the name its certificate must carry |
| `--spki string` |  | https: the SHA-256 of its public key, 64 hex digits, checked as well |
| `--unix string` |  | the target's Unix socket on the connector host, instead of --address |
| `--upstream string` |  | what the target speaks: tcp, http, https or h2c |
| `--verification string` |  | https: how its certificate is checked: verified; pinned-key, its --spki only; or unverified, which lets anyone between the connector and the target read and change the traffic |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |
| `--weight uint` |  | its share of the streams among targets of the same priority |

## rpmgr update connector

Change a connector's name, labels or transport.

```text
rpmgr update connector [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | update without checking that the connector is unchanged since this command read it |
| `--label value` |  | a label key=value; repeat for more; the labels replace the old ones |
| `--name string` |  | the connector's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--transport string` |  | the data-session transport: auto, quic or h2; empty is the instance's |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr update gateway-group

Change the fields of a gateway group that the flags name.

```text
rpmgr update gateway-group [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | update without checking that it is unchanged since this command read it |
| `--name string` |  | the group's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--public-hostname value` |  | a name under which its gateways are reached; repeat for more |
| `--region string` |  | where its gateways are, for people |
| `--trusted-proxy value` |  | a CIDR of a proxy in front of its gateways whose X-Forwarded-For counts; repeat for more |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr update gateway

Change the fields of a gateway that the flags name.

```text
rpmgr update gateway [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | update without checking that it is unchanged since this command read it |
| `--name string` |  | the gateway's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--tunnel-endpoint value` |  | a host:port at which connectors reach it; repeat for more |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr update port-pool

Change the fields of a port pool that the flags name.

```text
rpmgr update port-pool [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | update without checking that it is unchanged since this command read it |
| `--from string` |  | its first port |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--to string` |  | its last port |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr update ca-bundle

Change the fields of a ca bundle that the flags name.

```text
rpmgr update ca-bundle [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | update without checking that it is unchanged since this command read it |
| `--name string` |  | the bundle's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--pem-file string` |  | a file of 1 to 100 PEM certificates, each a trust anchor |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr update access-policy

Change an access policy's name, description or rules.

```text
rpmgr update access-policy [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--description string` |  | a description for people |
| `--force` |  | update without checking that the policy is unchanged since this command read it |
| `--name string` |  | the policy's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--passwords-file string` |  | a file of user:password lines for the basic-auth users; the others are asked for |
| `--rule value` |  | a rule: allow:\<cidr>,…, deny:\<cidr>,… or basic-auth:\<user>,…; repeat for more; a deny wins over every allow |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr update member

Change a member's role; granting Admin or Owner takes a step-up.

```text
rpmgr update member [flags] <user ID or e-mail address>
```

| Flag | Default | Description |
|---|---|---|
| `--role string` |  | the new role: owner, admin, operator or viewer |

## rpmgr update user

Grant or revoke the Instance Admin role; as Instance Admin, with a step-up.

```text
rpmgr update user [flags] <user ID or e-mail address>
```

| Flag | Default | Description |
|---|---|---|
| `--instance-admin` |  | grant the Instance Admin role, or revoke it with --instance-admin=false |

## rpmgr update settings

Change the org's settings, or with --instance the instance's.

```text
rpmgr update settings [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | update without checking that the settings are unchanged since this command read them |
| `--instance` |  | the instance's settings, for an Instance Admin |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--set value` |  | \<setting>=\<value>, a setting as get settings names it; an empty value restores the default; repeat for more |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr enable

Serve a resource again.

```text
rpmgr enable <command>
```

| Command | What it does |
|---|---|
| [`rpmgr enable route`](#rpmgr-enable-route) | Enable a route |
| [`rpmgr enable gateway`](#rpmgr-enable-gateway) | Let a drained gateway take connections again |

## rpmgr enable route

Enable a route.

```text
rpmgr enable route [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | change it without checking that it is unchanged since this command read it |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr enable gateway

Let a drained gateway take connections again.

```text
rpmgr enable gateway [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | change it without checking that it is unchanged since this command read it |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr disable

Stop serving a resource, keeping its configuration.

```text
rpmgr disable <command>
```

| Command | What it does |
|---|---|
| [`rpmgr disable route`](#rpmgr-disable-route) | Disable a route |

## rpmgr disable route

Disable a route.

```text
rpmgr disable route [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | change it without checking that it is unchanged since this command read it |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr drain

Stop a gateway taking new connections.

```text
rpmgr drain <command>
```

| Command | What it does |
|---|---|
| [`rpmgr drain gateway`](#rpmgr-drain-gateway) | Stop a gateway taking new connections, letting the open ones drain |

## rpmgr drain gateway

Stop a gateway taking new connections, letting the open ones drain.

```text
rpmgr drain gateway [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | change it without checking that it is unchanged since this command read it |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr decommission

Take an agent out of service for good.

```text
rpmgr decommission <command>
```

| Command | What it does |
|---|---|
| [`rpmgr decommission connector`](#rpmgr-decommission-connector) | Take a connector out of service for good, revoking its identity |
| [`rpmgr decommission gateway`](#rpmgr-decommission-gateway) | Take a gateway out of service for good, revoking its identity |

## rpmgr decommission connector

Take a connector out of service for good, revoking its identity.

```text
rpmgr decommission connector [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | decommission without checking that the connector is unchanged since this command read it |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |

## rpmgr decommission gateway

Take a gateway out of service for good, revoking its identity.

```text
rpmgr decommission gateway [flags] <id or name>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | decommission without checking that the gateway is unchanged since this command read it |

## rpmgr revoke

Revoke a credential.

```text
rpmgr revoke <command>
```

| Command | What it does |
|---|---|
| [`rpmgr revoke enrollment-token`](#rpmgr-revoke-enrollment-token) | Revoke an enrollment token, so that it enrolls nothing more |
| [`rpmgr revoke token`](#rpmgr-revoke-token) | Revoke one of your personal API tokens |

## rpmgr revoke enrollment-token

Revoke an enrollment token, so that it enrolls nothing more.

```text
rpmgr revoke enrollment-token <id>
```

## rpmgr revoke token

Revoke one of your personal API tokens.

```text
rpmgr revoke token <id>
```

## rpmgr set

Set an org's limit.

```text
rpmgr set <command>
```

| Command | What it does |
|---|---|
| [`rpmgr set port-quota`](#rpmgr-set-port-quota) | Set how many ports of a gateway group's pools the org may hold |
| [`rpmgr set smtp-password`](#rpmgr-set-smtp-password) | Set or remove the mail relay's password (Instance Admin) |

## rpmgr set port-quota

Set how many ports of a gateway group's pools the org may hold.

```text
rpmgr set port-quota [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--group string` |  | the gateway group, by name or ID |
| `--max int` |  | the most ports |
| `--protocol string` |  | tcp or udp |

## rpmgr set smtp-password

Set or remove the mail relay's password (Instance Admin).

```text
rpmgr set smtp-password [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--password-file string` |  | a file whose first line is the password; without it, the password is asked for |
| `--remove` |  | remove the password |

## rpmgr preview

Show what a change would do, saving nothing.

```text
rpmgr preview <command>
```

| Command | What it does |
|---|---|
| [`rpmgr preview route`](#rpmgr-preview-route) | Show what creating or changing a route would do, saving nothing |

## rpmgr preview route

Show what creating or changing a route would do, saving nothing.

```text
rpmgr preview route [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--bandwidth uint` |  | the route's bytes a second in each direction, shared by the group's gateways; 0 is no limit |
| `--certificate string` |  | http: the uploaded certificate's ID, with --tls-mode certificate |
| `--description string` |  | a description for people |
| `--disabled` |  | the route is not served |
| `--flow-idle-timeout duration` |  | tcp-udp: forget a UDP flow idle this long |
| `--group string` |  | the gateway group, by name or ID |
| `--host-header string` |  | http: the Host header towards the upstream; empty keeps the client's |
| `--hostname value` |  | a hostname of an http or tls-passthrough route; repeat for more |
| `--hsts duration` |  | http: the Strict-Transport-Security max-age; 0 sends none |
| `--http` |  | an http route: TLS ends at the gateway |
| `--idle-timeout duration` |  | tcp, tcp-udp: close a connection idle this long; udp: forget a flow idle this long |
| `--label value` |  | a label key=value; repeat for more |
| `--maintenance` |  | http: answer every request with the maintenance page, 503 |
| `--maintenance-message string` |  | http: plain text the maintenance page shows, at most 500 characters |
| `--max-body uint` |  | http: the largest request body in bytes; 0 is no limit |
| `--max-connections uint` |  | the route's open connections, flows or requests in flight, shared by the group's gateways; 0 is no limit |
| `--name string` |  | the route's name, unique in the org |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--path-prefix string` |  | http: the path prefix it serves |
| `--policy value` |  | an access policy, by name or ID; repeat for more |
| `--port uint` |  | tcp, udp, tcp-udp: the public port; 0 on create picks a free one |
| `--port80 string` |  | http: what port 80 does: redirect, serve or off |
| `--requests-per-second uint` |  | the route's requests, new connections or new flows a second, shared by the group's gateways; 0 is no limit |
| `--route string` |  | the ID of a route whose change to preview, rather than a new route |
| `--set-request-header value` |  | http: a header Name=value set towards the upstream; repeat for more |
| `--set-response-header value` |  | http: a header Name=value set towards the client; repeat for more |
| `--tcp` |  | a tcp route on a public port |
| `--tcp-udp` |  | a route on one public port number with both TCP and UDP |
| `--tls-mode string` |  | http: acme or certificate |
| `--tls-passthrough` |  | a TLS route the gateway passes through by its SNI |
| `--transport string` |  | the data-session transport: auto, quic or h2; empty is the connector's |
| `--udp` |  | a udp route on a public port |
| `--wait duration` |  | wait up to this long, at most 30s, for the agents to apply the change |
| `--websocket` | `true` | http: whether WebSocket upgrades pass |

## rpmgr verify

Check a proof now.

```text
rpmgr verify <command>
```

| Command | What it does |
|---|---|
| [`rpmgr verify domain`](#rpmgr-verify-domain) | Check a domain claim's proof now |

## rpmgr verify domain

Check a domain claim's proof now.

```text
rpmgr verify domain <id>
```

## rpmgr check

Check for new releases now.

```text
rpmgr check <command>
```

| Command | What it does |
|---|---|
| [`rpmgr check release`](#rpmgr-check-release) | Check for new releases now and wait for the check to end (Instance Admin) |

## rpmgr check release

Check for new releases now and wait for the check to end (Instance Admin).

```text
rpmgr check release
```

## rpmgr trust

Trust something without a proof.

```text
rpmgr trust <command>
```

| Command | What it does |
|---|---|
| [`rpmgr trust domain`](#rpmgr-trust-domain) | Mark a domain claim verified without a proof (Instance Admin) |

## rpmgr trust domain

Mark a domain claim verified without a proof (Instance Admin).

```text
rpmgr trust domain <id>
```

## rpmgr upload

Upload a file to the controller.

```text
rpmgr upload <command>
```

| Command | What it does |
|---|---|
| [`rpmgr upload certificate`](#rpmgr-upload-certificate) | Upload a certificate chain and its key for http routes |
| [`rpmgr upload release`](#rpmgr-upload-release) | Upload a release's signed manifest and signing-key statement (Instance Admin) |

## rpmgr upload certificate

Upload a certificate chain and its key for http routes.

```text
rpmgr upload certificate [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--chain string` |  | the PEM chain, leaf first |
| `--key string` |  | the leaf's PEM private key |

## rpmgr upload release

Upload a release's signed manifest and signing-key statement (Instance Admin).

```text
rpmgr upload release [flags] <dir>
```

| Flag | Default | Description |
|---|---|---|
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |

## rpmgr renew

Renew a certificate now.

```text
rpmgr renew <command>
```

| Command | What it does |
|---|---|
| [`rpmgr renew certificate`](#rpmgr-renew-certificate) | Renew an ACME certificate now, or obtain it if it failed |

## rpmgr renew certificate

Renew an ACME certificate now, or obtain it if it failed.

```text
rpmgr renew certificate <id>
```

## rpmgr remove

Remove a member from the org, or a user's second factor.

```text
rpmgr remove <command>
```

| Command | What it does |
|---|---|
| [`rpmgr remove member`](#rpmgr-remove-member) | End a membership; the user's tokens lose their access to the org |
| [`rpmgr remove second-factor`](#rpmgr-remove-second-factor) | Remove a user's authenticator and recovery codes, for one who lost both, and end their sessions; takes a step-up |

## rpmgr remove member

End a membership; the user's tokens lose their access to the org.

```text
rpmgr remove member <user ID or e-mail address>
```

## rpmgr remove second-factor

Remove a user's authenticator and recovery codes, for one who lost both, and end their sessions; takes a step-up.

```text
rpmgr remove second-factor <user ID or e-mail address>
```

## rpmgr advance

Move a rollout to its next stage.

```text
rpmgr advance <command>
```

| Command | What it does |
|---|---|
| [`rpmgr advance rollout`](#rpmgr-advance-rollout) | Move a running rollout to a higher percentage of the agents, or to all |

## rpmgr advance rollout

Move a running rollout to a higher percentage of the agents, or to all.

```text
rpmgr advance rollout [flags] (--percent <n> | --all) <rollout>
```

| Flag | Default | Description |
|---|---|---|
| `--all` |  | every agent |
| `--force` |  | advance without checking that the rollout is unchanged since this command read it |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
| `--percent int` |  | the share of agents, 1 to 99, above the current one |

## rpmgr pause

Pause a rollout.

```text
rpmgr pause <command>
```

| Command | What it does |
|---|---|
| [`rpmgr pause rollout`](#rpmgr-pause-rollout) | Pause a running rollout; agents offered the release keep it |

## rpmgr pause rollout

Pause a running rollout; agents offered the release keep it.

```text
rpmgr pause rollout [flags] <rollout>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | pause without checking that the rollout is unchanged since this command read it |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |

## rpmgr resume

Let a paused rollout run again.

```text
rpmgr resume <command>
```

| Command | What it does |
|---|---|
| [`rpmgr resume rollout`](#rpmgr-resume-rollout) | Let a paused rollout run again |

## rpmgr resume rollout

Let a paused rollout run again.

```text
rpmgr resume rollout [flags] <rollout>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | resume without checking that the rollout is unchanged since this command read it |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |

## rpmgr cancel

End a rollout for good.

```text
rpmgr cancel <command>
```

| Command | What it does |
|---|---|
| [`rpmgr cancel rollout`](#rpmgr-cancel-rollout) | End a running or paused rollout for good |

## rpmgr cancel rollout

End a running or paused rollout for good.

```text
rpmgr cancel rollout [flags] <rollout>
```

| Flag | Default | Description |
|---|---|---|
| `--force` |  | cancel without checking that the rollout is unchanged since this command read it |
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |

## rpmgr upgrade

Update agents to the controller's version.

```text
rpmgr upgrade <command>
```

| Command | What it does |
|---|---|
| [`rpmgr upgrade connector`](#rpmgr-upgrade-connector) | Update connectors to the controller's version, one after another, in its easy rollout (Instance Admin) |
| [`rpmgr upgrade gateway`](#rpmgr-upgrade-gateway) | Update gateways to the controller's version, one after another, in its easy rollout (Instance Admin) |

## rpmgr upgrade connector

Update connectors to the controller's version, one after another, in its easy rollout (Instance Admin).

```text
rpmgr upgrade connector [flags] <connector>…
```

| Flag | Default | Description |
|---|---|---|
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |

## rpmgr upgrade gateway

Update gateways to the controller's version, one after another, in its easy rollout (Instance Admin).

```text
rpmgr upgrade gateway [flags] <gateway>…
```

| Flag | Default | Description |
|---|---|---|
| `-o string` | `table` | output: table, yaml (the manifest, where the kind has one) or json |
