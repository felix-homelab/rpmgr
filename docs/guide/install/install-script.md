# The install scripts

rpmgr has two install scripts. The **global install script** installs the binary from a GitHub
release on any Linux host: you use it for the first host, the controller or all-in-one, and for
upgrades. The **controller's install script**, `/install.sh` on your controller, installs and
enrolls a gateway or a connector from the controller in one command, which the web UI writes for
you. This page describes every option of both, how they verify what they download, and what they
change on the host.

| | Global install script | The controller's `/install.sh` |
|---|---|---|
| Comes from | GitHub: attached to every release as `install.sh`, and `deploy/install.sh` in the repository | Your controller: `https://<public URL>/install.sh` |
| Downloads from | GitHub releases | The controller's release mirror, `/dl/<version>/` |
| Installs | The binary, the user `rpmgr` and its directories; then offers `rpmgr setup` | A gateway or connector: the binary, its boot file, its local policy, host tuning, its enrollment and its systemd unit |
| Use it for | The first host, any role, and upgrades | Every further gateway and connector |

Both verify the release with the release root keys they embed before they install anything, and
both need Linux, OpenSSL 3.0 or later and root (except for `--verify-only`). The other ways to
install, by hand and as a container, are in
[Manual installation and containers](manual.md).

## The global install script

### Before you start

- A Linux host on x86_64, aarch64, armv7l or riscv64, with the requirements of
  [10](../../10-operations.md#supported-platforms).
- `curl` or `wget`, OpenSSL 3.0 or later, and the usual base tools (`sed`, `grep`, `date`, `dd`,
  `od`, `wc`, `head`, `cut`, `tr`). The script checks each and names a missing one.
- Root, through `sudo`, except for `--verify-only`.

### Run it

Download the script into a file, then run the file:

```sh
curl -fsSLO https://github.com/felix-homelab/rpmgr/releases/latest/download/install.sh
sudo sh install.sh
```

> [!IMPORTANT]
> Until v0.1.0 is released, `releases/latest` finds no release. Take `install.sh` from the newest
> pre-release on the [Releases page](https://github.com/felix-homelab/rpmgr/releases) instead:
> `https://github.com/felix-homelab/rpmgr/releases/download/v<version>/install.sh`.

The copy attached to a release is pinned to that release: it installs that version unless
`--version` names another. The repository's copy, `deploy/install.sh`, is not pinned: it asks the
GitHub API for the latest release, or with `--prerelease` for the latest one including
pre-releases.

Run the script from a file, not piped into `sudo sh`. Piped, its standard input is the script, so
it cannot ask whether to run `rpmgr setup`, and on Ubuntu's `sudo-rs` nothing typed at the
terminal would reach a later prompt ([04](../../04-security.md#join-command)).

What you see on a first installation (abbreviated):

```text
rpmgr install: downloading rpmgr 0.1.0 for linux/amd64 from https://github.com/felix-homelab/rpmgr
rpmgr install: verified rpmgr 0.1.0 (manifest …)
rpmgr 0.1.0 (commit …, go…, linux/amd64)
release root keys:
  …
rpmgr install: installed rpmgr 0.1.0 to /usr/local/bin/rpmgr
Run rpmgr setup now? [Y/n]
```

Answer `Y`, or press Enter, to set the host up now in `rpmgr setup`'s forms
([Set up a host with rpmgr setup](setup.md)). Answer `n` to do it later with `sudo rpmgr setup`.

### Options

```text
sh install.sh [--version <version>] [--prerelease] [--no-setup] [--upgrade] [--restart]
              [--dir <directory>] [--verify-only]
```

| Option | What it does |
|---|---|
| `--version <version>` | Install this version, such as `0.1.0` or `0.1.0-rc.7`; a leading `v` is dropped. Default: the version the copy is pinned to, else the latest release |
| `--prerelease` | Without `--version`, and only in a copy that is not pinned, take the latest release including pre-releases |
| `--no-setup` | Do not offer to run `rpmgr setup`; print the next step instead |
| `--upgrade` | Upgrade a host that has rpmgr: refuse a host without `/usr/local/bin/rpmgr` before downloading anything, offer no setup, and after the version print only what is left to do ([Upgrades](upgrades.md)) |
| `--restart` | Restart every rpmgr service that runs, in the order controller, all-in-one, gateway, connector, and check that each stays up. Works with or without `--upgrade` |
| `--dir <directory>` | Download into this directory and keep the files there. Default: a temporary directory that the script removes |
| `--verify-only` | Download and verify the release, install nothing. Needs no root |
| `-h`, `--help` | Print the usage |

The install script of v0.1.0-rc.7 and earlier has neither `--upgrade` nor `--restart`
([Upgrades](upgrades.md#with-an-older-install-script)).

### What it does

1. **Checks** its arguments, the host's operating system and architecture, the tools it needs and
   the OpenSSL version. With `--upgrade`, it refuses a host without an installed `rpmgr`.
2. **Finds the version:** `--version`, else the pinned one, else asks the GitHub API.
3. **Downloads** five files of that release: `signing-key.json` and `manifest.json` with their
   `.minisig` signatures, and the binary for the host's architecture,
   `rpmgr-<version>-linux-<arch>`.
4. **Verifies** them ([below](#how-the-scripts-verify-a-release)). With `--verify-only`, it stops
   here.
5. **Installs**, as root: the system user `rpmgr` if it is missing, `/etc/rpmgr` (root, 0755),
   `/var/lib/rpmgr` (`rpmgr`, 0750), and the binary at `/usr/local/bin/rpmgr`, which replaces an
   existing one in one rename. Then it runs `rpmgr version --verbose`, which prints the version and
   the release root keys compiled into the binary.
6. **Services:** with `--restart`, it restarts each rpmgr service that runs and checks that it
   stays active for 5 s without systemd restarting it. Without, it names each service that still
   runs the previous binary and the command that restarts it.
7. **Setup:** unless `--no-setup` or `--upgrade` is given, it asks on the terminal whether to run
   `rpmgr setup`. Without a terminal it asks nothing and prints the next step.

The script writes no configuration. Run again, it replaces the binary and leaves the user, the
directories, the boot files and the database as they are.

### Verify the script itself

The script verifies what it downloads, but you fetch the script itself over HTTPS from GitHub and
trust it on first use. Every release file, `install.sh` included, carries a provenance attestation
of the release workflow. To check it before you run the script, with the GitHub command line `gh`:

```sh
gh attestation verify install.sh --repo felix-homelab/rpmgr \
  --signer-workflow felix-homelab/rpmgr/.github/workflows/release.yml
```

## The controller's install script

Every controller serves an install script at `https://<public URL>/install.sh`, made for its own
version and with the release root keys of its own binary. It downloads the release from the
controller's mirror, `https://<public URL>/dl/<version>/`, so a gateway or connector host needs to
reach only the controller, not GitHub.

The mirror holds the release files of the controller's own version. The controller fetches them
from GitHub at start and then daily while its release check is on, or you import them with
`rpmgr release import` ([Air-gapped installations](air-gapped.md)). A controller that cannot serve
installs, such as a build from source, serves a script that prints why and fails.

### The install command

You rarely type the command yourself. The web UI shows it with the controller's URL and CA pin
filled in:

- **For a connector:** under **Network → Connectors**, **Enroll a connector**, then
  **Create the token**. The dialog shows the **Install command** and the **Enrollment token**
  ([Enrolling connectors](../connectors/enroll.md)).
- **For a gateway:** under **Network → Gateways**, open the gateway group, then
  **Enrollment token…** on the gateway ([Gateways](../gateways.md)).
- **On the command line:** `rpmgr get install-command`, with `--role gateway` for a gateway and
  `--allow-target` and `--deny-target` for a connector's targets.

A connector's command looks like this:

```sh
curl -fsSLO 'https://panel.example.com/install.sh' && sudo sh install.sh \
  --controller 'https://panel.example.com' --ca-pin 'sha256:…' \
  --allow-target '192.168.1.20:8080'
```

The command downloads the script into the current directory and runs that file with `sudo`. The
token is not part of it: the installer asks for it, or reads it from a file or a variable
([below](#the-enrollment-token)). Every value is quoted for the shell, and each target is checked
as the local policy reads it, so a pasted command runs nothing but the installer.

### Options

| Option | What it does |
|---|---|
| `--controller <url>` | Required. The controller's `https://` URL, where the script downloads from and the agent enrolls |
| `--ca-pin <pin>` | Required, except with `--verify-only`. The pin of the controller's root CA, `sha256:<base64>`, which the enrollment checks the controller against ([Concepts](../concepts.md#trust)) |
| `--role gateway\|connector` | The role to install. Default: `connector` |
| `--allow-target <target>` | A target the connector's local policy allows. Repeat it for more. A connector only |
| `--deny-target <target>` | A target the connector's local policy denies, whatever allows it. Repeat it for more. A connector only |
| `--token-file <file>` | Read the enrollment or gateway token from this file instead of asking |
| `--tcp-bbr` | Also set the TCP congestion control to BBR in the host tuning |
| `--verify-only` | Download and verify the release, install nothing. Needs neither root nor a pin |

A target is an address or a subnet with an optional port or port range, an IPv6 address in
brackets, or a socket path, such as `10.0.0.5:5432`, `10.0.0.0/16` (all ports),
`127.0.0.1:200-500`, `[fd00::1]:443` or `/run/app.sock`
([The local policy](../connectors/local-policy.md)).

This script has no `--help`. It needs `curl` (not `wget`), OpenSSL 3.0 or later, the base tools
the global script needs, and `systemctl`, `useradd` and `install`.

### What it does

1. **Checks** its options: an `https://` controller URL, a pin, a role, no targets for a gateway, a
   readable token file.
2. **Downloads and verifies** the five release files for the host's architecture from
   `/dl/<version>/`, as the global script does. With `--verify-only`, it stops here.
3. **Installs**, as root: the user `rpmgr`, `/etc/rpmgr`, `/var/lib/rpmgr`, the updater's state
   directory `/var/lib/rpmgr-update` (root, 0700), and the binary at `/usr/local/bin/rpmgr`.
4. **Chooses the admin port:** 7382 for a gateway, 7383 for a connector, or the next free port
   when that one is taken, never 9090.
5. **Writes the boot file** `/etc/rpmgr/<role>.yaml` with the controller URL and the admin
   listener, if the file does not exist ([Boot files](../reference/boot-files.md)).
6. **A connector's local policy:** writes `/etc/rpmgr/policy.yaml` if it does not exist, allowing
   nothing, then adds the denied targets and after them the allowed ones, so that an allowed target
   never stands without the denials that narrow it.
7. **Records** how rpmgr was installed and the release it came from in `/var/lib/rpmgr-update/`,
   for the automatic updates that come later.
8. **Host tuning:** writes `/etc/sysctl.d/60-rpmgr.conf`, which raises the UDP buffers to what QUIC
   needs where they are lower, and with `--tcp-bbr` sets BBR. It applies the file at once, or says
   that it applies at the next boot
   ([03](../../03-connections.md#host-tuning-applied-by-the-installer)).
9. **Enrolls** with `rpmgr enroll`, unless the host has an identity already: then it says
   `this host is enrolled already; to enroll it again, run rpmgr enroll --replace`.
10. **Starts the service:** writes the unit `rpmgr systemd-unit` prints to
    `/etc/systemd/system/rpmgr-<role>.service`, then `systemctl daemon-reload` and
    `systemctl enable --now rpmgr-<role>`.

It ends with a line such as:

```text
rpmgr install: rpmgr 0.1.0 runs as rpmgr-connector; admin listener 127.0.0.1:7383
```

Check the agent with `sudo rpmgr status`, which ends with `Service: running and ready` once it
holds a session to the controller and has applied its configuration
([Status and diagnostics](../connectors/status-and-diagnostics.md)).

Run again on an enrolled host, the script replaces the binary and keeps the boot file, the policy
file and the identity. `systemctl enable --now` does not restart a service that runs, so restart it
yourself to run the new binary: `sudo systemctl restart rpmgr-<role>`.

### The enrollment token

The token never passes through the script: `rpmgr enroll` reads it itself, in this order, from

1. the file `--token-file` names, which should have mode 0600 and be deleted afterwards;
2. the environment variable `RPMGR_ENROLL_TOKEN`, which `sudo` passes on only when you ask it to,
   with `sudo --preserve-env=RPMGR_ENROLL_TOKEN`;
3. a prompt on the terminal, `Enrollment token:`, with echo off.

For an unattended installation, let your automation put the token into a file that only root can
read, such as `/root/token` with mode 0600, without writing it on a command line. Then:

```sh
curl -fsSLO 'https://panel.example.com/install.sh' && sudo sh install.sh \
  --controller 'https://panel.example.com' --ca-pin 'sha256:…' --token-file /root/token
sudo rm /root/token
```

If the script is piped into `sh` all the same, it warns before the prompt: under `sudo-rs`, the
prompt would take nothing you type. Stop it with Ctrl-C and run it from a file.

## How the scripts verify a release

Both scripts verify a release the same way, with OpenSSL, before they install anything. Each
release is signed in a chain that ends in keys compiled into rpmgr
([04](../../04-security.md#release-signing)):

1. **The root keys.** The script carries the release root keys. The global script carries those
   of the release it belongs to; the controller's script carries those of the controller's
   binary.
2. **The signing-key statement.** `signing-key.json` names the key that signs releases and the
   time it is valid. Its signature must come from one of the root keys, and the statement must be
   valid now.
3. **The manifest.** `manifest.json` lists the release's version and, for each binary, its size and
   SHA-256. Its signature must come from the signing key the statement names, and it must be the
   manifest of the version the script installs.
4. **The binary.** Its size and SHA-256 must be those the manifest lists for the host's
   architecture.

The signatures are minisign signatures, checked with `openssl dgst -blake2b512` and
`openssl pkeyutl`, each with its trusted comment. Any failure stops the script with
`rpmgr install: …` and exit code 1, and nothing is installed. A wrong clock can make a valid
statement look expired, so check the host's time if the statement is refused.

## Troubleshooting

| Message | What to do |
|---|---|
| `OpenSSL 3.0 or later is needed to verify the release; found: …` | Install OpenSSL 3, or a distribution that has it ([10](../../10-operations.md#supported-platforms)) |
| `curl or wget is needed`, `… is needed` | Install the named tool |
| `run as root: sudo sh install.sh` | Run the script with `sudo`, or use `--verify-only` |
| `nothing to upgrade: /usr/local/bin/rpmgr is not installed; install it without --upgrade` | `--upgrade` on a host without rpmgr: leave the option out |
| `no release found at https://api.github.com/repos/felix-homelab/rpmgr` | No stable release yet: use a pre-release's `install.sh`, `--version` or `--prerelease` |
| `cannot download … from https://…/dl/<version>/` | The controller's mirror is empty: its release check cannot reach GitHub. Import the release ([Air-gapped installations](air-gapped.md)) |
| `the signature of … does not verify`, `the binary's SHA-256 does not match the manifest` | The download is corrupt or not genuine. Do not install; download again, from another network if it repeats |
| `the signing-key statement is not valid now` | Check the host's clock; then the release |
| `--ca-pin is required (the controller's UI shows the command)` | Copy the whole command from the web UI |
| `a gateway has no local policy for --allow-target or --deny-target` | Leave the targets out of a gateway's command |
| `this controller serves no install script: …` | The controller cannot serve installs, for example a build from source; install the agent with the global script and `rpmgr setup` |
| `this host is enrolled already; to enroll it again, run rpmgr enroll --replace` | Not an error: the host keeps its identity. To enroll it again, see [Enrolling connectors](../connectors/enroll.md) |
