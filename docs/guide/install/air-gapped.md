# Air-gapped installations

rpmgr runs without internet access for the controller: you carry the release in, import it into
the controller's release mirror, and agents install from there. This page lists what rpmgr would
otherwise fetch from the internet, how to import a release with `rpmgr release import`, how the
`/dl/` mirror serves it, and what to do instead of ACME and the release check. Read it when the
controller cannot reach GitHub, or must not.

## What rpmgr fetches from the internet

| What | Who fetches it | Without internet |
|---|---|---|
| The release, for the first installation | The global install script, from GitHub | Carry the files in; install by hand or from your own mirror ([below](#install-the-controller)) |
| The release files of the controller's version, for its `/dl/` mirror | The controller's release check, at start and daily, from GitHub | `rpmgr release import` ([below](#import-the-release)) |
| Certificates for the web UI and the `http` routes | The controller, from the ACME CA (Let's Encrypt by default) | Your own ACME CA, or uploaded certificates ([below](#certificates)) |
| A domain's TXT record or HTTP token | The controller, from the domain's name servers or through its gateways | Mark the domain as trusted ([below](#domains)) |

Agents never fetch anything from the internet: the controller's `/install.sh` downloads from the
controller's mirror ([10](../../10-operations.md#ports)). Where a proxy leads out, the controller
can use it instead ([Environment variables](../reference/environment.md#proxies)).

## The /dl/ mirror

The controller serves the release of its own version at `https://<public URL>/dl/<version>/`:
`signing-key.json`, `manifest.json`, their `.minisig` signatures, and the Linux binaries the
manifest lists, and nothing else ([04](../../04-security.md#over-the-air-updates)).

- **On disk:** `/var/lib/rpmgr/dl/<version>/`, owned by the user `rpmgr`. The controller keeps a
  file only after the whole chain of signatures verifies and the file matches its size and SHA-256.
- **Filled by** the release check while it is on and GitHub answers, or by `rpmgr release import`.
- **Pruned:** once a version is complete, the directories of other versions go.
- **Used by** the controller's `/install.sh`, which downloads the five files it needs and verifies
  them again on the agent host
  ([The install scripts](install-script.md#the-controllers-install-script)).

Check what the mirror serves:

```sh
curl -fsS https://panel.example.com/dl/0.1.0/manifest.json
```

## Before you start

On a machine with internet access, download every file of the release you will install:

- `signing-key.json` and `signing-key.json.minisig`;
- `manifest.json` and `manifest.json.minisig`;
- every Linux binary: `rpmgr-<version>-linux-amd64`, `-linux-arm64`, `-linux-arm` and
  `-linux-riscv64`. The import needs all the Linux binaries the manifest lists;
- `install.sh`, if you install with it.

```sh
v=0.1.0
mkdir rpmgr-$v && cd rpmgr-$v
for f in signing-key.json signing-key.json.minisig manifest.json manifest.json.minisig \
  rpmgr-$v-linux-amd64 rpmgr-$v-linux-arm64 rpmgr-$v-linux-arm rpmgr-$v-linux-riscv64 install.sh; do
  curl -fsSLO "https://github.com/felix-homelab/rpmgr/releases/download/v$v/$f"
done
```

Carry the directory to the controller's host. The import verifies every file it takes, so a copy
that was damaged or changed on the way is refused.

## Install the controller

Without access to GitHub, the global install script cannot download the release. Either install
the binary by hand from the files you carried in
([Manual installation and containers](manual.md#install-the-binary)), or serve the release files
from a web server of your own over HTTPS, at the path the script expects, and point the script at
it
([Environment variables](../reference/environment.md#rpmgr_install_github-and-rpmgr_install_api)):

```sh
sudo env RPMGR_INSTALL_GITHUB=https://mirror.lan sh install.sh --version 0.1.0
```

Then set the host up with `rpmgr setup` ([Set up a host with rpmgr setup](setup.md)), with a
certificate that does not need the internet: `--tls files` with your certificate, `--tls
self-signed`, or `--acme-directory` with your own ACME CA ([below](#certificates)).

## Import the release

On the controller's host, import the release of the controller's own version:

```sh
sudo rpmgr release import /root/rpmgr-0.1.0
```

```text
Imported rpmgr 0.1.0 (manifest …); the controller serves it under /dl/0.1.0/.
```

- **Which release:** only the release of the binary's own version. A directory with another
  version is refused.
- **What it checks:** the chain the install scripts check, against the release root keys compiled
  into the binary: the signing-key statement, valid now, the manifest it signs, and the size and
  SHA-256 of each Linux binary ([04](../../04-security.md#release-signing)).
- **Where it goes:** into the mirror beside the database, given to the user `rpmgr`, which serves
  it. The running controller serves it at once.
- **Audit:** the import is recorded in the audit log with the actor `local-cli`.
- **Flags:** `--config <file>` names the boot file. Default: `$RPMGR_CONFIG`, else
  `/etc/rpmgr/controller.yaml`, else `/etc/rpmgr/all-in-one.yaml`.

A build from source has the version `dev`, which no release matches, so it imports nothing.

## Turn the release check off

Without internet access, the daily release check fails and logs a warning each time. Turn it off:

- **With the web UI:** as the Instance Admin, under **Settings**, in the **Updates** section, clear
  **Check for releases once a day** ([Settings](../operations/settings.md)).
- **With the command line:**

  ```sh
  rpmgr update settings --instance --set release_check=false
  ```

The mirror keeps what it has and serves it whether the check is on or off.

## Install the agents

Install gateways and connectors as usual, with the install command from the web UI
([The install scripts](install-script.md#the-controllers-install-script)). The agent hosts need
`https://<public URL>` only: the script downloads from `/dl/<version>/` and the agent enrolls with
the controller.

## Upgrade

1. Carry in the files of the new release, as above.
2. Upgrade the controller's binary by hand or from your mirror, and restart it
   ([Upgrades](upgrades.md)).
3. Import the new release with the new binary: `sudo rpmgr release import /root/rpmgr-<version>`.
   Once it is complete, the mirror drops the old version.
4. Upgrade the gateways and connectors from the controller
   ([Upgrades](upgrades.md#agent-hosts-without-access-to-github)).

## Certificates

The controller obtains certificates from an ACME CA, by default Let's Encrypt, for its public URL
and for `http` routes in ACME mode. Without access to it:

- **Your own ACME CA:** set it as the instance's ACME directory, at setup with
  `--acme-directory https://acme.lan/directory`, or later under **Settings**, **ACME certificates**,
  **ACME directory URL**. The CA must be reachable from the controller, and the gateways must be
  reachable from the CA for its challenges. Clients must trust the CA's root.
- **Uploaded certificates:** for the web UI, the boot file's `tls.cert_file` and `tls.key_file`
  ([Boot files](../reference/boot-files.md#controller)); for routes, certificates you upload under
  **Security → Domains & certificates** and select in the route
  ([Domains and certificates](../domains-and-certificates.md)).

## Domains

A route's hostname must lie under a domain the organisation has proved is its own. The proof by
DNS TXT record needs the domain's name servers, and the proof by HTTP token fetches the token
through the gateways. Where neither works, the Instance Admin can choose **Mark as trusted** on the
claim, or run `rpmgr trust domain <domain ID>`
([Domains and certificates](../domains-and-certificates.md)).
