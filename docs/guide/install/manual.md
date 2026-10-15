# Manual installation and containers

This page installs rpmgr without the install scripts' automation: the binary by hand, each role
with `init`, `enroll` and `systemd-unit`, a host without systemd, and the container image. Read it
when you want to see or control every step, when a configuration-management tool installs rpmgr,
or when you run rpmgr in containers. For the usual way, see
[The install scripts](install-script.md) and [Set up a host with rpmgr setup](setup.md).

## Install the binary

The global install script can verify a release for you without installing it. `--verify-only`
needs no root, and `--dir` keeps the downloaded files:

```sh
curl -fsSLO https://github.com/felix-homelab/rpmgr/releases/latest/download/install.sh
sh install.sh --verify-only --dir rpmgr-release
```

The script prints `verified rpmgr <version> (manifest …)` and leaves the binary of this host's
architecture, `rpmgr-<version>-linux-<arch>`, in `rpmgr-release/`. To verify by hand instead, check
the same chain with `minisign` and the release root keys
([04](../../04-security.md#release-signing)), and the provenance attestation with the GitHub
command line:

```sh
gh attestation verify rpmgr-release/rpmgr-0.1.0-linux-amd64 --repo felix-homelab/rpmgr \
  --signer-workflow felix-homelab/rpmgr/.github/workflows/release.yml
```

Then install the binary, the user and the directories as the script would:

```sh
sudo install -m 0755 rpmgr-release/rpmgr-0.1.0-linux-amd64 /usr/local/bin/rpmgr
rpmgr version --verbose      # the version and the release root keys compiled into it
sudo useradd --system --user-group --home-dir /var/lib/rpmgr --shell /usr/sbin/nologin rpmgr
sudo install -d -m 0755 /etc/rpmgr
sudo install -d -m 0750 -o rpmgr -g rpmgr /var/lib/rpmgr
```

The paths and modes are those of [10](../../10-operations.md#filesystem-layout). The service user
must never be able to write the binary.

## A controller or all-in-one by hand

### 1. Initialise it

```sh
sudo rpmgr all-in-one init --public-url https://panel.example.com
# or, for a controller alone:
sudo rpmgr controller init --public-url https://panel.example.com
```

| Flag | Meaning |
|---|---|
| `--public-url <url>` | The `https://` URL of the web UI, the API and the agents. Needed when the boot file does not exist |
| `--kek-source systemd-credential\|file` | Where the KEK of a new boot file is kept. Default: the systemd credential from systemd 250, else a file |
| `--kek-path <file>` | The KEK file with `--kek-source file`. Default: `/etc/rpmgr/kek` |
| `--config <file>` | The boot file. Default: `$RPMGR_CONFIG`, else `/etc/rpmgr/<role>.yaml` |

`init` writes the boot file if it does not exist, creates the KEK, the database with its
migrations, the trust domain and the CA. `all-in-one init` also creates the gateway group `default`
with the built-in gateway `local` and the built-in connector `local`, and enrolls both. It prints
(abbreviated):

```text
Initialised the all-in-one installation.
  trust domain: rpmgr-…
  CA pin:       sha256:…
  gateway:      gw_…
  connector:    con_…
  KEK:          new systemd credential /etc/rpmgr/credstore/rpmgr-kek
Back up the KEK separately: without it the database cannot be read.
The connector allows no target until its local policy does: rpmgr policy allow-target <host:port>.
Create the first user, Instance Admin and Owner, with this one-time link (valid …):
  https://panel.example.com/setup#…
```

- **It never overwrites** a boot file or a KEK: an existing one is read and used, so you can write
  the boot file first ([Boot files](../reference/boot-files.md)) and run `init` again after a
  failure. It refuses a database that is initialised already or in use by a running controller.
- **A KEK file** is created with mode 0600 and given to the user `rpmgr`. **A systemd credential**
  is encrypted with `systemd-creds` into `/etc/rpmgr/credstore/rpmgr-kek`, for this host only. An
  existing credential is readable only where systemd loads it, so `init` then runs under
  `systemd-run`:

  ```sh
  sudo systemd-run --pipe --wait \
    --property=LoadCredentialEncrypted=rpmgr-kek:/etc/rpmgr/credstore/rpmgr-kek \
    /usr/local/bin/rpmgr all-in-one init
  ```
- **What `init` creates** in `/var/lib/rpmgr` belongs to the user `rpmgr`, so the service starts
  without a `chown`.
- **Back up the KEK now,** apart from the database backups
  ([Backup and restore](../operations/backup-and-restore.md#back-up-the-kek)).

### 2. The certificate of the public URL

Without certificate files, the controller orders the certificate of a public name from Let's
Encrypt production at its first start. To use another CA first, such as Let's Encrypt's staging
CA, start with `rpmgr setup`, which sets the instance's ACME directory before the first start, or
give the controller certificate files in the boot file's `tls` section until you have changed the
ACME settings ([Boot files](../reference/boot-files.md#controller)).

### 3. The unit

```sh
rpmgr systemd-unit all-in-one | sudo tee /etc/systemd/system/rpmgr-all-in-one.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now rpmgr-all-in-one
curl -fsS http://127.0.0.1:7381/readyz     # prints "ok" once the role is ready
```

`rpmgr systemd-unit <role>` prints the hardened unit of `controller`, `gateway`, `connector` or
`all-in-one` ([10](../../10-operations.md#hardened-systemd-units)). For a controller or
all-in-one it reads the boot file, and the unit loads the KEK credential when the KEK is one.
`--bin <path>` names another binary than `/usr/local/bin/rpmgr`.

Then open the first-user link ([Quick start](../quick-start.md#5-create-your-account)).

## A gateway or connector by hand

You need the controller's URL and CA pin, and a token: an enrollment token for a connector, a
gateway token for a gateway ([Enrolling connectors](../connectors/enroll.md),
[Gateways](../gateways.md)). The example sets up a connector; a gateway is the same without the
policy, with `gateway` in place of `connector` and the admin port 7382.

1. **The boot file.** Write `/etc/rpmgr/connector.yaml`, owned by root with mode 0644:

   ```yaml
   version: 1
   controller:
     endpoints: ['https://panel.example.com']
   listen:
     admin: '127.0.0.1:7383'
   ```

2. **The local policy.** Allow the targets the connector may reach. The command creates
   `/etc/rpmgr/policy.yaml` if it is missing
   ([The local policy](../connectors/local-policy.md)):

   ```sh
   sudo rpmgr policy allow-target --no-reload 192.168.1.20:8080
   ```

3. **Enroll.** `rpmgr enroll` asks for the token on the terminal, or reads it from `--token-file`
   or `RPMGR_ENROLL_TOKEN`:

   ```sh
   sudo rpmgr enroll --controller https://panel.example.com --ca-pin 'sha256:…'
   sudo chown -R rpmgr:rpmgr /var/lib/rpmgr/identity
   ```

   It prints `Enrolled connector con_… in trust domain rpmgr-…; identity written to
   /var/lib/rpmgr/identity.` The service runs as `rpmgr`, so the identity must belong to that
   user.

4. **Host tuning.** Raise the UDP buffers `net.core.rmem_max` and `net.core.wmem_max` to the size
   QUIC asks for, in `/etc/sysctl.d/60-rpmgr.conf`, as the controller's `/install.sh` does
   ([03](../../03-connections.md#host-tuning-applied-by-the-installer)), then apply the file with
   `sudo sysctl -p /etc/sysctl.d/60-rpmgr.conf`.

5. **The unit.**

   ```sh
   rpmgr systemd-unit connector | sudo tee /etc/systemd/system/rpmgr-connector.service >/dev/null
   sudo systemctl daemon-reload
   sudo systemctl enable --now rpmgr-connector
   sudo rpmgr status        # ends with "Service: running and ready"
   ```

`rpmgr enroll` flags:

| Flag | Meaning |
|---|---|
| `--controller <url>` | Required. The controller's `https://<host>[:<port>]` |
| `--ca-pin <pin>` | Required. The pin of the controller's root CA, `sha256:<base64>` |
| `--token-file <file>` | Read the token from this file. Default: `RPMGR_ENROLL_TOKEN`, else a prompt |
| `--replace` | Replace an existing identity on this host ([Enrolling connectors](../connectors/enroll.md)) |
| `--identity-dir <dir>` | Where the identity is written. Default: `/var/lib/rpmgr/identity` |
| `--trust-bundle <file>` | Use this PEM trust bundle instead of downloading it |

**The trust bundle.** `rpmgr enroll` downloads the controller's trust bundle over HTTPS, from
`<controller URL>/.well-known/rpmgr/trust-bundle`, and keeps only the root that matches the pin.
The download needs a controller certificate that the host trusts. When it has none yet, such as a
self-signed one, fetch the bundle without checking the certificate and pass it in; the pin, not
the connection, authenticates it ([04](../../04-security.md#join-command)):

```sh
curl -fsSk https://panel.example.com/.well-known/rpmgr/trust-bundle -o bundle.pem
sudo rpmgr enroll --controller https://panel.example.com --ca-pin 'sha256:…' --trust-bundle bundle.pem
```

## Without systemd

Use `rpmgr setup --no-unit`, or the steps above without the unit, and start the role with your
own supervisor:

- **Run** `rpmgr <role> --config /etc/rpmgr/<role>.yaml` as the user `rpmgr`. A gateway,
  controller or all-in-one needs `CAP_NET_BIND_SERVICE` for the ports 80 and 443.
- **The KEK** must be a file: a systemd credential needs systemd.
- **Signals:** `SIGINT` or `SIGTERM` stops the role; a gateway, and the gateway of an all-in-one,
  drains first. `SIGHUP` makes a connector or all-in-one read its local policy again.
- **`rpmgr policy`** reloads the connector through `systemctl reload`. Without systemd, use
  `--no-reload`: the connector notices the changed file by itself.

Keep the hardening of the units in mind: the service user must not be able to write the binary,
the boot files or the policy file ([10](../../10-operations.md#hardened-systemd-units)).

## Container images

Every release publishes a multi-architecture image at `ghcr.io/felix-homelab/rpmgr`, for every
released Linux architecture ([10](../../10-operations.md#install-paths)):

- **Tags:** the version, such as `0.1.0` or `0.1.0-rc.7`; a stable release also gets `0.1`, `0`
  and `latest` while it is the highest of each. Pin a version in production.
- **Contents:** the release binary on a distroless static base, without a shell. `rpmgr` is the
  entry point, so the role is the command: `docker run … ghcr.io/felix-homelab/rpmgr gateway`.
- **User:** the image runs as the nonroot user, UID 65532.
- **Files:** mount the boot file at `/etc/rpmgr/<role>.yaml`, read-only, and the state as a volume
  at `/var/lib/rpmgr`, which the image gives to the nonroot user.
- **Signature:** the image is signed keylessly with cosign by the release workflow
  ([04](../../04-security.md#release-signing)).

Check the signature before you run an image:

```sh
cosign verify ghcr.io/felix-homelab/rpmgr:0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/felix-homelab/rpmgr/'
```

### An all-in-one in a container

The image tests run the all-in-one this way. The boot file keeps the KEK as a file in the state
volume, because a container has no systemd credential:

```yaml
# /srv/rpmgr/etc/all-in-one.yaml, readable by the container's user (mode 0644)
version: 1
public_url: https://panel.example.com
kek:
  source: file
  path: /var/lib/rpmgr/kek
```

```sh
docker volume create rpmgr-state
docker run --rm -v rpmgr-state:/var/lib/rpmgr -v /srv/rpmgr/etc:/etc/rpmgr:ro \
  ghcr.io/felix-homelab/rpmgr:0.1.0 all-in-one init        # prints the CA pin and the first-user link
docker run -d --name rpmgr --restart unless-stopped \
  -p 80:80/tcp -p 443:443/tcp -p 443:443/udp \
  -v rpmgr-state:/var/lib/rpmgr -v /srv/rpmgr/etc:/etc/rpmgr:ro \
  ghcr.io/felix-homelab/rpmgr:0.1.0 all-in-one
```

- **The KEK** lies in the same volume as the database, so a copy of the volume holds both. Copy the
  KEK out once and keep it apart from your backups:
  `docker cp rpmgr:/var/lib/rpmgr/kek ./rpmgr-kek`.
- **The local policy** of the built-in connector is `/etc/rpmgr/policy.yaml` in the mounted
  directory. Edit it on the host, then send `docker kill --signal HUP rpmgr`. The policy and its
  targets are seen from inside the container: `127.0.0.1` is the container itself
  ([Local policy file](../reference/policy-file.md)).
- **Port pools:** publish the ports of your `tcp` and `udp` routes too, such as
  `-p 20000-20099:20000-20099/tcp`.

### A gateway or connector in a container

Enroll once into the state volume, with a terminal for the token prompt, then run the role:

```sh
docker volume create rpmgr-connector
docker run --rm -it -v rpmgr-connector:/var/lib/rpmgr ghcr.io/felix-homelab/rpmgr:0.1.0 \
  enroll --controller https://panel.example.com --ca-pin 'sha256:…'
docker run -d --name rpmgr-connector --restart unless-stopped \
  -v rpmgr-connector:/var/lib/rpmgr -v /srv/rpmgr/etc:/etc/rpmgr:ro \
  ghcr.io/felix-homelab/rpmgr:0.1.0 connector
```

`/srv/rpmgr/etc` holds `connector.yaml`, as in [the steps above](#a-gateway-or-connector-by-hand),
and `policy.yaml`. Mount the directory rather than single files, so that an edited policy reaches
the container.

- **A connector** dials its targets from the container's network. With `--network host` it reaches
  the same addresses as the host.
- **A gateway** publishes `80/tcp`, `443/tcp`, `443/udp` and the port pools of its group. Docker
  lets the nonroot user bind ports below 1024 in the container's own network namespace. With
  `--network host`, set the host's `net.ipv4.ip_unprivileged_port_start` to 80 or lower; on
  Kubernetes, the pod sets that sysctl in its security context.
- **Host tuning:** the UDP buffer sizes are the host's, not the container's: apply them on the
  host ([03](../../03-connections.md#host-tuning-applied-by-the-installer)).

A Helm chart is planned for a later phase ([13](../../13-roadmap.md#phase-3--advanced)).
