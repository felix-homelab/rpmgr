# Backup and restore

The controller holds everything rpmgr knows: routes, agents, certificates, accounts and the audit
log. This page shows how to back it up while it runs, what a backup holds and what it does not, how
to keep the key-encryption key (KEK) safe, how to restore on the same host or a new one, and how to
test a restore. Read it when you set up a controller, and again before you need it.

Gateways and connectors need no backup: their configuration comes from the controller, and a lost
agent host is installed and enrolled again ([Enrolling connectors](../connectors/enroll.md)).

## What a backup holds

`rpmgr backup` writes one tar archive, mode 0600, with:

| File | Contents |
|---|---|
| `controller.db` | A consistent copy of the database, taken while the controller keeps running. Secrets in it, such as the CA's keys and the ACME account key, stay encrypted under the KEK |
| `revocations.log` | The revocation log: every revoked certificate and token, removed member and changed credential, which a restore applies again |
| `audit-checkpoints.log` | The signed checkpoints of the audit log |
| `backup.json` | The format, the rpmgr version, the time, the trust domain and the database epoch |

What a backup does **not** hold, and how to keep it:

| Not in the backup | Where it is | How to keep it |
|---|---|---|
| The KEK | `/etc/rpmgr/credstore/rpmgr-kek` (systemd credential) or `/etc/rpmgr/kek` (file) | Separately, apart from the backups ([below](#back-up-the-kek)) |
| The boot file, the local policy, the web UI's certificate files | `/etc/rpmgr/` | A copy of the directory; the certificate's key is secret |
| On an all-in-one, the identities of its built-in gateway and connector | `/var/lib/rpmgr/gateway/identity`, `/var/lib/rpmgr/connector/identity` | Not needed: the all-in-one enrolls them again when they are missing or out of date ([below](#restore-an-all-in-one)) |
| The release mirror | `/var/lib/rpmgr/dl/` | Not needed: the controller fetches it again, or you import it ([Air-gapped installations](../install/air-gapped.md)) |

The KEK and the database belong apart: a backup without its KEK cannot reveal the secrets in it, and
a KEK stored next to the backup defeats the encryption
([10](../../10-operations.md#backup-and-restore)).

## Back up the controller

On the controller's or all-in-one's host:

```sh
sudo rpmgr backup --out /root/rpmgr-$(date +%Y%m%dT%H%M).tar
```

```text
Wrote /root/rpmgr-20261015T0300.tar: the database of rpmgr-… (epoch …) with its revocation log and audit checkpoints.
Back up the KEK separately and keep it apart from this archive: without it the archive's secrets cannot be read.
```

- **While it runs:** the controller keeps serving during the backup.
- **Never overwrites:** `--out` must name a file that does not exist; a failed backup leaves
  nothing behind.
- **Audited:** the backup is recorded in the audit log with the actor `local-cli`.
- **The boot file:** `--config <file>`, default `$RPMGR_CONFIG`, else
  `/etc/rpmgr/controller.yaml`, else `/etc/rpmgr/all-in-one.yaml`.
- **In a container:** run it inside, into the state volume, and copy it out:
  `docker exec rpmgr /usr/bin/rpmgr backup --out /var/lib/rpmgr/backup.tar`, then
  `docker cp rpmgr:/var/lib/rpmgr/backup.tar .`.

Back up daily and before every upgrade of the controller, and copy each archive off the host
([10](../../10-operations.md#backup-and-restore)). A timer or a cron job can run the command; give
each archive a new name, as above.

## Back up the KEK

The KEK encrypts the secrets in the database. Without it, a backup restores accounts and routes,
but not the CA, the certificates or anything else secret. Back it up once, and again after every
`rpmgr kek rotate`, to a place apart from the database backups, such as offline media or a password
manager.

**A KEK file** (`kek.source: file`) is a short text file. Copy it to your safe place, such as
offline media:

```sh
sudo cp /etc/rpmgr/kek /media/offline/rpmgr-kek
```

**A systemd credential** (`kek.source: systemd-credential`, the default from systemd 250) is
encrypted for this host alone, so a copy of the credential file is useless on another host. Decrypt
it into a file, keep that, and delete it from the host:

```sh
sudo systemd-creds decrypt --name=rpmgr-kek /etc/rpmgr/credstore/rpmgr-kek /root/rpmgr-kek
# copy /root/rpmgr-kek to your safe place, then:
sudo rm /root/rpmgr-kek
```

The decrypted file has the format of a KEK file, so it serves either way on the host you restore
to ([below](#on-a-new-host)).

## The revocation log sink

Every revocation is first written to the controller's local `revocations.log`, which each backup
includes. A restore applies again every revocation made after the backup, so that a revoked
certificate or token does not come back. It reads them from the local log of the host it runs on,
which is lost with the host.

The boot setting `revocation_log.sink` keeps a copy off the host: a directory, usually on a share
mounted on the controller's host ([Boot files](../reference/boot-files.md#controller)). The
systemd unit lets the controller write only to `/var/lib/rpmgr`, unless it names the sink as well:
`rpmgr systemd-unit` reads the boot file and adds the sink, so write the unit again after setting
it. To set one up on a controller (on an all-in-one, use `all-in-one` in place of `controller`):

1. **Create the directory** and give it to the user `rpmgr`. On a share, the share's own
   permissions must let `rpmgr` write as well.

   ```sh
   sudo install -d -m 0750 -o rpmgr -g rpmgr /mnt/rpmgr-revocations
   ```

2. **Name it in the boot file,** `/etc/rpmgr/controller.yaml`:

   ```yaml
   revocation_log:
     sink: /mnt/rpmgr-revocations
   ```

3. **Write the unit again,** which now makes the sink writable for the service, and restart the
   controller:

   ```sh
   rpmgr systemd-unit controller | sudo tee /etc/systemd/system/rpmgr-controller.service >/dev/null
   grep ReadWritePaths /etc/systemd/system/rpmgr-controller.service
   sudo systemctl daemon-reload
   sudo systemctl restart rpmgr-controller
   ```

   `grep` shows the line the unit gained:

   ```text
   ReadWritePaths=-/mnt/rpmgr-revocations
   ```

   With `-`, the controller starts even when the directory is missing, such as a share that is not
   mounted yet; a share mounted later is writable at once. If you create a plain directory after
   the start, restart the controller. If you keep a unit of your own instead, add the same line to
   it with a drop-in: `sudo systemctl edit rpmgr-controller` opens an editor for it, under
   `[Service]`.

When the controller cannot write to the sink, it logs
`revocation log: the sink takes no entries; revocations are still enforced`.

Without a sink, **Settings** shows the warning that the revocation log has no copy off this host.
With one, it warns when an entry has waited too long to reach the sink
([10](../../10-operations.md#suggested-alerts)). Revocations are enforced at once either way
([10](../../10-operations.md#backup-and-restore)).

## Restore

A restore puts the database and the logs of a backup in place. It needs every controller stopped.

### Before you start

- **The backup archive,** from `rpmgr backup`.
- **The KEK that belongs to it:** the controller cannot start without it.
- **The revocations since the backup:** on the same host, the local `revocations.log`, which the
  restore reads by default; on a new host, the sink directory or the old host's `revocations.log`.
  Without them, the restore fails closed ([below](#when-the-restore-fails-closed)).
- **The same rpmgr version** as the backup, or a later one: the restore applies the binary's
  database migrations to the restored database.

### On the same host

```sh
sudo systemctl stop rpmgr-all-in-one          # or rpmgr-controller
sudo rpmgr restore --in /root/rpmgr-20261015T0300.tar
sudo systemctl start rpmgr-all-in-one
curl -fsS http://127.0.0.1:7381/readyz        # prints "ok" once the controller is ready
```

```text
Restored the backup of rpmgr-… taken 2026-10-15T03:00:00Z: new epoch … (was …).
Applied … revocations since the backup again; … of them name something the backup does not hold.
Every session, enrollment token, reset link and open invitation of the backup is invalidated.
The replaced files are kept with the suffix .before-restore-20261015T091500Z. Start one controller, check /readyz, then the others;
re-enroll agents enrolled after the backup.
```

| Flag | Meaning |
|---|---|
| `--in <file>` | Required. The archive of `rpmgr backup` |
| `--revocation-log <dir or file>` | A revocation-log sink directory, or a controller's `revocations.log`. Repeat it for each. Default: the state directory's `revocations.log` |
| `--config <file>` | The boot file, as for `rpmgr backup` |

The restore refuses to run while a controller holds the database. It prepares everything next to
the live files and renames them into place only when every step succeeded, so a failed restore
changes nothing. The replaced files stay in `/var/lib/rpmgr` with the suffix
`.before-restore-<time>`; delete them once the restored controller runs.

### On a new host

When the old host is lost, or to move the controller:

1. **Install** the same rpmgr version, or a later one, without setup:
   `sudo sh install.sh --no-setup` ([The install scripts](../install/install-script.md)).
2. **Put back `/etc/rpmgr`:** the boot file, or a new one with the same keys
   ([Boot files](../reference/boot-files.md)), and on an all-in-one the local policy and any
   certificate files. Keep the same public URL, and point its DNS name at the new host.
3. **Put back the KEK** the way the boot file names it:

   ```sh
   # kek.source: file
   sudo install -m 0600 -o rpmgr -g rpmgr rpmgr-kek /etc/rpmgr/kek
   # kek.source: systemd-credential
   sudo install -d -m 0700 /etc/rpmgr/credstore
   sudo systemd-creds encrypt --name=rpmgr-kek rpmgr-kek /etc/rpmgr/credstore/rpmgr-kek
   # either way, then delete the decrypted copy:
   sudo rm rpmgr-kek
   ```

4. **Restore,** with the revocations since the backup:

   ```sh
   sudo rpmgr restore --in rpmgr-20261015T0300.tar --revocation-log /mnt/rpmgr-revocations
   ```

   Without a sink, pass the old host's `revocations.log` if you still have it. Without either, the
   restore fails closed.
5. **Install the unit and start it,** here for a controller; for an all-in-one, use `all-in-one` in
   place of `controller` ([below](#restore-an-all-in-one)). The unit makes the revocation-log sink
   of the boot file writable ([above](#the-revocation-log-sink)).

   ```sh
   rpmgr systemd-unit controller | sudo tee /etc/systemd/system/rpmgr-controller.service >/dev/null
   sudo systemctl daemon-reload
   sudo systemctl enable --now rpmgr-controller
   ```

Agents find the new host as before: by the public URL, or by the **Controller endpoints for
agents** the restored instance settings list, which must then lead to the new host too
([Settings](settings.md#web-ui-and-controller-endpoints)).

### Restore an all-in-one

An all-in-one's built-in gateway and connector keep their identities in the state directory, which
the backup does not hold. The all-in-one recovers them by itself at start, before its gateway runs
([10](../../10-operations.md#install)):

- **On the same host,** they stay in place.
- **On a new host,** their identities are missing: the all-in-one enrolls each again through its
  own controller, as the same gateway and connector, with their IDs and routes.
- **Renewed after the backup:** the built-in gateway and connector renew their certificates like
  any agent, so the restored database may not know the certificate an identity holds. The
  all-in-one then enrolls that agent again too, as it does one whose certificate is revoked or
  expired longer than the grace period.

Each enrollment revokes the certificates the restored database records for the agent, and the audit
log shows the token it used with the reason, such as "all-in-one's own gateway: its identity is
missing". A certificate issued after the backup, which the restored database does not record, stays
valid until it expires, as any agent's does ([What the restore changes](#what-the-restore-changes)):
on a move, stop the old host for good.

An identity that names another agent, such as a copy from another installation, is replaced in the
same way. An identity that cannot be read at all stops the start with its path: delete that
directory and start the service again.

A revocation stays, so a built-in gateway or connector whose identity is revoked as a whole, as when
the restore applies a revocation logged after the backup, cannot enroll again as itself. The
all-in-one then replaces it with a new built-in gateway or connector, with a new ID: the gateway
keeps its group, name and tunnel endpoints, the connector its name and the targets of its routes.
The audit log shows the old one decommissioned and the new one created, with the reason.

### What the restore changes

A restore takes the instance back to the time of the backup, and secures it:

- **A new database epoch.** Agents accept the restored configuration, whose revision numbers are
  lower, only together with the new epoch ([03](../../03-connections.md#revisions-and-ordering)).
- **Revocations stay.** Every revocation logged after the backup is applied again, with its
  original time and reason. A certificate revoked after the backup stays revoked everywhere.
- **One-time credentials of the backup are invalidated:** every session, so everybody signs in
  again; every enrollment token; every unused password-reset link and open invitation.
- **Changed credentials:** a password changed after the backup is cleared and must be reset; an
  authenticator or recovery codes changed after it must be set up again.
- **Agents enrolled after the backup** are unknown to the restored controller and must enroll
  again. **Agents that renewed their certificate after the backup** keep their session, but cannot
  renew that certificate again: enroll them again before it expires
  ([Enrolling connectors](../connectors/enroll.md)).

### When the restore fails closed

When the revocations since the backup may be incomplete, the restore still applies every one it
can read, then fails closed: no source was given and the local log is missing, a source cannot be
read, the sink's chain is broken, or an entry has a kind this version does not know. It prints
`FAILED CLOSED` with the reasons, and the instance enters **restore review**:

- The instance and every organisation are **read-only**: changes are refused with
  `RESTORE_REVIEW`, except revocations, the review itself and each user's own password, second
  factor and sessions.
- Every **API token** is suspended, and every user must **reset their password** and set up their
  **second factor** again. The Instance Admin makes reset links on the controller host with
  `sudo rpmgr user reset-password --email <address>`, or users request one themselves when a mail
  relay is set up ([Sign-in and two-factor authentication](../accounts/sign-in-and-mfa.md)).
- Each organisation's **Owner** confirms its members and roles and resumes its API tokens one by
  one. The Instance Admin confirms an organisation without an Owner with
  `sudo rpmgr restore confirm --org <org>`.
- The **Instance Admin** ends the instance-wide review on the controller host:

  ```sh
  sudo rpmgr restore confirm
  ```

  It prints `Ended the instance-wide restore review.` and names the organisations still in review.
  Only this command ends it; no API call and no Owner can.

## Test a restore

A backup you have never restored is a hope, not a backup. Test one at least every quarter
([10](../../10-operations.md#backup-and-restore)):

1. **A test host** without access to the internet or to your agents, such as a VM on an isolated
   network. The restored copy has your CA, your accounts and your ACME account; it must not order
   certificates or take part in your installation.
2. **Restore** a recent backup there, with the KEK from your safe place, as
   [on a new host](#on-a-new-host). Without a copy of the revocation log since the backup, the test
   restore fails closed into restore review, which does no harm on a test host: you then sign in
   with a reset link.
3. **Check:** `curl -fsS http://127.0.0.1:7381/readyz` prints `ok`, and `sudo rpmgr ca status`
   shows the trust domain and the root pin you know. From a machine on the isolated network whose
   hosts file points the public URL's name at the test host, sign in with a reset link from
   `sudo rpmgr user reset-password --email <address>`, and check that your routes are there.
4. **Destroy** the test host and the copies of the KEK and the backup on it.

The test proves that the archive is complete, that the KEK opens it, and that you know the steps.
