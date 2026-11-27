# PKI

rpmgr runs its own certificate authority: every gateway, connector and controller proves who it is
with a certificate from it, and every connection between them checks those certificates. This page
is for the Instance Admin and for whoever enrolls agents: it explains the CA and its pin, how to
see its keys, how to rotate its intermediate, and the settings for agent certificates.

## What the CA is

`rpmgr controller init`, or `rpmgr all-in-one init`, creates the CA once, with a **trust domain**
such as `rpmgr-ewl35s75` that names the installation for good. The CA has four keys, kept in the
controller's database under the KEK ([04](../../04-security.md#ca-hierarchy)):

| Key | Web UI | What it does |
|---|---|---|
| Root | **Root** | Signs intermediates only. Agents pin it; it is the one thing they trust |
| Issuing intermediate | **Intermediate** | Issues the certificates of agents and controller nodes |
| Configuration signing | **Snapshot signing** | Signs the configuration and the revocation list each agent receives, so that an agent runs only what the controller sent |
| Audit checkpoints | **Audit checkpoints** | Signs the checkpoints of the audit log ([Audit log](audit-log.md#signed-checkpoints)) |

- **Agent certificates** carry the agent's identity, such as
  `spiffe://rpmgr-ewl35s75/org/org_…/connector/con_…`, and are short-lived. Each agent renews its
  own over its control session, with a new key every time, long before it expires. An agent that
  was offline past the expiry gets a new one within a **grace period**, and has to re-enroll after
  it ([04](../../04-security.md#leaf-certificates);
  [Enrolling connectors](../connectors/enroll.md#re-enroll-a-connector)).
- **The controller's web certificate**, which browsers and the command line see at the public URL,
  is a different one: from ACME, from files, or self-signed
  ([Domains and certificates](../domains-and-certificates.md)). Agents never rely on it except to
  download the CA's certificates at enrollment, and then they check those against the pin.

## The CA pin

The **CA pin** is `sha256:` and the base64 SHA-256 of the root's public key, such as
`sha256:XOCDT8EkqMT2J5JWgt+BH8H82MFTr37JH+8l70Fe2vk=`. It is not a secret.

- Every install command carries it as `--ca-pin`, and `rpmgr enroll` needs it.
- At enrollment, the host downloads the controller's certificates and keeps only the root that
  matches the pin. Nothing in between, such as a TLS-intercepting proxy, can make it trust another
  CA, and there is no "trust on first use" ([04](../../04-security.md#join-command)).
- A pin of another installation fails with `pki: no root in the bundle matches the pin`.

You find the pin:

- in the web UI, under **Settings**, **PKI**: **Root pin, for rpmgr enroll --ca-pin**;
- in every install command the web UI or `rpmgr get install-command` shows;
- in the output of `rpmgr controller init`, and with `rpmgr ca status` on the controller host.

## See the CA's keys

### With the web UI

Under **Settings**, the Instance Admin opens **PKI**. **Certificate authority** shows the trust
domain, the root pin, and each key whose certificate has not expired: **Key**, **State**,
**Subject**, **Valid** and **Replaced on**, the day the schedule replaces it. The states are
**Next** (made ahead and announced to agents, not signing yet), **Active** and **Retired**
(replaced, still verifying what it signed until it expires). With the root offline the page says
so, has no rotation button, and shows a notice while the next intermediate waits for the root's
signature or its signature is not valid, and while the sealed root key may still be recoverable
([Take the root offline](#take-the-root-offline)).

### With the command line

On the controller host, as root; it needs no KEK:

```sh
sudo rpmgr ca status
```

```text
Trust domain: rpmgr-ewl35s75
Root pin:     sha256:XOCDT8EkqMT2J5JWgt+BH8H82MFTr37JH+8l70Fe2vk=
Root key:     online (sealed in the database)

KIND              STATE   NOT BEFORE  NOT AFTER   ROTATES     SUBJECT
root              active  YYYY-MM-DD  YYYY-MM-DD  -           CN=rpmgr root CA rpmgr-ewl35s75
intermediate      active  YYYY-MM-DD  YYYY-MM-DD  YYYY-MM-DD  CN=rpmgr issuing CA rpmgr-ewl35s75
config-signing    active  YYYY-MM-DD  YYYY-MM-DD  YYYY-MM-DD
audit-checkpoint  active  YYYY-MM-DD  YYYY-MM-DD  YYYY-MM-DD
```

The lifetimes and the rotation schedule behind the dates are in
[04](../../04-security.md#ca-hierarchy). With the root offline, the `Root key` line says so, and a
warning follows until the KEK is rotated ([Take the root offline](#take-the-root-offline)).

## Rotate the issuing intermediate

The controller rotates the intermediate on its own, well before it expires, with an overlap: the
new one issues from then on, and the old one keeps verifying the certificates it issued until they
expire. Agents get the new chain with their next renewal. The snapshot-signing and audit-checkpoint
keys rotate the same way, announced to agents ahead ([04](../../04-security.md#ca-rotation)).

Rotate it by hand only when you have a reason, such as a suspicion that its key was exposed:

- **Web UI**: **Settings**, **PKI**, **Rotate the intermediate now…**, confirm with **Rotate it**,
  and confirm it is you (a step-up).
- **Command line**, on the controller host; it needs the KEK:

  ```sh
  sudo rpmgr ca rotate-intermediate
  ```

  ```text
  The new issuing intermediate CN=rpmgr issuing CA rpmgr-ewl35s75 is active, valid until YYYY-MM-DDTHH:MM:SSZ; the old one is retired and keeps
  verifying the certificates it issued. Running controllers load it …; agents
  receive the new chain at their next renewal.
  ```

  With the KEK in a systemd credential, run it inside a unit that loads the credential, as the
  runbooks show
  ([Rotate the issuing intermediate](../../10-operations.md#rotate-the-issuing-intermediate);
  [Rotate the KEK](../../10-operations.md#rotate-the-kek)). The command is recorded in the
  instance's audit log as `local-cli`.

  With the KEK in a Vault or OpenBao Transit key (`kek.source: kms`), the command reads the
  credential files of the boot file and asks Transit to wrap the new key, so it runs as a user that
  can read those files, and Transit must be reachable. If it is not, the command stops with the
  reason and changes nothing
  ([Boot files](../reference/boot-files.md#controller)).

Running controllers load the new intermediate on their own, shortly after
([04](../../04-security.md#ca-rotation)). When every agent's certificate is issued by the new
intermediate, the rotation is complete.

## Agent certificates and passwords

The Instance Admin sets, under **Settings**, **PKI**, in **Agent certificates and passwords**:

- **Agent certificate lifetime (days)**: how long an agent's certificate lasts. Shorter limits how
  long a stolen certificate is useful if a revocation cannot be pushed; agents renew at a fixed
  share of it.
- **Grace after expiry (days, 0 for none)**: how long after its certificate expired an agent that
  was offline may still get a new one without re-enrolling; 0 turns the grace period off.
- **Password hashing**: **Default**, or **Low memory (below 1 GiB)** for small controller hosts.
  New and changed passwords use it; others are upgraded at their next sign-in
  ([04](../../04-security.md#human-authentication-and-sessions)).

The ranges and defaults of the first two are in [04](../../04-security.md#leaf-certificates). With
the command line:

```sh
rpmgr update settings --instance --set leaf_certificate_lifetime=3d --set expired_certificate_grace=14d
```

A new lifetime applies to the certificates issued from then on, at each agent's next renewal.

## Revocation

Revoking takes effect at once, and does not wait for certificates to expire
([04](../../04-security.md#revocation)):

- Decommissioning a connector or gateway, `rpmgr leave`, a re-enrollment and the purge of an
  ephemeral connector revoke the agent's identity or its old certificates.
- The controller sends every gateway, connector and controller node a signed **deny-list** of
  revoked certificates and identities, apart from their configuration. Each keeps it on disk and
  checks it on every connection, so a revoked connector is refused at once, even by a gateway that
  restarted while the controller was down. Sessions of a revoked agent are closed immediately.
- An entry stays on the list only until the certificate it covers would have expired, which keeps
  the list small. There is no CRL and no OCSP: every party that checks certificates has the list.
- Every revocation is also written to the revocation log, outside the database, so that restoring
  an older backup cannot bring a revoked certificate back
  ([Backup and restore](backup-and-restore.md)).

`rpmgr status` on an agent host shows how many entries its deny-list has
([Status and diagnostics](../connectors/status-and-diagnostics.md#rpmgr-status)).

## Take the root offline

By default the root's key is sealed in the controller's database under the KEK. For a high-assurance
installation it can leave the controller: it moves into a file that a passphrase protects, you keep
the file on offline media, and the root signs only on a host you choose, when a new intermediate is
due ([Offline root CA](../../04-security.md#offline-root-ca)). A controller that runs keeps serving.
It cannot sign an intermediate itself, and it has no command that brings the root's key back.

1. On the controller host, as root, with the KEK (in a systemd credential, run it inside a unit
   that loads it, as the runbooks show):

   ```sh
   sudo rpmgr ca offline-root --out /root/rpmgr-root.age
   ```

   It writes the file, reads it again from disk, checks that its key is the database's, and only
   then removes the key from the database. It never overwrites a file. It generates a passphrase and
   shows it once, and stores it nowhere. Pass `--passphrase-file <file>` or `--prompt` to use your
   own; it must be long and unpredictable enough, and is never an argument. If the command fails
   after the key may already be marked as offline, it keeps the file and shows the generated
   passphrase with the error: write it down, and read `rpmgr ca status` before you go on.
2. Write the passphrase down and keep it apart from the media. Move the file to offline media and
   delete every other copy, on the controller host too. Keep a second copy of the media.
3. **Rotate the KEK** and destroy the old one. Removing the key from the database does not erase
   what was sealed: free pages, the write-ahead log and every older backup still hold it, and the
   old KEK opens it. `rpmgr ca status` and **Settings**, **PKI** warn until the KEK is rotated
   ([Rotate the KEK](../../10-operations.md#rotate-the-kek)). Take a new backup afterwards; backups
   made before cannot be opened any more, which is the point.

A restore of an older backup that still held the key takes it out again, and says so
([Backup and restore](backup-and-restore.md)).

### Sign the next intermediate

The intermediate is not replaced on its own while the root is offline: the controller makes the
key and waits for a signature. **Settings**, **PKI** says when it is time, and
`rpmgr ca rotate-intermediate` refuses without `--csr-out`
([Rotate the issuing intermediate](../../10-operations.md#rotate-the-issuing-intermediate)):

```sh
sudo rpmgr ca rotate-intermediate --csr-out next.csr    # on the controller host
rpmgr ca sign-intermediate --root-file rpmgr-root.age --csr next.csr --out next.crt   # offline host
sudo rpmgr ca import-intermediate --in next.crt         # controller host
```

**Settings**, **PKI** and `rpmgr ca status` show a notice with the key's hash while the request
waits for its signature. It turns critical shortly before the active intermediate expires
([04](../../04-security.md#offline-root-ca)); an expired intermediate cannot issue certificates. If
the signed intermediate is not valid when the schedule would use it, for instance because the
offline host's clock was off, a critical notice says so: make a new request, sign it and import it,
which retires the stale one.

The first command prints the SHA-256 of the new key. `sign-intermediate` needs no database, KEK or
controller. It asks for the passphrase and shows the subject, the key's hash, the validity and the
constraints: compare the hash with the first command's, and confirm (`--yes` replaces the question
on a host where nobody is, and then needs `--key-sha256` with that hash). `import-intermediate`
needs no KEK. It refuses a certificate that is for another key, does not chain to the root, is not
limited to the trust domain or has the wrong path length, and changes nothing then. The commands are
recorded in the instance's audit log as `local-cli`.

## Rotate the root

The root lasts ten years. When you want a new one earlier, for instance to move to an offline root
or to retire an old key, you rotate it **without enrolling anything again**: the old root vouches
for the new one, both roots are trusted for a while, and agents that are online take the new root
from their snapshots ([Root rotation](../../04-security.md#root-rotation)). A root whose key
leaked is not rotated this way, see below.

```sh
sudo rpmgr ca new-root          # on the controller host
```

With the root online this makes the new root and its intermediate, lets the old root sign both, and
moves issuing to the new root at once. It prints the **new pin**, which you use once the old root is
dropped; until then the install commands and `rpmgr ca status` keep the old pin, so that an agent
you enroll meanwhile holds both roots. Running controllers load the change within a minute.
Certificates that were issued before keep working, agents that know only the old
root keep verifying the new certificates, and gateways and the controller accept both roots with
no restart.

With the root **offline** the command needs `--csr-out` and stops after it wrote two requests; the
old root signs them on its host, and you import both:

```sh
sudo rpmgr ca new-root --csr-out new-root.csr                  # controller host: new-root.csr and new-root.csr.intermediate
rpmgr ca sign-intermediate --kind cross-root --root-file rpmgr-root.age --csr new-root.csr --out x.crt          # offline host
rpmgr ca sign-intermediate --root-file rpmgr-root.age --csr new-root.csr.intermediate --out y.crt               # offline host
sudo rpmgr ca import-intermediate --in x.crt                    # controller host, then the same for y.crt
```

`new-root` prints the key hashes to compare with what `sign-intermediate` shows. Nothing changes
until both certificates are in; the controller then moves issuing to the new root within the hour,
and `rpmgr ca status` says what still waits. The old root's key never goes into the database.
While a rotation runs, `rpmgr ca rotate-intermediate` is refused, so do not let one that waits
stall: `rpmgr ca status` and the controller's log warn when the active intermediate expires
within 30 days. `rpmgr ca new-root --abort` gives up a rotation that has not moved issuing: it
removes the new root and its intermediate, and the old root issues as before.

**The new root is online.** After a rotation of an offline root the new root's key is in the
database, sealed under the KEK, and `rpmgr ca status` warns "issuing root online". Once issuing has
moved, take it offline again with `rpmgr ca offline-root`, as in [the offline
root](#take-the-root-offline), and rotate the KEK.

**Watch the overlap.** `rpmgr ca status` shows both roots, the date from which the old root can be
dropped (the longest agent certificate lifetime plus the grace period for expired certificates,
37 days with the defaults, [Settings](settings.md)), and the **agents that do not hold the new
root**: those that have not connected since, or that are too old to learn it. Update, re-enroll or
decommission them.

**Drop the old root.** The controller does it by itself after the overlap, but never while an
enabled agent that connected since still lacks the new root: it logs "root rotation stalled" then.
You can do it by hand:

```sh
sudo rpmgr ca drop-root
```

Before the date it refuses and names the date; `--force` is accepted before it only while no
enabled agent seen within the overlap lacks the new root, one that was offline across the switch
included. After the overlap, `--strand-stragglers` drops the old root although some agents lack the
new one, after asking (`--yes` skips the question): they have to be enrolled again, and the drop
lists them. Disabled agents that lack the new root are named in `ca status` and in the drop output.
After the drop the bundle is the new root
alone, and agents that were online learn it from their next snapshot. An agent drops a root only
on a snapshot that is newer than the one it runs and that it can verify without that root, so a
replayed old snapshot changes nothing.

## The root, if it leaked

If the root's key is compromised, every certificate is untrusted, and the old root must not
survive in any form. `rpmgr ca new-root --compromised` replaces it with a new root in the same
trust domain, so every identity and route stays, **but every agent has to enroll again**: agents
trust the old root until they do, so none can connect to the new controller, and public traffic
stops with the gateways. Plan for that outage
([Root compromise](../../10-operations.md#root-compromise),
[04](../../04-security.md#root-compromise)).

1. **Stop what you can reach.** Stop the gateways and connectors you can, so the old key's
   exposure ends now and not when their certificates expire.
2. **Stop the controller, then replace the root** on the controller host (these `ca` commands work on a
   SQLite controller only in this phase). The command refuses
   while a controller runs, asks for a confirmation, and writes one single-use token per connector
   and gateway to a new file that only you can read; it never overwrites a file and never prints a
   token:

   ```sh
   sudo rpmgr ca new-root --compromised --tokens-out /root/reenroll-tokens
   ```

   It ends every key of the old CA and wipes the sealed ones, revokes every certificate,
   invalidates the enrollment tokens that were unused, and prints the **new pin**. All-in-one's own
   gateway and connector, and ephemeral connectors, get no token: an ephemeral connector needs a new
   enrollment token. `--token-ttl`
   sets how long the tokens last. If the command fails, nothing changed and the file is removed;
   run it again. A file left by an interrupted run is never overwritten, so delete it first.
3. **Start the controller.** It trusts the new root alone. `rpmgr ca status` warns, naming them,
   until every connector and gateway has enrolled again.
4. **Enroll every agent again, gateways first.** Each line of the file holds the agent's role,
   org, ID and name, then its token, separated by tabs. Take the token of one agent to a file on
   its host, and enroll with the new pin; the agent keeps its identity and routes:

   ```sh
   awk -F'\t' '$3 == "<id>" { printf "%s", $5 }' /root/reenroll-tokens > token
   chmod 0600 token
   sudo rpmgr enroll --controller https://panel.example.com --ca-pin <new pin> --token-file token --replace
   ```

   An agent that is given the old pin finds no matching root and stops, and its token stays
   unused. Delete the tokens file and the token files when every agent has enrolled.
5. **Find out how the key leaked**, and rotate the KEK ([Rotate the KEK](../../10-operations.md#rotate-the-kek)).

A backup taken before the replacement is refused by `rpmgr restore` on this host, because it would
bring the compromised root back; a restore on another host that has none of this host's
`revocations.log` cannot know, so **destroy the backups from before the replacement**. Restore a
later one, and take a backup now
([Backup and restore](backup-and-restore.md#the-revocation-log-sink)). Keep the controller's
database and its KEK, which protects the CA's keys, apart and backed up.
