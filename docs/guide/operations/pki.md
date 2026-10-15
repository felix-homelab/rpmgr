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
(replaced, still verifying what it signed until it expires).

### With the command line

On the controller host, as root; it needs no KEK:

```sh
sudo rpmgr ca status
```

```text
Trust domain: rpmgr-ewl35s75
Root pin:     sha256:XOCDT8EkqMT2J5JWgt+BH8H82MFTr37JH+8l70Fe2vk=

KIND              STATE   NOT BEFORE  NOT AFTER   ROTATES     SUBJECT
root              active  YYYY-MM-DD  YYYY-MM-DD  -           CN=rpmgr root CA rpmgr-ewl35s75
intermediate      active  YYYY-MM-DD  YYYY-MM-DD  YYYY-MM-DD  CN=rpmgr issuing CA rpmgr-ewl35s75
config-signing    active  YYYY-MM-DD  YYYY-MM-DD  YYYY-MM-DD
audit-checkpoint  active  YYYY-MM-DD  YYYY-MM-DD  YYYY-MM-DD
```

The lifetimes and the rotation schedule behind the dates are in
[04](../../04-security.md#ca-hierarchy).

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

## The root

The root cannot be rotated yet: rotating it with an overlap is planned for Phase 2
([13](../../13-roadmap.md#phase-2--production)). If the root's key is compromised, every certificate
is untrusted: set up a new controller, which creates a new root and pin, and enroll every agent
again with the new pin ([Root compromise](../../10-operations.md#root-compromise)). Keep the
controller's database and its KEK, which protects the CA's keys, apart and backed up
([Backup and restore](backup-and-restore.md)).
