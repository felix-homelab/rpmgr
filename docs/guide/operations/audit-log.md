# Audit log

rpmgr records every change and every security event in an audit log that can prove it was not
altered. This page is for Owners and Admins who review what happened in their organisation, and for
the Instance Admin, who also reviews the instance: it covers what is recorded, how to read and
verify the log, signed checkpoints, and how long entries are kept.

## What is recorded

- **Every request that changes something**, through the web UI, the command line or the API,
  whether it succeeded, failed or was refused. Requests that only read are not recorded
  ([04](../../04-security.md#audit-log)).
- **Security events**: sign-ins and failed sign-ins, step-ups, sign-outs; API tokens made, used and
  revoked; enrollments, re-enrollments and failed enrollments; revoked identities and certificates;
  authenticators set up or removed; password resets and changes; members added, changed and
  removed.
- **Work the controller does on its own**, with the actor type `system` and the job as the actor,
  such as `acme` or `purge-agents`: ACME certificates, the purge of ephemeral connectors, the
  removal of old entries.
- **Local administration** on the controller host, such as `rpmgr ca rotate-intermediate`,
  `rpmgr kek rotate`, `rpmgr restore` or `rpmgr user reset-password`, with the actor `local-cli`.
- **Agents' own actions**, with the actor type `agent`: an enrollment, and `rpmgr leave` with the
  routes it deletes.

A failed sign-in is recorded the same way for an unknown address as for a wrong password, and a
failed enrollment with its address and reason, never the token. Refusals of a rate limit to an
anonymous caller are not recorded, so that a flood cannot fill the log; a metric counts them
instead ([Monitoring](monitoring.md#metrics)).

Each entry holds:

| Field | Web UI | What it holds |
|---|---|---|
| `seq` | **Entry** | Its place in its chain, from 1 |
| `time` | | When it was recorded |
| `actorType`, `actorId` | **Actor type** | `user`, `agent`, `system` or `anonymous`, and the user, agent or job |
| `credentialId` | **Credential** | The session or API token it acted with, never the secret |
| `authMethod` | **Authentication** | How it signed in: `session`, `token`, `pwd+otp` … |
| `ip`, `userAgent` | **Address**, **User agent** | The client |
| `requestId` | **Request ID** | The request's ID, as the API's `Rpmgr-Request-Id` header returns it |
| `action` | | What was done: the API method, such as `rpmgr.v1.RouteService.UpdateRoute` or `rpmgr.v1.AuthService.Login`, or a named event, such as `token.create`, `token.use`, `identity.revoke`, `route.delete`, `connector.enroll`, `connector.reenroll`, `agent.enroll` (a failed enrollment), `ca.rotate_intermediate`, `audit.export` or `audit.prune` |
| `targetType`, `targetId` | | The kind and ID of what it was done to |
| `result` | | `success`, `failure` or `denied` |
| `diff` | | The request, with its secrets replaced |
| `reason` | **Reason** | A reason or detail, if any |

An API token's use is recorded when its first use, or a use from a new address, is written, not on
every request; every request it makes names it as the credential.

## Chains

Entries form **hash chains**: each entry's hash covers the one before it, so an entry that is
changed, removed or put in another place breaks the chain from there on.

- **Each organisation has its own chain**, with its members' changes and events. Its Owners and
  Admins read it (the permission `audit.read`).
- **The instance chain** holds what belongs to no organisation: failed sign-ins, failed
  enrollments, local administration, and the Instance Admin's changes to the instance. Only the
  Instance Admin reads it.

## Read the log

### With the web UI

1. Open **Audit log**. It shows **This organisation**'s entries, newest first. The Instance Admin
   can switch to **The instance**.
2. To narrow it down, fill in **Action, exactly** (the whole action, such as `route.delete` or
   `rpmgr.v1.RouteService.UpdateRoute`), **Actor ID** (a user's `usr_…`, an agent's ID, or a job
   such as `acme` or `local-cli`), or both, and select **Filter**.
3. Open an entry to see its details and the request it recorded. **Older entries** loads more.

### With the API

The command line has no audit command; use the API with a token that has the scope `audit.read`
([API](../reference/api.md)):

```sh
curl -sS https://panel.example.com/rpmgr.v1.AuditService/ListAuditEntries \
  -H "Authorization: Bearer $RPMGR_TOKEN" -H "Content-Type: application/json" \
  -d '{"orgId":"org_01M4ZEHHDQE4HAJFN45X0ZD08D","action":"route.delete","pageSize":100}'
```

`ListInstanceAuditEntries` reads the instance chain, for a token of the Instance Admin with the
scope `instance.admin`. Both page with `pageToken`, newest first. Exporting the log is planned for
Phase 2 ([05](../../05-features.md#observability)).

## Verify a chain

Verification walks a whole chain from its start, or, once retention removed its first entries, from
the signed checkpoint just before the first entry left. It checks every entry against its own hash
and its predecessor's, then compares the last entry with the chain's recorded head, so a missing
entry, a changed one, one out of order or a cut-off end is found. It also checks every signed
checkpoint of the chain: its signature, and that it matches the entry it covers.

- **Web UI**: on **Audit log**, select **Verify the chain**. It answers
  **The chain is intact up to entry 31.** and
  **Its last signed checkpoint covers entry 14, from …**, or
  **The chain is broken at entry …:** with what is wrong there.
- **API**: `AuditService.VerifyAuditChain` with the org's ID, or `VerifyInstanceAuditChain`:

  ```json
  {"verification":{"intact":true,"headSeq":"31","lastCheckpoint":{"seq":"14","time":"2026-10-15T09:34:12.001231Z","keyId":"f20eb22453c4309d9eaf7888b1329e0396875e31807e515a66f919488a9f9a84"}}}
  ```

A broken chain means someone with access to the database changed it, or the database was damaged.
Keep the database as it is, compare it with a backup and the checkpoints, and treat the instance as
compromised until you know which.

## Export a chain with its proofs

An export is a file that proves itself: it holds a chain's entries, the hashes that link them and
the signed checkpoints, so that it can be verified away from the controller. Exporting takes the
permission `audit.read` for an org's chain, or the Instance Admin for the instance chain, and a
step-up ([Step-up](../../04-security.md#human-authentication-and-sessions)).

`AuditService.ExportAudit` (an org's chain) and `ExportInstanceAudit` (the instance chain) stream
the chain as JSON Lines, in parts of lines:

1. The first line is the header: the format (`rpmgr-audit-export/1`), the chain, the seq of its
   first and last entry, the seq of its newest checkpoint (`anchored_seq`) and the certificates the
   checkpoints verify with.
2. Then each entry with every field the hash covers, `prev_hash` and `hash`, and each checkpoint
   after the entry it covers. After retention removed the first entries, the export starts with the
   checkpoint that anchors the first entry left.
3. Entries after the newest checkpoint are flagged `unanchored`. No signature covers them yet; a
   later export, made after the next checkpoint, anchors them.

Every export is an entry in the chain, `audit.export`, written before the chain is read. An export
that breaks off is recorded a second time with the result `failure`.

## Signed checkpoints

Anyone who can write to the database could rewrite a whole chain and recompute its hashes. Signed
**checkpoints** guard against that: the controller regularly signs each chain's head with the CA's
audit-checkpoint key ([PKI](pki.md)), on a schedule in
[03](../../03-connections.md#timeouts-keepalive-and-backoff). A checkpoint is stored in the
database and appended to `/var/lib/rpmgr/audit-checkpoints.log`, which every backup includes. Each
line of that file carries the signer's certificate, so it can be checked with the CA's
certificates alone.

The metric `rpmgr_audit_checkpoint_age_seconds` tells how long the oldest entry has waited for a
checkpoint. For now both copies are on the controller's host, so the protection reaches only an
attacker who can change the database but not the host. Sending checkpoints to an external sink is
planned for Phase 2 ([04](../../04-security.md#audit-log)).

## How long entries are kept

Entries are kept for the instance's **audit retention**, which the Instance Admin sets: under
**Settings**, in **Audit log**, **Keep audit entries (days)**, within the range the form shows
([10](../../10-operations.md#runtime-settings-ui--settings)). With the command line:

```sh
rpmgr update settings --instance --set audit_retention=730d
```

Old entries go only as a whole beginning of a chain, up to a checkpoint, so that the rest still
verifies from that checkpoint. Each removal is recorded in the chain as `audit.prune`. A longer
retention keeps more history in the database and in backups.

## Related records

- **Revocations** are also written to a separate revocation log outside the database, which a
  restore replays, so that restoring an old backup cannot bring back a revoked credential
  ([Backup and restore](backup-and-restore.md); [04](../../04-security.md#revocation-log)).
- **Requests**: every recorded API request answers with `Rpmgr-Request-Id`; look the ID up in the
  entry's **Request ID** to find what a script did.
