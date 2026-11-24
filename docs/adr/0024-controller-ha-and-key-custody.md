# ADR-0024: PostgreSQL for the controller, keys in Transit or offline, roots replaced by cross-signing

Status: Accepted (decided by the product owner: plan R20 to R26, 2026-10-19, and D174 and D175,
2026-11-24) · Date: 2026-11-24 · Extends [ADR-0008](0008-internal-ca-mtls-spiffe.md) and
[ADR-0011](0011-sqlite-postgres-ent-atlas.md)

## Context

[ADR-0011](0011-sqlite-postgres-ent-atlas.md) chose PostgreSQL for HA and left its operation open.
[ADR-0008](0008-internal-ca-mtls-spiffe.md) named an offline root and said a root compromise cannot
be repaired in-band. Phase 2 builds both ([D58](../14-open-decisions.md#project-and-process)).

- **The database holds every secret and is reached over a network.** A password in a DSN, an
  unverified TLS connection or a second controller on the same database each break a promise of
  [04](../04-security.md).
- **A KEK on the controller's disk is the weakest link** of the envelope encryption. A key service
  that never releases the KEK, and a root that is not on the controller at all, remove it.
- **A root cannot be swapped in the field** without a way for agents to trust a new one. The pin of
  [ADR-0008](0008-internal-ca-mtls-spiffe.md) rules out trust on first use, so the new root must be
  vouched for by the old one.
- **The image has no `pg_dump`**, and a backup that other tools made skips the steps of a restore.

## Decision

**The database** ([06](../06-data-model.md#database-engines), [D174](../14-open-decisions.md#engineering),
[D176](../14-open-decisions.md#engineering), [D177](../14-open-decisions.md#engineering))
- Every PostgreSQL major the project supports when a release ships; the controller refuses an older
  server at start.
- The password comes from a file or a systemd credential; the TLS connection is `verify-full`
  except on loopback or a Unix socket; advisory locks guard migrations and the controller.
- A **copier** moves a database between the dialects in foreign-key order, keeping `config_seq`,
  the `db_epoch` of a migration and every sealed value byte for byte. `rpmgr migrate-db` runs it
  in both directions ([D175](../14-open-decisions.md#engineering)); `rpmgr backup` and
  `rpmgr restore` run it between PostgreSQL and the SQLite archive.
- A lease expires by the database's clock, so skewed replica clocks cannot make two holders.

**The KEK** ([04](../04-security.md#secrets-at-rest-and-in-logs), [D178](../14-open-decisions.md#engineering))
- The data key is wrapped through a `Wrapper`: a local AES-256-GCM key as today, or a Vault or
  OpenBao **Transit** key that the controller asks to encrypt, decrypt and rewrap. Envelope format
  v2 records which; v1 stays readable.
- Nothing is derived from the KEK any more. The keys of page tokens are random, sealed in the
  database like any other secret.

**The root** ([04](../04-security.md#offline-root-ca), [04](../04-security.md#root-rotation),
[D179](../14-open-decisions.md#engineering), [D180](../14-open-decisions.md#engineering))
- The root key may leave the controller as an **age-passphrase file**; the database then holds the
  certificate only. The root signs intermediates and cross-certificates on an offline host.
- A planned rotation **cross-signs** the new root, and the new issuing intermediate, with the old
  root, and ships both roots in `Welcome` and snapshots; an agent keeps a root only when a
  cross-certificate from a root it trusts verifies.
- A compromised root is replaced **within the same trust domain**, without a cross-certificate. The
  data plane is cut until every agent has re-enrolled; the runbook says so.

## Consequences

**Positive**

- A stolen database dump or disk image opens nothing without the KEK, and with Transit the KEK is
  never on the host.
- A leaked controller host no longer leaks the root once the root is offline **and the KEK has been
  rotated**, which the ceremony includes: the sealed key survives in free pages, logs and old
  backups until the KEK that wrapped it is destroyed.
- A root can be rotated without re-enrolling a fleet that is online during the overlap.
- One copier serves migration, backup and restore, so there is one path to test.

**Negative**

- A Transit outage stops what has to open a secret that is not loaded yet.
- An offline root is only as safe as its passphrase and the medium it is kept on.
- Root compromise stays a hard cut. A new trust domain would cost the same re-enrollment and lose
  identities, so it is not chosen.
- A row-by-row copy is slower than `pg_dump` on a large database.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| The vendors' Vault client library | A large dependency tree for four calls, and the controller's error handling and logging would sit behind it ([08](../08-software-stack.md#data)) |
| `pg_dump` in the image | Adds a PostgreSQL client of a version that must match the server, and skips the restore's steps |
| A hardware token for the offline root | Stronger, but the Phase 2 operators are homelabs and small companies that own none; a later `ca` backend can add it |
| Root rotation by re-enrollment only | Every agent re-enrolls by hand, also when nothing leaked |
| A new trust domain after a compromise | Changes every identity and every route's owner records, and the data plane is cut all the same |
| A lease clock per replica with a safety margin | A margin is a guess; the database's own clock is one source |

## Verification

Each part has a slice in P2-M08 and P2-M09 ([13](../13-roadmap.md#phase-2--production)) and named
tests in [12](../12-testing-and-quality.md#security-testing). What is not yet checked is the
Transit API of both Vault and OpenBao (VB-28), the whole suite on the oldest and the newest
PostgreSQL major (VB-29) and conditional create on object stores other than the CI container
(VB-24).
