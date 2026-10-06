# ADR-0011: SQLite by default, PostgreSQL for HA, Ent with Atlas migrations

Status: Proposed (design phase) · Date: 2026-10-06

## Context

The Controller needs a relational store that:

- has **zero operations overhead** for homelab and small installs: one file, no extra service;
- supports **high availability**, with several controller replicas sharing state;
- builds into a **static binary** (`CGO_ENABLED=0`, [ADR-0002](0002-one-binary-three-roles.md));
- uses **versioned, reviewed migrations**, not schema changes derived at runtime;
- enforces **tenancy in one place** ([ADR-0012](0012-org-scoped-tenancy.md)).

Every additional SQL dialect multiplies migration and test work.

## Decision

**Databases**
- **SQLite** is the default, using **`modernc.org/sqlite`** (pure Go, so no cgo). It is
  single-node only.
  - Pin a current release at implementation.
  - Confirm platform coverage for every Controller target OS/arch [V S8]. Only the Controller role
    needs the database driver.
- **PostgreSQL** is used for HA and larger installs. Several controllers share it, and singleton
  jobs run under database leases ([10](../10-operations.md#high-availability)).
- **MySQL/MariaDB is dropped.** The importer still **reads** source databases in all three
  dialects (SQLite, MySQL, PostgreSQL) ([11](../11-migration.md)).

**Access layer and migrations**
- **Ent** is the data-access layer: a typed, generated client from one Go schema for both dialects.
  Its interceptors and privacy rules carry org scoping
  ([06](../06-data-model.md#tenancy-enforcement)).
- **Atlas** produces versioned, forward-only migrations from the Ent schema: one directory per
  dialect, linted, with an `atlas.sum` integrity file. Migrations are embedded in the binary.
- Migrations run under a database lock at startup, or explicitly with `rpmgr migrate` in HA mode.
- SQLite takes a `VACUUM INTO` backup before migrating.
- CI applies every migration on both dialects ([12](../12-testing-and-quality.md)).

## Consequences

**Positive**

- Homelab installs need nothing but the binary; companies can move to PostgreSQL for HA.
- One schema definition, typed queries and generated migrations reduce drift.
- Tenancy enforcement lives in the access layer instead of in every query by convention.

**Negative**

- Ent and Atlas are significant dependencies. Atlas's open-source feature set and licensing must be
  checked before committing [V S5].
- Two dialects still need two migration directories and CI on both.
- Moving SQLite → PostgreSQL needs a supported export/import path (`rpmgr backup` /
  `rpmgr restore` across dialects) ([10](../10-operations.md#high-availability)).
- Code generation adds a build step.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| sqlc + goose | Excellent for one dialect, but supporting SQLite and PostgreSQL means two query sets; tenancy only by convention |
| bun | Viable fallback (dialect-aware query builder, migrations); weaker typed generation and no privacy-rule layer |
| GORM | AutoMigrate culture instead of versioned migrations, zero-value update pitfalls, runtime reflection |
| PostgreSQL only | Forces an extra service on every homelab install |
| Keep MySQL | A third dialect for migrations, tests and support, for little demand |
| Embedded key-value store (bbolt, Badger) | No relational constraints; composite foreign keys are part of tenancy enforcement |

## Verification

- **S5**: Ent + Atlas on both dialects. Covers generated migrations, composite `(org_id, id)`
  foreign keys, privacy rules that deny by default, and the licensing/feature check.
- **S8**: `modernc.org/sqlite` (current release) on every Controller target platform, plus WAL-mode
  durability and concurrency for the expected write rate.

**Rules** ([D18](../14-open-decisions.md#engineering)), agreed before the spikes run:
- Only Apache-2.0 parts are used: Ent and the `ariga.io/atlas` Go library. If Atlas CLI features
  rpmgr needs are not in the Apache-2.0 build, migrations are generated through Ent's Go API.
- If Ent fails the S5 criteria (privacy rules that deny by default, composite foreign keys), the
  data layer uses **bun** with hand-written versioned migrations, and this ADR is superseded.
- The Controller ships only on the platforms where S8 passes; the others are documented as
  unsupported.
