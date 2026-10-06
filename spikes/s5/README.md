# Spike S5: Ent + Atlas on SQLite and PostgreSQL, tenancy in one place

Throw-away code for spike S5 (issue #9, [docs/13-roadmap.md](../../docs/13-roadmap.md#phase-0--spikes)).
The result is written up in `docs/spikes/S5.md`. This branch is never merged; it is archived as
the tag `spike/s5`.

## What is here

| Path | What |
|---|---|
| `ent/schema/` | Subset schema: orgs, gateway_groups, connectors, routes, route_targets, health_checks (the last added in migration 2) |
| `ent/schema/mixin.go`, `scope.go` | `OrgMixin` (org_id, UNIQUE (org_id, id)); deny-by-default policy, org filter interceptor, org mutation hook |
| `ent/` | Generated Ent client (`go generate ./ent`) |
| `authz/` | `OrgScope`: only this package can put a scope into a context; audited system scope |
| `store/compositefk.go` | Ent diff hook that turns foreign keys between org-owned tables into composite `(org_id, …)` keys |
| `store/store.go`, `migrate.go` | Open both dialects; generate migrations through Ent's Go API; apply them with Atlas's executor and an own revision table; compare the live schema with Ent |
| `migrations/{sqlite,postgres}/` | Generated, versioned migrations with `atlas.sum`; embedded with `embed.FS` |
| `cmd/s5` | `diff`, `hash`, `apply`, `check` without the Atlas CLI |
| `store/*_test.go` | Every pass criterion, on both dialects |
| `results/` | Raw outputs of the runs below |

## Versions

Go 1.27.1; `entgo.io/ent` v0.14.6 (generator pinned as a go.mod tool); `ariga.io/atlas` v1.3.0;
`modernc.org/sqlite` v1.60.1 (SQLite 3.53.4); `github.com/jackc/pgx/v5` v5.11.0;
`golang.org/x/tools` v0.51.0 (raised, see `scripts/init-module.sh`); PostgreSQL 18.6 and 16.15
(`postgres:18-alpine`, `postgres:16-alpine`); Atlas CLI community edition built from the v1.3.0
source.

## Repeat the runs

Paths are relative to `spikes/s5`. PostgreSQL in Docker, on a random loopback port:

```sh
docker run -d --rm --name rpmgr-s5-pg18 -e POSTGRES_USER=s5 -e POSTGRES_PASSWORD=s5 \
  -p 127.0.0.1::5432 postgres:18-alpine
docker run -d --rm --name rpmgr-s5-pg16 -e POSTGRES_USER=s5 -e POSTGRES_PASSWORD=s5 \
  -p 127.0.0.1::5432 postgres:16-alpine
docker port rpmgr-s5-pg18 5432   # → 127.0.0.1:<port18>
docker port rpmgr-s5-pg16 5432   # → 127.0.0.1:<port16>
```

| Run | Command | Output |
|---|---|---|
| Tests, SQLite + PostgreSQL 18 | `scripts/test.sh <port18> 18` | `results/test-sqlite-postgres18.txt` |
| Tests, SQLite + PostgreSQL 16 | `scripts/test.sh <port16> 16` | `results/test-sqlite-postgres16.txt` |
| Apply from empty, re-apply, compare with Ent | `scripts/apply-check.sh <port18>` | `results/apply-check.txt` |
| Regenerate the newest migration, compare byte for byte | `scripts/regen-check.sh <port18>` | `results/regen-check.txt` |
| Atlas CLI community edition | `scripts/atlas-community.sh <atlas-src> <port18>` | `results/atlas-community-cli.txt` |

`<atlas-src>` is the extracted `https://codeload.github.com/ariga/atlas/tar.gz/refs/tags/v1.3.0`.
The tests need `RPMGR_S5_PG` (an admin DSN); `scripts/test.sh` sets it and requires PostgreSQL
(`RPMGR_S5_REQUIRE_PG=1`), and runs with `-race` when a C compiler is present.

Generating code and migrations:

```sh
go generate ./ent                                   # Ent client
go run ./cmd/s5 diff -dialect sqlite -name <name>   # next SQLite migration (dev DB in memory)
go run ./cmd/s5 diff -dialect postgres -dev 'postgres://s5:s5@127.0.0.1:<port>/<empty db>?sslmode=disable' -name <name>
```

The schema imports the generated `ent/intercept` package, so a checkout without generated code
needs two passes (first without `scope.go`'s interceptor). Migration 1 was generated with the
pre-release of `ariga.io/atlas` that Ent v0.14.6 requires, before the version was pinned; with
v1.3.0 it replays without a plan, passes lint, applies and matches the Ent schema, and migration 2
regenerates byte-identically (`results/regen-check.txt`).
