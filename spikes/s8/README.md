# Spike S8: pure-Go SQLite on the controller's platforms

Throw-away code for spike S8 ([docs/13-roadmap.md](../../docs/13-roadmap.md#phase-0--spikes),
issue #12). The result is written up in `docs/spikes/S8.md`. This directory lives only on the
branch `tmp/s8-sqlite-platforms` and, afterwards, the tag `spike/s8`.

**Question:** does `modernc.org/sqlite` (pure Go, `CGO_ENABLED=0`) cover the controller's
platforms linux/amd64, arm64, armv7 and riscv64: its own test suite, WAL, `VACUUM INTO`?

**Rule (agreed before the spike):** the controller ships only on platforms that pass; the others
are documented as unsupported.

## What is here

| File | Purpose |
|---|---|
| `store.go` | The controller's SQLite access pattern from docs/06: DSN with pragmas applied to every connection, one writer connection plus a read-only pool, a schema subset with composite `(org_id, id)` foreign keys, the `config_seq` revision counter |
| `store_test.go` | Pragmas on every pooled connection (`journal_mode=WAL`, `busy_timeout`, `foreign_keys`, `synchronous` FULL and NORMAL); read-only readers; invalid DSNs, missing directories, non-database files; composite foreign keys incl. cross-org inserts and updates, `RESTRICT`, `CASCADE`, `NOT NULL`; one writer with 8 concurrent readers (snapshot consistency, no partial commits); `busy_timeout` expiry and waiting; gap-free revisions from 16 goroutines over two writer pools with rolled-back transactions; `VACUUM INTO` under write load, restore and failure paths |
| `crash_test.go` | A writer child process killed with SIGKILL (a) inside a ~20 MiB uncommitted transaction that has spilled into the WAL and (b) during `wal_checkpoint(TRUNCATE)`; after reopening: `integrity_check`, every reported commit present, nothing of the interrupted transaction |
| `run.sh` | Builds both test suites for all targets and runs them; logs to `results/` |
| `qemu.Dockerfile` | Debian trixie with `qemu-user-static`, for running foreign binaries explicitly (no host `binfmt_misc` change) |
| `results/` | Raw logs of the runs recorded in `docs/spikes/S8.md` |

## Versions

Go 1.27.1 (`toolchain` in `go.mod`); `modernc.org/sqlite` v1.60.1 (SQLite 3.53.4),
`modernc.org/libc` v1.77.1. `modernc.org/sqlite` v1.60.1 raises the module's `go` directive to
1.26.0. QEMU 10.0.13 (Debian 13 package `qemu-user-static`).

## Repeating the runs

```sh
# From this directory, with Go and Docker installed. BIN defaults to ./bin.
./run.sh build                       # go test -c for both suites × 4 targets; builds the QEMU image
./run.sh own                         # the spike's tests: amd64 native, others under QEMU
./run.sh suite                       # modernc.org/sqlite's own test suite (about 30–90 min emulated)
./run.sh all amd64 arm64             # any subset of targets

# On an arm64 host such as the Raspberry Pi 5 of the reference testbed (D30, D38): run arm64
# and armv7 natively instead of emulated.
EMULATE= ./run.sh all arm64 arm
```

The native suite run of `TestConcurrentGoroutines` re-runs itself with `go test -race`; this
needs Go and a C compiler on the host. Under emulation the suite runs with `-inner`, which skips
only that step, and the five OFD-locking tests that re-execute the binary run in their child mode
instead (see `run.sh`).

## Notes for Phase 1

- Turn on `sqlite.StrictPragmas(true)` at start: the DSN comes from the boot file, and by
  default a `_pragma` value runs everything after a `;` as well.
- Map both `SQLITE_CONSTRAINT_FOREIGNKEY` (787) and `SQLITE_CONSTRAINT_TRIGGER` (1811, how SQLite
  reports `ON DELETE RESTRICT`) to the foreign-key error.
- `VACUUM INTO` fails on a `query_only` connection (`SQLITE_READONLY`); `rpmgr backup` opens an
  ordinary connection, which does not take the write lock.
