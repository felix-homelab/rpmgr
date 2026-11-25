# Move between SQLite and PostgreSQL

`rpmgr migrate-db` copies a stopped controller's database into an empty one, from SQLite to
PostgreSQL or back. This page shows both directions, what the command checks and refuses, and what
it leaves behind. Read it before the move, and keep [Backup and restore](backup-and-restore.md) at
hand: a backup is the way back if anything goes wrong.

A controller can run on PostgreSQL only in the release that wires it in. Until then the command is
for preparing the move and for copying a database to a test host; its target, a boot file with
`driver: postgres`, is not yet accepted by the controller itself.

## What the command does

- It reads two files and never a database address. `--from` is a SQLite database or a boot file;
  `--to-file` is a boot file. Only the `database` section of each is read, so no password and no
  connection string is an argument. An argument that looks like one is refused.
- It copies every table into the empty target in one transaction, checks the row count and a
  content hash of every table against the source, and commits only when they agree. A failed copy
  leaves the target empty.
- It **never reads the KEK and never opens a secret**. Sealed values are copied byte for byte, so
  the target opens with the same KEK as the source, and the boot files given to the command need no
  `kek` section. The database epoch is kept, so agents see no break.
- It takes the controller lock on both databases and refuses while a controller holds either.
- Once the target has committed, it **retires the source**: a controller refuses to start on it,
  because two controllers on the same history would give agents two versions of the truth.
  `--no-retire` leaves the source usable, for a test copy; you then never run a controller on both.
- It records the migration in the target's audit log, as the actor `local-cli`
  ([Audit log](audit-log.md)).

## Move to PostgreSQL

1. Make an empty PostgreSQL database and a role that owns it, with a TLS certificate the controller
   can verify. Put the role's password in a file only the service user can read, or in a systemd
   credential; it never goes into the connection string.
2. Back up the controller (`rpmgr backup`), then stop it.
3. Copy the boot file and change its `database` section:

   ```yaml
   database:
     driver: postgres
     dsn: postgres://rpmgr@db.example.com/rpmgr?sslmode=verify-full
     password_file: /etc/rpmgr/database-password
   ```

4. Run the command with the boot file you have and the one you made:

   ```sh
   sudo rpmgr migrate-db --from /etc/rpmgr/controller.yaml --to-file /etc/rpmgr/controller-pg.yaml
   ```

   It prints each table with its row count, then one line that says the counts and hashes agree.
5. Put the new boot file in place and start the controller (from the release that runs on
   PostgreSQL).
6. Keep the SQLite database until the controller on PostgreSQL has run for a while. It is retired,
   so it cannot start by mistake.

## Move back to SQLite

Stop the controller and run the command the other way: `--from` is the PostgreSQL boot file and
`--to-file` a boot file with `driver: sqlite` and a database path that does not exist yet. The
PostgreSQL database is retired the same way.

## What it refuses

| Refusal | What to do |
|---|---|
| A controller holds the source or the target | Stop it, then run the command again |
| The target is not empty, or holds tables of something else | Use a new, empty database |
| The target's schema differs from the source's | Use an empty database, or migrate both to the same release |
| The source is behind this release | Run `rpmgr migrate` on it first, or upgrade |
| The source is retired already | It was moved before; use its target |
| A database address as an argument | Name the boot file instead |
| Source and target are the same database | Name two different databases |

None of them changes the source, and none of them leaves anything half copied in the target.

## Check the result

- Start the controller on the target and open `rpmgr status`: it shows the same revision as before.
- Agents stay connected, because the database epoch did not change.
- The target's audit log has an entry `database.migrate` by `local-cli`, with the hash that the
  command printed.

The rules behind this page are in [06](../../06-data-model.md#copying-a-database) and
[10](../../10-operations.md#moving-between-sqlite-and-postgresql); the command is in the
[CLI reference](../reference/cli.md).
