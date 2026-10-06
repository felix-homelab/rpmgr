// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ariga.io/atlas/sql/migrate"

	"github.com/felix-homelab/rpmgr/spikes/s5/store"
)

// TestMigrate_FromEmptyMatchesEnt: every migration applies cleanly to an empty database, a second
// run applies nothing, and the resulting schema equals the Ent schema, composite keys included.
func TestMigrate_FromEmptyMatchesEnt(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		ctx := context.Background()
		db, _ := emptyDB(t, d)
		dir := embeddedDir(t, name)
		if err := store.Migrate(ctx, d, db, dir, 0); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		if err := store.Migrate(ctx, d, db, dir, 0); err != nil {
			t.Fatalf("second migrate: %v", err)
		}
		if err := store.Check(ctx, d, db); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+store.RevisionTable).Scan(&n); err != nil {
			t.Fatal(err)
		}
		files, _ := dir.Files()
		if n != len(files) {
			t.Fatalf("revisions: got %d, want %d", n, len(files))
		}
	})
}

// TestMigrate_IncrementalKeepsData: data written at migration 1 survives migration 2, which on
// SQLite rebuilds route_targets and routes to add a composite foreign key and a column.
func TestMigrate_IncrementalKeepsData(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		ctx := context.Background()
		db, _ := emptyDB(t, d)
		dir := embeddedDir(t, name)
		if err := store.Migrate(ctx, d, db, dir, 1); err != nil {
			t.Fatalf("migration 1: %v", err)
		}
		// Fixtures at schema version 1, written with plain SQL (the Ent client is at version 2).
		for _, q := range []string{
			"INSERT INTO orgs (id, name, slug) VALUES ('org_a', 'A', 'a'), ('org_b', 'B', 'b')",
			"INSERT INTO gateway_groups (id, org_id, name) VALUES ('gwg_a', 'org_a', 'eu'), ('gwg_b', 'org_b', 'eu')",
			"INSERT INTO connectors (id, org_id, name) VALUES ('con_a', 'org_a', 'nas'), ('con_b', 'org_b', 'nas')",
			"INSERT INTO routes (id, org_id, name, type, enabled, gateway_group_id) VALUES ('rte_a', 'org_a', 'web', 'http', true, 'gwg_a'), ('rte_b', 'org_b', 'web', 'http', false, 'gwg_b')",
			"INSERT INTO route_targets (id, org_id, host, port, connector_id, route_id) VALUES ('tgt_a', 'org_a', 'h', 80, 'con_a', 'rte_a'), ('tgt_b', 'org_b', 'h', 81, 'con_b', 'rte_b')",
		} {
			if _, err := db.ExecContext(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		if err := store.Migrate(ctx, d, db, dir, 0); err != nil {
			t.Fatalf("migration 2: %v", err)
		}
		if err := store.Check(ctx, d, db); err != nil {
			t.Fatal(err)
		}
		var port int
		var enabled bool
		var desc string
		if err := db.QueryRowContext(ctx, "SELECT t.port, r.enabled, r.description FROM route_targets t JOIN routes r ON r.id = t.route_id WHERE t.id = 'tgt_b'").Scan(&port, &enabled, &desc); err != nil {
			t.Fatal(err)
		}
		if port != 81 || enabled || desc != "" {
			t.Fatalf("data after migration 2: port %d enabled %v description %q", port, enabled, desc)
		}
		// The new composite key is enforced: org B's target cannot use org A's health check.
		if _, err := db.ExecContext(ctx, "INSERT INTO health_checks (id, org_id, type, interval_seconds) VALUES ('hck_a', 'org_a', 'tcp', 10)"); err != nil {
			t.Fatal(err)
		}
		_, err := db.ExecContext(ctx, "UPDATE route_targets SET health_check_id = 'hck_a' WHERE id = 'tgt_b'")
		if !isFKViolation(err) {
			t.Fatalf("cross-org health check after migration 2: want a foreign-key violation, got %v", err)
		}
		if _, err := db.ExecContext(ctx, "UPDATE route_targets SET health_check_id = 'hck_a' WHERE id = 'tgt_a'"); err != nil {
			t.Fatalf("same-org health check: %v", err)
		}
	})
}

// copyDir copies an Atlas directory into memory.
func copyDir(t *testing.T, src migrate.Dir) *migrate.MemDir {
	t.Helper()
	files, err := src.Files()
	if err != nil {
		t.Fatal(err)
	}
	dst := &migrate.MemDir{}
	for _, f := range files {
		if err := dst.WriteFile(f.Name(), f.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := src.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.WriteSumFile(dst, sum); err != nil {
		t.Fatal(err)
	}
	return dst
}

// TestMigrate_ChecksumMismatchRefused: an edited migration or an unlisted file is refused before
// anything runs.
func TestMigrate_ChecksumMismatchRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		ctx := context.Background()
		files, _ := embeddedDir(t, name).Files()

		edited := copyDir(t, embeddedDir(t, name))
		if err := edited.WriteFile(files[0].Name(), append(files[0].Bytes(), []byte("\n-- edited\n")...)); err != nil {
			t.Fatal(err)
		}
		db, _ := emptyDB(t, d)
		if err := store.Migrate(ctx, d, db, edited, 0); !errors.Is(err, migrate.ErrChecksumMismatch) {
			t.Fatalf("edited file: want ErrChecksumMismatch, got %v", err)
		}

		extra := copyDir(t, embeddedDir(t, name))
		if err := extra.WriteFile("20991231000000_extra.sql", []byte("CREATE TABLE extra (id text);\n")); err != nil {
			t.Fatal(err)
		}
		if err := store.Migrate(ctx, d, db, extra, 0); !errors.Is(err, migrate.ErrChecksumMismatch) {
			t.Fatalf("unlisted file: want ErrChecksumMismatch, got %v", err)
		}
		var n int
		err := db.QueryRowContext(ctx, "SELECT count(*) FROM orgs").Scan(&n)
		if err == nil {
			t.Fatal("orgs exists although every run was refused")
		}
	})
}

// withFile returns the embedded directory plus one extra file, with a valid atlas.sum.
func withFile(t *testing.T, name, file, body string) migrate.Dir {
	t.Helper()
	dir := copyDir(t, embeddedDir(t, name))
	if err := dir.WriteFile(file, []byte(body)); err != nil {
		t.Fatal(err)
	}
	sum, err := dir.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.WriteSumFile(dir, sum); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestMigrate_FailingFileRollsBack: a migration that fails half-way leaves no table and no
// revision behind.
func TestMigrate_FailingFileRollsBack(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		ctx := context.Background()
		db, _ := emptyDB(t, d)
		dir := withFile(t, name, "20991231000000_broken.sql",
			"CREATE TABLE half_done (id text NOT NULL);\nINSERT INTO no_such_table VALUES (1);\n")
		err := store.Migrate(ctx, d, db, dir, 0)
		if err == nil || !strings.Contains(err.Error(), "20991231000000_broken.sql") {
			t.Fatalf("want an error naming the broken file, got %v", err)
		}
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM half_done").Scan(&n); err == nil {
			t.Fatal("half_done exists: the failed file was not rolled back")
		}
		if err := db.QueryRowContext(ctx, rebind(d, "SELECT count(*) FROM "+store.RevisionTable+" WHERE version = ?"), "20991231000000").Scan(&n); err != nil || n != 0 {
			t.Fatalf("revision of the failed file: count %d, err %v", n, err)
		}
		// The earlier files were applied and stay applied.
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM route_targets").Scan(&n); err != nil {
			t.Fatalf("route_targets after the failed file: %v", err)
		}
	})
}

// TestMigrate_SQLiteRebuildViolationRefused: a SQLite migration that switches foreign keys off,
// as Atlas's table rebuilds do, and leaves a violating row is refused by the foreign_key_check and
// rolled back.
func TestMigrate_SQLiteRebuildViolationRefused(t *testing.T) {
	ctx := context.Background()
	db, _ := emptyDB(t, store.SQLite)
	dir := withFile(t, "sqlite", "20991231000000_orphan.sql", strings.Join([]string{
		"PRAGMA foreign_keys = off;",
		"INSERT INTO orgs (id, name, slug) VALUES ('org_x', 'X', 'x');",
		"INSERT INTO route_targets (id, org_id, host, port, connector_id, route_id) VALUES ('tgt_x', 'org_x', 'h', 80, 'con_missing', 'rte_missing');",
		"PRAGMA foreign_keys = on;",
	}, "\n")+"\n")
	err := store.Migrate(ctx, store.SQLite, db, dir, 0)
	if err == nil || !strings.Contains(err.Error(), "foreign key violations") {
		t.Fatalf("want a foreign_key_check failure, got %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM orgs WHERE id = 'org_x'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("org_x after the refused file: count %d, err %v", n, err)
	}
	var fk int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign keys after the refused file: %d, err %v", fk, err)
	}
}

// TestMigrate_DirectoryUpToDate: generating again from the Ent schema yields no new migration,
// the check CI runs so that committed migrations never lag the schema.
func TestMigrate_DirectoryUpToDate(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		dev, _ := emptyDB(t, d)
		err := store.Diff(context.Background(), d, dev, copyDir(t, embeddedDir(t, name)), "check")
		if !errors.Is(err, migrate.ErrNoPlan) {
			t.Fatalf("want migrate.ErrNoPlan (directory up to date), got %v", err)
		}
	})
}

// TestCheck_DetectsMissingCompositeKey: Check fails when a composite key is missing from the live
// schema, so the schema-equality test of CI would catch it.
func TestCheck_DetectsMissingCompositeKey(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		ctx := context.Background()
		_, db := migratedClient(t, d, name)
		switch d {
		case store.Postgres:
			if _, err := db.ExecContext(ctx, `ALTER TABLE route_targets DROP CONSTRAINT route_targets_connectors_targets,
  ADD CONSTRAINT route_targets_connectors_targets FOREIGN KEY (connector_id) REFERENCES connectors (id)`); err != nil {
				t.Fatal(err)
			}
		case store.SQLite:
			// SQLite cannot drop a constraint: rebuild route_targets with a single-column key.
			for _, q := range []string{
				"PRAGMA foreign_keys = off",
				"CREATE TABLE new_rt (id text NOT NULL, org_id text NOT NULL, host text NOT NULL, port integer NOT NULL, connector_id text NOT NULL, health_check_id text NULL, route_id text NOT NULL, PRIMARY KEY (id), CONSTRAINT route_targets_connectors_targets FOREIGN KEY (connector_id) REFERENCES connectors (id) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT route_targets_health_checks_targets FOREIGN KEY (org_id, health_check_id) REFERENCES health_checks (org_id, id) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT route_targets_routes_targets FOREIGN KEY (org_id, route_id) REFERENCES routes (org_id, id) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT route_targets_orgs FOREIGN KEY (org_id) REFERENCES orgs (id) ON UPDATE NO ACTION ON DELETE NO ACTION)",
				"DROP TABLE route_targets",
				"ALTER TABLE new_rt RENAME TO route_targets",
				"CREATE UNIQUE INDEX routetarget_org_id_id ON route_targets (org_id, id)",
				"PRAGMA foreign_keys = on",
			} {
				if _, err := db.ExecContext(ctx, q); err != nil {
					t.Fatalf("%s: %v", q, err)
				}
			}
		}
		err := store.Check(ctx, d, db)
		if err == nil || !strings.Contains(err.Error(), "connectors_targets") {
			t.Fatalf("want Check to report the changed key, got %v", err)
		}
	})
}
