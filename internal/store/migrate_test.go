// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ariga.io/atlas/sql/migrate"

	"github.com/felix-homelab/rpmgr/internal/store"
)

// forEachStoreDB runs f with an empty database of each dialect.
func forEachStoreDB(t *testing.T, f func(t *testing.T, db *store.DB)) {
	t.Helper()
	ctx := context.Background()
	t.Run("sqlite", func(t *testing.T) {
		f(t, openTest(t, filepath.Join(t.TempDir(), "m.db"), store.SQLiteOptions{}))
	})
	t.Run("postgres", func(t *testing.T) {
		admin := os.Getenv("RPMGR_TEST_PG")
		if admin == "" {
			if os.Getenv("RPMGR_TEST_REQUIRE_PG") == "1" {
				t.Fatal("RPMGR_TEST_PG is not set but PostgreSQL is required")
			}
			t.Skip("RPMGR_TEST_PG not set")
		}
		db, err := store.OpenPostgres(ctx, newPGDatabase(t, admin))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		f(t, db)
	})
}

// testDir returns a migration directory with the given files and a valid atlas.sum.
func testDir(t *testing.T, files ...string) *migrate.MemDir {
	t.Helper()
	dir := &migrate.MemDir{}
	for i := 0; i+1 < len(files); i += 2 {
		if err := dir.WriteFile(files[i], []byte(files[i+1])); err != nil {
			t.Fatal(err)
		}
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

const (
	m1 = "CREATE TABLE parents (id varchar(64) NOT NULL, name varchar(64) NOT NULL, PRIMARY KEY (id));\n" +
		"CREATE TABLE children (id varchar(64) NOT NULL, parent_id varchar(64) NOT NULL, PRIMARY KEY (id), " +
		"CONSTRAINT children_parent FOREIGN KEY (parent_id) REFERENCES parents (id));\n"
	m2 = "ALTER TABLE parents ADD COLUMN note varchar(64) NOT NULL DEFAULT '';\n"
)

func count(t *testing.T, db *store.DB, q string) int {
	t.Helper()
	var n int
	if err := db.Reader.QueryRow(q).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestMigrate_AppliesOnceAndKeepsData(t *testing.T) {
	forEachStoreDB(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		one := testDir(t, "20261001000000_one.sql", m1)
		if n, err := store.Migrate(ctx, db, one); err != nil || n != 1 {
			t.Fatalf("first migration: %d applied, %v", n, err)
		}
		if _, err := db.Writer.Exec("INSERT INTO parents (id, name) VALUES ('p', 'p')"); err != nil {
			t.Fatal(err)
		}
		two := testDir(t, "20261001000000_one.sql", m1, "20261002000000_two.sql", m2)
		if p, err := store.Pending(ctx, db, two); err != nil || len(p) != 1 || p[0].Version() != "20261002000000" {
			t.Fatalf("pending: %v, %v", p, err)
		}
		if n, err := store.Migrate(ctx, db, two); err != nil || n != 1 {
			t.Fatalf("second migration: %d applied, %v", n, err)
		}
		if n, err := store.Migrate(ctx, db, two); err != nil || n != 0 {
			t.Fatalf("third run: %d applied, %v; want nothing", n, err)
		}
		if got := count(t, db, "SELECT count(*) FROM parents WHERE id = 'p' AND note = ''"); got != 1 {
			t.Errorf("data after migration 2: %d rows", got)
		}
		if got := count(t, db, "SELECT count(*) FROM "+store.RevisionTable); got != 2 {
			t.Errorf("revisions: %d, want 2", got)
		}
	})
}

func TestMigrate_ChecksumMismatchRefused(t *testing.T) {
	forEachStoreDB(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		edited := testDir(t, "20261001000000_one.sql", m1)
		if err := edited.WriteFile("20261001000000_one.sql", []byte(m1+"-- edited\n")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Migrate(ctx, db, edited); !errors.Is(err, migrate.ErrChecksumMismatch) {
			t.Errorf("edited file: %v, want ErrChecksumMismatch", err)
		}
		unlisted := testDir(t, "20261001000000_one.sql", m1)
		if err := unlisted.WriteFile("20261009000000_extra.sql", []byte("CREATE TABLE extra (id varchar(8));\n")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Migrate(ctx, db, unlisted); !errors.Is(err, migrate.ErrChecksumMismatch) {
			t.Errorf("unlisted file: %v, want ErrChecksumMismatch", err)
		}
		if _, err := db.Reader.Exec("SELECT 1 FROM parents"); err == nil {
			t.Error("parents exists although every run was refused")
		}
	})
}

// TestMigrate_UnknownMigrationRefused: a database with an applied migration that the directory does
// not hold, as one a newer version or a development build before the baseline made, is refused
// before anything runs, also when the directory has newer files.
func TestMigrate_UnknownMigrationRefused(t *testing.T) {
	forEachStoreDB(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		if _, err := store.Migrate(ctx, db, testDir(t, "20261001000000_one.sql", m1, "20261002000000_two.sql", m2)); err != nil {
			t.Fatal(err)
		}
		squashed := testDir(t, "20261003000000_baseline.sql", "CREATE TABLE baseline (id varchar(8));\n")
		if _, err := store.Pending(ctx, db, squashed); !errors.Is(err, store.ErrUnknownMigration) || !strings.Contains(err.Error(), "20261001000000") {
			t.Errorf("pending: %v, want ErrUnknownMigration naming 20261001000000", err)
		}
		if _, err := store.Migrate(ctx, db, squashed); !errors.Is(err, store.ErrUnknownMigration) {
			t.Errorf("migrate: %v, want ErrUnknownMigration", err)
		}
		if _, err := db.Reader.Exec("SELECT 1 FROM baseline"); err == nil {
			t.Error("the refused directory ran")
		}
		older := testDir(t, "20261001000000_one.sql", m1)
		if _, err := store.Migrate(ctx, db, older); !errors.Is(err, store.ErrUnknownMigration) {
			t.Errorf("a directory without the newest applied migration: %v, want ErrUnknownMigration", err)
		}
	})
}

func TestMigrate_FailingFileRollsBack(t *testing.T) {
	forEachStoreDB(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		dir := testDir(t, "20261001000000_one.sql", m1,
			"20261002000000_broken.sql", "CREATE TABLE half_done (id varchar(8));\nINSERT INTO no_such_table VALUES (1);\n")
		n, err := store.Migrate(ctx, db, dir)
		if err == nil || !strings.Contains(err.Error(), "20261002000000_broken.sql") || n != 1 {
			t.Fatalf("want the broken file named after one applied file, got %d, %v", n, err)
		}
		if _, err := db.Reader.Exec("SELECT 1 FROM half_done"); err == nil {
			t.Error("half_done exists: the failed file was not rolled back")
		}
		if got := count(t, db, "SELECT count(*) FROM "+store.RevisionTable); got != 1 {
			t.Errorf("revisions after the failed file: %d, want 1", got)
		}
	})
}

func TestMigrate_SQLiteForeignKeyViolationRefused(t *testing.T) {
	ctx := context.Background()
	db := openTest(t, filepath.Join(t.TempDir(), "fk.db"), store.SQLiteOptions{})
	dir := testDir(t, "20261001000000_one.sql", m1,
		"20261002000000_orphan.sql", "PRAGMA foreign_keys = off;\nINSERT INTO children (id, parent_id) VALUES ('c', 'missing');\nPRAGMA foreign_keys = on;\n")
	_, err := store.Migrate(ctx, db, dir)
	if err == nil || !strings.Contains(err.Error(), "foreign key violations") {
		t.Fatalf("want a foreign_key_check failure, got %v", err)
	}
	if got := count(t, db, "SELECT count(*) FROM children"); got != 0 {
		t.Errorf("orphan row survived: %d", got)
	}
	var fk int
	if err := db.Writer.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign keys after the refused file: %d, %v", fk, err)
	}
}
