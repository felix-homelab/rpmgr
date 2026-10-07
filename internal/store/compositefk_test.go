// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ariga.io/atlas/sql/migrate"
	atlas "ariga.io/atlas/sql/schema"

	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
)

// TestOrgForeignKey_RawSQL: the org_id of an org-owned table references orgs(id), a key the diff
// hook adds; the composite keys between org-owned tables are tested with the tables that have
// them (fleet schema).
func TestOrgForeignKey_RawSQL(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, db *store.DB) {
		a, b := seed(t, c)
		ctx := context.Background()
		for name, q := range map[string]string{
			"unknown org":               "INSERT INTO gateway_groups (id, org_id, name) VALUES ('gwg_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R', 'org_none', 'x')",
			"move to an unknown org":    "UPDATE gateway_groups SET org_id = 'org_none' WHERE id = '" + a.gwg + "'",
			"delete an org with groups": "DELETE FROM orgs WHERE id = '" + b.org + "'",
		} {
			if _, err := db.Writer.ExecContext(ctx, q); !store.IsForeignKeyViolation(err) {
				t.Errorf("%s: want a foreign-key violation, got %v", name, err)
			}
		}
	})
}

// TestMigrations_EmbeddedMatchEnt: the embedded migrations apply to an empty database, a second run
// applies nothing, and the live schema equals the Ent schema, composite keys included.
func TestMigrations_EmbeddedMatchEnt(t *testing.T) {
	forEachDialect(t, func(t *testing.T, _ *ent.Client, db *store.DB) {
		ctx := context.Background()
		dir, err := migrations.Dir(db.Dialect)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := store.Migrate(ctx, db, dir); err != nil || n != 0 {
			t.Fatalf("second run: %d applied, %v", n, err)
		}
		if err := store.Check(ctx, db); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Writer.ExecContext(ctx, "DROP INDEX gatewaygroup_org_id_name"); err != nil {
			t.Fatal(err)
		}
		if err := store.Check(ctx, db); err == nil || !strings.Contains(err.Error(), "gatewaygroup_org_id_name") {
			t.Fatalf("Check after dropping an index: %v, want a difference", err)
		}
	})
}

// TestMigrations_UpToDate: generating again from the Ent schema yields no new migration, so the
// committed migrations never lag the schema (docs/12-testing-and-quality.md, "Database tests").
func TestMigrations_UpToDate(t *testing.T) {
	ctx := context.Background()
	for _, d := range []string{store.SQLite, store.Postgres} {
		t.Run(d, func(t *testing.T) {
			var dev *sql.DB
			var err error
			if d == store.SQLite {
				dev, err = sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "dev.db")+"?_pragma=foreign_keys(1)")
			} else {
				admin := os.Getenv("RPMGR_TEST_PG")
				if admin == "" {
					if os.Getenv("RPMGR_TEST_REQUIRE_PG") == "1" {
						t.Fatal("RPMGR_TEST_PG is not set but PostgreSQL is required")
					}
					t.Skip("RPMGR_TEST_PG not set")
				}
				dev, err = sql.Open("pgx", newPGDatabase(t, admin))
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = dev.Close() }()
			embedded, err := migrations.Dir(d)
			if err != nil {
				t.Fatal(err)
			}
			dir := &migrate.MemDir{}
			files, err := embedded.Files()
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range files {
				if err := dir.WriteFile(f.Name(), f.Bytes()); err != nil {
					t.Fatal(err)
				}
			}
			sum, err := embedded.Checksum()
			if err != nil {
				t.Fatal(err)
			}
			if err := migrate.WriteSumFile(dir, sum); err != nil {
				t.Fatal(err)
			}
			if err := store.Diff(ctx, d, dev, dir, "check"); !errors.Is(err, migrate.ErrNoPlan) {
				t.Fatalf("regenerating from the Ent schema: %v; run tools/storemigrate diff and commit the new migration", err)
			}
		})
	}
}

func TestMigrations_UnknownDialect(t *testing.T) {
	if _, err := migrations.Dir("mysql"); err == nil {
		t.Error("migrations.Dir accepted mysql")
	}
}

// TestSQLite_PragmaForeignKeysIgnoredInTransaction records the SQLite behaviour that Migrate works
// around: "PRAGMA foreign_keys = off" inside a transaction changes nothing.
func TestSQLite_PragmaForeignKeysIgnoredInTransaction(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "p.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		"CREATE TABLE p (id text PRIMARY KEY)",
		"CREATE TABLE c (id text PRIMARY KEY, p_id text NOT NULL REFERENCES p (id))",
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "PRAGMA foreign_keys = off"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO c (id, p_id) VALUES ('c1', 'missing')"); !store.IsForeignKeyViolation(err) {
		t.Fatalf("inside a transaction the pragma took effect? insert error: %v", err)
	}
}

// TestRewriteForeignKeys: the diff hook converts keys between org-owned tables, keeps exceptions,
// is idempotent, and refuses a parent without UNIQUE (org_id, id).
func TestRewriteForeignKeys(t *testing.T) {
	str := &atlas.ColumnType{Type: &atlas.StringType{T: "text"}}
	build := func(parentUnique bool) (*atlas.Schema, *atlas.Table) {
		orgs := atlas.NewTable("orgs").AddColumns(atlas.NewColumn("id").SetType(str.Type))
		pid, porg := atlas.NewColumn("id").SetType(str.Type), atlas.NewColumn("org_id").SetType(str.Type)
		parent := atlas.NewTable("parents").AddColumns(pid, porg)
		if parentUnique {
			parent.AddIndexes(atlas.NewUniqueIndex("parent_org_id_id").AddColumns(porg, pid))
		}
		corg, cpar, cgwg := atlas.NewColumn("org_id").SetType(str.Type), atlas.NewColumn("parent_id").SetType(str.Type), atlas.NewColumn("gateway_group_id").SetType(str.Type)
		child := atlas.NewTable("children").AddColumns(atlas.NewColumn("id").SetType(str.Type), corg, cpar, cgwg)
		child.AddForeignKeys(
			atlas.NewForeignKey("children_parents").AddColumns(cpar).SetRefTable(parent).AddRefColumns(pid),
			atlas.NewForeignKey("children_groups").AddColumns(cgwg).SetRefTable(parent).AddRefColumns(pid),
		)
		return atlas.New("main").AddTables(orgs, parent, child), child
	}
	s, child := build(true)
	skip := map[string]bool{"children.gateway_group_id": true}
	for i := 0; i < 2; i++ { // twice: idempotent
		if err := store.RewriteForeignKeys(s, skip); err != nil {
			t.Fatal(err)
		}
	}
	fk, _ := child.ForeignKey("children_parents")
	if len(fk.Columns) != 2 || fk.Columns[0].Name != "org_id" || fk.RefColumns[0].Name != "org_id" {
		t.Fatalf("children_parents not composite: %+v", fk.Columns)
	}
	ex, _ := child.ForeignKey("children_groups")
	if len(ex.Columns) != 1 {
		t.Fatal("the exception was rewritten")
	}
	orgFKs := 0
	for _, f := range child.ForeignKeys {
		if f.RefTable.Name == "orgs" {
			orgFKs++
		}
	}
	if orgFKs != 1 {
		t.Fatalf("org_id → orgs(id) keys: %d, want 1", orgFKs)
	}
	s2, _ := build(false)
	if err := store.RewriteForeignKeys(s2, skip); err == nil {
		t.Fatal("parent without UNIQUE (org_id, id) was accepted")
	}
}
