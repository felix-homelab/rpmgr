// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	atlas "ariga.io/atlas/sql/schema"

	"github.com/felix-homelab/rpmgr/spikes/s5/ent"
	"github.com/felix-homelab/rpmgr/spikes/s5/store"
)

// TestCompositeFK_CrossOrgReferenceRejectedThroughEnt: even in org B's own scope, a route target of
// org B cannot point at org A's connector or health check; the database refuses it.
func TestCompositeFK_CrossOrgReferenceRejectedThroughEnt(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		c, _ := migratedClient(t, d, name)
		a, b := seed(t, c)
		ctxB := orgCtx(t, b.org)

		_, err := c.RouteTarget.Create().SetOrgID(b.org).SetRouteID(b.rte).SetConnectorID(a.con).
			SetHost("h").SetPort(80).Save(ctxB)
		if !ent.IsConstraintError(err) {
			t.Fatalf("org A's connector in org B's target: want a constraint error, got %v", err)
		}
		_, err = c.RouteTarget.UpdateOneID(b.tgt).SetHealthCheckID(a.hck).Save(ctxB)
		if !ent.IsConstraintError(err) {
			t.Fatalf("org A's health check on org B's target: want a constraint error, got %v", err)
		}
		// The system scope passes the Ent layer, but not the database.
		_, err = c.RouteTarget.Create().SetOrgID(b.org).SetRouteID(a.rte).SetConnectorID(b.con).
			SetHost("h").SetPort(80).Save(systemCtx(t))
		if !ent.IsConstraintError(err) {
			t.Fatalf("system scope, org A's route in org B's target: want a constraint error, got %v", err)
		}
	})
}

// TestCompositeFK_RawSQLCannotCrossOrgs: with plain SQL, past every Ent rule, no row can reference
// another org's row, and a parent's org cannot change under its children.
func TestCompositeFK_RawSQLCannotCrossOrgs(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		c, db := migratedClient(t, d, name)
		a, b := seed(t, c)
		ctx := context.Background()
		ins := rebind(d, "INSERT INTO route_targets (id, org_id, host, port, connector_id, route_id) VALUES (?, ?, 'h', 80, ?, ?)")

		cases := []struct {
			name string
			q    string
			args []any
		}{
			{"org B target, org A connector", ins, []any{"tgt_x1", b.org, a.con, b.rte}},
			{"org B target, org A route", ins, []any{"tgt_x2", b.org, b.con, a.rte}},
			{"org A target, org B route and connector", ins, []any{"tgt_x3", a.org, b.con, b.rte}},
			{"unknown org", ins, []any{"tgt_x4", "org_none", b.con, b.rte}},
			{"move a target to org A", rebind(d, "UPDATE route_targets SET org_id = ? WHERE id = ?"), []any{a.org, b.tgt}},
			{"move a connector with targets to org B", rebind(d, "UPDATE connectors SET org_id = ?, name = 'moved' WHERE id = ?"), []any{b.org, a.con}},
			{"delete a connector with targets", rebind(d, "DELETE FROM connectors WHERE id = ?"), []any{a.con}},
			{"org B target, org A health check", rebind(d, "UPDATE route_targets SET health_check_id = ? WHERE id = ?"), []any{a.hck, b.tgt}},
		}
		for _, tc := range cases {
			if _, err := db.ExecContext(ctx, tc.q, tc.args...); !isFKViolation(err) {
				t.Errorf("%s: want a foreign-key violation, got %v", tc.name, err)
			}
		}
		// Positive control: the same statement within one org works.
		if _, err := db.ExecContext(ctx, ins, "tgt_ok", b.org, b.con, b.rte); err != nil {
			t.Fatalf("same-org insert: %v", err)
		}
	})
}

// TestCompositeFK_SharedGatewayGroupAllowed: routes.gateway_group_id stays single-column, so a route
// of org B can use a gateway group of the system org (D14); grants are checked above the database.
func TestCompositeFK_SharedGatewayGroupAllowed(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		c, _ := migratedClient(t, d, name)
		_, b := seed(t, c)
		sys := systemCtx(t)
		systemOrg := c.Org.Create().SetName("system").SetSlug("system").SaveX(sys)
		shared := c.GatewayGroup.Create().SetOrgID(systemOrg.ID).SetName("shared").SaveX(sys)
		if _, err := c.Route.Create().SetOrgID(b.org).SetName("on-shared").SetType("tcp").
			SetGatewayGroupID(shared.ID).Save(orgCtx(t, b.org)); err != nil {
			t.Fatalf("route on a shared gateway group: %v", err)
		}
	})
}

// TestSQLite_ForeignKeysMustBeOn: SQLite enforces no foreign key unless the connection enables it;
// the store opens connections with the pragma and refuses a connection without it.
func TestSQLite_ForeignKeysMustBeOn(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "fk.db")
	db, err := store.OpenDB(ctx, store.SQLite, store.SQLiteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, store.SQLite, db, embeddedDir(t, "sqlite"), 0); err != nil {
		t.Fatal(err)
	}
	a, b := seed(t, store.NewClient(store.SQLite, db))
	db.Close()

	plain, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if _, err := plain.ExecContext(ctx, "INSERT INTO route_targets (id, org_id, host, port, connector_id, route_id) VALUES ('tgt_bad', ?, 'h', 80, ?, ?)", b.org, a.con, b.rte); err != nil {
		t.Fatalf("without the pragma SQLite accepted nothing? %v", err)
	}
	if _, err := store.OpenDB(ctx, store.SQLite, "file:"+path); err == nil {
		t.Fatal("store.OpenDB accepted a DSN without foreign keys")
	}
}

// TestSQLite_PragmaForeignKeysIgnoredInTransaction records the SQLite behaviour that Migrate works
// around: "PRAGMA foreign_keys = off" inside a transaction changes nothing.
func TestSQLite_PragmaForeignKeysIgnoredInTransaction(t *testing.T) {
	ctx := context.Background()
	db, _ := emptyDB(t, store.SQLite)
	var version string
	if err := db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("SQLite %s (modernc.org/sqlite)", version)
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
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "PRAGMA foreign_keys = off"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO c (id, p_id) VALUES ('c1', 'missing')"); !isFKViolation(err) {
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
