// SPDX-License-Identifier: Apache-2.0

// Package storetest provides migrated test databases of both dialects and test scopes for the
// tests of packages built on the store. The PostgreSQL databases need RPMGR_TEST_PG, an admin
// DSN; without it they are skipped, unless RPMGR_TEST_REQUIRE_PG=1 (as in CI).
package storetest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"

	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
)

// Dialects are the dialects ForEachDialect runs.
var Dialects = []string{store.SQLite, store.Postgres}

// ForEachDialect runs f as a subtest with a fresh, migrated database of each dialect.
func ForEachDialect(t *testing.T, f func(t *testing.T, db *store.DB)) {
	t.Helper()
	for _, d := range Dialects {
		t.Run(d, func(t *testing.T) { f(t, Migrated(t, d)) })
	}
}

// Migrated returns a fresh database of dialect d with every embedded migration applied.
func Migrated(t testing.TB, d string) *store.DB {
	t.Helper()
	ctx := context.Background()
	var db *store.DB
	var err error
	switch d {
	case store.SQLite:
		db, err = store.OpenSQLite(ctx, filepath.Join(t.TempDir(), "t.db"), store.SQLiteOptions{})
	case store.Postgres:
		db, err = store.OpenPostgres(ctx, NewPostgresDatabase(t))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dir, err := migrations.Dir(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Migrate(ctx, db, dir); err != nil {
		t.Fatal(err)
	}
	return db
}

// NewPostgresDatabase creates an empty PostgreSQL database, dropped after the test, and returns
// its DSN. It skips the test when RPMGR_TEST_PG is not set.
func NewPostgresDatabase(t testing.TB) string {
	t.Helper()
	adminDSN := os.Getenv("RPMGR_TEST_PG")
	if adminDSN == "" {
		if os.Getenv("RPMGR_TEST_REQUIRE_PG") == "1" {
			t.Fatal("RPMGR_TEST_PG is not set but PostgreSQL is required")
		}
		t.Skip("RPMGR_TEST_PG not set")
	}
	admin, err := sql.Open("pgx", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "rpmgr_t_" + hex.EncodeToString(b)
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
		_ = admin.Close()
	})
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

// SystemCtx returns a context with the system scope, recorded nowhere.
func SystemCtx(t testing.TB) context.Context {
	t.Helper()
	ctx, err := authz.System(context.Background(), "test-fixtures", "create test fixtures",
		func(context.Context, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

// OrgCtx returns a context with the scope of org orgID for a member "usr_of_<orgID>".
func OrgCtx(t testing.TB, orgID string) context.Context {
	t.Helper()
	p := authz.Principal{UserID: "usr_of_" + orgID, Memberships: map[string]string{orgID: "admin"}}
	ctx, err := authz.ForOrg(context.Background(), p, orgID)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

// Init initialises the instance with a test trust domain.
func Init(t testing.TB, db *store.DB) store.Revision {
	t.Helper()
	rev, err := store.InitInstance(SystemCtx(t), db, "rpmgr-teststor")
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

// Org creates an org with the given slug in the system scope and returns its ID.
func Org(t testing.TB, db *store.DB, slug string) string {
	t.Helper()
	return db.Client().Org.Create().SetName(slug).SetSlug(slug).SaveX(SystemCtx(t)).ID
}
