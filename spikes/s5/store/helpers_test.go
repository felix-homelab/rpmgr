// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"ariga.io/atlas/sql/migrate"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/felix-homelab/rpmgr/spikes/s5/authz"
	"github.com/felix-homelab/rpmgr/spikes/s5/ent"
	"github.com/felix-homelab/rpmgr/spikes/s5/migrations"
	"github.com/felix-homelab/rpmgr/spikes/s5/store"
)

// The PostgreSQL tests need RPMGR_S5_PG, an admin DSN such as
// postgres://s5:s5@127.0.0.1:5432/postgres?sslmode=disable. Without it they are skipped, unless
// RPMGR_S5_REQUIRE_PG=1 (README.md).
var dialects = []struct{ name, d string }{{"sqlite", store.SQLite}, {"postgres", store.Postgres}}

// forEachDialect runs f as a subtest per dialect.
func forEachDialect(t *testing.T, f func(t *testing.T, d, name string)) {
	t.Helper()
	for _, dl := range dialects {
		t.Run(dl.name, func(t *testing.T) {
			if dl.d == store.Postgres && os.Getenv("RPMGR_S5_PG") == "" {
				if os.Getenv("RPMGR_S5_REQUIRE_PG") == "1" {
					t.Fatal("RPMGR_S5_PG is not set but PostgreSQL is required")
				}
				t.Skip("RPMGR_S5_PG not set")
			}
			f(t, dl.d, dl.name)
		})
	}
}

func randName() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// emptyDB returns a fresh, empty database of dialect d and its DSN.
func emptyDB(t *testing.T, d string) (*sql.DB, string) {
	t.Helper()
	ctx := context.Background()
	var dsn string
	switch d {
	case store.SQLite:
		dsn = store.SQLiteDSN(filepath.Join(t.TempDir(), "test.db"))
	case store.Postgres:
		admin, err := sql.Open("pgx", os.Getenv("RPMGR_S5_PG"))
		if err != nil {
			t.Fatal(err)
		}
		name := "s5t_" + randName()
		if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			admin.Close()
		})
		u, err := url.Parse(os.Getenv("RPMGR_S5_PG"))
		if err != nil {
			t.Fatal(err)
		}
		u.Path = "/" + name
		dsn = u.String()
	}
	db, err := store.OpenDB(ctx, d, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, dsn
}

// embeddedDir returns the embedded migrations of the dialect.
func embeddedDir(t *testing.T, name string) migrate.Dir {
	t.Helper()
	dir, err := migrations.Dir(name)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// migratedClient returns an Ent client on a fresh database with every migration applied.
func migratedClient(t *testing.T, d, name string) (*ent.Client, *sql.DB) {
	t.Helper()
	db, _ := emptyDB(t, d)
	if err := store.Migrate(context.Background(), d, db, embeddedDir(t, name), 0); err != nil {
		t.Fatal(err)
	}
	return store.NewClient(d, db), db
}

// auditLog is a test audit sink.
type auditLog struct {
	mu      sync.Mutex
	entries []string
	fail    error
}

func (a *auditLog) record(_ context.Context, actor, reason string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return a.fail
	}
	a.entries = append(a.entries, actor+": "+reason)
	return nil
}

func systemCtx(t *testing.T) context.Context {
	t.Helper()
	a := &auditLog{}
	ctx, err := authz.System(context.Background(), "test-fixtures", "create test fixtures", a.record)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func orgCtx(t *testing.T, orgID string) context.Context {
	t.Helper()
	p := authz.Principal{UserID: "usr_" + orgID, Memberships: map[string]string{orgID: "admin"}}
	ctx, err := authz.ForOrg(context.Background(), p, orgID)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

// tenant holds one org's fixture rows.
type tenant struct {
	org, gwg, con, rte, tgt, hck string
}

// seed creates two orgs with identical resources, as the cross-tenant leak suite does
// (docs/12-testing-and-quality.md, "Database tests").
func seed(t *testing.T, c *ent.Client) (a, b tenant) {
	t.Helper()
	ctx := systemCtx(t)
	mk := func(slug string) tenant {
		o := c.Org.Create().SetName(slug).SetSlug(slug).SaveX(ctx)
		g := c.GatewayGroup.Create().SetOrgID(o.ID).SetName("eu").SaveX(ctx)
		con := c.Connector.Create().SetOrgID(o.ID).SetName("nas").SaveX(ctx)
		h := c.HealthCheck.Create().SetOrgID(o.ID).SetType("tcp").SaveX(ctx)
		r := c.Route.Create().SetOrgID(o.ID).SetName("web").SetType("http").SetGatewayGroupID(g.ID).SaveX(ctx)
		tg := c.RouteTarget.Create().SetOrgID(o.ID).SetRouteID(r.ID).SetConnectorID(con.ID).
			SetHost("127.0.0.1").SetPort(8080).SetHealthCheckID(h.ID).SaveX(ctx)
		return tenant{org: o.ID, gwg: g.ID, con: con.ID, rte: r.ID, tgt: tg.ID, hck: h.ID}
	}
	return mk("org-a"), mk("org-b")
}

// isFKViolation reports whether err is a foreign-key violation of either dialect.
func isFKViolation(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "23503"
	}
	return err != nil && strings.Contains(err.Error(), "FOREIGN KEY constraint failed")
}

// rebind turns ? placeholders into $n for PostgreSQL.
func rebind(d, q string) string {
	if d != store.Postgres {
		return q
	}
	var b strings.Builder
	n := 0
	for _, c := range q {
		if c == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}
