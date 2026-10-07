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
	"sort"
	"sync"
	"testing"

	"entgo.io/ent/privacy"
	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
	_ "modernc.org/sqlite"             // registers "sqlite"

	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
)

// The PostgreSQL runs need RPMGR_TEST_PG, an admin DSN such as
// postgres://rpmgr:rpmgr@127.0.0.1:5432/postgres?sslmode=disable; without it they are skipped,
// unless RPMGR_TEST_REQUIRE_PG=1 (as in CI).
func forEachDialect(t *testing.T, f func(t *testing.T, c *ent.Client)) {
	t.Helper()
	for _, d := range []string{store.SQLite, store.Postgres} {
		t.Run(d, func(t *testing.T) {
			f(t, store.NewClient(d, emptyDB(t, d)))
		})
	}
}

// emptyDB returns a fresh database with the current schema. Until migrations exist, the schema
// is created by Ent directly.
func emptyDB(t *testing.T, d string) *sql.DB {
	t.Helper()
	ctx := context.Background()
	var db *sql.DB
	var err error
	switch d {
	case store.SQLite:
		db, err = sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "t.db")+"?_pragma=foreign_keys(1)")
	case store.Postgres:
		admin := os.Getenv("RPMGR_TEST_PG")
		if admin == "" {
			if os.Getenv("RPMGR_TEST_REQUIRE_PG") == "1" {
				t.Fatal("RPMGR_TEST_PG is not set but PostgreSQL is required")
			}
			t.Skip("RPMGR_TEST_PG not set")
		}
		db, err = pgDatabase(t, admin)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.NewClient(d, db).Schema.Create(ctx); err != nil {
		t.Fatal(err)
	}
	return db
}

func pgDatabase(t *testing.T, adminDSN string) (*sql.DB, error) {
	admin, err := sql.Open("pgx", adminDSN)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "rpmgr_t_" + hex.EncodeToString(b)
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
		_ = admin.Close()
	})
	u, err := url.Parse(adminDSN)
	if err != nil {
		return nil, err
	}
	u.Path = "/" + name
	return sql.Open("pgx", u.String())
}

type auditLog struct {
	mu      sync.Mutex
	entries []string
	fail    error
}

func (a *auditLog) record(_ context.Context, job, reason string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return a.fail
	}
	a.entries = append(a.entries, job+": "+reason)
	return nil
}

func systemCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, err := authz.System(context.Background(), "test-fixtures", "create test fixtures", (&auditLog{}).record)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func orgCtx(t *testing.T, orgID string) context.Context {
	t.Helper()
	p := authz.Principal{UserID: "usr_of_" + orgID, Memberships: map[string]string{orgID: "admin"}}
	ctx, err := authz.ForOrg(context.Background(), p, orgID)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

type tenant struct{ org, gwg string }

// seed creates two orgs with identical resources, as the cross-tenant leak suite does
// (docs/12-testing-and-quality.md, "Database tests").
func seed(t *testing.T, c *ent.Client) (a, b tenant) {
	t.Helper()
	ctx := systemCtx(t)
	mk := func(slug string) tenant {
		o := c.Org.Create().SetName(slug).SetSlug(slug).SaveX(ctx)
		g := c.GatewayGroup.Create().SetOrgID(o.ID).SetName("eu").SaveX(ctx)
		return tenant{org: o.ID, gwg: g.ID}
	}
	return mk("org-a"), mk("org-b")
}

func groupNames(t *testing.T, c *ent.Client) []string {
	t.Helper()
	var out []string
	for _, g := range c.GatewayGroup.Query().AllX(systemCtx(t)) {
		out = append(out, g.OrgID+"/"+g.Name)
	}
	sort.Strings(out)
	return out
}

func wantDenied(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, privacy.Deny) {
		t.Fatalf("%s: want privacy.Deny, got %v", what, err)
	}
}

func wantNotFound(t *testing.T, what string, err error) {
	t.Helper()
	if !ent.IsNotFound(err) {
		t.Fatalf("%s: want NotFound, got %v", what, err)
	}
}

func TestScope_NoScopeDenied(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client) {
		a, _ := seed(t, c)
		ctx := context.Background()
		_, err := c.GatewayGroup.Query().All(ctx)
		wantDenied(t, "list", err)
		_, err = c.GatewayGroup.Get(ctx, a.gwg)
		wantDenied(t, "get", err)
		_, err = c.GatewayGroup.Query().Count(ctx)
		wantDenied(t, "count", err)
		_, err = c.GatewayGroup.Create().SetOrgID(a.org).SetName("x").Save(ctx)
		wantDenied(t, "create", err)
		_, err = c.GatewayGroup.UpdateOneID(a.gwg).SetName("x").Save(ctx)
		wantDenied(t, "update", err)
		err = c.GatewayGroup.DeleteOneID(a.gwg).Exec(ctx)
		wantDenied(t, "delete", err)
		_, err = c.Org.Query().All(ctx)
		wantDenied(t, "list orgs", err)
		if got := groupNames(t, c); len(got) != 2 {
			t.Fatalf("groups changed: %v", got)
		}
	})
}

func TestScope_DecisionContextDoesNotBypass(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client) {
		a, b := seed(t, c)
		bare := privacy.DecisionContext(context.Background(), privacy.Allow)
		_, err := c.GatewayGroup.Query().All(bare)
		wantDenied(t, "list without scope", err)
		_, err = c.GatewayGroup.UpdateOneID(a.gwg).SetName("x").Save(bare)
		wantDenied(t, "update without scope", err)

		ctxB := privacy.DecisionContext(orgCtx(t, b.org), privacy.Allow)
		gs, err := c.GatewayGroup.Query().All(ctxB)
		if err != nil || len(gs) != 1 || gs[0].ID != b.gwg {
			t.Fatalf("list in org B: %v, %v", gs, err)
		}
		_, err = c.GatewayGroup.UpdateOneID(a.gwg).SetName("stolen").Save(ctxB)
		wantNotFound(t, "update org A's group from org B", err)
		_, err = c.GatewayGroup.Create().SetOrgID(a.org).SetName("planted").Save(ctxB)
		wantDenied(t, "create in org A from org B", err)
		if got := groupNames(t, c); got[0] != a.org+"/eu" && got[1] != a.org+"/eu" {
			t.Fatalf("org A's group changed: %v", got)
		}
	})
}

func TestScope_OtherOrgIDsAreNotFound(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client) {
		a, b := seed(t, c)
		ctxB := orgCtx(t, b.org)
		_, err := c.GatewayGroup.Get(ctxB, a.gwg)
		wantNotFound(t, "get group", err)
		_, err = c.GatewayGroup.Query().Where(gatewaygroup.ID(a.gwg)).Only(ctxB)
		wantNotFound(t, "query by ID", err)
		_, err = c.Org.Get(ctxB, a.org)
		wantNotFound(t, "get org", err)
		_, err = c.GatewayGroup.UpdateOneID(a.gwg).SetName("stolen").Save(ctxB)
		wantNotFound(t, "update group", err)
		err = c.GatewayGroup.DeleteOneID(a.gwg).Exec(ctxB)
		wantNotFound(t, "delete group", err)
		if g := c.GatewayGroup.GetX(systemCtx(t), a.gwg); g.Name != "eu" {
			t.Fatalf("org A's group renamed to %q", g.Name)
		}
	})
}

func TestScope_ListsSeeOwnOrgOnly(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client) {
		_, b := seed(t, c)
		ctxB := orgCtx(t, b.org)
		if n := c.GatewayGroup.Query().CountX(ctxB); n != 1 {
			t.Fatalf("count groups: %d", n)
		}
		orgs := c.Org.Query().AllX(ctxB)
		if len(orgs) != 1 || orgs[0].ID != b.org {
			t.Fatalf("orgs: %v", orgs)
		}
		if ids := c.GatewayGroup.Query().IDsX(ctxB); len(ids) != 1 || ids[0] != b.gwg {
			t.Fatalf("IDs: %v", ids)
		}
	})
}

func TestScope_BulkMutationsTouchOwnOrgOnly(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client) {
		a, b := seed(t, c)
		ctxB := orgCtx(t, b.org)
		if n := c.GatewayGroup.Update().SetName("renamed").SaveX(ctxB); n != 1 {
			t.Fatalf("bulk update affected %d rows", n)
		}
		if n := c.GatewayGroup.Delete().ExecX(ctxB); n != 1 {
			t.Fatalf("bulk delete affected %d rows", n)
		}
		if g, err := c.GatewayGroup.Get(systemCtx(t), a.gwg); err != nil || g.Name != "eu" {
			t.Fatalf("org A's group after org B's bulk changes: %v, %v", g, err)
		}
	})
}

func TestScope_CreateInOtherOrgDenied(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client) {
		a, b := seed(t, c)
		ctxB := orgCtx(t, b.org)
		_, err := c.GatewayGroup.Create().SetOrgID(a.org).SetName("planted").Save(ctxB)
		wantDenied(t, "create group in org A", err)
		_, err = c.GatewayGroup.Create().SetName("no-org").Save(ctxB)
		if err == nil {
			t.Fatal("create without org_id accepted")
		}
		_, err = c.Org.Create().SetName("new").SetSlug("new").Save(ctxB)
		wantDenied(t, "create org", err)
		_, err = c.Org.UpdateOneID(b.org).SetName("renamed").Save(ctxB)
		wantDenied(t, "rename own org", err)
		if _, err := c.GatewayGroup.Create().SetOrgID(b.org).SetName("us").Save(ctxB); err != nil {
			t.Fatalf("create in own org: %v", err)
		}
		if n := c.GatewayGroup.Query().CountX(systemCtx(t)); n != 3 {
			t.Fatalf("groups: %d, want 3", n)
		}
	})
}

func TestScope_SystemScopeIsAudited(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client) {
		seed(t, c)
		log := &auditLog{}
		ctx, err := authz.System(context.Background(), "ephemeral-purge", "purge disconnected ephemeral connectors", log.record)
		if err != nil {
			t.Fatal(err)
		}
		if n := c.GatewayGroup.Query().CountX(ctx); n != 2 {
			t.Fatalf("system scope sees %d groups, want 2", n)
		}
		if len(log.entries) != 1 || log.entries[0] != "ephemeral-purge: purge disconnected ephemeral connectors" {
			t.Fatalf("audit entries: %v", log.entries)
		}
	})
}

func TestSchema_Validation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client) {
		ctx := systemCtx(t)
		if _, err := c.Org.Create().SetName("x").SetSlug("Not A Slug").Save(ctx); err == nil {
			t.Error("org slug with spaces and capitals accepted")
		}
		if _, err := c.Org.Create().SetID("rte_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R").SetName("x").SetSlug("x").Save(ctx); err == nil {
			t.Error("org with an ID of another type accepted")
		}
		o := c.Org.Create().SetName("x").SetSlug("dup").SaveX(ctx)
		if _, err := c.Org.Create().SetName("y").SetSlug("dup").Save(ctx); err == nil {
			t.Error("duplicate org slug accepted")
		}
		c.GatewayGroup.Create().SetOrgID(o.ID).SetName("eu").SaveX(ctx)
		if _, err := c.GatewayGroup.Create().SetOrgID(o.ID).SetName("eu").Save(ctx); err == nil {
			t.Error("duplicate group name in one org accepted")
		}
	})
}
