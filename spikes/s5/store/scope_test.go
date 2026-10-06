// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"sort"
	"testing"

	"entgo.io/ent/privacy"

	"github.com/felix-homelab/rpmgr/spikes/s5/authz"
	"github.com/felix-homelab/rpmgr/spikes/s5/ent"
	"github.com/felix-homelab/rpmgr/spikes/s5/ent/route"
)

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

// routeNames lists all route names in the system scope, to show what really is in the database.
func routeNames(t *testing.T, c *ent.Client) []string {
	t.Helper()
	rs := c.Route.Query().AllX(systemCtx(t))
	var out []string
	for _, r := range rs {
		out = append(out, r.OrgID+"/"+r.Name)
	}
	sort.Strings(out)
	return out
}

// TestScope_NoScopeDenied: without a scope, every query and mutation is denied.
func TestScope_NoScopeDenied(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		c, _ := migratedClient(t, d, name)
		a, _ := seed(t, c)
		ctx := context.Background()

		_, err := c.Route.Query().All(ctx)
		wantDenied(t, "list", err)
		_, err = c.Route.Get(ctx, a.rte)
		wantDenied(t, "get", err)
		_, err = c.Route.Query().Count(ctx)
		wantDenied(t, "count", err)
		_, err = c.Connector.Create().SetOrgID(a.org).SetName("x").Save(ctx)
		wantDenied(t, "create", err)
		_, err = c.Route.UpdateOneID(a.rte).SetName("x").Save(ctx)
		wantDenied(t, "update", err)
		err = c.Route.DeleteOneID(a.rte).Exec(ctx)
		wantDenied(t, "delete", err)
		_, err = c.Org.Query().All(ctx)
		wantDenied(t, "list orgs", err)
		if got := routeNames(t, c); len(got) != 2 {
			t.Fatalf("routes changed: %v", got)
		}
	})
}

// TestScope_DecisionContextDoesNotBypass: privacy.DecisionContext(ctx, privacy.Allow) skips Ent's
// policies, but the interceptor and the mutation hook still require a scope and still filter by org.
func TestScope_DecisionContextDoesNotBypass(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		c, _ := migratedClient(t, d, name)
		a, b := seed(t, c)

		bare := privacy.DecisionContext(context.Background(), privacy.Allow)
		_, err := c.Route.Query().All(bare)
		wantDenied(t, "list without scope", err)
		_, err = c.Route.UpdateOneID(a.rte).SetName("x").Save(bare)
		wantDenied(t, "update without scope", err)

		ctxB := privacy.DecisionContext(orgCtx(t, b.org), privacy.Allow)
		rs, err := c.Route.Query().All(ctxB)
		if err != nil || len(rs) != 1 || rs[0].ID != b.rte {
			t.Fatalf("list in org B: %v, %v", rs, err)
		}
		_, err = c.Route.UpdateOneID(a.rte).SetName("stolen").Save(ctxB)
		wantNotFound(t, "update org A's route from org B", err)
		_, err = c.Connector.Create().SetOrgID(a.org).SetName("planted").Save(ctxB)
		wantDenied(t, "create in org A from org B", err)
		if got := routeNames(t, c); got[0] != a.org+"/web" {
			t.Fatalf("org A's route changed: %v", got)
		}
	})
}

// TestScope_OtherOrgIDsAreNotFound: org B using org A's IDs gets NotFound for reads, updates and
// deletes, and nothing of org A changes. NotFound, not PermissionDenied, so existence does not leak.
func TestScope_OtherOrgIDsAreNotFound(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		c, _ := migratedClient(t, d, name)
		a, b := seed(t, c)
		ctxB := orgCtx(t, b.org)

		_, err := c.Route.Get(ctxB, a.rte)
		wantNotFound(t, "get route", err)
		_, err = c.Connector.Get(ctxB, a.con)
		wantNotFound(t, "get connector", err)
		_, err = c.Route.Query().Where(route.ID(a.rte)).Only(ctxB)
		wantNotFound(t, "query by ID", err)
		_, err = c.Org.Get(ctxB, a.org)
		wantNotFound(t, "get org", err)
		_, err = c.Route.UpdateOneID(a.rte).SetName("stolen").Save(ctxB)
		wantNotFound(t, "update route", err)
		_, err = c.RouteTarget.UpdateOneID(a.tgt).SetPort(1).Save(ctxB)
		wantNotFound(t, "update target", err)
		err = c.RouteTarget.DeleteOneID(a.tgt).Exec(ctxB)
		wantNotFound(t, "delete target", err)

		sys := systemCtx(t)
		if r := c.Route.GetX(sys, a.rte); r.Name != "web" {
			t.Fatalf("org A's route renamed to %q", r.Name)
		}
		if tg := c.RouteTarget.GetX(sys, a.tgt); tg.Port != 8080 {
			t.Fatalf("org A's target port changed to %d", tg.Port)
		}
	})
}

// TestScope_ListsAndTraversalsSeeOwnOrgOnly: lists, counts, edge traversals and eager loading
// return only the scope's org.
func TestScope_ListsAndTraversalsSeeOwnOrgOnly(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		c, _ := migratedClient(t, d, name)
		a, b := seed(t, c)
		ctxB := orgCtx(t, b.org)

		if n := c.Route.Query().CountX(ctxB); n != 1 {
			t.Fatalf("count routes: %d", n)
		}
		orgs := c.Org.Query().AllX(ctxB)
		if len(orgs) != 1 || orgs[0].ID != b.org {
			t.Fatalf("orgs: %v", orgs)
		}
		tgts := c.Connector.Query().QueryTargets().AllX(ctxB)
		if len(tgts) != 1 || tgts[0].ID != b.tgt {
			t.Fatalf("traversal connector → targets: %v", tgts)
		}
		// A traversal that starts at org A's route reaches nothing: every step is filtered.
		if n := c.Route.Query().Where(route.ID(a.rte)).QueryTargets().CountX(ctxB); n != 0 {
			t.Fatalf("traversal from org A's route: %d targets", n)
		}
		if n := c.Route.Query().Where(route.ID(b.rte)).QueryTargets().CountX(ctxB); n != 1 {
			t.Fatalf("traversal from own route: %d targets", n)
		}
		rs := c.Route.Query().WithTargets().AllX(ctxB)
		if len(rs) != 1 || len(rs[0].Edges.Targets) != 1 || rs[0].Edges.Targets[0].ID != b.tgt {
			t.Fatalf("eager loading: %+v", rs)
		}
	})
}

// TestScope_BulkMutationsTouchOwnOrgOnly: an update or delete without a WHERE clause changes only
// the scope's org.
func TestScope_BulkMutationsTouchOwnOrgOnly(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		c, _ := migratedClient(t, d, name)
		a, b := seed(t, c)
		ctxB := orgCtx(t, b.org)

		if n := c.Route.Update().SetEnabled(false).SaveX(ctxB); n != 1 {
			t.Fatalf("bulk update affected %d rows", n)
		}
		if n := c.RouteTarget.Delete().ExecX(ctxB); n != 1 {
			t.Fatalf("bulk delete affected %d rows", n)
		}
		sys := systemCtx(t)
		if !c.Route.GetX(sys, a.rte).Enabled {
			t.Fatal("org A's route was disabled by org B")
		}
		if _, err := c.RouteTarget.Get(sys, a.tgt); err != nil {
			t.Fatalf("org A's target was deleted by org B: %v", err)
		}
	})
}

// TestScope_CreateInOtherOrgDenied: a create must name the scope's org; orgs themselves change
// only in the system scope.
func TestScope_CreateInOtherOrgDenied(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		c, _ := migratedClient(t, d, name)
		a, b := seed(t, c)
		ctxB := orgCtx(t, b.org)

		_, err := c.Connector.Create().SetOrgID(a.org).SetName("planted").Save(ctxB)
		wantDenied(t, "create connector in org A", err)
		_, err = c.Org.Create().SetName("new").SetSlug("new").Save(ctxB)
		wantDenied(t, "create org", err)
		_, err = c.Org.UpdateOneID(b.org).SetName("renamed").Save(ctxB)
		wantDenied(t, "rename own org", err)
		if _, err := c.Connector.Create().SetOrgID(b.org).SetName("own").Save(ctxB); err != nil {
			t.Fatalf("create in own org: %v", err)
		}
		if n := c.Connector.Query().CountX(systemCtx(t)); n != 3 {
			t.Fatalf("connectors: %d, want 3", n)
		}
	})
}

// TestScope_SystemScopeIsAudited: the system scope sees every org, and only with an audit record.
func TestScope_SystemScopeIsAudited(t *testing.T) {
	forEachDialect(t, func(t *testing.T, d, name string) {
		c, _ := migratedClient(t, d, name)
		seed(t, c)
		log := &auditLog{}
		ctx, err := authz.System(context.Background(), "ephemeral-purge", "purge disconnected ephemeral connectors", log.record)
		if err != nil {
			t.Fatal(err)
		}
		if n := c.Route.Query().CountX(ctx); n != 2 {
			t.Fatalf("system scope sees %d routes, want 2", n)
		}
		if len(log.entries) != 1 || log.entries[0] != "ephemeral-purge: purge disconnected ephemeral connectors" {
			t.Fatalf("audit entries: %v", log.entries)
		}
		if _, err := authz.System(context.Background(), "job", "reason", nil); !errors.Is(err, authz.ErrNoAudit) {
			t.Fatalf("system scope without audit sink: %v", err)
		}
		failing := &auditLog{fail: errors.New("sink down")}
		if _, err := authz.System(context.Background(), "job", "reason", failing.record); err == nil {
			t.Fatal("system scope granted although the audit record failed")
		}
		if _, err := authz.System(context.Background(), "", "", log.record); err == nil {
			t.Fatal("system scope granted without job name and reason")
		}
	})
}

// TestAuthz_ScopeOnlyFromAuthz: a scope needs a membership, and nothing but package authz can put
// one into a context.
func TestAuthz_ScopeOnlyFromAuthz(t *testing.T) {
	p := authz.Principal{UserID: "usr_1", Memberships: map[string]string{"org_a": "viewer"}}
	if _, err := authz.ForOrg(context.Background(), p, "org_b"); !errors.Is(err, authz.ErrNotMember) {
		t.Fatalf("non-member: %v", err)
	}
	if _, err := authz.ForOrg(context.Background(), authz.Principal{}, "org_a"); !errors.Is(err, authz.ErrNotMember) {
		t.Fatalf("empty principal: %v", err)
	}
	type fakeKey struct{}
	forged := context.WithValue(context.Background(), fakeKey{}, authz.OrgScope{})
	if _, ok := authz.FromContext(forged); ok {
		t.Fatal("a forged context value was accepted as a scope")
	}
	ctx, err := authz.ForOrg(context.Background(), p, "org_a")
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := authz.FromContext(ctx); !ok || s.OrgID() != "org_a" || s.System() || s.Actor() != "usr_1" {
		t.Fatalf("scope: %+v %v", s, ok)
	}
}
