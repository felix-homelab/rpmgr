// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/privacy"

	"github.com/felix-homelab/rpmgr/spikes/s5/authz"
)

// The store enforces tenancy in three parts, all bound to the authz.OrgScope in the context:
//
//  1. Policy: a deny-by-default privacy policy. Without a scope, every query and mutation is
//     denied. Ent evaluates policies allow-by-default and skips them entirely when a caller sets
//     privacy.DecisionContext(ctx, privacy.Allow), so the policy alone is not the boundary.
//  2. Interceptor: every query and traversal (including edge queries and eager loading) gets
//     "WHERE org_id = <scope>". Another org's IDs therefore yield NotFound, not PermissionDenied,
//     so existence does not leak.
//  3. Hook: every update and delete gets the same predicate; a create must name the scope's org.
//
// The interceptor and the hook run regardless of privacy decisions in the context. The system
// scope (authz.System, audited) passes all three.

// errNoScope is returned when the context carries no authz.OrgScope.
func errNoScope() error { return privacy.Denyf("store: no org scope in context") }

// scopePolicy denies everything unless the context carries a scope.
func scopePolicy() ent.Policy {
	rule := privacy.ContextQueryMutationRule(func(ctx context.Context) error {
		if _, ok := authz.FromContext(ctx); ok {
			return privacy.Allow
		}
		return errNoScope()
	})
	return privacy.Policy{
		Query:    privacy.QueryPolicy{rule, privacy.AlwaysDenyRule()},
		Mutation: privacy.MutationPolicy{rule, privacy.AlwaysDenyRule()},
	}
}

type wherer interface {
	WhereP(...func(*sql.Selector))
}

// filterInterceptor adds "<column> = <scope org>" to every query.
func filterInterceptor(column string) ent.Interceptor {
	return ent.TraverseFunc(func(ctx context.Context, q ent.Query) error {
		s, ok := authz.FromContext(ctx)
		if !ok {
			return errNoScope()
		}
		if s.System() {
			return nil
		}
		w, ok := q.(wherer)
		if !ok {
			return privacy.Denyf("store: query %T cannot be scoped", q)
		}
		w.WhereP(sql.FieldEQ(column, s.OrgID()))
		return nil
	})
}

// orgMutationHook scopes updates and deletes to the scope's org and refuses creates in another org.
func orgMutationHook(next ent.Mutator) ent.Mutator {
	return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		s, ok := authz.FromContext(ctx)
		if !ok {
			return nil, errNoScope()
		}
		if s.System() {
			return next.Mutate(ctx, m)
		}
		if m.Op().Is(ent.OpCreate) {
			v, ok := m.Field("org_id")
			if !ok || v != s.OrgID() {
				return nil, privacy.Denyf("store: create of %s outside the scope's org", m.Type())
			}
			return next.Mutate(ctx, m)
		}
		w, ok := m.(wherer)
		if !ok {
			return nil, privacy.Denyf("store: mutation %T cannot be scoped", m)
		}
		w.WhereP(sql.FieldEQ("org_id", s.OrgID()))
		return next.Mutate(ctx, m)
	})
}

// systemOnlyHook lets only the system scope change a table (the orgs table).
func systemOnlyHook(next ent.Mutator) ent.Mutator {
	return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		s, ok := authz.FromContext(ctx)
		if !ok {
			return nil, errNoScope()
		}
		if !s.System() {
			return nil, privacy.Denyf("store: %s can only be changed in the system scope", m.Type())
		}
		return next.Mutate(ctx, m)
	})
}

func (OrgMixin) Policy() ent.Policy { return scopePolicy() }
func (OrgMixin) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{filterInterceptor("org_id")}
}
func (OrgMixin) Hooks() []ent.Hook       { return []ent.Hook{orgMutationHook} }
func (OrgTableMixin) Policy() ent.Policy { return scopePolicy() }
func (OrgTableMixin) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{filterInterceptor("id")}
}
func (OrgTableMixin) Hooks() []ent.Hook { return []ent.Hook{systemOnlyHook} }
