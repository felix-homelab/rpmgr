// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// OrgMixin makes a table org-owned (docs/06-data-model.md, "Tenancy enforcement"):
//   - a NOT NULL, immutable org_id;
//   - a UNIQUE (org_id, id) index, which the composite foreign keys of child tables reference;
//   - the org filter on every query and traversal (interceptor), the org check on every mutation
//     (hook), and the deny-by-default privacy policy (scope.go).
type OrgMixin struct{ mixin.Schema }

func (OrgMixin) Fields() []ent.Field {
	return []ent.Field{field.String("org_id").NotEmpty().Immutable()}
}

func (OrgMixin) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "id").Unique()}
}

// OrgTableMixin applies the scope rules to the orgs table itself: a scope sees only its own org,
// and only the system scope changes orgs.
type OrgTableMixin struct{ mixin.Schema }
