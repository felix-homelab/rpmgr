// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// Org is the tenancy boundary (docs/06-data-model.md, "Identity and access"). It is not org-owned
// itself; OrgTableMixin restricts it.
type Org struct{ ent.Schema }

// Mixin applies the scope rules of the orgs table.
func (Org) Mixin() []ent.Mixin { return []ent.Mixin{OrgTableMixin{}} }

// Fields of an org.
func (Org) Fields() []ent.Field {
	return []ent.Field{
		idField("org"),
		field.String("name").NotEmpty(),
		field.String("slug").NotEmpty().Unique().Match(slugRe),
		field.Time("created_at").Immutable().Default(time.Now),
		// restore_review_since is set by a restore that failed closed: the org is read-only until
		// its Owner, or the Instance Admin, confirms its memberships and roles.
		field.Time("restore_review_since").Optional().Nillable(),
	}
}
