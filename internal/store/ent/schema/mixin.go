// SPDX-License-Identifier: Apache-2.0

// Package schema is rpmgr's database schema in Ent (docs/06-data-model.md).
package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"

	"github.com/felix-homelab/rpmgr/internal/ids"
)

// idField is the text primary key of every table (docs/06-data-model.md, "Identifiers").
func idField(prefix string) ent.Field {
	return field.String("id").Immutable().NotEmpty().
		DefaultFunc(func() string { return ids.New(prefix) }).
		Validate(func(id string) error {
			if !ids.Valid(prefix, id) {
				return &invalidIDError{prefix: prefix}
			}
			return nil
		})
}

type invalidIDError struct{ prefix string }

func (e *invalidIDError) Error() string { return "schema: not a valid " + e.prefix + "_ ID" }

// OrgMixin makes a table org-owned (docs/06-data-model.md, "Tenancy enforcement"):
//   - a NOT NULL, immutable org_id;
//   - a UNIQUE (org_id, id) index, which the composite foreign keys of child tables reference;
//   - the org filter on every query and traversal (interceptor), the org check on every mutation
//     (hook) and the deny-by-default privacy policy (scope.go).
type OrgMixin struct{ mixin.Schema }

// Fields returns org_id.
func (OrgMixin) Fields() []ent.Field {
	return []ent.Field{field.String("org_id").NotEmpty().Immutable()}
}

// Indexes returns UNIQUE (org_id, id).
func (OrgMixin) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "id").Unique()}
}

// OrgTableMixin applies the scope rules to the orgs table itself: a scope sees only its own org,
// and only the system scope changes orgs.
type OrgTableMixin struct{ mixin.Schema }

// SystemMixin makes a table usable only in the system scope, for queries and mutations alike: the
// CA's keys.
type SystemMixin struct{ mixin.Schema }
