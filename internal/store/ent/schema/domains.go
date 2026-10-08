// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Domain is an org's claim on a name (docs/06-data-model.md, "Routes";
// docs/04-security.md, "Route and hostname ownership"). A route's hostnames must fall under a
// verified domain of its org. The name is unique within the instance, whatever its status, so no
// two orgs can claim it at once.
type Domain struct{ ent.Schema }

// Mixin makes domains org-owned.
func (Domain) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (Domain) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "domains"}}
}

// Fields of a domain.
func (Domain) Fields() []ent.Field {
	return []ent.Field{
		idField("dom"),
		// fqdn is lower-case ASCII (IDNA) without a trailing dot.
		field.String("fqdn").NotEmpty().MaxLen(253).Immutable(),
		// wildcard: false covers exactly fqdn; true covers fqdn and every name below it.
		field.Bool("wildcard").Default(false).Immutable(),
		field.Enum("status").Values("pending", "pending_approval", "verified", "failed").Default("pending"),
		field.Enum("method").Values("dns_txt", "http", "trusted", "delegated").Default("dns_txt"),
		// challenge_value is the random value the DNS TXT record or the HTTP token must carry.
		field.String("challenge_value").NotEmpty(),
		field.Time("created_at").Immutable().Default(time.Now),
		field.Time("verified_at").Optional().Nillable(),
		field.Time("last_checked_at").Optional().Nillable(),
		field.Int64("version").Positive().Default(1),
	}
}

// Indexes: a name is claimed once in the instance.
func (Domain) Indexes() []ent.Index {
	return []ent.Index{index.Fields("fqdn").Unique()}
}
