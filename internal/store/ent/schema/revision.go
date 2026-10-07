// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"regexp"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

// InstanceMixin marks an instance-level table: not org-owned, used by every configuration
// transaction whatever its org, and like every table unusable without a scope.
type InstanceMixin struct{ mixin.Schema }

// Policy denies every query and mutation without a scope.
func (InstanceMixin) Policy() ent.Policy { return scopePolicy() }

// trustDomainRe is `rpmgr-` and 8 base32 characters (docs/04-security.md, "Trust domain").
var trustDomainRe = regexp.MustCompile(`^rpmgr-[a-z2-7]{8}$`)

// Instance is the single row that describes the installation: its trust domain, which never
// changes, and its database epoch, which changes at every restore (docs/03-connections.md,
// "Revisions and ordering").
type Instance struct{ ent.Schema }

// Mixin makes the instance row instance-level.
func (Instance) Mixin() []ent.Mixin { return []ent.Mixin{InstanceMixin{}} }

// Annotations name the table.
func (Instance) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "instance"}}
}

// Fields of the instance row; its ID is always 1.
func (Instance) Fields() []ent.Field {
	return []ent.Field{
		field.Int("id").Range(1, 1).Immutable(),
		field.String("trust_domain").Immutable().Match(trustDomainRe),
		field.String("db_epoch").NotEmpty(),
		field.Time("created_at").Immutable().Default(time.Now),
	}
}

// ConfigSeq is the single-row counter of configuration revisions. Every configuration
// transaction increments it with a row lock as its first statement, so commit order equals
// revision order.
type ConfigSeq struct{ ent.Schema }

// Mixin makes the counter instance-level.
func (ConfigSeq) Mixin() []ent.Mixin { return []ent.Mixin{InstanceMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (ConfigSeq) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "config_seq"}}
}

// Fields of the counter; its ID is always 1.
func (ConfigSeq) Fields() []ent.Field {
	return []ent.Field{
		field.Int("id").Range(1, 1).Immutable(),
		field.Int64("seq").NonNegative(),
	}
}

// ConfigRevision records one configuration transaction (docs/06-data-model.md, "System").
type ConfigRevision struct{ ent.Schema }

// Mixin makes revisions instance-level.
func (ConfigRevision) Mixin() []ent.Mixin { return []ent.Mixin{InstanceMixin{}} }

// Fields of a revision; its ID is the revision's seq.
func (ConfigRevision) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("id").StorageKey("seq").Positive().Immutable(),
		field.String("db_epoch").NotEmpty().Immutable(),
		field.String("actor").NotEmpty().Immutable(),
		field.Strings("changed_resources").Optional().Immutable(),
		field.Time("created_at").Immutable().Default(time.Now),
	}
}
