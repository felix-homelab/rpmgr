// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// User is a person who signs in (docs/06-data-model.md, "Identity and access"). Users are global,
// not org-scoped: a user can be a member of several orgs. Only the system scope reads or writes
// them; the API reaches them through the caller's own identity.
type User struct{ ent.Schema }

// Mixin makes users system-only.
func (User) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Fields of a user. email is stored lower-case; password_hash is argon2id in PHC format, null for
// a user who never set one.
func (User) Fields() []ent.Field {
	return []ent.Field{
		idField("usr"),
		field.String("email").NotEmpty().MaxLen(254),
		field.String("display_name").NotEmpty().MaxLen(100),
		field.String("password_hash").Optional().Nillable().Sensitive(),
		field.Enum("status").Values("active", "disabled").Default("active"),
		// instance_admin is the instance-level role (docs/04-security.md, "Roles").
		field.Bool("instance_admin").Default(false),
		field.Time("created_at").Immutable().Default(time.Now),
		field.Time("last_login_at").Optional().Nillable(),
	}
}

// Edges of a user.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("memberships", Membership.Type),
	}
}

// Indexes: one user per e-mail address.
func (User) Indexes() []ent.Index {
	return []ent.Index{index.Fields("email").Unique()}
}

// Membership is a user's role in an org.
type Membership struct{ ent.Schema }

// Mixin makes memberships org-owned.
func (Membership) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Fields of a membership.
func (Membership) Fields() []ent.Field {
	return []ent.Field{
		idField("mem"),
		field.String("user_id").NotEmpty().Immutable(),
		field.Enum("role").Values("owner", "admin", "operator", "viewer"),
		field.String("created_by").NotEmpty().Immutable(),
		field.Time("created_at").Immutable().Default(time.Now),
	}
}

// Edges of a membership.
func (Membership) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("memberships").Field("user_id").Unique().Required().Immutable(),
	}
}

// Indexes: one membership per user and org.
func (Membership) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "user_id").Unique()}
}

// PasswordReset is a one-time link that sets a user's password, or, without a user, creates the
// first user (docs/04-security.md, "Human authentication and sessions"). Only the token's hash is
// stored.
type PasswordReset struct{ ent.Schema }

// Mixin makes reset links system-only.
func (PasswordReset) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Fields of a reset link.
func (PasswordReset) Fields() []ent.Field {
	return []ent.Field{
		idField("prs"),
		field.String("user_id").Optional().Nillable().Immutable(),
		field.Bytes("token_hash").NotEmpty().Immutable(),
		field.String("created_by").NotEmpty().Immutable(),
		field.Time("created_at").Immutable().Default(time.Now),
		field.Time("expires_at").Immutable(),
		field.Time("used_at").Optional().Nillable(),
	}
}

// Edges of a reset link.
func (PasswordReset) Edges() []ent.Edge {
	return []ent.Edge{
		// A link of a deleted user goes with the user; it must never turn into a first-user link.
		edge.To("user", User.Type).Field("user_id").Unique().Immutable().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Indexes: tokens are looked up by hash.
func (PasswordReset) Indexes() []ent.Index {
	return []ent.Index{index.Fields("token_hash").Unique()}
}
