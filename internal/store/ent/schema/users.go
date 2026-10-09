// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
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

// Session is a signed-in browser (docs/04-security.md, "Human authentication and sessions"). Only
// the token's hash is stored. elevated_until is when the last step-up stops counting; amr lists
// how the user authenticated (pwd, otp).
type Session struct{ ent.Schema }

// Mixin makes sessions system-only.
func (Session) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Fields of a session.
func (Session) Fields() []ent.Field {
	return []ent.Field{
		idField("ses"),
		field.String("user_id").NotEmpty().Immutable(),
		field.Bytes("token_hash").NotEmpty(),
		field.Time("created_at").Immutable(),
		field.Time("last_seen_at"),
		field.Time("idle_expires_at"),
		field.Time("absolute_expires_at").Immutable(),
		field.Time("elevated_until").Optional().Nillable(),
		field.Strings("amr"),
		field.String("ip").MaxLen(64),
		field.String("user_agent").MaxLen(512),
		field.Time("revoked_at").Optional().Nillable(),
	}
}

// Edges of a session.
func (Session) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("user", User.Type).Field("user_id").Unique().Required().Immutable().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Indexes: tokens are looked up by hash, sessions listed per user.
func (Session) Indexes() []ent.Index {
	return []ent.Index{index.Fields("token_hash").Unique(), index.Fields("user_id")}
}

// TOTPCredential is a user's authenticator app (docs/04-security.md, "Human authentication and
// sessions"). seed_enc is the secret under the KEK; confirmed_at is null until the user entered a
// first code; last_step is the time step of the last code used, so that no code works twice.
type TOTPCredential struct{ ent.Schema }

// Mixin makes TOTP credentials system-only.
func (TOTPCredential) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (TOTPCredential) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "totp_credentials"}}
}

// Fields of a TOTP credential.
func (TOTPCredential) Fields() []ent.Field {
	return []ent.Field{
		idField("tot"),
		field.String("user_id").NotEmpty().Immutable(),
		field.Bytes("seed_enc").NotEmpty().Immutable().Sensitive(),
		field.Time("created_at").Immutable(),
		field.Time("confirmed_at").Optional().Nillable(),
		field.Int64("last_step").Default(0),
	}
}

// Edges of a TOTP credential.
func (TOTPCredential) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("user", User.Type).Field("user_id").Unique().Required().Immutable().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Indexes: one authenticator per user.
func (TOTPCredential) Indexes() []ent.Index {
	return []ent.Index{index.Fields("user_id").Unique()}
}

// RecoveryCode is one of a user's one-time recovery codes; only its hash is stored.
type RecoveryCode struct{ ent.Schema }

// Mixin makes recovery codes system-only.
func (RecoveryCode) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Fields of a recovery code.
func (RecoveryCode) Fields() []ent.Field {
	return []ent.Field{
		idField("rcv"),
		field.String("user_id").NotEmpty().Immutable(),
		field.Bytes("code_hash").NotEmpty().Immutable(),
		field.Time("created_at").Immutable(),
		field.Time("used_at").Optional().Nillable(),
	}
}

// Edges of a recovery code.
func (RecoveryCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("user", User.Type).Field("user_id").Unique().Required().Immutable().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Indexes: codes are looked up by hash.
func (RecoveryCode) Indexes() []ent.Index {
	return []ent.Index{index.Fields("code_hash").Unique(), index.Fields("user_id")}
}

// Invitation is a one-time link that makes its holder a member of an org with a role
// (docs/04-security.md, "Human authentication and sessions"). Only the token's hash is stored.
type Invitation struct{ ent.Schema }

// Mixin makes invitations org-owned.
func (Invitation) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Fields of an invitation; email is stored lower-case.
func (Invitation) Fields() []ent.Field {
	return []ent.Field{
		idField("inv"),
		field.String("email").NotEmpty().MaxLen(254).Immutable(),
		field.Enum("role").Values("owner", "admin", "operator", "viewer").Immutable(),
		field.Bytes("token_hash").NotEmpty().Immutable(),
		field.String("created_by").NotEmpty().Immutable(),
		field.Time("created_at").Immutable(),
		field.Time("expires_at").Immutable(),
		field.Time("accepted_at").Optional().Nillable(),
		field.String("accepted_by").Optional().Nillable(),
	}
}

// Indexes: tokens are looked up by hash.
func (Invitation) Indexes() []ent.Index {
	return []ent.Index{index.Fields("token_hash").Unique()}
}

// APIToken is an API token of a user in one org (docs/04-security.md, "Human authentication and
// sessions"). Only its hash is stored, with a prefix that tells tokens apart in lists. Its
// permissions are its scopes intersected with the owner's current role in the org, at every
// request.
type APIToken struct{ ent.Schema }

// Mixin makes API tokens org-owned.
func (APIToken) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (APIToken) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "api_tokens"}}
}

// Fields of an API token. mfa records that its creator had signed in with a second factor, which
// an org's MFA policy then accepts from the token.
func (APIToken) Fields() []ent.Field {
	return []ent.Field{
		idField("atk"),
		field.Enum("owner_type").Values("user", "service_account").Immutable(),
		field.String("owner_id").NotEmpty().Immutable(),
		field.String("name").NotEmpty().MaxLen(100),
		field.String("prefix").NotEmpty().Immutable(),
		field.Bytes("token_hash").NotEmpty().Immutable(),
		field.Strings("scopes").Immutable(),
		field.Bool("mfa").Default(false).Immutable(),
		field.Time("created_at").Immutable(),
		field.Time("expires_at").Immutable(),
		field.Time("last_used_at").Optional().Nillable(),
		field.String("last_used_ip").Optional().MaxLen(64),
		field.Time("revoked_at").Optional().Nillable(),
		// step_up_at is the token's last step-up (D63): with it, the token makes the changes that
		// need one for the step-up window.
		field.Time("step_up_at").Optional().Nillable(),
	}
}

// Indexes: tokens are looked up by hash and listed per owner.
func (APIToken) Indexes() []ent.Index {
	return []ent.Index{index.Fields("token_hash").Unique(), index.Fields("org_id", "owner_id")}
}
