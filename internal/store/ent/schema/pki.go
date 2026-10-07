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

// CAKey is one of the instance's CA and signing keys (docs/04-security.md, "CA hierarchy"): its
// certificate and its private key, envelope-encrypted under the KEK. Only the system scope reads or
// writes them.
type CAKey struct{ ent.Schema }

// Mixin makes CA keys system-only.
func (CAKey) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (CAKey) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "ca_keys"}}
}

// Fields of a CA key. key_enc is null for an offline root (Phase 2). Each kind has one active key;
// the CA refuses to load otherwise. (A partial unique index would say so, but PostgreSQL rewrites
// its predicate with casts, so the live schema would never equal the Ent schema.)
func (CAKey) Fields() []ent.Field {
	return []ent.Field{
		idField("cak"),
		field.Enum("kind").Values("root", "intermediate", "config_signing", "audit_checkpoint").Immutable(),
		field.String("algorithm").NotEmpty().Immutable(),
		field.Bytes("public_key").NotEmpty().Immutable(),
		field.Bytes("certificate").NotEmpty().Immutable(),
		field.Bytes("key_enc").Optional().Nillable(),
		field.Time("not_before").Immutable(),
		field.Time("not_after").Immutable(),
		field.Enum("status").Values("next", "active", "retired"),
	}
}

// IssuedCertificate records a leaf the CA issued (docs/04-security.md, "Revocation"): the source
// of revocation and Reauth decisions. Agent certificates belong to their org; controller node
// certificates have no org, so only the system scope sees them.
type IssuedCertificate struct{ ent.Schema }

// Annotations name the table as docs/06-data-model.md does.
func (IssuedCertificate) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "issued_certificates"}}
}

// Fields of an issued certificate; the ID is the serial number in lower-case hexadecimal.
func (IssuedCertificate) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").StorageKey("serial").NotEmpty().Immutable(),
		field.String("org_id").Optional().Nillable().Immutable(),
		field.Enum("subject_type").Values("connector", "gateway", "controller").Immutable(),
		field.String("subject_id").NotEmpty().Immutable(),
		field.String("spiffe_id").NotEmpty().Immutable(),
		field.String("pubkey_sha256").NotEmpty().Immutable(),
		field.Time("not_before").Immutable(),
		field.Time("not_after").Immutable(),
		field.Time("first_seen_at").Optional().Nillable(),
		field.Time("superseded_at").Optional().Nillable(),
		field.Time("revoked_at").Optional().Nillable(),
		field.String("revocation_reason").Default(""),
	}
}

// Indexes find the certificates of a subject.
func (IssuedCertificate) Indexes() []ent.Index {
	return []ent.Index{index.Fields("subject_id")}
}

// Policy denies every query and mutation without a scope.
func (IssuedCertificate) Policy() ent.Policy { return scopePolicy() }

// Interceptors show an org scope only its own org's certificates.
func (IssuedCertificate) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{filterInterceptor("org_id")}
}

// Hooks scope every mutation to the scope's org, as for org-owned tables; certificates without an
// org are changed only in the system scope.
func (IssuedCertificate) Hooks() []ent.Hook { return []ent.Hook{orgMutationHook} }

// SecretMeta records which KEK version seals each envelope-encrypted column of a row, so that
// `rpmgr kek status` lists what a KEK rotation has not re-wrapped yet (docs/04-security.md,
// "Secrets at rest and in logs").
type SecretMeta struct{ ent.Schema }

// Mixin makes the records instance-level: every scope that seals a secret writes one.
func (SecretMeta) Mixin() []ent.Mixin { return []ent.Mixin{InstanceMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (SecretMeta) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "secrets_meta"}}
}

// Fields of a record.
func (SecretMeta) Fields() []ent.Field {
	return []ent.Field{
		field.String("table_name").NotEmpty().Immutable(),
		field.String("row_id").NotEmpty().Immutable(),
		field.String("column_name").NotEmpty().Immutable(),
		field.String("kek_version").NotEmpty(),
		field.Time("created_at").Immutable().Default(time.Now),
	}
}

// Indexes allow one record per sealed column of a row.
func (SecretMeta) Indexes() []ent.Index {
	return []ent.Index{index.Fields("table_name", "row_id", "column_name").Unique()}
}
