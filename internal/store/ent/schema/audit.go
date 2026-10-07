// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/privacy"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// AuditEntry is one entry of the audit log (docs/04-security.md, "Audit log"). The entries form
// one hash chain per org, and one for instance-level events, whose org_id is NULL. Only
// internal/audit writes them, with plain SQL; every Ent mutation is refused, so no code updates or
// deletes an entry through Ent. A scope reads only its own org's entries; the system scope reads
// every chain.
type AuditEntry struct{ ent.Schema }

// Annotations name the table as docs/06-data-model.md does.
func (AuditEntry) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "audit_log"}}
}

// Fields of an entry; internal/audit hashes all of them except prev_hash and hash.
func (AuditEntry) Fields() []ent.Field {
	return []ent.Field{
		idField("aud"),
		field.String("org_id").Optional().Nillable().Immutable(),
		field.Int64("seq").Positive().Immutable(),
		field.Bytes("prev_hash").Immutable(),
		field.Bytes("hash").Immutable(),
		field.Time("ts").Immutable(),
		field.Enum("actor_type").Values("user", "agent", "system", "anonymous").Immutable(),
		field.String("actor_id").Default("").Immutable(),
		field.String("credential_id").Default("").Immutable(),
		field.String("auth_method").Default("").Immutable(),
		field.String("ip").Default("").Immutable(),
		field.String("user_agent").Default("").Immutable(),
		field.String("request_id").Default("").Immutable(),
		field.String("action").NotEmpty().Immutable(),
		field.String("target_type").Default("").Immutable(),
		field.String("target_id").Default("").Immutable(),
		field.Enum("result").Values("success", "failure", "denied").Immutable(),
		field.Text("diff").Default("").Immutable(),
		field.String("reason").Default("").Immutable(),
	}
}

// Indexes make seq unique within each chain; the instance chain has a NULL org_id, which a plain
// unique index would not compare.
func (AuditEntry) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("org_id", "seq").Unique(),
		index.Fields("seq").Unique().StorageKey("auditentry_instance_seq").
			Annotations(entsql.IndexWhere("org_id IS NULL")),
	}
}

// Policy denies every query without a scope.
func (AuditEntry) Policy() ent.Policy { return scopePolicy() }

// Interceptors show an org scope only its own org's entries.
func (AuditEntry) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{filterInterceptor("org_id")}
}

// Hooks refuse every Ent mutation.
func (AuditEntry) Hooks() []ent.Hook { return []ent.Hook{auditOnlyHook} }

// AuditHead is the head of one audit chain: the seq and hash of its last entry. The chain is the
// org ID, or "instance". An append increments seq with a row lock as its first step, so appends to
// one chain are linear under concurrency, and verification compares the last entry with the head,
// so a deleted tail is detected.
type AuditHead struct{ ent.Schema }

// Annotations name the table.
func (AuditHead) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "audit_heads"}}
}

// Fields of a head; its ID is the chain.
func (AuditHead) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").StorageKey("chain").NotEmpty().Immutable(),
		field.Int64("seq").NonNegative(),
		field.Bytes("hash"),
	}
}

// Policy denies every query without a scope.
func (AuditHead) Policy() ent.Policy { return scopePolicy() }

// Interceptors show an org scope only its own org's head.
func (AuditHead) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{filterInterceptor("chain")}
}

// Hooks refuse every Ent mutation.
func (AuditHead) Hooks() []ent.Hook { return []ent.Hook{auditOnlyHook} }

// auditOnlyHook refuses every Ent mutation of the audit tables: internal/audit appends with plain
// SQL, and nothing updates or deletes.
func auditOnlyHook(ent.Mutator) ent.Mutator {
	return ent.MutateFunc(func(_ context.Context, m ent.Mutation) (ent.Value, error) {
		return nil, privacy.Denyf("store: %s is written only by the audit package", m.Type())
	})
}
