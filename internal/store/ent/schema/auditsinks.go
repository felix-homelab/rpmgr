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

	"github.com/felix-homelab/rpmgr/internal/sinkverify"
)

// AuditSink is an external destination of the audit log (docs/04-security.md, "Audit log";
// docs/06-data-model.md, "Observability (Phase 2)"). Sinks are instance-level: only the system
// scope reads or changes them. The secret is write-only.
type AuditSink struct{ ent.Schema }

// Mixin makes audit sinks system-only.
func (AuditSink) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (AuditSink) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "audit_sinks"}}
}

// Fields of a sink. settings holds what the kind needs besides its secret (a webhook's url); entries
// says whether the entries go with the checkpoints, which always do.
func (AuditSink) Fields() []ent.Field {
	return []ent.Field{
		idField("ask"),
		field.Enum("kind").Values("syslog", "webhook", "s3").Immutable(),
		field.String("name").NotEmpty(),
		field.JSON("settings", map[string]string{}).Optional(),
		field.Bytes("secret_enc").Optional().Nillable().Sensitive(),
		field.Bool("entries").Default(false),
		field.Bool("enabled").Default(true),
		field.String("last_error").Default(""),
		field.Time("last_success_at").Optional().Nillable(),
		field.JSON("verification", &sinkverify.Verification{}).Optional(),
		field.Time("created_at").Immutable().Default(time.Now),
	}
}

// Indexes make the names unique.
func (AuditSink) Indexes() []ent.Index { return []ent.Index{index.Fields("name").Unique()} }

// Edges: the cursors of a sink go with it.
func (AuditSink) Edges() []ent.Edge {
	return []ent.Edge{edge.From("cursors", AuditSinkCursor.Type).Ref("sink")}
}

// AuditSinkCursor is how far one sink has acknowledged one chain (the org ID, or "instance"): the
// last entry seq and checkpoint seq it holds. It is advanced only after the sink acknowledged a
// batch. oldest_unshipped_at is when the oldest item the sink has not acknowledged was appended,
// NULL when none; the backlog metric and alert read it.
type AuditSinkCursor struct{ ent.Schema }

// Mixin makes cursors system-only.
func (AuditSinkCursor) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (AuditSinkCursor) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "audit_sink_cursors"}}
}

// Fields of a cursor.
func (AuditSinkCursor) Fields() []ent.Field {
	return []ent.Field{
		idField("asc"),
		field.String("sink_id").NotEmpty().Immutable(),
		field.String("chain").NotEmpty().Immutable(),
		field.Int64("entry_seq").NonNegative().Default(0),
		field.Int64("checkpoint_seq").NonNegative().Default(0),
		field.Time("oldest_unshipped_at").Optional().Nillable(),
	}
}

// Indexes allow one cursor per sink and chain.
func (AuditSinkCursor) Indexes() []ent.Index {
	return []ent.Index{index.Fields("sink_id", "chain").Unique()}
}

// Edges: the sink, whose deletion deletes its cursors.
func (AuditSinkCursor) Edges() []ent.Edge {
	return []ent.Edge{edge.To("sink", AuditSink.Type).Field("sink_id").Unique().Required().Immutable().
		Annotations(entsql.OnDelete(entsql.Cascade))}
}
