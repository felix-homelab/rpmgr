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

// AgentSession is the current control session of one agent (docs/06-data-model.md, "Desired vs
// observed state"). Only the control-session handlers write it. Its session_epoch rises with
// every new session of the agent, so of two replicas the one with the older epoch knows it was
// superseded. Its ID is the agent's ID; the agent's row may be gone, so there is no foreign key.
type AgentSession struct{ ent.Schema }

// Mixin makes agent sessions org-owned.
func (AgentSession) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (AgentSession) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "agent_sessions"}}
}

// Fields of an agent session.
func (AgentSession) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").StorageKey("agent_id").NotEmpty().Immutable(),
		field.Int64("session_epoch").Positive(),
		field.String("controller_node").NotEmpty(),
		field.String("remote_addr").Default(""),
		field.String("agent_version").Default(""),
		field.Strings("capabilities").Optional(),
		field.Time("connected_at").Default(time.Now),
		field.Time("last_seen_at").Default(time.Now),
	}
}

// AgentState is what one agent runs and what it was sent (docs/06-data-model.md, "Desired vs
// observed state"); the apply status of a write is derived from it. Only the control-session
// handlers write it. Its ID is the agent's ID; the agent's row may be gone, so there is no foreign
// key.
type AgentState struct{ ent.Schema }

// Mixin makes agent states org-owned.
func (AgentState) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (AgentState) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "agent_state"}}
}

// Fields of an agent state. A revision is stored as its database epoch and sequence number.
func (AgentState) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").StorageKey("agent_id").NotEmpty().Immutable(),
		field.String("boot_id").Default(""),
		field.Int64("clock_offset_ms").Default(0),
		// The snapshot the agent applied last.
		field.String("applied_db_epoch").Default(""),
		field.Int64("applied_seq").NonNegative().Default(0),
		field.Bytes("applied_hash").Optional(),
		field.Time("last_ack_at").Optional().Nillable(),
		// The snapshot the controller sent last.
		field.String("pushed_db_epoch").Default(""),
		field.Int64("pushed_seq").NonNegative().Default(0),
		field.Bytes("pushed_hash").Optional(),
		field.Time("pushed_at").Optional().Nillable(),
		// The snapshot the agent rejected last, and why.
		field.String("rejected_db_epoch").Default(""),
		field.Int64("rejected_seq").NonNegative().Default(0),
		field.Bytes("rejected_hash").Optional(),
		field.JSON("last_rejection", []map[string]string{}).Optional(),
	}
}

// CompiledSnapshot is a snapshot as it was sent: the last five per agent are kept, for diffing
// and support.
type CompiledSnapshot struct{ ent.Schema }

// Mixin makes compiled snapshots org-owned.
func (CompiledSnapshot) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (CompiledSnapshot) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "compiled_snapshots"}}
}

// Fields of a compiled snapshot: the signed message's parts, as sent.
func (CompiledSnapshot) Fields() []ent.Field {
	return []ent.Field{
		field.String("agent_id").NotEmpty().Immutable(),
		field.String("db_epoch").NotEmpty().Immutable(),
		field.Int64("seq").NonNegative().Immutable(),
		field.Bytes("hash").NotEmpty().Immutable(),
		field.Int("size_bytes").NonNegative().Immutable(),
		field.Bytes("payload").Immutable(),
		field.Bytes("signature").NotEmpty().Immutable(),
		field.String("key_id").NotEmpty().Immutable(),
		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

// Indexes find an agent's snapshots, newest first.
func (CompiledSnapshot) Indexes() []ent.Index {
	return []ent.Index{index.Fields("agent_id", "id")}
}

// ResourceStatus is one resource that an agent reports not ready, with why (docs/06-data-model.md,
// "Desired vs observed state"); a resource without a row is ready, or not reported yet. Only the
// control-session handlers write it. There is no foreign key to the agent, whose row may be gone.
type ResourceStatus struct{ ent.Schema }

// Mixin makes resource statuses org-owned.
func (ResourceStatus) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (ResourceStatus) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "resource_status"}}
}

// Fields of a resource status. reason is the agent protocol's NotReadyReason name.
func (ResourceStatus) Fields() []ent.Field {
	return []ent.Field{
		idField("rst"),
		field.String("agent_id").NotEmpty().Immutable(),
		field.String("resource_id").NotEmpty().Immutable(),
		field.String("reason").NotEmpty(),
		field.String("detail").Default(""),
		field.Time("since"),
	}
}

// Indexes: one row per agent and resource.
func (ResourceStatus) Indexes() []ent.Index {
	return []ent.Index{index.Fields("agent_id", "resource_id").Unique()}
}
