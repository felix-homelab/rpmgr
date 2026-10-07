// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
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
