// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Event is one event of the outbox (docs/06-data-model.md, "Observability (Phase 2)"): written in
// the transaction of the change it reports, so it exists exactly when the change committed. Only
// internal/events writes events, with plain SQL; the retention job deletes them. An instance event
// has a NULL org_id; an org scope reads only its own org's events.
type Event struct{ ent.Schema }

// Annotations name the table as docs/06-data-model.md does.
func (Event) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "events"}}
}

// Fields of an event, the envelope a webhook delivers (docs/07-api.md, "Webhooks (Phase 2)").
func (Event) Fields() []ent.Field {
	return []ent.Field{
		idField("evt"),
		field.String("org_id").Optional().Nillable().Immutable(),
		field.String("type").NotEmpty().Immutable(),
		field.Time("ts").Immutable(),
		field.Enum("actor_type").Values("user", "agent", "system", "anonymous").Immutable(),
		field.String("actor_id").Default("").Immutable(),
		field.String("subject_type").Default("").Immutable(),
		field.String("subject_id").Default("").Immutable(),
		field.String("subject_name").Default("").Immutable(),
		field.String("summary").Default("").Immutable(),
		field.Strings("changed").Optional().Immutable(),
	}
}

// Indexes serve the delivery of an org's events in order, and the retention job.
func (Event) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "id"), index.Fields("ts")}
}

// Policy denies every query without a scope.
func (Event) Policy() ent.Policy { return scopePolicy() }

// Interceptors show an org scope only its own org's events.
func (Event) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{filterInterceptor("org_id")}
}

// Hooks scope deletes to the scope's org; the system scope's retention job deletes any.
func (Event) Hooks() []ent.Hook { return []ent.Hook{orgMutationHook} }
