// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Alert is one alert about one subject (docs/06-data-model.md, "Observability (Phase 2)"): the
// singleton alert job moves it from pending to firing once its condition held for its duration,
// and to resolved once it no longer holds, writing an event at each of the two steps. An instance
// alert has a NULL org_id; an org scope reads only its own org's alerts.
type Alert struct{ ent.Schema }

// Annotations name the table as docs/06-data-model.md does.
func (Alert) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "alerts"}}
}

// Fields of an alert. subject_name is the subject's name when the alert was first seen, for the
// events and e-mails of a subject that is gone by the time its alert resolves.
func (Alert) Fields() []ent.Field {
	return []ent.Field{
		idField("alr"),
		field.String("org_id").Optional().Nillable().Immutable(),
		field.String("kind").NotEmpty().Immutable(),
		field.String("subject_type").NotEmpty().Immutable(),
		field.String("subject_id").NotEmpty().Immutable(),
		field.String("subject_name").Default(""),
		field.Enum("state").Values("pending", "firing", "resolved"),
		field.Time("since").Immutable(),
		field.Time("fired_at").Optional().Nillable(),
		field.Time("resolved_at").Optional().Nillable(),
	}
}

// Indexes serve the job's read of the open alerts and the Overview's of an org's.
func (Alert) Indexes() []ent.Index {
	return []ent.Index{index.Fields("state"), index.Fields("org_id", "state")}
}

// Policy denies every query without a scope.
func (Alert) Policy() ent.Policy { return scopePolicy() }

// Interceptors show an org scope only its own org's alerts.
func (Alert) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{filterInterceptor("org_id")}
}

// Hooks scope writes to the scope's org; the system scope's alert job writes any.
func (Alert) Hooks() []ent.Hook { return []ent.Hook{orgMutationHook} }
