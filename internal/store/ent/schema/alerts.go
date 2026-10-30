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

// StatusMark is the last state the status events reported for one subject: an agent's connection,
// an agent's applied configuration, a route's status (docs/06-data-model.md, "Observability
// (Phase 2)"). The singleton job compares what it observes with the mark and writes an event only
// for a change, so a restart neither replays nor loses one. The ID is "<kind>:<subject id>".
type StatusMark struct{ ent.Schema }

// Annotations name the table as docs/06-data-model.md does.
func (StatusMark) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "status_marks"}}
}

// Fields of a status mark. changed_at is when the mark last changed, which bounds the events of a
// flapping subject.
func (StatusMark) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").NotEmpty().Immutable(),
		field.String("org_id").Optional().Nillable().Immutable(),
		field.String("state").NotEmpty(),
		field.Time("changed_at"),
	}
}

// Policy denies every query without a scope.
func (StatusMark) Policy() ent.Policy { return scopePolicy() }

// Interceptors show an org scope only its own org's marks.
func (StatusMark) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{filterInterceptor("org_id")}
}

// Hooks scope writes to the scope's org; the system scope's job writes any.
func (StatusMark) Hooks() []ent.Hook { return []ent.Hook{orgMutationHook} }

// MailJob is the e-mail of one event: an alert's firing or resolving, a webhook endpoint's
// disabling (docs/06-data-model.md, "Observability (Phase 2)"). The singleton mail job makes one
// for each such event and sends it to the recipients of its org, retrying a failure until the
// give-up time; a failed mail never touches the alert or the delivery that caused it.
type MailJob struct{ ent.Schema }

// Annotations name the table as docs/06-data-model.md does.
func (MailJob) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "mail_jobs"}}
}

// Fields of a mail job. done lists the recipients that got the mail, so a retry sends only to
// the others.
func (MailJob) Fields() []ent.Field {
	return []ent.Field{
		idField("mlj"),
		field.String("org_id").Optional().Nillable().Immutable(),
		field.String("event_id").NotEmpty().Immutable().Unique(),
		field.Enum("state").Values("pending", "sent", "skipped", "given_up"),
		field.Int("attempts").Default(0),
		field.Time("next_attempt_at"),
		field.Time("created_at").Immutable(),
		field.Strings("done").Optional(),
	}
}

// Indexes serve the job's read of the mails that are due.
func (MailJob) Indexes() []ent.Index {
	return []ent.Index{index.Fields("state", "next_attempt_at")}
}

// Policy denies every query without a scope.
func (MailJob) Policy() ent.Policy { return scopePolicy() }

// Interceptors show an org scope only its own org's mails.
func (MailJob) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{filterInterceptor("org_id")}
}

// Hooks scope writes to the scope's org; the system scope's mail job writes any.
func (MailJob) Hooks() []ent.Hook { return []ent.Hook{orgMutationHook} }
