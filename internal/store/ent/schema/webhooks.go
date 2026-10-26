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

// Webhook is an endpoint that receives events (docs/06-data-model.md, "Observability (Phase 2)";
// docs/07-api.md, "Webhooks (Phase 2)"). An org's endpoint receives that org's events; an
// instance endpoint, with a NULL org_id, the instance events. The secrets are write-only.
type Webhook struct{ ent.Schema }

// Annotations name the table as docs/06-data-model.md does.
func (Webhook) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "webhooks"}}
}

// Fields of an endpoint. enabled_at is when it was made or last enabled: it receives the events
// from then on, so none of the time it was disabled are sent. failing_since is the first failed
// delivery after its last success.
func (Webhook) Fields() []ent.Field {
	return []ent.Field{
		idField("whk"),
		field.String("org_id").Optional().Nillable().Immutable(),
		field.String("url").NotEmpty(),
		field.Bytes("secret_enc").NotEmpty().Sensitive(),
		field.Bytes("previous_secret_enc").Optional().Nillable().Sensitive(),
		field.Time("previous_until").Optional().Nillable(),
		field.Strings("event_types").Optional(),
		field.Bool("enabled").Default(true),
		field.Enum("disabled_reason").Values("failing", "person").Optional().Nillable(),
		field.Time("enabled_at").Default(time.Now),
		field.Time("last_success_at").Optional().Nillable(),
		field.Time("failing_since").Optional().Nillable(),
		field.Time("created_at").Immutable().Default(time.Now),
		field.Int64("version").Positive().Default(1),
	}
}

// Indexes serve the delivery job's read of the enabled endpoints.
func (Webhook) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id"), index.Fields("enabled")}
}

// Policy denies every query without a scope.
func (Webhook) Policy() ent.Policy { return scopePolicy() }

// Interceptors show an org scope only its own org's endpoints.
func (Webhook) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{filterInterceptor("org_id")}
}

// Hooks scope writes to the scope's org; instance endpoints only the system scope writes.
func (Webhook) Hooks() []ent.Hook { return []ent.Hook{orgMutationHook} }

// WebhookDelivery is one attempt to deliver one event to one endpoint; unique per endpoint, event
// and attempt. next_attempt_at is set while a retry is due, and cleared by a success or when the
// delivery is given up.
type WebhookDelivery struct{ ent.Schema }

// Annotations name the table as docs/06-data-model.md does.
func (WebhookDelivery) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "webhook_deliveries"}}
}

// Fields of an attempt. org_id is the endpoint's (NULL for an instance endpoint); event_type
// stays when the event is purged before the delivery.
func (WebhookDelivery) Fields() []ent.Field {
	return []ent.Field{
		idField("whd"),
		field.String("webhook_id").NotEmpty().Immutable(),
		field.String("org_id").Optional().Nillable().Immutable(),
		field.String("event_id").NotEmpty().Immutable(),
		field.String("event_type").Default("").Immutable(),
		field.Int("attempt").Positive().Immutable(),
		field.Int("status_code").Default(0).Immutable(),
		field.String("error").Default("").Immutable(),
		field.Time("sent_at").Immutable(),
		field.Time("next_attempt_at").Optional().Nillable(),
	}
}

// Indexes: one row per attempt, the due retries, and the newest attempts of an endpoint.
func (WebhookDelivery) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("webhook_id", "event_id", "attempt").Unique(),
		index.Fields("next_attempt_at"),
		index.Fields("webhook_id", "sent_at"),
	}
}

// Policy denies every query without a scope.
func (WebhookDelivery) Policy() ent.Policy { return scopePolicy() }

// Interceptors show an org scope only its own org's deliveries.
func (WebhookDelivery) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{filterInterceptor("org_id")}
}

// Hooks scope writes to the scope's org; the delivery job writes as the system scope.
func (WebhookDelivery) Hooks() []ent.Hook { return []ent.Hook{orgMutationHook} }
