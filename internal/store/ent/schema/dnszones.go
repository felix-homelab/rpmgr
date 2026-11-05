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

// DNSZone is a provider zone imported into rpmgr (docs/06-data-model.md, "DNS (Phase 2)";
// docs/15-dns.md, "Connecting, importing and disconnecting"). rpmgr publishes records only in
// managed zones, and only for names of the zone's own org. The name, the zone's apex, is unique in
// the instance: a zone belongs to one org.
type DNSZone struct{ ent.Schema }

// Mixin makes zones org-owned and versioned.
func (DNSZone) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}, VersionMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (DNSZone) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "dns_zones"}}
}

// Fields of a zone. sync_state starts as held (docs/15-dns.md, "Held zones and plan approval");
// held_reason says why. provider_status is what the last call to the provider found for this zone.
// The gates and defaults are those of docs/15-dns.md, "Publication rules" and "Timers and limits".
func (DNSZone) Fields() []ent.Field {
	return []ent.Field{
		idField("dnz"),
		field.String("dns_provider_id").NotEmpty().Immutable(),
		field.String("provider_zone_id").NotEmpty().MaxLen(64).Immutable(),
		field.String("name").NotEmpty().MaxLen(253).Immutable(),
		field.Enum("sync_state").Values("active", "held", "disabled").Default("held"),
		field.String("held_reason").Default("").MaxLen(64),
		// pending_plan is the plan of the last pass of a held zone, as JSON, and its hash. On an
		// active zone the hash is the one an Owner or Admin approved: the next pass applies that
		// plan only (docs/15-dns.md, "Held zones and plan approval").
		field.Bytes("pending_plan").Optional(),
		field.String("pending_plan_hash").Default("").MaxLen(64),
		field.Enum("provider_status").Values("ok", "permission_denied", "unreachable", "rate_limited").Default("ok"),
		field.Bool("publish_route_hostnames").Default(true),
		field.Bool("allow_proxied").Default(false),
		field.Bool("allow_wildcards").Default(false),
		field.Int("delete_threshold").Default(10).NonNegative(),
		field.Int("default_ttl").Default(300).Positive(),
		field.Time("last_synced_at").Optional().Nillable(),
		// sync_requested_at is when someone last asked for a full pass ("Sync now"). The DNS job
		// runs on one replica, which the request may not have reached: it reads the time from here.
		// removal_requested: removing the zone with its records was approved (the approved removal
		// plan is in pending_plan); the DNS job, under its lease, deletes the owned records and then
		// the zone.
		field.Bool("removal_requested").Default(false),
		field.Time("sync_requested_at").Optional().Nillable(),
		field.Time("created_at").Immutable().Default(time.Now),
	}
}

// Edges: the provider the zone is imported from, of the same org (composite foreign key).
func (DNSZone) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("dns_provider", DNSProvider.Type).Field("dns_provider_id").Unique().Required().Immutable(),
	}
}

// Indexes: a name is imported once; a provider's zone is imported once.
func (DNSZone) Indexes() []ent.Index {
	return []ent.Index{index.Fields("name").Unique(), index.Fields("dns_provider_id", "provider_zone_id").Unique()}
}
