// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// DNSRecord is one row of the ownership ledger: a provider record that rpmgr owns
// (docs/06-data-model.md, "DNS (Phase 2)"; docs/15-dns.md, "Ownership ledger"). The DNS job may
// change or delete only a record that has a row. The ledger is controller-managed durable state:
// it is written by the DNS job and by adopt and release, and never rebuilt from the provider. The
// row is written in state creating before the provider call, and its ID is in the record's marker
// comment.
type DNSRecord struct{ ent.Schema }

// Mixin makes ledger rows org-owned. They are not versioned: no API writes them concurrently, the
// DNS job runs under one lease.
func (DNSRecord) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (DNSRecord) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "dns_records"}}
}

// Fields of a ledger row. name is the record's name, normalised; content, ttl and proxied are what
// the job last wrote or found in sync. provider_record_id is NULL until the provider's ID is
// known. reason says why a row is in state error or drifted. adopted_from is the original content
// of an adopted record (docs/15-dns.md, "Ownership ledger").
func (DNSRecord) Fields() []ent.Field {
	return []ent.Field{
		idField("dnr"),
		field.String("dns_zone_id").NotEmpty().Immutable(),
		field.String("name").NotEmpty().MaxLen(253),
		field.Enum("type").Values("A", "AAAA", "CNAME", "TXT"),
		field.String("content").MaxLen(4096),
		field.Int("ttl").Positive(),
		field.Bool("proxied").Default(false),
		field.String("provider_record_id").MaxLen(64).Optional().Nillable(),
		field.Enum("state").Values("creating", "synced", "drifted", "orphaned", "error", "deleting").Default("creating"),
		field.String("reason").Default("").MaxLen(512),
		field.String("adopted_from").Default("").MaxLen(4096),
		field.Time("adopted_at").Optional().Nillable(),
		field.Time("last_synced_at").Optional().Nillable(),
	}
}

// Edges: the zone, of the same org (composite foreign key).
func (DNSRecord) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("zone", DNSZone.Type).Field("dns_zone_id").Unique().Required().Immutable(),
	}
}

// Indexes: a provider's record is owned once per zone; a zone's rows are found by zone.
func (DNSRecord) Indexes() []ent.Index {
	return []ent.Index{index.Fields("dns_zone_id", "provider_record_id").Unique(), index.Fields("dns_zone_id", "name")}
}
