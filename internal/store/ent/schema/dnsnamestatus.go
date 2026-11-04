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

// DNSNameStatus is the dns_status of one name in a managed zone (docs/06-data-model.md,
// "Desired vs observed state"; docs/15-dns.md, "Publication rules"). Only the DNS job writes it, in
// the transaction that commits its pass; it never touches the route status.
type DNSNameStatus struct{ ent.Schema }

// Mixin makes name statuses org-owned.
func (DNSNameStatus) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (DNSNameStatus) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "dns_name_status"}}
}

// Fields of a name status. name is normalised and may start with "*."; reason says why a name is
// not published, in fixed words or the provider's; since is when the status last changed.
func (DNSNameStatus) Fields() []ent.Field {
	return []ent.Field{
		idField("dnt"),
		field.String("dns_zone_id").NotEmpty().Immutable(),
		field.String("name").NotEmpty().MaxLen(253).Immutable(),
		field.Enum("status").Values("not_managed", "pending", "published", "conflict", "ambiguous", "held", "error"),
		field.String("reason").Default("").MaxLen(512),
		field.Time("since").Default(time.Now),
	}
}

// Edges: the zone, of the same org (composite foreign key).
func (DNSNameStatus) Edges() []ent.Edge {
	return []ent.Edge{edge.To("zone", DNSZone.Type).Field("dns_zone_id").Unique().Required().Immutable()}
}

// Indexes: one row per zone and name.
func (DNSNameStatus) Indexes() []ent.Index {
	return []ent.Index{index.Fields("dns_zone_id", "name").Unique()}
}
