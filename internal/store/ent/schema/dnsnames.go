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

// DNSName is a name that an org points at a gateway group without a route, such as
// ssh.example.com for a tcp route or *.apps.example.com (docs/06-data-model.md, "DNS (Phase 2)";
// docs/15-dns.md, "Concepts"). It always lies under a verified domain of the org, and its group is
// one of the org's own. The name is unique in the instance.
type DNSName struct{ ent.Schema }

// Mixin makes names org-owned and versioned.
func (DNSName) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}, VersionMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (DNSName) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "dns_names"}}
}

// Fields of a name. fqdn is normalised (internal/domains) and may start with "*."; ttl is in
// seconds, and 0 is the zone's default_ttl; domain_id is the verified domain that covers the name
// when it is created, so that the domain stays while the name does.
func (DNSName) Fields() []ent.Field {
	return []ent.Field{
		idField("dnn"),
		field.String("fqdn").NotEmpty().MaxLen(253).Immutable(),
		field.String("gateway_group_id").NotEmpty(),
		field.String("domain_id").NotEmpty().Immutable(),
		field.Int("ttl").Default(0).NonNegative(),
		field.Time("created_at").Immutable().Default(time.Now),
	}
}

// Edges: the group and the covering domain, both of the same org (composite foreign keys).
func (DNSName) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("group", GatewayGroup.Type).Field("gateway_group_id").Unique().Required(),
		edge.To("domain", Domain.Type).Field("domain_id").Unique().Required().Immutable(),
	}
}

// Indexes: a name is created once; the names of a group are found by group.
func (DNSName) Indexes() []ent.Index {
	return []ent.Index{index.Fields("fqdn").Unique(), index.Fields("gateway_group_id"), index.Fields("domain_id")}
}
