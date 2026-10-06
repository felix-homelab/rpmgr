// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"github.com/felix-homelab/rpmgr/spikes/s5/ids"
)

// idField is the text primary key of every table (docs/06-data-model.md, "Identifiers").
func idField(prefix string) ent.Field {
	return field.String("id").Immutable().NotEmpty().DefaultFunc(func() string { return ids.New(prefix) })
}

// Org is the tenancy boundary. It is not org-owned itself; OrgPolicy restricts it.
type Org struct{ ent.Schema }

func (Org) Mixin() []ent.Mixin { return []ent.Mixin{OrgTableMixin{}} }

func (Org) Fields() []ent.Field {
	return []ent.Field{
		idField("org"),
		field.String("name").NotEmpty(),
		field.String("slug").NotEmpty().Unique(),
	}
}

// GatewayGroup is org-owned; shared groups belong to the system org (D14).
type GatewayGroup struct{ ent.Schema }

func (GatewayGroup) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

func (GatewayGroup) Fields() []ent.Field {
	return []ent.Field{idField("gwg"), field.String("name").NotEmpty()}
}

func (GatewayGroup) Edges() []ent.Edge {
	return []ent.Edge{edge.To("routes", Route.Type)}
}

func (GatewayGroup) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "name").Unique()}
}

// Connector is org-owned.
type Connector struct{ ent.Schema }

func (Connector) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

func (Connector) Fields() []ent.Field {
	return []ent.Field{idField("con"), field.String("name").NotEmpty()}
}

func (Connector) Edges() []ent.Edge {
	return []ent.Edge{edge.To("targets", RouteTarget.Type)}
}

func (Connector) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "name").Unique()}
}

// Route is org-owned. Its gateway group may belong to the system org (a shared group, D14), so
// routes.gateway_group_id is the one foreign key here that is not composite
// (store.CompositeForeignKeys, exception list).
type Route struct{ ent.Schema }

func (Route) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

func (Route) Fields() []ent.Field {
	return []ent.Field{
		idField("rte"),
		field.String("name").NotEmpty(),
		field.Enum("type").Values("http", "tcp", "udp", "tls_passthrough"),
		field.String("gateway_group_id").NotEmpty(),
		field.Bool("enabled").Default(true),
	}
}

func (Route) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("gateway_group", GatewayGroup.Type).Ref("routes").Field("gateway_group_id").
			Unique().Required(),
		edge.To("targets", RouteTarget.Type),
	}
}

func (Route) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "name").Unique()}
}

// RouteTarget is org-owned and references a route and a connector of the same org through
// composite (org_id, …) foreign keys.
type RouteTarget struct{ ent.Schema }

func (RouteTarget) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

func (RouteTarget) Fields() []ent.Field {
	return []ent.Field{
		idField("tgt"),
		field.String("route_id").NotEmpty(),
		field.String("connector_id").NotEmpty(),
		field.String("host").NotEmpty(),
		field.Int("port").Range(1, 65535),
	}
}

func (RouteTarget) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("route", Route.Type).Ref("targets").Field("route_id").Unique().Required(),
		edge.From("connector", Connector.Type).Ref("targets").Field("connector_id").Unique().Required(),
	}
}
