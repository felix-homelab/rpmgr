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

// Routes and ports (docs/06-data-model.md, "Routes", "Gateway groups and ports").

// PortPool is a range of public ports of a gateway group that routes may allocate. In Phase 1 it
// belongs to the org that owns the group; pools of shared groups come with them (Phase 2).
type PortPool struct{ ent.Schema }

// Mixin makes port pools org-owned.
func (PortPool) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (PortPool) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "port_pools"}}
}

// Fields of a port pool.
func (PortPool) Fields() []ent.Field {
	return []ent.Field{
		idField("pp"),
		field.String("gateway_group_id").NotEmpty().Immutable(),
		field.Enum("protocol").Values("tcp", "udp").Immutable(),
		field.Int("port_from").Range(1, 65535),
		field.Int("port_to").Range(1, 65535),
	}
}

// Edges of a port pool.
func (PortPool) Edges() []ent.Edge {
	return []ent.Edge{edge.To("group", GatewayGroup.Type).Field("gateway_group_id").Unique().Required().Immutable()}
}

// PortAllocation is one public port of a gateway group in use by a route.
type PortAllocation struct{ ent.Schema }

// Mixin makes port allocations org-owned.
func (PortAllocation) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (PortAllocation) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "port_allocations"}}
}

// Fields of a port allocation.
func (PortAllocation) Fields() []ent.Field {
	return []ent.Field{
		idField("pa"),
		field.String("gateway_group_id").NotEmpty().Immutable(),
		field.Enum("protocol").Values("tcp", "udp").Immutable(),
		field.Int("port").Range(1, 65535).Immutable(),
		field.String("route_id").Optional().Nillable(),
	}
}

// Edges of a port allocation.
func (PortAllocation) Edges() []ent.Edge {
	return []ent.Edge{edge.To("group", GatewayGroup.Type).Field("gateway_group_id").Unique().Required().Immutable()}
}

// Indexes: a port of a group is allocated once.
func (PortAllocation) Indexes() []ent.Index {
	return []ent.Index{index.Fields("gateway_group_id", "protocol", "port").Unique()}
}

// PortQuota caps the ports an org may allocate in a gateway group; without a row only the pools
// limit it.
type PortQuota struct{ ent.Schema }

// Mixin makes port quotas org-owned.
func (PortQuota) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (PortQuota) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "port_quotas"}}
}

// Fields of a port quota.
func (PortQuota) Fields() []ent.Field {
	return []ent.Field{
		idField("pq"),
		field.String("gateway_group_id").NotEmpty().Immutable(),
		field.Enum("protocol").Values("tcp", "udp").Immutable(),
		field.Int("max_ports").NonNegative(),
	}
}

// Edges of a port quota.
func (PortQuota) Edges() []ent.Edge {
	return []ent.Edge{edge.To("group", GatewayGroup.Type).Field("gateway_group_id").Unique().Required().Immutable()}
}

// Indexes: one quota per org, group and protocol.
func (PortQuota) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "gateway_group_id", "protocol").Unique()}
}

// Route is the only place a route exists (docs/06-data-model.md, "Routes"); its type's table
// holds the rest.
type Route struct{ ent.Schema }

// Mixin makes routes org-owned.
func (Route) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (Route) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "routes"}}
}

// Fields of a route. transport pins the data-session transport on every connector serving it;
// null is each connector's own (docs/03-connections.md, "Transport selection").
func (Route) Fields() []ent.Field {
	return []ent.Field{
		idField("rt"),
		field.String("name").NotEmpty().Match(slugRe),
		field.Enum("type").Values("http", "tcp", "udp", "tls_passthrough").Immutable(),
		field.String("gateway_group_id").NotEmpty().Immutable(),
		field.Bool("enabled").Default(true),
		field.Enum("transport").Values("auto", "quic", "h2").Optional().Nillable(),
		field.String("description").Default(""),
		field.JSON("labels", map[string]string{}).Optional(),
		field.Int64("version").Positive().Default(1),
		field.Time("created_at").Immutable().Default(time.Now),
		field.Time("updated_at").Default(time.Now),
		field.String("updated_by").Default(""),
	}
}

// Edges of a route.
func (Route) Edges() []ent.Edge {
	return []ent.Edge{edge.To("group", GatewayGroup.Type).Field("gateway_group_id").Unique().Required().Immutable()}
}

// Indexes: names are unique per org.
func (Route) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "name").Unique()}
}

// RouteTCP is the TCP part of a tcp route, one row per route.
type RouteTCP struct{ ent.Schema }

// Mixin makes it org-owned.
func (RouteTCP) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (RouteTCP) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "route_tcp"}}
}

// Fields of a tcp route. idle_timeout closes a connection without traffic for that long; 0 never.
func (RouteTCP) Fields() []ent.Field {
	return []ent.Field{
		field.String("route_id").NotEmpty().Unique().Immutable(),
		field.String("port_allocation_id").NotEmpty().Unique(),
		field.Enum("listener_mode").Values("plain", "http_connect").Default("plain"),
		field.Int("idle_timeout_seconds").NonNegative().Default(3600),
	}
}

// Edges of a tcp route.
func (RouteTCP) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("route", Route.Type).Field("route_id").Unique().Required().Immutable(),
		edge.To("port", PortAllocation.Type).Field("port_allocation_id").Unique().Required(),
	}
}

// RouteTarget is where a connector delivers a route's connections; several targets balance and
// fail over.
type RouteTarget struct{ ent.Schema }

// Mixin makes route targets org-owned.
func (RouteTarget) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (RouteTarget) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "route_targets"}}
}

// Fields of a route target: an address and port, or a unix socket, on the connector's host.
func (RouteTarget) Fields() []ent.Field {
	return []ent.Field{
		idField("tg"),
		field.String("route_id").NotEmpty().Immutable(),
		field.String("connector_id").NotEmpty(),
		field.Enum("kind").Values("address", "unix"),
		field.String("host").Default(""),
		field.Int("port").Range(0, 65535).Default(0),
		field.String("unix_path").Default(""),
		field.Enum("upstream_protocol").Values("tcp", "http", "https", "h2c").Default("tcp"),
		field.String("tls_server_name").Default(""),
		field.String("tls_spki_sha256").Default(""),
		field.Enum("proxy_protocol").Values("none", "v1", "v2").Default("none"),
		field.Int("weight").Range(1, 1000).Default(1),
		field.Int("priority").NonNegative().Default(0),
		field.Bool("enabled").Default(true),
	}
}

// Edges of a route target: the route and the connector of the same org.
func (RouteTarget) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("route", Route.Type).Field("route_id").Unique().Required().Immutable(),
		edge.To("connector", Connector.Type).Field("connector_id").Unique().Required(),
	}
}

// Indexes find a route's and a connector's targets.
func (RouteTarget) Indexes() []ent.Index {
	return []ent.Index{index.Fields("route_id"), index.Fields("connector_id")}
}
