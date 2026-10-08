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

// Mixin makes port pools org-owned and versioned.
func (PortPool) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}, VersionMixin{}} }

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

// Mixin makes routes org-owned and versioned.
func (Route) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}, VersionMixin{}} }

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

// Indexes: one row per route and one route per port allocation. The fields' Unique alone does not
// make the migration generator emit an index.
func (RouteTCP) Indexes() []ent.Index {
	return []ent.Index{index.Fields("route_id").Unique(), index.Fields("port_allocation_id").Unique()}
}

// RouteUDP is the UDP part of a udp route, one row per route.
type RouteUDP struct{ ent.Schema }

// Mixin makes it org-owned.
func (RouteUDP) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (RouteUDP) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "route_udp"}}
}

// Fields of a udp route. flow_idle_timeout ends a flow without datagrams for that long
// (docs/03-connections.md, "Timeouts, keepalive and backoff").
func (RouteUDP) Fields() []ent.Field {
	return []ent.Field{
		field.String("route_id").NotEmpty().Unique().Immutable(),
		field.String("port_allocation_id").NotEmpty().Unique(),
		field.Int("flow_idle_timeout_seconds").Positive().Default(60),
	}
}

// Edges of a udp route.
func (RouteUDP) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("route", Route.Type).Field("route_id").Unique().Required().Immutable(),
		edge.To("port", PortAllocation.Type).Field("port_allocation_id").Unique().Required(),
	}
}

// Indexes: one row per route and one route per port allocation.
func (RouteUDP) Indexes() []ent.Index {
	return []ent.Index{index.Fields("route_id").Unique(), index.Fields("port_allocation_id").Unique()}
}

// RouteHTTP is the HTTP part of an http route, one row per route; its hostnames and path
// prefixes are route_hostnames rows.
type RouteHTTP struct{ ent.Schema }

// Mixin makes it org-owned.
func (RouteHTTP) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (RouteHTTP) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "route_http"}}
}

// Fields of an http route (docs/06-data-model.md, "Routes"). path_prefix applies to every hostname
// of the route, whose route_hostnames rows copy it. tls_mode acme uses the certificate ACME obtains
// for the hostnames, certificate the uploaded certificate_id. host_header is "preserve" or the
// Host value sent upstream; max_body_bytes 0 sets no limit.
func (RouteHTTP) Fields() []ent.Field {
	return []ent.Field{
		field.String("route_id").NotEmpty().Unique().Immutable(),
		field.String("path_prefix").Default(""),
		field.JSON("header_matches", map[string]string{}).Optional(),
		field.Enum("tls_mode").Values("acme", "certificate").Default("acme"),
		field.String("certificate_id").Optional().Nillable(),
		field.Enum("port80").Values("redirect", "serve", "off").Default("redirect"),
		// hsts_max_age_seconds sends Strict-Transport-Security over HTTPS; 0 sends none.
		field.Int("hsts_max_age_seconds").NonNegative().Default(0),
		field.String("host_header").NotEmpty().Default("preserve"),
		field.JSON("request_headers_set", map[string]string{}).Optional(),
		field.JSON("response_headers_set", map[string]string{}).Optional(),
		field.Bool("websocket").Default(true),
		field.Int64("max_body_bytes").NonNegative().Default(0),
		field.Bool("dns_proxied").Default(false),
	}
}

// Edges of an http route.
func (RouteHTTP) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("route", Route.Type).Field("route_id").Unique().Required().Immutable(),
		edge.To("certificate", Certificate.Type).Field("certificate_id").Unique(),
	}
}

// Indexes: one row per route, and the routes of a certificate.
func (RouteHTTP) Indexes() []ent.Index {
	return []ent.Index{index.Fields("route_id").Unique(), index.Fields("certificate_id")}
}

// RouteTarget is where a connector delivers a route's connections; several targets balance and
// fail over.
type RouteTarget struct{ ent.Schema }

// Mixin makes route targets org-owned and versioned.
func (RouteTarget) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}, VersionMixin{}} }

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
		field.String("tls_ca_bundle_id").Optional().Nillable(),
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
		edge.To("ca_bundle", CABundle.Type).Field("tls_ca_bundle_id").Unique(),
	}
}

// Indexes find a route's and a connector's targets, and a CA bundle's.
func (RouteTarget) Indexes() []ent.Index {
	return []ent.Index{index.Fields("route_id"), index.Fields("connector_id"), index.Fields("tls_ca_bundle_id")}
}

// RouteHostname is one hostname of an http or tls_passthrough route, under a verified domain of
// the route's org (docs/06-data-model.md, "Routes"). The group, the type and the path prefix are
// copied from the route so that the uniqueness rule can be declared here; within a group a
// hostname is either one tls_passthrough route or any number of http routes, which
// routes.AddHostname enforces inside the configuration transaction.
type RouteHostname struct{ ent.Schema }

// Mixin makes route hostnames org-owned.
func (RouteHostname) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (RouteHostname) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "route_hostnames"}}
}

// Fields of a route hostname. hostname is normalised (internal/domains) and may start with "*."
// for http routes; path_prefix is "" for tls_passthrough.
func (RouteHostname) Fields() []ent.Field {
	return []ent.Field{
		field.String("route_id").NotEmpty().Immutable(),
		field.String("gateway_group_id").NotEmpty().Immutable(),
		field.Enum("route_type").Values("http", "tls_passthrough").Immutable(),
		field.String("hostname").NotEmpty().MaxLen(253).Immutable(),
		field.String("path_prefix").Default("").Immutable(),
		field.String("domain_id").NotEmpty(),
	}
}

// Edges of a route hostname: the route and the covering domain of the same org.
func (RouteHostname) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("route", Route.Type).Field("route_id").Unique().Required().Immutable(),
		edge.To("domain", Domain.Type).Field("domain_id").Unique().Required(),
	}
}

// Indexes: a hostname and path prefix are served once per group; a route's hostnames are found
// by route.
func (RouteHostname) Indexes() []ent.Index {
	return []ent.Index{index.Fields("gateway_group_id", "hostname", "path_prefix").Unique(), index.Fields("route_id")}
}

// AccessPolicy is an org's reusable list of rules that routes apply (docs/06-data-model.md,
// "Routing").
type AccessPolicy struct{ ent.Schema }

// Mixin makes access policies org-owned and versioned.
func (AccessPolicy) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}, VersionMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (AccessPolicy) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "access_policies"}}
}

// Fields of an access policy.
func (AccessPolicy) Fields() []ent.Field {
	return []ent.Field{
		idField("ap"),
		field.String("name").NotEmpty().MaxLen(100),
		field.String("description").Default("").MaxLen(1000),
	}
}

// Indexes: names are unique per org.
func (AccessPolicy) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "name").Unique()}
}

// PolicyRule is one rule of an access policy; a policy's rules apply in the order of position.
// params is an rpmgr.v1.PolicyRuleParams message.
type PolicyRule struct{ ent.Schema }

// Mixin makes policy rules org-owned.
func (PolicyRule) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (PolicyRule) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "policy_rules"}}
}

// Fields of a policy rule.
func (PolicyRule) Fields() []ent.Field {
	return []ent.Field{
		idField("pr"),
		field.String("policy_id").NotEmpty().Immutable(),
		field.Int("position").NonNegative(),
		field.Enum("kind").Values("ip_allow", "ip_deny", "basic_auth", "oidc", "rate_limit", "require_header"),
		field.Bytes("params"),
	}
}

// Edges of a policy rule.
func (PolicyRule) Edges() []ent.Edge {
	return []ent.Edge{edge.To("policy", AccessPolicy.Type).Field("policy_id").Unique().Required().Immutable()}
}

// Indexes: one rule per position of a policy.
func (PolicyRule) Indexes() []ent.Index {
	return []ent.Index{index.Fields("policy_id", "position").Unique()}
}

// RoutePolicy applies an access policy to a route; a route's policies apply in the order of
// position, each policy once.
type RoutePolicy struct{ ent.Schema }

// Mixin makes route policies org-owned.
func (RoutePolicy) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (RoutePolicy) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "route_policies"}}
}

// Fields of a route policy.
func (RoutePolicy) Fields() []ent.Field {
	return []ent.Field{
		field.String("route_id").NotEmpty().Immutable(),
		field.String("policy_id").NotEmpty().Immutable(),
		field.Int("position").NonNegative(),
	}
}

// Edges of a route policy: the route and the policy, of the same org.
func (RoutePolicy) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("route", Route.Type).Field("route_id").Unique().Required().Immutable(),
		edge.To("policy", AccessPolicy.Type).Field("policy_id").Unique().Required().Immutable(),
	}
}

// Indexes: a policy once per route, one per position, and the routes of a policy.
func (RoutePolicy) Indexes() []ent.Index {
	return []ent.Index{index.Fields("route_id", "policy_id").Unique(), index.Fields("route_id", "position").Unique(),
		index.Fields("policy_id")}
}
