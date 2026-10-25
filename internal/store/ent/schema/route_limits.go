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

// RouteLimit holds a route's limits, for the route as a whole, at most one row per route; a route
// without limits has none (docs/03-connections.md, "Route limits").
type RouteLimit struct{ ent.Schema }

// Mixin makes it org-owned.
func (RouteLimit) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (RouteLimit) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "route_limits"}}
}

// Fields of a route's limits; each 0 is no limit.
func (RouteLimit) Fields() []ent.Field {
	return []ent.Field{
		field.String("route_id").NotEmpty().Unique().Immutable(),
		field.Int64("max_connections").NonNegative().Default(0),
		field.Int64("requests_per_sec").NonNegative().Default(0),
		field.Int64("bandwidth_bytes_per_sec").NonNegative().Default(0),
	}
}

// Edges of a route's limits.
func (RouteLimit) Edges() []ent.Edge {
	return []ent.Edge{edge.To("route", Route.Type).Field("route_id").Unique().Required().Immutable()}
}

// Indexes: one row per route.
func (RouteLimit) Indexes() []ent.Index {
	return []ent.Index{index.Fields("route_id").Unique()}
}
