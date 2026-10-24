// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"regexp"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// slugRe is the form of names that appear in URLs and DNS labels.
var slugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// GatewayGroup is a set of at most four gateways that publish routes together
// (docs/06-data-model.md, "Fleet"). Shared groups belong to the system org (D14). Its DNS target
// arrives with managed DNS (Phase 2), and its other settings with the slices that use them.
type GatewayGroup struct{ ent.Schema }

// Mixin makes gateway groups org-owned.
func (GatewayGroup) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}, VersionMixin{}} }

// Fields of a gateway group.
func (GatewayGroup) Fields() []ent.Field {
	return []ent.Field{
		idField("gwg"),
		field.String("name").NotEmpty().Match(slugRe),
		field.String("region").Optional(),
		// public_hostnames are the DNS names or anycast addresses of public traffic.
		field.Strings("public_hostnames").Optional().Validate(validateHostnames),
		// trusted_proxy_cidrs are the proxies whose forwarding headers gateways keep
		// (docs/03-connections.md, "HTTP routes").
		field.Strings("trusted_proxy_cidrs").Optional().Validate(validateCIDRs),
	}
}

// Indexes: names are unique per org.
func (GatewayGroup) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "name").Unique()}
}

// MaxPageBytes is the largest custom page (docs/03-connections.md, "Timeouts, keepalive and
// backoff").
const MaxPageBytes = 64 << 10

// GatewayPage is a page a gateway group replaced with its own, one per kind (D132): set by the
// group's owner org, fetched by the group's gateways by content_sha256.
type GatewayPage struct{ ent.Schema }

// Mixin makes gateway pages org-owned: the group's owner org.
func (GatewayPage) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (GatewayPage) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "gateway_pages"}}
}

// Fields of a gateway page.
func (GatewayPage) Fields() []ent.Field {
	return []ent.Field{
		idField("gwp"),
		field.String("gateway_group_id").NotEmpty().Immutable(),
		field.Enum("kind").Values("not_found", "unavailable", "maintenance").Immutable(),
		field.Text("html").NotEmpty().MaxLen(MaxPageBytes),
		// content_sha256 is the SHA-256 of html, by which gateways fetch it.
		field.Bytes("content_sha256").MinLen(32).MaxLen(32),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.String("updated_by").Optional(),
	}
}

// Edges of a gateway page.
func (GatewayPage) Edges() []ent.Edge {
	return []ent.Edge{edge.To("group", GatewayGroup.Type).Field("gateway_group_id").Unique().Required().Immutable()}
}

// Indexes: one page of each kind per group.
func (GatewayPage) Indexes() []ent.Index {
	return []ent.Index{index.Fields("gateway_group_id", "kind").Unique()}
}
