// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"regexp"

	"entgo.io/ent"
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
