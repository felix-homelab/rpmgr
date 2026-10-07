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
// (docs/06-data-model.md, "Fleet"). Shared groups belong to the system org (D14). Its other
// columns arrive with the fleet schema.
type GatewayGroup struct{ ent.Schema }

// Mixin makes gateway groups org-owned.
func (GatewayGroup) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Fields of a gateway group.
func (GatewayGroup) Fields() []ent.Field {
	return []ent.Field{idField("gwg"), field.String("name").NotEmpty().Match(slugRe)}
}

// Indexes: names are unique per org.
func (GatewayGroup) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "name").Unique()}
}
