// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// MaxGatewaysPerGroup bounds a gateway group, because every connector serving a route keeps a
// data session to every gateway of its group (docs/03-connections.md, "Multiple gateways").
const MaxGatewaysPerGroup = 4

// ErrGroupFull is returned when a gateway group already has MaxGatewaysPerGroup gateways.
var ErrGroupFull = errors.New("store: the gateway group already has 4 gateways")

// Gateway is one gateway of a group (docs/06-data-model.md, "Fleet"). An Admin creates it before
// it enrolls (R15), so its identity columns are empty until then. A decommissioned gateway stays
// as a tombstone and no longer counts towards its group's limit.
type Gateway struct{ ent.Schema }

// Mixin makes gateways org-owned.
func (Gateway) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Fields of a gateway.
func (Gateway) Fields() []ent.Field {
	return []ent.Field{
		idField("gw"),
		field.String("gateway_group_id").NotEmpty().Immutable(),
		field.String("name").NotEmpty().Match(slugRe),
		// slot is the gateway's place in its group, 1 to 4, unique among its active gateways; the
		// store assigns it, and the unique index keeps a group at four under concurrent creates.
		field.Int("slot").Range(1, MaxGatewaysPerGroup).Immutable(),
		// tunnel_endpoints are host:port addresses where connectors reach this gateway, over QUIC
		// and TCP (docs/03-connections.md, "Establishment"); WSS hostnames come in Phase 2.
		field.Strings("tunnel_endpoints").Validate(validateEndpoints),
		field.String("spiffe_id").Optional(),
		field.String("pubkey_sha256").Optional(),
		field.Bool("enabled").Default(true),
		field.String("desired_version").Optional(),
		field.Time("created_at").Immutable().Default(time.Now),
		field.Time("decommissioned_at").Optional().Nillable(),
	}
}

// Edges of a gateway.
func (Gateway) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("group", GatewayGroup.Type).Field("gateway_group_id").Unique().Required().Immutable(),
	}
}

// Indexes: names are unique per org, slots per group among active gateways.
func (Gateway) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("org_id", "name").Unique(),
		index.Fields("gateway_group_id", "slot").Unique().
			Annotations(entsql.IndexWhere("decommissioned_at IS NULL")),
	}
}

func validateEndpoints(eps []string) error {
	for _, e := range eps {
		host, port, err := net.SplitHostPort(e)
		if n, perr := strconv.Atoi(port); err != nil || perr != nil || host == "" || n < 1 || n > 65535 {
			return fmt.Errorf("tunnel endpoint %q: want host:port", e)
		}
	}
	return nil
}

// Connector is one enrolled connector (docs/06-data-model.md, "Fleet").
type Connector struct{ ent.Schema }

// Mixin makes connectors org-owned.
func (Connector) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Fields of a connector. transport overrides the data-session transport; null is the instance
// default (docs/03-connections.md, "Transport selection").
func (Connector) Fields() []ent.Field {
	return []ent.Field{
		idField("con"),
		field.String("name").NotEmpty().Match(slugRe),
		field.JSON("labels", map[string]string{}).Optional(),
		field.String("spiffe_id").NotEmpty(),
		field.String("pubkey_sha256").NotEmpty(),
		field.Bool("ephemeral").Default(false).Immutable(),
		field.Bool("enabled").Default(true),
		field.Enum("transport").Values("auto", "quic", "h2").Optional().Nillable(),
		field.String("desired_version").Optional(),
		field.Time("created_at").Immutable().Default(time.Now),
		field.Time("decommissioned_at").Optional().Nillable(),
	}
}

// Indexes: names are unique per org.
func (Connector) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "name").Unique()}
}

// EnrollmentToken is a token that enrolls one agent or, if multi-use, several
// (docs/04-security.md, "Tokens"). A gateway token is bound to the gateway an Admin created (R15);
// a re-enrollment token to its connector.
type EnrollmentToken struct{ ent.Schema }

// Mixin makes enrollment tokens org-owned.
func (EnrollmentToken) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Fields of an enrollment token; the token itself is stored only as its SHA-256.
func (EnrollmentToken) Fields() []ent.Field {
	return []ent.Field{
		idField("enr"),
		field.Bytes("token_hash").NotEmpty().Unique().Immutable(),
		field.Enum("role").Values("connector", "gateway").Immutable(),
		field.String("gateway_group_id").Optional().Nillable().Immutable(),
		field.String("gateway_id").Optional().Nillable().Immutable(),
		field.String("connector_id").Optional().Nillable().Immutable(),
		field.JSON("labels", map[string]string{}).Optional(),
		field.Bool("ephemeral").Default(false).Immutable(),
		// max_uses is null for unlimited uses, which only ephemeral tokens may have; create a token
		// with max_uses 0 to ask for that (docs/04-security.md, "Tokens"). Unset means 1.
		field.Int("max_uses").Positive().Optional().Nillable().Immutable(),
		field.Int("use_count").NonNegative().Default(0),
		field.Time("expires_at").Immutable(),
		field.String("created_by").NotEmpty().Immutable(),
		field.Time("created_at").Immutable().Default(time.Now),
		field.Time("last_used_at").Optional().Nillable(),
		field.String("last_used_ip").Optional(),
		field.Time("revoked_at").Optional().Nillable(),
	}
}

// Edges of an enrollment token.
func (EnrollmentToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("group", GatewayGroup.Type).Field("gateway_group_id").Unique().Immutable(),
		edge.To("gateway", Gateway.Type).Field("gateway_id").Unique().Immutable(),
		edge.To("connector", Connector.Type).Field("connector_id").Unique().Immutable(),
	}
}

// validateCIDRs accepts prefixes such as 203.0.113.0/24 and 2001:db8::/32.
func validateCIDRs(cidrs []string) error {
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil || p != p.Masked() {
			return fmt.Errorf("trusted proxy %q: want a prefix such as 203.0.113.0/24", c)
		}
	}
	return nil
}

// hostnameRe is a DNS name of at least two labels, lower case, without a trailing dot.
var hostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validateHostnames accepts DNS names and IP addresses.
func validateHostnames(names []string) error {
	for _, n := range names {
		if _, err := netip.ParseAddr(n); err != nil && (len(n) > 253 || !hostnameRe.MatchString(n)) {
			return fmt.Errorf("public hostname %q: want a DNS name or an IP address", n)
		}
	}
	return nil
}
