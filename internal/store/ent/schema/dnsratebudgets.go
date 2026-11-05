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

// DNSRateBudget is the request budget of one DNS provider (docs/06-data-model.md, "DNS (Phase 2)";
// docs/15-dns.md, "Batches, failures and the rate budget"; D164). The DNS job and the DNS-01
// adapter take every request from the row in a transaction, on whichever replica they run, so the
// replicas never add up past the budget. The row is runtime state and is created when the first
// request is taken; it goes with the provider.
type DNSRateBudget struct{ ent.Schema }

// Mixin makes budgets org-owned, as the provider is, and versioned: a taker commits only if nobody
// else took from the row meanwhile.
func (DNSRateBudget) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}, VersionMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (DNSRateBudget) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "dns_rate_budgets"}}
}

// Fields of a budget. window_started_at, used and dns01_used are the current window: requests
// taken by the job and the DNS-01 adapter together, and by the DNS-01 adapter alone. blocked_until
// is the end of a retry-after block, unset when there is none.
func (DNSRateBudget) Fields() []ent.Field {
	return []ent.Field{
		idField("dnb"),
		field.String("dns_provider_id").NotEmpty().Immutable(),
		field.Time("window_started_at").Default(time.Now),
		field.Int("used").Default(0).NonNegative(),
		field.Int("dns01_used").Default(0).NonNegative(),
		field.Time("blocked_until").Optional().Nillable(),
	}
}

// Edges: the provider, of the same org (composite foreign key).
func (DNSRateBudget) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("dns_provider", DNSProvider.Type).Field("dns_provider_id").Unique().Required().Immutable(),
	}
}

// Indexes: one budget per provider.
func (DNSRateBudget) Indexes() []ent.Index {
	return []ent.Index{index.Fields("dns_provider_id").Unique()}
}
