// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// DNSProvider is an org's connected account at a DNS host (docs/06-data-model.md, "DNS (Phase 2)";
// docs/15-dns.md, "Connecting, importing and disconnecting"). Its API token is sealed under the
// KEK and write-only: no API, export or log shows it. The name is unique within the org.
type DNSProvider struct{ ent.Schema }

// Mixin makes providers org-owned and versioned.
func (DNSProvider) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}, VersionMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (DNSProvider) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "dns_providers"}}
}

// Fields of a provider. account_id is set only for an account-owned token. status is what the last
// check of the token found; token_expires_at is zero (NULL) for a token that does not expire;
// last_error is why the token is invalid, empty otherwise.
func (DNSProvider) Fields() []ent.Field {
	return []ent.Field{
		idField("dnp"),
		field.Enum("kind").Values("cloudflare").Immutable(),
		field.String("name").NotEmpty().MaxLen(64),
		field.Bytes("credential_enc").NotEmpty().Sensitive(),
		field.String("account_id").Default("").MaxLen(64),
		field.Enum("status").Values("ok", "invalid").Default("ok"),
		field.Time("token_expires_at").Optional().Nillable(),
		field.Time("last_checked_at").Optional().Nillable(),
		field.String("last_error").Default("").MaxLen(512),
		field.Time("created_at").Immutable().Default(time.Now),
	}
}

// Indexes: a name is used once in an org.
func (DNSProvider) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "name").Unique()}
}
