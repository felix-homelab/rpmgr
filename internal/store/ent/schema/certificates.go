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

// Certificate is a public TLS certificate of an org's http routes, uploaded or obtained with ACME
// (docs/06-data-model.md, "Routes"; docs/04-security.md, "Controller certificates"). Gateways
// fetch its chain and key by content hash.
type Certificate struct{ ent.Schema }

// Mixin makes certificates org-owned.
func (Certificate) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (Certificate) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "certificates"}}
}

// Fields of a certificate. chain is the DER certificates, leaf first, concatenated; key_enc is
// the leaf's PKCS #8 private key under the KEK; content_sha256 is the hash of what a gateway
// fetches, both together.
func (Certificate) Fields() []ent.Field {
	return []ent.Field{
		idField("crt"),
		field.Enum("source").Values("acme", "uploaded").Immutable(),
		// sans are the leaf's DNS names, normalised.
		field.Strings("sans"),
		field.Time("not_before"),
		field.Time("not_after"),
		field.Bytes("chain").NotEmpty(),
		field.Bytes("key_enc").NotEmpty().Sensitive(),
		field.Bytes("content_sha256").NotEmpty(),
		field.Enum("status").Values("pending", "active", "failed").Default("active"),
		field.String("last_error").Optional(),
		field.String("issuer").Optional(),
		field.Time("created_at").Immutable().Default(time.Now),
		field.Int64("version").Positive().Default(1),
	}
}

// CABundle is a set of an org's CA certificates that verify the certificates of HTTPS upstreams
// (docs/06-data-model.md, "Routes"), referenced by route_targets.tls_ca_bundle_id.
type CABundle struct{ ent.Schema }

// Mixin makes CA bundles org-owned.
func (CABundle) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (CABundle) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "ca_bundles"}}
}

// Fields of a CA bundle: pem holds CERTIFICATE blocks only (certs.CheckBundle).
func (CABundle) Fields() []ent.Field {
	return []ent.Field{
		idField("cab"),
		field.String("name").NotEmpty().MaxLen(100),
		field.Bytes("pem").NotEmpty(),
		field.Time("created_at").Immutable().Default(time.Now),
		field.Int64("version").Positive().Default(1),
	}
}

// Indexes: names are unique per org.
func (CABundle) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id", "name").Unique()}
}
