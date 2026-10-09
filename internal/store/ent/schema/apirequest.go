// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// APIRequest is a Create request of the public API with a request_id, kept for the deduplication
// window so that a retry gets the first response instead of a second resource
// (docs/07-api.md, "Resource design"). Only the system scope reads or writes it.
type APIRequest struct{ ent.Schema }

// Mixin makes API requests system-only.
func (APIRequest) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (APIRequest) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "api_requests"}}
}

// Fields of an API request. response_enc is the response under the KEK, with the row as its
// context; it is null until the first request answered.
func (APIRequest) Fields() []ent.Field {
	return []ent.Field{
		idField("arq"),
		field.String("caller_id").NotEmpty().Immutable(),
		field.String("method").NotEmpty().Immutable(),
		field.String("request_id").NotEmpty().MaxLen(128).Immutable(),
		field.Bytes("request_hash").Immutable(),
		field.Bytes("response_enc").Optional().Nillable(),
		field.Time("created_at").Immutable(),
	}
}

// Indexes: one row per caller, method and request_id; pruning by age.
func (APIRequest) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("caller_id", "method", "request_id").Unique(),
		index.Fields("created_at"),
	}
}
