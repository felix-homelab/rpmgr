// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// Lease is the lock of one singleton job (docs/10-operations.md, "High availability"). Its fencing
// token rises at every takeover, so a replica that lost the lease cannot commit work started
// under it. internal/lease writes it with plain SQL in the system scope.
type Lease struct{ ent.Schema }

// Mixin makes leases system-only.
func (Lease) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (Lease) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "leases"}}
}

// Fields of a lease; its ID is the job's name. expires_at is in Unix milliseconds, so both
// dialects compare it as a number.
func (Lease) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").StorageKey("name").NotEmpty().Immutable(),
		field.String("holder"),
		field.Int64("fencing_token").Positive(),
		field.Int64("expires_at"),
	}
}
