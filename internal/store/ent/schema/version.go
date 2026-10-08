// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

// VersionMixin gives a resource a version, its etag in the API (docs/07-api.md, "Concurrency"),
// which every update raises by one.
type VersionMixin struct{ mixin.Schema }

// Fields returns version.
func (VersionMixin) Fields() []ent.Field {
	return []ent.Field{field.Int64("version").Default(1).Positive()}
}

// Hooks raise the version at every update.
func (VersionMixin) Hooks() []ent.Hook {
	return []ent.Hook{func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if m.Op().Is(ent.OpUpdate | ent.OpUpdateOne) {
				if v, ok := m.(interface{ AddVersion(int64) }); ok {
					v.AddVersion(1)
				}
			}
			return next.Mutate(ctx, m)
		})
	}}
}
