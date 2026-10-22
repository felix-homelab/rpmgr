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

// Release is a verified release manifest that the release check listed or an Instance Admin
// uploaded or imported (docs/06-data-model.md, "Webhooks and releases (Phase 2)";
// docs/04-security.md, "Over-the-air updates"). Releases belong to the instance, so only the
// system scope reads and writes them.
type Release struct{ ent.Schema }

// Mixin makes releases system-only.
func (Release) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (Release) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "releases"}}
}

// Fields of a release. manifest, signing_key_statement and their signatures are the signed files
// as they were verified; mirrored_at is set once the mirror holds every artifact.
func (Release) Fields() []ent.Field {
	return []ent.Field{
		idField("rel"),
		field.String("version").NotEmpty(),
		field.Enum("channel").Values("stable", "prerelease"),
		field.Int64("manifest_seq").Positive(),
		field.Bytes("manifest").NotEmpty(),
		field.Bytes("signature").NotEmpty(),
		field.Bytes("signing_key_statement").NotEmpty(),
		field.Bytes("statement_signature").NotEmpty(),
		field.Enum("source").Values("check", "upload", "import"),
		field.Time("mirrored_at").Optional().Nillable(),
		field.Time("created_at").Immutable().Default(time.Now),
	}
}

// Indexes: one row per version; a manifest of the same version with a higher seq replaces it.
func (Release) Indexes() []ent.Index {
	return []ent.Index{index.Fields("version").Unique()}
}

// Rollout is a staged rollout of one release to the connectors and gateways (D121). At most one
// rollout is running or paused: active is true exactly then, which a hook keeps in step with
// state, and a partial unique index allows one row with it.
type Rollout struct{ ent.Schema }

// Mixin makes rollouts system-only and versioned.
func (Rollout) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}, VersionMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (Rollout) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "rollouts"}}
}

// Fields of a rollout. percentage is the share of agents the current stage covers, 0 for the
// canary stage and 100 for all.
func (Rollout) Fields() []ent.Field {
	return []ent.Field{
		idField("rol"),
		field.String("release_id").NotEmpty().Immutable(),
		field.Enum("stage").Values("canary", "percentage", "all").Default("canary"),
		field.Int("percentage").Range(0, 100).Default(0),
		field.Enum("state").Values("running", "paused", "completed", "cancelled").Default("running"),
		field.Bool("active").Default(true),
		field.String("pause_reason").Default(""),
		field.String("created_by").NotEmpty().Immutable(),
		field.Time("created_at").Immutable().Default(time.Now),
		field.String("updated_by").Default(""),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Edges: the release a rollout installs; a release with a rollout cannot be deleted.
func (Rollout) Edges() []ent.Edge {
	return []ent.Edge{edge.To("release", Release.Type).Field("release_id").Unique().Required().Immutable()}
}

// Indexes: at most one rollout running or paused.
func (Rollout) Indexes() []ent.Index {
	return []ent.Index{index.Fields("active").Unique().Annotations(entsql.IndexWhere("active"))}
}

// RolloutTarget is one agent's progress in a rollout, one row per agent from the rollout's
// creation. There is no foreign key to the agent, a connector or a gateway; deleting an agent's
// row deletes its targets with it.
type RolloutTarget struct{ ent.Schema }

// Mixin makes rollout targets system-only.
func (RolloutTarget) Mixin() []ent.Mixin { return []ent.Mixin{SystemMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (RolloutTarget) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "rollout_targets"}}
}

// Fields of a rollout target. bucket places the agent in the percentages (Bucket); version_before
// is the version it ran when the rollout was created.
func (RolloutTarget) Fields() []ent.Field {
	return []ent.Field{
		idField("rlt"),
		field.String("rollout_id").NotEmpty().Immutable(),
		field.String("agent_id").NotEmpty().Immutable(),
		field.Enum("agent_kind").Values("connector", "gateway").Immutable(),
		field.Bool("canary").Default(false).Immutable(),
		field.Int("bucket").Range(0, 99).Immutable(),
		field.Enum("state").
			Values("pending", "offered", "staged", "updated", "rolled_back", "refused", "skipped", "stalled").
			Default("pending"),
		field.String("reason").Default(""),
		field.String("version_before").Default(""),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Edges: the rollout a target belongs to.
func (RolloutTarget) Edges() []ent.Edge {
	return []ent.Edge{edge.To("rollout", Rollout.Type).Field("rollout_id").Unique().Required().Immutable()}
}

// Indexes: one row per rollout and agent; an agent's rows are found by its ID.
func (RolloutTarget) Indexes() []ent.Index {
	return []ent.Index{index.Fields("rollout_id", "agent_id").Unique(), index.Fields("agent_id")}
}
