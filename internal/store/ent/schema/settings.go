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

// InstanceSetting is the single row that holds the instance's runtime settings: the serialised
// rpmgr.v1.InstanceSettings message, so every setting is typed and validated
// (docs/06-data-model.md, "System"). Unset fields have their defaults.
type InstanceSetting struct{ ent.Schema }

// Mixin makes the settings instance-level; the API allows only the Instance Admin to change them.
func (InstanceSetting) Mixin() []ent.Mixin { return []ent.Mixin{InstanceMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (InstanceSetting) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "instance_settings"}}
}

// Fields of the instance settings; the ID is always 1.
func (InstanceSetting) Fields() []ent.Field {
	return []ent.Field{
		field.Int("id").Range(1, 1).Immutable(),
		field.Bytes("value"),
		field.Int64("version").Positive(),
		field.String("updated_by").NotEmpty(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// OrgSetting holds one org's runtime settings: the serialised rpmgr.v1.OrgSettings message.
type OrgSetting struct{ ent.Schema }

// Mixin makes org settings org-owned.
func (OrgSetting) Mixin() []ent.Mixin { return []ent.Mixin{OrgMixin{}} }

// Annotations name the table as docs/06-data-model.md does.
func (OrgSetting) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "org_settings"}}
}

// Fields of an org's settings.
func (OrgSetting) Fields() []ent.Field {
	return []ent.Field{
		idField("ost"),
		field.Bytes("value"),
		field.Int64("version").Positive(),
		field.String("updated_by").NotEmpty(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Indexes: one settings row per org.
func (OrgSetting) Indexes() []ent.Index {
	return []ent.Index{index.Fields("org_id").Unique()}
}
