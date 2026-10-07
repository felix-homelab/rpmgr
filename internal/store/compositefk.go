// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"

	atlas "ariga.io/atlas/sql/schema"
	entschema "entgo.io/ent/dialect/sql/schema"
)

// OrgColumn is the tenancy column of every org-owned table.
const OrgColumn = "org_id"

// CompositeFKExceptions lists the foreign keys between org-owned tables that stay single-column,
// as "<table>.<column>". routes.gateway_group_id may point at a shared gateway group of the system
// org, which other orgs use through grants (D14, docs/06-data-model.md, "Tenancy enforcement").
var CompositeFKExceptions = []string{"routes.gateway_group_id", "port_allocations.gateway_group_id"}

// CompositeForeignKeys is an Ent diff hook that rewrites the desired schema before Atlas diffs it,
// because Ent cannot declare composite foreign keys (docs/06-data-model.md, "Tenancy
// enforcement"). For every table with an org_id column it:
//
//   - adds org_id → orgs(id);
//   - replaces each single-column foreign key to another org-owned table, c → parent(id), with
//     (org_id, c) → parent(org_id, id), unless "<table>.<c>" is in except;
//   - requires the parent's UNIQUE (org_id, id) index (OrgMixin declares it), which both SQLite
//     and PostgreSQL need for a composite foreign key.
//
// The composite key keeps ON DELETE NO ACTION, so deleting a parent that still has children of the
// same org is refused, as for Ent's own keys.
func CompositeForeignKeys(except ...string) entschema.DiffHook {
	skip := make(map[string]bool, len(except))
	for _, e := range except {
		skip[e] = true
	}
	return func(next entschema.Differ) entschema.Differ {
		return entschema.DiffFunc(func(current, desired *atlas.Schema) ([]atlas.Change, error) {
			if err := RewriteForeignKeys(desired, skip); err != nil {
				return nil, err
			}
			return next.Diff(current, desired)
		})
	}
}

// RewriteForeignKeys applies the CompositeForeignKeys rules to s in place. It is idempotent.
func RewriteForeignKeys(s *atlas.Schema, skip map[string]bool) error {
	orgs, ok := s.Table("orgs")
	if !ok {
		return fmt.Errorf("store: schema has no orgs table")
	}
	orgsID, ok := orgs.Column("id")
	if !ok {
		return fmt.Errorf("store: orgs has no id column")
	}
	for _, t := range s.Tables {
		org, ok := t.Column(OrgColumn)
		if !ok || t == orgs {
			continue
		}
		if !referencesOrgs(t, org, orgs) {
			t.AddForeignKeys(atlas.NewForeignKey(t.Name + "_orgs").
				AddColumns(org).SetRefTable(orgs).AddRefColumns(orgsID).
				SetOnUpdate(atlas.NoAction).SetOnDelete(atlas.NoAction))
		}
		for i, fk := range t.ForeignKeys {
			if len(fk.Columns) != 1 || fk.RefTable == orgs || skip[t.Name+"."+fk.Columns[0].Name] {
				continue
			}
			refOrg, ok := fk.RefTable.Column(OrgColumn)
			if !ok {
				continue // the parent is not org-owned (e.g. users)
			}
			if !hasUniqueIndex(fk.RefTable, OrgColumn, fk.RefColumns[0].Name) {
				return fmt.Errorf("store: %s needs UNIQUE (%s, %s) for the composite key from %s",
					fk.RefTable.Name, OrgColumn, fk.RefColumns[0].Name, t.Name)
			}
			col := fk.Columns[0]
			col.ForeignKeys = removeFK(col.ForeignKeys, fk)
			composite := atlas.NewForeignKey(fk.Symbol).SetTable(t).
				AddColumns(org, col).SetRefTable(fk.RefTable).AddRefColumns(refOrg, fk.RefColumns[0]).
				SetOnUpdate(atlas.NoAction).SetOnDelete(atlas.NoAction)
			t.ForeignKeys[i] = composite
		}
	}
	return nil
}

func referencesOrgs(t *atlas.Table, org *atlas.Column, orgs *atlas.Table) bool {
	for _, fk := range t.ForeignKeys {
		if fk.RefTable == orgs && len(fk.Columns) == 1 && fk.Columns[0] == org {
			return true
		}
	}
	return false
}

func hasUniqueIndex(t *atlas.Table, cols ...string) bool {
	for _, idx := range t.Indexes {
		if !idx.Unique || len(idx.Parts) != len(cols) {
			continue
		}
		match := true
		for i, p := range idx.Parts {
			if p.C == nil || p.C.Name != cols[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func removeFK(fks []*atlas.ForeignKey, fk *atlas.ForeignKey) []*atlas.ForeignKey {
	out := fks[:0]
	for _, f := range fks {
		if f != fk {
			out = append(out, f)
		}
	}
	return out
}
