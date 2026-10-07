// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"ariga.io/atlas/sql/migrate"
	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	entschema "entgo.io/ent/dialect/sql/schema"

	entmigrate "github.com/felix-homelab/rpmgr/internal/store/ent/migrate"
)

// Diff writes the next migration file, named name, into dir: the changes between the migrations
// already in dir, replayed on the clean development database dev, and the Ent schema with
// composite foreign keys. It returns migrate.ErrNoPlan when dir is up to date (S5: Ent's Go API
// with the Apache-2.0 ariga.io/atlas library; the community Atlas CLI cannot read Ent schemas).
func Diff(ctx context.Context, d string, dev *sql.DB, dir migrate.Dir, name string) error {
	m, err := entschema.NewMigrate(entsql.OpenDB(d, dev),
		entschema.WithDir(dir),
		entschema.WithMigrationMode(entschema.ModeReplay),
		entschema.WithDialect(d),
		entschema.WithFormatter(migrate.DefaultFormatter),
		entschema.WithDropColumn(true),
		entschema.WithDropIndex(true),
		entschema.WithErrNoPlan(true),
		entschema.WithDiffHook(CompositeForeignKeys(CompositeFKExceptions...)),
	)
	if err != nil {
		return err
	}
	return m.NamedDiff(ctx, name, entmigrate.Tables...)
}

// Check compares the live schema of db with the Ent schema, composite foreign keys included
// (docs/12-testing-and-quality.md, "Database tests"). It plans what Ent would change and fails
// if the plan is not empty; nothing is applied.
func Check(ctx context.Context, db *DB) error {
	var changes []string
	m, err := entschema.NewMigrate(entsql.OpenDB(db.Dialect, db.Writer),
		entschema.WithDialect(db.Dialect),
		entschema.WithDropColumn(true),
		entschema.WithDropIndex(true),
		entschema.WithDiffHook(CompositeForeignKeys(CompositeFKExceptions...)),
		entschema.WithApplyHook(func(entschema.Applier) entschema.Applier {
			return entschema.ApplyFunc(func(_ context.Context, _ dialect.ExecQuerier, plan *migrate.Plan) error {
				for _, c := range plan.Changes {
					changes = append(changes, c.Cmd)
				}
				return nil // record only, never apply
			})
		}),
	)
	if err != nil {
		return err
	}
	if err := m.Create(ctx, entmigrate.Tables...); err != nil {
		return err
	}
	if len(changes) > 0 {
		return fmt.Errorf("store: live schema differs from the Ent schema:\n%s", strings.Join(changes, "\n"))
	}
	return nil
}
