// SPDX-License-Identifier: Apache-2.0

// Package migrations embeds the versioned migrations of both dialects in the binary
// (docs/06-data-model.md, "Migrations"). They are generated with tools/storemigrate and committed;
// CI fails if regenerating them yields a new file.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"

	"ariga.io/atlas/sql/migrate"
)

//go:embed sqlite postgres
var files embed.FS

// Dir returns the migrations of a dialect ("sqlite3" or "postgres", as store.SQLite and
// store.Postgres) as an in-memory Atlas directory with its atlas.sum.
func Dir(dialect string) (migrate.Dir, error) {
	name, ok := map[string]string{"sqlite3": "sqlite", "postgres": "postgres"}[dialect]
	if !ok {
		return nil, fmt.Errorf("migrations: unknown dialect %q", dialect)
	}
	entries, err := fs.ReadDir(files, name)
	if err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}
	dir := &migrate.MemDir{}
	for _, e := range entries {
		b, err := files.ReadFile(name + "/" + e.Name())
		if err != nil {
			return nil, err
		}
		if err := dir.WriteFile(e.Name(), b); err != nil {
			return nil, err
		}
	}
	return dir, nil
}
