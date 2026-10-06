// SPDX-License-Identifier: Apache-2.0

// Package migrations embeds the versioned migrations of both dialects, as the rpmgr binary will
// (docs/06-data-model.md, "Migrations").
package migrations

import (
	"embed"
	"fmt"
	"io/fs"

	"ariga.io/atlas/sql/migrate"
)

//go:embed sqlite/*.sql sqlite/atlas.sum postgres/*.sql postgres/atlas.sum
var files embed.FS

// Dir returns the embedded migration directory of a dialect ("sqlite" or "postgres") as an
// in-memory Atlas directory, including its atlas.sum.
func Dir(dialectName string) (migrate.Dir, error) {
	entries, err := fs.ReadDir(files, dialectName)
	if err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}
	dir := &migrate.MemDir{}
	for _, e := range entries {
		b, err := files.ReadFile(dialectName + "/" + e.Name())
		if err != nil {
			return nil, err
		}
		if err := dir.WriteFile(e.Name(), b); err != nil {
			return nil, err
		}
	}
	return dir, nil
}
