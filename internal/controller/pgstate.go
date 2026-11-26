// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"path/filepath"

	"github.com/felix-homelab/rpmgr/internal/config"
)

// postgresStateDir is the state directory of a controller on PostgreSQL, where its revocation log
// and audit checkpoints are: the database's DSN names no directory then
// (docs/10-operations.md, "Filesystem layout").
var postgresStateDir = "/var/lib/rpmgr"

// bootDatabase reads the database a backup or restore works on from a controller's or all-in-one's
// boot file. A PostgreSQL database is read from the `database` section alone, as `migrate-db` does,
// because the boot file's other sections are not this command's business.
func bootDatabase(path string) (config.Database, error) {
	if d, err := config.LoadDatabase(path); err == nil && d.Driver == "postgres" {
		return d, nil
	}
	cfg, err := loadController(path)
	if err != nil {
		return config.Database{}, err
	}
	return config.Database{Driver: cfg.Database.Driver, DSN: cfg.Database.DSN}, nil
}

// stateDir is the directory of the controller's local state, which holds its logs.
func stateDir(d config.Database) string {
	if d.Driver == "postgres" {
		return postgresStateDir
	}
	return filepath.Dir(d.DSN)
}
