// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"errors"

	"github.com/felix-homelab/rpmgr/internal/config"
)

// bootConfig reads what a backup or restore works on from a controller's or all-in-one's boot file.
// A PostgreSQL file is read from the `database` section alone, as `migrate-db` does, when the rest
// of it does not load, because the boot file's other sections are not this command's business; its
// state directory is then the default one (Controller.State).
func bootConfig(path string) (config.Controller, error) {
	d, derr := config.LoadDatabase(path)
	cfg, err := loadController(path)
	if err == nil {
		if derr != nil && cfg.Database.Driver == "postgres" {
			return config.Controller{}, derr // not a file of a SQLite controller: say what is wrong with its section
		}
		return cfg, nil
	}
	if derr == nil && d.Driver == "postgres" {
		cfg = config.Controller{Database: d}
		if stateDirOverride != "" {
			cfg.StateDir = stateDirOverride
		}
		return cfg, nil
	}
	// Of a PostgreSQL file only the database section is read, so its fault is named too.
	return config.Controller{}, errors.Join(err, derr)
}
