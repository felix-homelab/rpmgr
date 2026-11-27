// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// ErrNotControllerHost is returned on PostgreSQL when this host's state directory lacks the
// controller's node identity or its revocation log. A SQLite database is a file of the state
// directory, so the host that has it has the rest; a PostgreSQL database can be reached from any
// host, and a controller or a command that created these files from nothing would start with a
// log that misses every revocation made before.
var ErrNotControllerHost = errors.New("controller: this host's state directory does not hold the controller's node ID and revocation log; " +
	"run this on the controller host, or move controller-node.id and revocations.log here and, for a new host, run `rpmgr controller adopt-state`")

const (
	nodeIDFile        = "controller-node.id"
	revocationLogFile = "revocations.log"
)

// requireHostState refuses, on PostgreSQL, a host whose state directory does not hold both files
// of this installation. It creates nothing. SQLite needs no such check.
func requireHostState(cfg config.Controller) error {
	if cfg.Database.Driver != "postgres" {
		return nil
	}
	for _, name := range []string{nodeIDFile, revocationLogFile} {
		p := filepath.Join(cfg.State(), name)
		if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("%w (missing or not a file: %s)", ErrNotControllerHost, p)
		}
	}
	return nil
}

// createHostState creates the files that requireHostState looks for, those that are missing, and
// returns their paths: `rpmgr controller init` does it for a new database, `rpmgr controller
// adopt-state` for an operator who moves the controller to a new host on purpose.
func createHostState(cfg config.Controller) ([]string, error) {
	var made []string
	id := filepath.Join(cfg.State(), nodeIDFile)
	if _, err := os.Lstat(id); errors.Is(err, os.ErrNotExist) {
		if _, err := nodeIdentity(id); err != nil {
			return made, err
		}
		made = append(made, id)
	} else if err != nil {
		return made, err
	}
	log := filepath.Join(cfg.State(), revocationLogFile)
	if _, err := os.Lstat(log); errors.Is(err, os.ErrNotExist) {
		if _, err := revlog.Open(log, nil); err != nil {
			return made, err
		}
		made = append(made, log)
	} else if err != nil {
		return made, err
	}
	return made, nil
}

// AdoptState is `rpmgr controller adopt-state`: on a PostgreSQL controller's new host, it creates
// the node ID and the empty revocation log that a controller needs there, and returns what it
// created. Run it only when the old host's files are gone for good (a log that is lost misses
// every revocation made before): a host that has the files keeps them.
func AdoptState(ctx context.Context, path string) ([]string, error) {
	cfg, err := loadController(path)
	if err != nil {
		return nil, err
	}
	if cfg.Database.Driver != "postgres" {
		return nil, errors.New("controller: only a controller on PostgreSQL adopts a state directory; a SQLite database brings its own")
	}
	db, err := openDatabase(ctx, cfg, nil, dbOptions{Lock: true, Local: true})
	if err != nil {
		if errors.Is(err, store.ErrLocked) {
			return nil, ErrStopController
		}
		return nil, err
	}
	defer func() { _ = db.Close() }()
	return createHostState(cfg)
}
