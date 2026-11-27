// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
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

// ErrHostReplaced is returned on PostgreSQL when the database names another host as the one that
// runs its controller: `rpmgr controller adopt-state` on that host replaced this one. This host's
// revocation log lacks what the other host appended since, so it must not start.
var ErrHostReplaced = errors.New("controller: this host was replaced as the controller host by `rpmgr controller adopt-state` on another host; " +
	"do not start the controller here, or run `adopt-state --old-host-lost` here after moving that host's revocations.log")

// refuseReplacedHost refuses, from the database as it is (raw SQL, no migration), a host whose node
// ID is not the one the database names as the controller's.
func refuseReplacedHost(ctx context.Context, cfg config.Controller, db *store.DB) error {
	local, err := nodeIdentity(filepath.Join(cfg.State(), nodeIDFile), false)
	if err != nil {
		return err
	}
	active, err := store.RawActiveNode(ctx, db)
	if err != nil {
		return err
	}
	if active != "" && active != local {
		return ErrHostReplaced
	}
	return nil
}

// claimHost records this host as the controller's if the database names none, and refuses a host
// that is not the one it names.
func claimHost(ctx context.Context, db *store.DB, nodeID string) error {
	active, err := store.ActiveNode(ctx, db)
	if err != nil {
		return err
	}
	switch active {
	case nodeID:
		return nil
	case "":
		return store.SetActiveNode(ctx, db, nodeID)
	}
	return ErrHostReplaced
}

// ErrStaleLog is returned by adopt-state when this host has a revocation log and the database names
// another host as the controller's: that log lacks what the active host appended since.
var ErrStaleLog = errors.New("controller: this host's revocation log is not the active host's")

// refuseStaleLog refuses adopt-state on a host that holds a revocation log while the database names
// another host: the log is stale, and a controller that started with it would miss every
// revocation the active host recorded since. There is no override: the operator replaces it with
// the active host's log, or moves it aside, and adopt-state then starts a new one.
func refuseStaleLog(ctx context.Context, cfg config.Controller, db *store.DB) error {
	log := filepath.Join(cfg.State(), revocationLogFile)
	if _, err := os.Lstat(log); err != nil {
		return nil // none, or unreadable, which createHostState reports
	}
	active, err := store.RawActiveNode(ctx, db)
	if err != nil || active == "" {
		return err
	}
	if local, err := nodeIdentity(filepath.Join(cfg.State(), nodeIDFile), false); err == nil && local == active {
		return nil
	}
	return fmt.Errorf("%w: %s may lack revocations that host %s recorded since; replace it with that host's revocations.log, "+
		"or move it aside (adopt-state then starts an empty one)", ErrStaleLog, log, active)
}

// createHostState creates the files that requireHostState looks for, those that are missing, and
// returns their paths and the node ID: `rpmgr controller init` does it for a new database,
// `rpmgr controller adopt-state` for an operator who moves the controller to a new host on
// purpose.
func createHostState(cfg config.Controller) (made []string, nodeID string, err error) {
	id := filepath.Join(cfg.State(), nodeIDFile)
	if _, err := os.Lstat(id); errors.Is(err, os.ErrNotExist) {
		made = append(made, id)
	} else if err != nil {
		return nil, "", err
	}
	if nodeID, err = nodeIdentity(id, true); err != nil {
		return nil, "", err
	}
	log := filepath.Join(cfg.State(), revocationLogFile)
	if _, err := os.Lstat(log); errors.Is(err, os.ErrNotExist) {
		if _, err := revlog.Open(log, nil); err != nil {
			return made, nodeID, err
		}
		made = append(made, log)
	} else if err != nil {
		return made, nodeID, err
	}
	return made, nodeID, nil
}

// ErrAdoptNeedsAck is returned by adopt-state without the acknowledgement that the old host is
// lost.
var ErrAdoptNeedsAck = errors.New("controller: adopt-state makes this host the controller's and the database refuses every other; " +
	"pass --old-host-lost to confirm that the old host will not run the controller again")

// AdoptState is `rpmgr controller adopt-state`: on a PostgreSQL controller's new host, it creates
// the node ID and the empty revocation log that a controller needs there, those that are missing,
// and records this host in the database as the controller's, so that the old host, should it come
// back, is refused (ErrHostReplaced). It returns what it created. oldHostLost is the operator's
// confirmation. Run it only when the old host's files are gone for good: a log that is lost misses
// every revocation made before.
func AdoptState(ctx context.Context, path string, oldHostLost bool) ([]string, error) {
	cfg, err := loadController(path)
	if err != nil {
		return nil, err
	}
	if cfg.Database.Driver != "postgres" {
		return nil, errors.New("controller: only a controller on PostgreSQL adopts a state directory; a SQLite database brings its own")
	}
	if !oldHostLost {
		return nil, ErrAdoptNeedsAck
	}
	db, err := openDatabase(ctx, cfg, nil, dbOptions{Lock: true, Local: true})
	if err != nil {
		if errors.Is(err, store.ErrLocked) {
			return nil, ErrStopController
		}
		return nil, err
	}
	defer func() { _ = db.Close() }()
	if err := settleLock(ctx, db); err != nil {
		return nil, err
	}
	dir, err := migrations.Dir(db.Dialect)
	if err != nil {
		return nil, err
	}
	if pending, err := store.Pending(ctx, db, dir); err != nil {
		return nil, err
	} else if len(pending) > 0 {
		return nil, fmt.Errorf("%w: it is behind this binary by %d migrations; start the controller once, or run `rpmgr migrate`, before adopt-state", store.ErrSchemaMismatch, len(pending))
	}
	if err := store.ClaimFence(ctx, db); err != nil {
		return nil, err
	}
	if err := refuseStaleLog(ctx, cfg, db); err != nil {
		return nil, err
	}
	made, id, err := createHostState(cfg)
	if err != nil {
		return made, err
	}
	sys, err := authz.System(ctx, "local-cli", "rpmgr controller adopt-state", audit.SystemScopes(db))
	if err != nil {
		return made, err
	}
	was, err := store.ActiveNode(sys, db)
	if err != nil {
		return made, err
	}
	if was == id {
		return made, nil
	}
	if err := store.SetActiveNode(sys, db, id); err != nil {
		return made, err
	}
	_, err = audit.Record(sys, db, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "controller.adopt_state",
		TargetType: "instance", TargetID: "1", Result: audit.Success, Reason: "controller host " + was + " replaced by " + id})
	return made, err
}
