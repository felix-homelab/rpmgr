// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/felix-homelab/rpmgr/internal/store"
)

// ErrRetired is store.ErrRetired: the database was retired by `rpmgr migrate-db`.
var ErrRetired = store.ErrRetired

// refuseRetired is the check of every command that opens a database without the controller lock,
// before it begins; the write transactions check again (store.SQLiteOptions.RefuseRetired).
func refuseRetired(ctx context.Context, db *store.DB) error {
	at, to, retired, err := db.Retired(ctx)
	if err != nil {
		return err
	}
	if retired {
		return fmt.Errorf("%w (retired %s to %s)", ErrRetired, at.UTC().Format(time.RFC3339), to)
	}
	return nil
}
