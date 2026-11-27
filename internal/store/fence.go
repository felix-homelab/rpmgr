// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/felix-homelab/rpmgr/internal/store/ent"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
)

// ErrLockLost is returned by every statement and commit of a PostgreSQL database whose controller
// lock was lost (DB.LockLost): another controller may hold the database already, so nothing this
// one still has in flight may reach it (docs/06-data-model.md, "Connecting to PostgreSQL").
var ErrLockLost = errors.New("store: the PostgreSQL controller lock was lost")

// fence is the state that the fenced driver checks. Two fences stop a controller that is no longer
// the holder: the lock's loss as the controller sees it (lost), and the fence epoch it claimed
// (epoch), which a later holder bumps. The first is local and needs the controller to notice; the
// second is checked by the server inside every write transaction (FOR SHARE on the instance row),
// so a transaction of an earlier controller fails whenever it arrives and however late.
type fence struct {
	lost      <-chan struct{}
	exclusive bool         // a single controller, which claims an epoch
	epoch     atomic.Int64 // the claimed epoch; 0 until ClaimFence
}

func (f *fence) check() error {
	select {
	case <-f.lost: // a nil channel never fires: SQLite, or no lock
		return ErrLockLost
	default:
		return nil
	}
}

// checkEpoch reads the fence epoch in tx, which holds the row FOR SHARE until it ends: a later
// holder's bump waits for this transaction, or comes first and fails it.
func (f *fence) checkEpoch(ctx context.Context, tx dialect.Tx) error {
	want := f.epoch.Load()
	if want == 0 {
		return nil
	}
	var got sql.NullInt64
	rows, err := tx.(interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	}).QueryContext(ctx, "SELECT fence_epoch FROM instance WHERE id = 1 FOR SHARE")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		if err := rows.Scan(&got); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if got.Int64 != want {
		return fmt.Errorf("%w: another controller claimed the database (epoch %d, ours %d)", ErrLockLost, got.Int64, want)
	}
	return nil
}

// claimLockTimeout is how long ClaimFence waits for a transaction of an earlier controller.
var claimLockTimeout = 10 * time.Second

// ClaimFence makes db's controller the one whose write transactions the server accepts: it bumps
// the fence epoch of the instance row and from then on checks it in every write transaction. It
// waits for a transaction of an earlier controller that still holds the row, up to
// docs/03-connections.md's "Controller lock check" bound, and refuses to go on when one does not
// end (its session was ended at open, so only a server that does not answer is left). On SQLite,
// without the lock, with a shared lock, and before the instance exists, it does nothing.
func ClaimFence(ctx context.Context, db *DB) error {
	if db.Dialect != Postgres || !db.fence.exclusive {
		return nil
	}
	tx, err := db.Writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", claimLockTimeout.Milliseconds())); err != nil {
		return err
	}
	var epoch sql.NullInt64
	err = tx.QueryRowContext(ctx, "UPDATE instance SET fence_epoch = coalesce(fence_epoch, 0) + 1 WHERE id = 1 RETURNING fence_epoch").Scan(&epoch)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil // not initialised yet
	case err != nil:
		return fmt.Errorf("store: cannot claim the database from the previous controller: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	db.fence.epoch.Store(epoch.Int64)
	return nil
}

// fencedDriver is the Ent driver of a database that holds the controller lock: from the moment the
// lock is lost, no statement starts and no transaction commits, whichever way the write is made
// (Ent mutation, raw SQL in a transaction, a job's own transaction).
type fencedDriver struct {
	*entsql.Driver
	*fence
}

func (d fencedDriver) Exec(ctx context.Context, q string, args, v any) error {
	if err := d.check(); err != nil {
		return err
	}
	return d.Driver.Exec(ctx, q, args, v)
}

func (d fencedDriver) Query(ctx context.Context, q string, args, v any) error {
	if err := d.check(); err != nil {
		return err
	}
	return d.Driver.Query(ctx, q, args, v)
}

func (d fencedDriver) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	return d.Driver.ExecContext(ctx, q, args...)
}

func (d fencedDriver) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	return d.Driver.QueryContext(ctx, q, args...)
}

func (d fencedDriver) Tx(ctx context.Context) (dialect.Tx, error) {
	return d.BeginTx(ctx, nil)
}

func (d fencedDriver) BeginTx(ctx context.Context, opts *sql.TxOptions) (dialect.Tx, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	tx, err := d.Driver.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if err := d.checkEpoch(ctx, tx); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return fencedTx{Tx: tx, fence: d.fence}, nil
}

type fencedTx struct {
	dialect.Tx
	*fence
}

func (t fencedTx) Exec(ctx context.Context, q string, args, v any) error {
	if err := t.check(); err != nil {
		return err
	}
	return t.Tx.Exec(ctx, q, args, v)
}

func (t fencedTx) Query(ctx context.Context, q string, args, v any) error {
	if err := t.check(); err != nil {
		return err
	}
	return t.Tx.Query(ctx, q, args, v)
}

func (t fencedTx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	return t.Tx.(interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
	}).ExecContext(ctx, q, args...)
}

func (t fencedTx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	return t.Tx.(interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	}).QueryContext(ctx, q, args...)
}

// Commit refuses to commit after the loss and rolls the transaction back instead.
func (t fencedTx) Commit() error {
	if err := t.check(); err != nil {
		_ = t.Rollback()
		return err
	}
	return t.Tx.Commit()
}

// ActiveNode is the node ID of the host that runs this database's controller on PostgreSQL, or ""
// while none has claimed it (docs/06-data-model.md, "Connecting to PostgreSQL"). ctx needs a scope.
func ActiveNode(ctx context.Context, db *DB) (string, error) {
	inst, err := db.ReadClient().Instance.Get(ctx, 1)
	if err != nil {
		return "", err
	}
	if inst.ActiveNode == nil {
		return "", nil
	}
	return *inst.ActiveNode, nil
}

// SetActiveNode records id as the host that runs the controller: `rpmgr controller init` and
// `adopt-state` do, and the first controller that starts on a database that has none.
func SetActiveNode(ctx context.Context, db *DB, id string) error {
	return WriteTx(ctx, db, func(tx *ent.Tx) error { return tx.Instance.UpdateOneID(1).SetActiveNode(id).Exec(ctx) })
}
