// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
)

// ErrLockLost is returned by every statement and commit of a PostgreSQL database whose controller
// lock was lost (DB.LockLost): another controller may hold the database already, so nothing this
// one still has in flight may reach it (docs/06-data-model.md, "Connecting to PostgreSQL").
var ErrLockLost = errors.New("store: the PostgreSQL controller lock was lost")

// fence is closed-channel state shared by the fenced driver and the transactions it starts.
type fence struct{ lost <-chan struct{} }

func (f fence) check() error {
	select {
	case <-f.lost: // a nil channel never fires: SQLite, or no lock
		return ErrLockLost
	default:
		return nil
	}
}

// fencedDriver is the Ent driver of a database that holds the controller lock: from the moment the
// lock is lost, no statement starts and no transaction commits, whichever way the write is made
// (Ent mutation, raw SQL in a transaction, a job's own transaction).
type fencedDriver struct {
	*entsql.Driver
	fence
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
	return fencedTx{Tx: tx, fence: d.fence}, nil
}

type fencedTx struct {
	dialect.Tx
	fence
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
