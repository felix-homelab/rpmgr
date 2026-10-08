// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// Revision identifies a configuration state (docs/03-connections.md, "Revisions and ordering").
// Seq orders revisions within one DBEpoch; a restore starts a new epoch.
type Revision struct {
	DBEpoch string
	Seq     int64
}

// ErrInitialised is returned by InitInstance when the database already holds an installation.
var ErrInitialised = errors.New("store: the database is already initialised")

// InitInstance creates the instance row with the trust domain and a new database epoch, and the
// revision counter at 0. It runs once, at `rpmgr controller init`.
func InitInstance(ctx context.Context, db *DB, trustDomain string) (Revision, error) {
	var rev Revision
	err := withTx(ctx, db.client, nil, func(tx *ent.Tx) error {
		var err error
		rev, err = InitInstanceTx(ctx, tx, trustDomain)
		return err
	})
	return rev, err
}

// InitInstanceTx is InitInstance in the caller's transaction, so that `rpmgr controller init`
// creates the instance and its CA together or not at all.
func InitInstanceTx(ctx context.Context, tx *ent.Tx, trustDomain string) (Revision, error) {
	epoch, err := newEpoch()
	if err != nil {
		return Revision{}, err
	}
	if _, err := tx.Instance.Create().SetID(1).SetTrustDomain(trustDomain).SetDbEpoch(epoch).Save(ctx); err != nil {
		if ent.IsConstraintError(err) {
			return Revision{}, ErrInitialised
		}
		return Revision{}, err
	}
	if err := tx.ConfigSeq.Create().SetID(1).SetSeq(0).Exec(ctx); err != nil {
		return Revision{}, err
	}
	return Revision{DBEpoch: epoch}, nil
}

// NewEpoch gives the database a new epoch, as every restore does, even of the same backup: agents
// accept lower revisions only together with a new epoch.
func NewEpoch(ctx context.Context, db *DB) (string, error) {
	epoch, err := newEpoch()
	if err != nil {
		return "", err
	}
	n, err := db.client.Instance.Update().SetDbEpoch(epoch).Save(ctx)
	if err != nil {
		return "", err
	}
	if n != 1 {
		return "", errors.New("store: the database is not initialised")
	}
	return epoch, nil
}

// ConfigTx runs fn as one configuration transaction and returns its revision. The transaction
// increments config_seq with a row lock as its first statement, so every configuration write
// holds that lock until it commits and commit order equals revision order; then fn makes its
// changes and returns the IDs of the resources it changed; then the revision is recorded with the
// scope's actor. If fn fails, nothing of it, the revision included, is committed.
func ConfigTx(ctx context.Context, db *DB, fn func(tx *ent.Tx) ([]string, error)) (Revision, error) {
	s, ok := authz.FromContext(ctx)
	if !ok {
		return Revision{}, errors.New("store: a configuration transaction needs a scope")
	}
	var rev Revision
	err := withTx(ctx, db.client, db.writeTxOptions(), func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(ctx, "UPDATE config_seq SET seq = seq + 1 WHERE id = 1 RETURNING seq")
		if err != nil {
			return err
		}
		if err := scanOne(rows, &rev.Seq); err != nil {
			return fmt.Errorf("store: config_seq: %w", err)
		}
		inst, err := tx.Instance.Get(ctx, 1)
		if err != nil {
			return err
		}
		rev.DBEpoch = inst.DbEpoch
		changed, err := fn(tx)
		if err != nil {
			return err
		}
		if err := tx.ConfigRevision.Create().SetID(rev.Seq).SetDbEpoch(rev.DBEpoch).
			SetActor(s.Actor()).SetChangedResources(changed).Exec(ctx); err != nil {
			return err
		}
		return runTxHook(ctx, tx)
	})
	if err != nil {
		return Revision{}, err
	}
	return rev, nil
}

// WriteTx runs fn as a write transaction that is not a configuration change, so it records no
// revision: audit entries, sessions, observed state. Like ConfigTx it is READ COMMITTED on
// PostgreSQL and runs on the single writer on SQLite, so on SQLite it must not be called while the
// same goroutine holds another write transaction.
func WriteTx(ctx context.Context, db *DB, fn func(tx *ent.Tx) error) error {
	return withTx(ctx, db.client, db.writeTxOptions(), func(tx *ent.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return runTxHook(ctx, tx)
	})
}

type txHookKey struct{}

// WithTxHook returns ctx with a hook that every ConfigTx and WriteTx under it runs last, in the
// transaction, so its writes commit or roll back with the transaction's; an error rolls it back.
// A hook already in ctx runs after it. The API appends the audit entry of a request with it
// (docs/04-security.md, "Audit log").
func WithTxHook(ctx context.Context, hook func(ctx context.Context, tx *ent.Tx) error) context.Context {
	prev, _ := ctx.Value(txHookKey{}).(func(context.Context, *ent.Tx) error)
	if prev == nil {
		return context.WithValue(ctx, txHookKey{}, hook)
	}
	return context.WithValue(ctx, txHookKey{}, func(ctx context.Context, tx *ent.Tx) error {
		if err := hook(ctx, tx); err != nil {
			return err
		}
		return prev(ctx, tx)
	})
}

// WithoutTxHook returns ctx without the hook, for transactions that must not run it: the audit
// package's own.
func WithoutTxHook(ctx context.Context) context.Context {
	return context.WithValue(ctx, txHookKey{}, (func(context.Context, *ent.Tx) error)(nil))
}

// CarryTxHook returns dst with the transaction hook of src, if src has one: a service that writes
// under a scope of its own still commits the request's audit entry and request_id with its change.
func CarryTxHook(dst, src context.Context) context.Context {
	if hook, _ := src.Value(txHookKey{}).(func(context.Context, *ent.Tx) error); hook != nil {
		return context.WithValue(dst, txHookKey{}, hook)
	}
	return dst
}

func runTxHook(ctx context.Context, tx *ent.Tx) error {
	if hook, _ := ctx.Value(txHookKey{}).(func(context.Context, *ent.Tx) error); hook != nil {
		return hook(ctx, tx)
	}
	return nil
}

// ReadTx runs fn in one consistent read snapshot, labelled with the revision it shows: a
// REPEATABLE READ transaction on PostgreSQL, a read transaction of the read-only pool on SQLite.
// The snapshot compiler reads through it, so that every replica compiles the same snapshot for
// the same revision.
func ReadTx(ctx context.Context, db *DB, fn func(tx *ent.Tx, rev Revision) error) error {
	opts := &sql.TxOptions{ReadOnly: true}
	if db.Dialect == Postgres {
		opts.Isolation = sql.LevelRepeatableRead
	}
	return withTx(ctx, db.readClient, opts, func(tx *ent.Tx) error {
		var rev Revision
		rows, err := tx.QueryContext(ctx, "SELECT seq FROM config_seq WHERE id = 1")
		if err != nil {
			return err
		}
		if err := scanOne(rows, &rev.Seq); err != nil {
			return fmt.Errorf("store: config_seq: %w", err)
		}
		inst, err := tx.Instance.Get(ctx, 1)
		if err != nil {
			return err
		}
		rev.DBEpoch = inst.DbEpoch
		return fn(tx, rev)
	})
}

// writeTxOptions is READ COMMITTED on PostgreSQL: a second writer then waits for the row lock on
// config_seq instead of failing with a serialisation error. SQLite's writer begins IMMEDIATE.
func (db *DB) writeTxOptions() *sql.TxOptions {
	if db.Dialect == Postgres {
		return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	return nil
}

func withTx(ctx context.Context, c *ent.Client, opts *sql.TxOptions, fn func(tx *ent.Tx) error) (err error) {
	tx, err := c.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func scanOne(rows *sql.Rows, dst any) error {
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return errors.New("no row; is the database initialised?")
	}
	if err := rows.Scan(dst); err != nil {
		return err
	}
	return rows.Close()
}

func newEpoch() (string, error) {
	u, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return u.String(), nil
}
