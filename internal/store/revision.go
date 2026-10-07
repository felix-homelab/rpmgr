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
	epoch, err := newEpoch()
	if err != nil {
		return Revision{}, err
	}
	err = withTx(ctx, db.client, nil, func(tx *ent.Tx) error {
		if _, err := tx.Instance.Create().SetID(1).SetTrustDomain(trustDomain).SetDbEpoch(epoch).Save(ctx); err != nil {
			if ent.IsConstraintError(err) {
				return ErrInitialised
			}
			return err
		}
		return tx.ConfigSeq.Create().SetID(1).SetSeq(0).Exec(ctx)
	})
	if err != nil {
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
		return tx.ConfigRevision.Create().SetID(rev.Seq).SetDbEpoch(rev.DBEpoch).
			SetActor(s.Actor()).SetChangedResources(changed).Exec(ctx)
	})
	if err != nil {
		return Revision{}, err
	}
	return rev, nil
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
