// SPDX-License-Identifier: Apache-2.0

// Package s8 checks that the pure-Go SQLite driver modernc.org/sqlite behaves as the rpmgr
// controller needs it to, on every platform the controller may ship on (spike S8,
// docs/13-roadmap.md; docs/06-data-model.md, "Database engines"). It is throw-away spike code.
package s8

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Options are the per-connection settings the controller applies (06: WAL mode,
// busy_timeout, one writer connection).
type Options struct {
	BusyTimeoutMS int    // PRAGMA busy_timeout
	Synchronous   string // PRAGMA synchronous: FULL or NORMAL
	CacheSizeKiB  int    // PRAGMA cache_size as -KiB; 0 keeps SQLite's default
}

// DefaultOptions are the values the spike recommends for the controller.
var DefaultOptions = Options{BusyTimeoutMS: 5000, Synchronous: "FULL"}

// DSN returns a modernc.org/sqlite DSN that applies the options to every connection the pool
// opens, so no connection can miss a pragma (for example foreign_keys, which is off by default).
func DSN(path string, o Options, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", o.BusyTimeoutMS))
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous("+o.Synchronous+")")
	if o.CacheSizeKiB > 0 {
		q.Add("_pragma", fmt.Sprintf("cache_size(-%d)", o.CacheSizeKiB))
	}
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Set("_txlock", "immediate") // writers take the write lock at BEGIN, not mid-transaction
	}
	return "file:" + path + "?" + q.Encode()
}

// Store is the controller's SQLite access pattern: exactly one writer connection, which
// serialises all writes, and a pool of read-only connections.
type Store struct {
	W *sql.DB // single writer connection
	R *sql.DB // readers
}

// Open opens a store on path with the given options and reader pool size.
func Open(path string, o Options, readers int) (*Store, error) {
	w, err := sql.Open("sqlite", DSN(path, o, false))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	if err := w.Ping(); err != nil {
		w.Close()
		return nil, err
	}
	r, err := sql.Open("sqlite", DSN(path, o, true))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(readers)
	r.SetMaxIdleConns(readers)
	if err := r.Ping(); err != nil {
		w.Close()
		r.Close()
		return nil, err
	}
	return &Store{W: w, R: r}, nil
}

// Close closes both pools.
func (s *Store) Close() error {
	errR := s.R.Close()
	errW := s.W.Close()
	if errW != nil {
		return errW
	}
	return errR
}

// Schema is a subset of the controller schema (06) with the tenancy constraints: org_id NOT NULL
// on every org-owned table and composite (org_id, id) foreign keys between them, plus the
// single-row config_seq counter and config_revisions (03, "Revisions and ordering").
const Schema = `
CREATE TABLE orgs (
  id   TEXT PRIMARY KEY,
  name TEXT NOT NULL
);
CREATE TABLE connectors (
  id     TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs (id),
  name   TEXT NOT NULL,
  UNIQUE (org_id, id),
  UNIQUE (org_id, name)
);
CREATE TABLE routes (
  id     TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs (id),
  name   TEXT NOT NULL,
  UNIQUE (org_id, id)
);
CREATE TABLE route_targets (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL,
  route_id     TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  host         TEXT NOT NULL,
  port         INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  FOREIGN KEY (org_id, route_id) REFERENCES routes (org_id, id) ON DELETE CASCADE,
  FOREIGN KEY (org_id, connector_id) REFERENCES connectors (org_id, id) ON DELETE RESTRICT
);
CREATE TABLE config_seq (
  id  INTEGER PRIMARY KEY CHECK (id = 1),
  seq INTEGER NOT NULL
);
INSERT INTO config_seq (id, seq) VALUES (1, 0);
CREATE TABLE config_revisions (
  seq   INTEGER PRIMARY KEY,
  actor TEXT NOT NULL
);
`

// Migrate creates the schema in one transaction.
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, Schema); err != nil {
		return err
	}
	return tx.Commit()
}

// NextRevision increments config_seq as the first statement of a configuration transaction and
// records the revision, the controller's ordering mechanism (03). It returns the new seq.
func NextRevision(ctx context.Context, tx *sql.Tx, actor string) (int64, error) {
	var seq int64
	if err := tx.QueryRowContext(ctx,
		`UPDATE config_seq SET seq = seq + 1 WHERE id = 1 RETURNING seq`).Scan(&seq); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO config_revisions (seq, actor) VALUES (?, ?)`, seq, actor); err != nil {
		return 0, err
	}
	return seq, nil
}
