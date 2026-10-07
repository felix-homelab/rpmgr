// SPDX-License-Identifier: Apache-2.0

// Package store is rpmgr's database: the Ent client and schema (ent/), and how the controller
// opens SQLite or PostgreSQL and applies its migrations (docs/06-data-model.md). Every query and
// mutation needs an authz scope in its context.
package store

import (
	"database/sql"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"

	"github.com/felix-homelab/rpmgr/internal/store/ent"
	_ "github.com/felix-homelab/rpmgr/internal/store/ent/runtime" // registers policies, hooks and interceptors
)

// Dialects supported by the store (ADR-0011). Phase 1 boot files accept only SQLite (D57).
const (
	SQLite   = dialect.SQLite
	Postgres = dialect.Postgres
)

// NewClient returns an Ent client on db.
func NewClient(d string, db *sql.DB) *ent.Client {
	return ent.NewClient(ent.Driver(entsql.OpenDB(d, db)))
}
