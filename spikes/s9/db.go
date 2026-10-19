// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The spike's schema: the parts of rpmgr's that S9 is about. config.seq stands for the
// configuration revision (a broadcast push), agent_rev.seq for a change of one agent's snapshot
// (a targeted push), agent_sessions is the session registry (06, agent_sessions) and
// controller_nodes the replicas (10, High availability).
const schema = `
DROP TABLE IF EXISTS config, agent_sessions, agent_rev, controller_nodes;
CREATE TABLE config (id int PRIMARY KEY, seq bigint NOT NULL);
INSERT INTO config VALUES (1, 0);
CREATE TABLE agent_sessions (
	agent_id text PRIMARY KEY,
	node text NOT NULL,
	session_epoch bigint NOT NULL,
	connected_at timestamptz
);
CREATE TABLE agent_rev (agent_id text PRIMARY KEY, seq bigint NOT NULL DEFAULT 0);
CREATE TABLE controller_nodes (node_id text PRIMARY KEY, internal_address text NOT NULL, last_seen timestamptz NOT NULL);
`

// Channels: one broadcast channel for revisions and one per replica for targeted signals.
const revChannel = "s9_rev"

func nodeChannel(node string) string { return "s9_node_" + node }

// dsn is the PostgreSQL the spike uses; README starts it.
func dsn() string {
	if v := os.Getenv("S9_DSN"); v != "" {
		return v
	}
	return "postgres://postgres:s9@127.0.0.1:55419/postgres?sslmode=disable"
}

func setupDB(ctx context.Context, agents int) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, err
	}
	rows := make([][]any, agents)
	for i := range rows {
		rows[i] = []any{agentID(i)}
	}
	if _, err := pool.CopyFrom(ctx, pgx.Identifier{"agent_rev"}, []string{"agent_id"}, pgx.CopyFromRows(rows)); err != nil {
		return nil, err
	}
	return pool, nil
}

func agentID(i int) string { return fmt.Sprintf("a%04d", i) }

// pushRevision commits the next configuration revision and signals every replica in the same
// transaction. The payload carries the revision and t0, the time just before the commit, so the
// agents can measure commit-to-agent latency.
func pushRevision(ctx context.Context, pool *pgxpool.Pool) (seq int64, t0 time.Time, err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, t0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx, `UPDATE config SET seq = seq + 1 WHERE id = 1 RETURNING seq`).Scan(&seq); err != nil {
		return 0, t0, err
	}
	t0 = time.Now()
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, revChannel, fmt.Sprintf("%d %d", seq, t0.UnixNano())); err != nil {
		return 0, t0, err
	}
	return seq, t0, tx.Commit(ctx)
}

// pushAgent commits a change of one agent's snapshot and signals the replica that holds its
// session. The registry row is read FOR SHARE: a registration running at the same time either
// commits first, and the signal goes to the new replica, or waits for this commit, and reads the
// new agent_rev after its own upsert. Either way the change reaches the agent.
func pushAgent(ctx context.Context, q pgx.Tx, agent string) (int64, error) {
	var seq int64
	if err := q.QueryRow(ctx, `UPDATE agent_rev SET seq = seq + 1 WHERE agent_id = $1 RETURNING seq`, agent).Scan(&seq); err != nil {
		return 0, err
	}
	var node string
	err := q.QueryRow(ctx, `SELECT node FROM agent_sessions WHERE agent_id = $1 FOR SHARE`, agent).Scan(&node)
	if err == pgx.ErrNoRows || node == "" {
		return seq, nil // no session: the next registration reads agent_rev
	}
	if err != nil {
		return 0, err
	}
	payload := fmt.Sprintf("push %s %d %d", agent, seq, time.Now().UnixNano())
	_, err = q.Exec(ctx, `SELECT pg_notify($1, $2)`, nodeChannel(node), payload)
	return seq, err
}

func pushAgentTx(ctx context.Context, pool *pgxpool.Pool, agent string) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	seq, err := pushAgent(ctx, tx, agent)
	if err != nil {
		return 0, err
	}
	return seq, tx.Commit(ctx)
}

// parseFields splits a payload into fields and integers.
func atoi(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}
