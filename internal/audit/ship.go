// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The reads of the audit sinks (docs/04-security.md, "Audit log"): what a chain holds after a
// sink's cursor. They only read, and take no lock on a chain's head, so a sink never delays an
// append.

// chainWhere is the condition that selects the chain of orgID, its placeholder numbered next.
func chainWhere(orgID string, next int) (string, []any) {
	if orgID == "" {
		return "org_id IS NULL", nil
	}
	return fmt.Sprintf("org_id = $%d", next), []any{orgID}
}

// CheckpointsAfter returns at most limit checkpoints of the chain of orgID with a seq above seq,
// oldest first.
func CheckpointsAfter(ctx context.Context, tx *ent.Tx, orgID string, seq int64, limit int) ([]Checkpoint, error) {
	cond, args := chainWhere(orgID, 2)
	rows, err := tx.QueryContext(ctx, fmt.Sprintf("SELECT id, seq, head_hash, ts, key_id, signature FROM audit_checkpoints WHERE seq > $1 AND %s ORDER BY seq LIMIT %d", cond, limit),
		append([]any{seq}, args...)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Checkpoint
	for rows.Next() {
		c := Checkpoint{OrgID: orgID}
		if err := rows.Scan(&c.ID, &c.Seq, &c.HeadHash, &c.Time, &c.KeyID, &c.Signature); err != nil {
			return nil, err
		}
		c.Time = c.Time.UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// EntriesAfter returns at most limit entries of the chain of orgID with a seq above seq, oldest
// first.
func EntriesAfter(ctx context.Context, tx *ent.Tx, orgID string, seq int64, limit int) ([]Entry, error) {
	cond, args := chainWhere(orgID, 2)
	rows, err := tx.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM audit_log WHERE seq > $1 AND %s ORDER BY seq LIMIT %d", entryColumns, cond, limit),
		append([]any{seq}, args...)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		e.OrgID, e.Time = orgID, e.Time.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// Heads returns the seq of the last entry of every chain that has entries, by chain name (an org
// ID, or InstanceChain).
func Heads(ctx context.Context, tx *ent.Tx) (map[string]int64, error) {
	rows, err := tx.QueryContext(ctx, "SELECT chain, seq FROM audit_heads WHERE seq > 0")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int64{}
	for rows.Next() {
		var chain string
		var seq int64
		if err := rows.Scan(&chain, &seq); err != nil {
			return nil, err
		}
		out[chain] = seq
	}
	return out, rows.Err()
}

// OldestAfter returns the time of the oldest checkpoint of the chain of orgID after checkpoint
// seq cp and, if entries is set, of the oldest entry after entry seq; ok is false when there is
// none.
func OldestAfter(ctx context.Context, tx *ent.Tx, orgID string, cp, entry int64, entries bool) (oldest time.Time, ok bool, err error) {
	cond, args := chainWhere(orgID, 2)
	for _, q := range []struct {
		table string
		seq   int64
		on    bool
	}{{"audit_checkpoints", cp, true}, {"audit_log", entry, entries}} {
		if !q.on {
			continue
		}
		rows, err := tx.QueryContext(ctx, fmt.Sprintf("SELECT ts FROM %s WHERE seq > $1 AND %s ORDER BY seq LIMIT 1", q.table, cond), append([]any{q.seq}, args...)...)
		if err != nil {
			return time.Time{}, false, err
		}
		var ts time.Time
		found, err := scanFirst(rows, &ts)
		if err != nil {
			return time.Time{}, false, err
		}
		if found && (!ok || ts.Before(oldest)) {
			oldest, ok = ts.UTC(), true
		}
	}
	return oldest, ok, nil
}

// Stamp is when the checkpoint at Seq of a chain was made.
type Stamp struct {
	Seq  int64
	Time time.Time
}

// CheckpointStamps returns the seq and time of every checkpoint with a seq above seq, by chain
// name (an org ID, or InstanceChain), each chain's oldest first: the one read the backlog of every
// sink and chain is counted from.
func CheckpointStamps(ctx context.Context, tx *ent.Tx, seq int64) (map[string][]Stamp, error) {
	rows, err := tx.QueryContext(ctx, "SELECT org_id, seq, ts FROM audit_checkpoints WHERE seq > $1 ORDER BY org_id, seq", seq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]Stamp{}
	for rows.Next() {
		var org *string
		var s Stamp
		if err := rows.Scan(&org, &s.Seq, &s.Time); err != nil {
			return nil, err
		}
		chain := InstanceChain
		if org != nil {
			chain = *org
		}
		s.Time = s.Time.UTC()
		out[chain] = append(out[chain], s)
	}
	return out, rows.Err()
}

// EntryTimeAfter returns the time of the oldest entry of the chain of orgID after entry seq; ok is
// false when there is none.
func EntryTimeAfter(ctx context.Context, tx *ent.Tx, orgID string, seq int64) (ts time.Time, ok bool, err error) {
	cond, args := chainWhere(orgID, 2)
	rows, err := tx.QueryContext(ctx, "SELECT ts FROM audit_log WHERE seq > $1 AND "+cond+" ORDER BY seq LIMIT 1", append([]any{seq}, args...)...)
	if err != nil {
		return time.Time{}, false, err
	}
	ok, err = scanFirst(rows, &ts)
	return ts.UTC(), ok, err
}
