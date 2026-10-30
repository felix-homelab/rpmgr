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

// CheckpointCount is how many checkpoints of a chain lie after a cursor, and when the oldest of
// them was made.
type CheckpointCount struct {
	Count  int64
	Oldest time.Time
}

// SinkChain names the cursor of one sink on one chain.
type SinkChain struct{ Sink, Chain string }

// CheckpointBacklog counts the checkpoints that sinks have not shipped, in SQL, so that its cost
// and its result are bounded by the number of chains and cursors, not of checkpoints: all returns
// every chain's checkpoints from the start, for a sink that has no cursor on it yet, and after
// returns, for every cursor, the checkpoints after it. A pair without checkpoints to come is
// absent.
func CheckpointBacklog(ctx context.Context, tx *ent.Tx) (all map[string]CheckpointCount, after map[SinkChain]CheckpointCount, err error) {
	all, after = map[string]CheckpointCount{}, map[SinkChain]CheckpointCount{}
	rows, err := tx.QueryContext(ctx, "SELECT COALESCE(org_id, $1), COUNT(*), MIN(ts) FROM audit_checkpoints GROUP BY COALESCE(org_id, $1)", InstanceChain)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var chain string
		var c CheckpointCount
		var ts any
		if err := rows.Scan(&chain, &c.Count, &ts); err != nil {
			return nil, nil, err
		}
		if c.Oldest, err = timeOf(ts); err != nil {
			return nil, nil, err
		}
		all[chain] = c
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	cur, err := tx.QueryContext(ctx, `SELECT k.sink_id, k.chain, COUNT(*), MIN(c.ts) FROM audit_sink_cursors k
JOIN audit_checkpoints c ON COALESCE(c.org_id, $1) = k.chain AND c.seq > k.checkpoint_seq GROUP BY k.sink_id, k.chain`, InstanceChain)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = cur.Close() }()
	for cur.Next() {
		var key SinkChain
		var c CheckpointCount
		var ts any
		if err := cur.Scan(&key.Sink, &key.Chain, &c.Count, &ts); err != nil {
			return nil, nil, err
		}
		if c.Oldest, err = timeOf(ts); err != nil {
			return nil, nil, err
		}
		after[key] = c
	}
	return all, after, cur.Err()
}

// timeOf is the time an aggregate over a time column returns: the drivers give a time, or text
// for the databases that keep time as text.
func timeOf(v any) (time.Time, error) {
	switch t := v.(type) {
	case time.Time:
		return t.UTC(), nil
	case string:
		return parseTime(t)
	case []byte:
		return parseTime(string(t))
	case nil:
		return time.Time{}, nil
	}
	return time.Time{}, fmt.Errorf("audit: a time of type %T", v)
}

func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("audit: %q is no time", s)
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
