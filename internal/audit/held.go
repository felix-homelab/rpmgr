// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// heldBatch is how many checkpoints CheckHeld looks up in one query.
const heldBatch = 200

// CheckHeld compares checkpoints that a copy outside the database holds, such as an object-storage
// sink (docs/04-security.md, "Audit log"), with the chain of orgID: each must name the hash that
// the database holds for the entry at its seq, and none may lie beyond the chain's head, which
// would mean that entries were cut below it. The caller has verified the held checkpoints'
// signatures. A checkpoint older than the first entry the retention left cannot be compared and is
// not counted. It returns how many were compared, and a *ChainError at the lowest seq that does not
// fit. The chain itself must be verified separately (VerifyChain): the stored hash of an entry
// proves nothing about its content.
func CheckHeld(ctx context.Context, db *store.DB, orgID string, held []Checkpoint) (compared int, err error) {
	chain := chainOf(orgID)
	held = slices.SortedFunc(slices.Values(held), func(a, b Checkpoint) int { return int(a.Seq - b.Seq) })
	err = store.ReadTx(ctx, db, func(tx *ent.Tx, _ store.Revision) error {
		compared = 0
		cond, args := chainWhere(orgID, 1)
		rows, err := tx.QueryContext(ctx, "SELECT min(seq), max(seq) FROM audit_log WHERE "+cond, args...)
		if err != nil {
			return err
		}
		var first, head *int64
		if _, err := scanFirst(rows, &first, &head); err != nil {
			return err
		}
		for len(held) > 0 {
			n := min(heldBatch, len(held))
			batch := held[:n]
			held = held[n:]
			hashes, err := hashesAt(ctx, tx, orgID, batch)
			if err != nil {
				return err
			}
			for _, c := range batch {
				switch h, ok := hashes[c.Seq]; {
				case first != nil && c.Seq < *first:
					// Retention removed the entry; the chain verifies from a checkpoint after it.
				case head == nil || c.Seq > *head:
					return &ChainError{chain, c.Seq, "the chain is shorter than a checkpoint held outside the database: entries were removed"}
				case !ok || !bytes.Equal(h, c.HeadHash):
					return &ChainError{chain, c.Seq, "the chain does not match a checkpoint held outside the database: it was rewritten"}
				default:
					compared++
				}
			}
		}
		return nil
	})
	return compared, err
}

// hashesAt returns the stored hash of the entries of the chain at the seqs of cps.
func hashesAt(ctx context.Context, tx *ent.Tx, orgID string, cps []Checkpoint) (map[int64][]byte, error) {
	cond, args := chainWhere(orgID, 1)
	marks := make([]string, len(cps))
	for i, c := range cps {
		args = append(args, c.Seq)
		marks[i] = fmt.Sprintf("$%d", len(args))
	}
	rows, err := tx.QueryContext(ctx, "SELECT seq, hash FROM audit_log WHERE "+cond+" AND seq IN ("+strings.Join(marks, ",")+")", args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[int64][]byte{}
	for rows.Next() {
		var seq int64
		var h []byte
		if err := rows.Scan(&seq, &h); err != nil {
			return nil, err
		}
		out[seq] = h
	}
	return out, rows.Err()
}
