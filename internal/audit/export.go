// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// ExportFormat names the format of an audit export (docs/04-security.md, "Audit log").
const ExportFormat = "rpmgr-audit-export/1"

// The types of the lines of an export.
const (
	LineHeader     = "header"
	LineEntry      = "entry"
	LineCheckpoint = "checkpoint"
)

// ExportHeader is the first line of an export: the chain, the seqs of its first and last entry,
// the seq of its newest checkpoint, after which entries are the unanchored tail, and the
// certificates its checkpoints verify with (in DER).
type ExportHeader struct {
	Type          string    `json:"type"`
	Format        string    `json:"format"`
	Chain         string    `json:"chain"`
	Exported      time.Time `json:"exported"`
	FirstSeq      int64     `json:"first_seq"`
	LastSeq       int64     `json:"last_seq"`
	AnchoredSeq   int64     `json:"anchored_seq"`
	Root          []byte    `json:"root"`
	Intermediates [][]byte  `json:"intermediates"`
	Signers       [][]byte  `json:"signers"`
}

// ExportEntry is an entry of an export, every field as the chain hashes it.
type ExportEntry struct {
	Type         string    `json:"type"`
	Seq          int64     `json:"seq"`
	ID           string    `json:"id"`
	Time         time.Time `json:"time"`
	ActorType    string    `json:"actor_type"`
	ActorID      string    `json:"actor_id"`
	CredentialID string    `json:"credential_id"`
	AuthMethod   string    `json:"auth_method"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	RequestID    string    `json:"request_id"`
	Action       string    `json:"action"`
	TargetType   string    `json:"target_type"`
	TargetID     string    `json:"target_id"`
	Result       string    `json:"result"`
	Diff         string    `json:"diff"`
	Reason       string    `json:"reason"`
	PrevHash     []byte    `json:"prev_hash"`
	Hash         []byte    `json:"hash"`
	// Unanchored marks an entry after the newest checkpoint, which a later export anchors.
	Unanchored bool `json:"unanchored,omitempty"`
}

// ExportCheckpoint is a checkpoint of an export, after the entry whose seq it covers.
type ExportCheckpoint struct {
	Type      string    `json:"type"`
	Seq       int64     `json:"seq"`
	HeadHash  []byte    `json:"head_hash"`
	Time      time.Time `json:"time"`
	KeyID     string    `json:"key_id"`
	Signature []byte    `json:"signature"`
}

// Export writes the chain of orgID, the instance chain for an empty orgID, as JSON Lines in one
// read snapshot, calling line with each line without its end (docs/04-security.md, "Audit log"):
// the header with trust's certificates, then the entries in order, each checkpoint after the entry
// it covers and the checkpoint that anchors a chain retention shortened before its first entry.
// The entries after the newest checkpoint are marked unanchored. An org scope exports only its own
// org's chain; the instance chain needs the system scope.
func Export(ctx context.Context, db *store.DB, orgID string, trust Trust, now time.Time, line func([]byte) error) error {
	s, ok := authz.FromContext(ctx)
	if !ok {
		return errors.New("audit: an export needs a scope")
	}
	if !s.System() && (orgID == "" || orgID != s.OrgID()) {
		return ErrOutsideScope
	}
	write := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return line(b)
	}
	return store.ReadTx(ctx, db, func(tx *ent.Tx, _ store.Revision) error {
		cps, err := checkpoints(ctx, tx, orgID, "ORDER BY seq")
		if err != nil {
			return err
		}
		where, args := "org_id IS NULL", []any(nil)
		if orgID != "" {
			where, args = "org_id = $1", []any{orgID}
		}
		rows, err := tx.QueryContext(ctx, "SELECT min(seq), max(seq) FROM audit_log WHERE "+where, args...)
		if err != nil {
			return err
		}
		var first, last *int64
		if _, err := scanFirst(rows, &first, &last); err != nil {
			return err
		}
		h := ExportHeader{Type: LineHeader, Format: ExportFormat, Chain: chainOf(orgID), Exported: now.UTC(),
			Intermediates: raws(trust.Intermediates...), Signers: raws(trust.Signers...)}
		if trust.Root != nil {
			h.Root = trust.Root.Raw
		}
		if first != nil {
			h.FirstSeq, h.LastSeq = *first, *last
		}
		if len(cps) > 0 {
			h.AnchoredSeq = cps[len(cps)-1].Seq
		}
		if err := write(h); err != nil {
			return err
		}
		next := 0 // the next checkpoint to write
		flush := func(upTo int64) error {
			for ; next < len(cps) && cps[next].Seq <= upTo; next++ {
				c := cps[next]
				if err := write(ExportCheckpoint{Type: LineCheckpoint, Seq: c.Seq, HeadHash: c.HeadHash, Time: c.Time,
					KeyID: c.KeyID, Signature: c.Signature}); err != nil {
					return err
				}
			}
			return nil
		}
		if err := flush(h.FirstSeq - 1); err != nil {
			return err
		}
		entries, err := tx.QueryContext(ctx, "SELECT "+entryColumns+" FROM audit_log WHERE "+where+" ORDER BY seq", args...)
		if err != nil {
			return err
		}
		defer func() { _ = entries.Close() }()
		for entries.Next() {
			e, err := scanEntry(entries)
			if err != nil {
				return err
			}
			if err := write(ExportEntry{Type: LineEntry, Seq: e.Seq, ID: e.ID, Time: e.Time.UTC(), ActorType: string(e.ActorType),
				ActorID: e.ActorID, CredentialID: e.CredentialID, AuthMethod: e.AuthMethod, IP: e.IP, UserAgent: e.UserAgent,
				RequestID: e.RequestID, Action: e.Action, TargetType: e.TargetType, TargetID: e.TargetID, Result: string(e.Result),
				Diff: e.Diff, Reason: e.Reason, PrevHash: e.PrevHash, Hash: e.Hash, Unanchored: e.Seq > h.AnchoredSeq}); err != nil {
				return err
			}
			if err := flush(e.Seq); err != nil {
				return err
			}
		}
		if err := entries.Err(); err != nil {
			return err
		}
		return flush(math.MaxInt64) // a chain retention emptied keeps its anchoring checkpoint
	})
}

func raws(certs ...*x509.Certificate) [][]byte {
	out := make([][]byte, 0, len(certs))
	for _, c := range certs {
		if c != nil {
			out = append(out, c.Raw)
		}
	}
	return out
}
