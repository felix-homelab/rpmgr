// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The checkpoint schedule (docs/03-connections.md, "Timeouts, keepalive and backoff"): a chain
// with entries after its last checkpoint gets one at least every CheckpointEvery, and after
// CheckpointEntries entries.
const (
	CheckpointEvery   = time.Hour
	CheckpointEntries = 1000
)

// Checkpoint is a signed statement of a chain's head: its seq and hash at a time, signed with the
// audit-checkpoint key (docs/04-security.md, "Audit log").
type Checkpoint struct {
	ID        string
	OrgID     string // empty: the instance chain
	Seq       int64
	HeadHash  []byte
	Time      time.Time
	KeyID     string // pki.KeyID of the signing key's certificate
	Signature []byte // ECDSA over the SHA-256 of signed()
	// Certificate is the signing key's certificate, in DER; the local log keeps it, so that the log
	// verifies with the root and the intermediates alone.
	Certificate []byte
}

// Chain returns the chain the checkpoint is of.
func (c Checkpoint) Chain() string { return chainOf(c.OrgID) }

// signed is what the signature covers: a version label, the chain's name, the seq, the head's
// hash with its length and the time in microseconds.
func (c Checkpoint) signed() []byte {
	b := append([]byte("rpmgr audit checkpoint v1\x00"), c.Chain()...)
	b = binary.AppendVarint(append(b, 0), c.Seq)
	b = append(binary.AppendUvarint(b, uint64(len(c.HeadHash))), c.HeadHash...)
	return binary.AppendVarint(b, c.Time.UnixMicro())
}

// Due returns the rule of the checkpoint job at now: a chain with entries after its last
// checkpoint, CheckpointEntries of them or CheckpointEvery after that checkpoint.
func Due(now time.Time) func(head Head, last *Checkpoint) bool {
	return func(head Head, last *Checkpoint) bool {
		return Pending(head, last) && (last == nil || head.Seq-last.Seq >= CheckpointEntries || now.Sub(last.Time) >= CheckpointEvery)
	}
}

// Pending reports whether a chain has entries after its last checkpoint; at shutdown each such
// chain gets one.
func Pending(head Head, last *Checkpoint) bool { return last == nil || head.Seq > last.Seq }

// WriteCheckpoints signs and stores in tx a checkpoint of every chain for which due holds, given
// its head and its last checkpoint, nil for none, and returns them with the signer's certificate.
func WriteCheckpoints(ctx context.Context, tx *ent.Tx, signer pki.KeyPair, now time.Time, due func(head Head, last *Checkpoint) bool) ([]Checkpoint, error) {
	rows, err := tx.QueryContext(ctx, "SELECT chain, seq, hash FROM audit_heads WHERE seq > 0 ORDER BY chain")
	if err != nil {
		return nil, err
	}
	var heads []Head
	for rows.Next() {
		var h Head
		if err := rows.Scan(&h.Chain, &h.Seq, &h.Hash); err != nil {
			_ = rows.Close()
			return nil, err
		}
		heads = append(heads, h)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	var out []Checkpoint
	for _, h := range heads {
		last, err := lastCheckpoint(ctx, tx, orgOf(h.Chain))
		if err != nil {
			return nil, err
		}
		if !due(h, last) {
			continue
		}
		c := Checkpoint{ID: ids.New("acp"), OrgID: orgOf(h.Chain), Seq: h.Seq, HeadHash: h.Hash, Time: now.UTC().Truncate(time.Microsecond),
			KeyID: pki.KeyID(signer.Cert), Certificate: signer.Cert.Raw}
		digest := sha256.Sum256(c.signed())
		if c.Signature, err = ecdsa.SignASN1(rand.Reader, signer.Key, digest[:]); err != nil {
			return nil, err
		}
		var org any
		if c.OrgID != "" {
			org = c.OrgID
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_checkpoints (id, org_id, seq, head_hash, ts, key_id, signature)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, c.ID, org, c.Seq, c.HeadHash, c.Time, c.KeyID, c.Signature); err != nil {
			return nil, fmt.Errorf("audit: checkpoint of %s: %w", h.Chain, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func orgOf(chain string) string {
	if chain == InstanceChain {
		return ""
	}
	return chain
}

// lastCheckpoint returns the newest checkpoint of the chain of orgID, or nil.
func lastCheckpoint(ctx context.Context, tx *ent.Tx, orgID string) (*Checkpoint, error) {
	cps, err := checkpoints(ctx, tx, orgID, "ORDER BY seq DESC LIMIT 1")
	if err != nil || len(cps) == 0 {
		return nil, err
	}
	return &cps[0], nil
}

func checkpoints(ctx context.Context, tx *ent.Tx, orgID, tail string) ([]Checkpoint, error) {
	q, args := "SELECT id, seq, head_hash, ts, key_id, signature FROM audit_checkpoints WHERE org_id IS NULL "+tail, []any(nil)
	if orgID != "" {
		q, args = "SELECT id, seq, head_hash, ts, key_id, signature FROM audit_checkpoints WHERE org_id = $1 "+tail, []any{orgID}
	}
	rows, err := tx.QueryContext(ctx, q, args...)
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

// Trust verifies checkpoint signatures: the root, and every intermediate and audit-checkpoint
// certificate the CA has had (pki.SignerCertificates).
type Trust struct {
	Root          *x509.Certificate
	Intermediates []*x509.Certificate
	Signers       []*x509.Certificate
}

// VerifySignature checks that a key the trust certifies for audit checkpoints at c's time signed
// c. The key's certificate is one of the trust's signers, or c's own.
func (t Trust) VerifySignature(c Checkpoint) error {
	var cert *x509.Certificate
	for _, s := range t.Signers {
		if pki.KeyID(s) == c.KeyID {
			cert = s
		}
	}
	if cert == nil && len(c.Certificate) > 0 {
		if own, err := x509.ParseCertificate(c.Certificate); err == nil && pki.KeyID(own) == c.KeyID {
			cert = own
		}
	}
	if cert == nil {
		return fmt.Errorf("audit: no certificate for key %s", c.KeyID)
	}
	if err := pki.VerifySigner(cert, t.Intermediates, t.Root, pki.PurposeAuditCheckpoint, c.Time); err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	digest := sha256.Sum256(c.signed())
	if !ok || !ecdsa.VerifyASN1(pub, digest[:], c.Signature) {
		return errors.New("audit: the checkpoint's signature does not verify")
	}
	return nil
}

// VerifyChain verifies the chain of orgID as Verify does, but from its anchor: its genesis, or,
// once retention removed its first entries, the signed checkpoint just before the first entry
// left. Every checkpoint of the chain must carry a valid signature and, while its entry is left,
// that entry's hash. It returns the head and the chain's last checkpoint, nil for none.
func VerifyChain(ctx context.Context, db *store.DB, orgID string, trust Trust) (Head, *Checkpoint, error) {
	s, ok := authz.FromContext(ctx)
	if !ok {
		return Head{}, nil, errors.New("audit: verification needs a scope")
	}
	if !s.System() && (orgID == "" || orgID != s.OrgID()) {
		return Head{}, nil, ErrOutsideScope
	}
	chain := chainOf(orgID)
	var head Head
	var last *Checkpoint
	err := store.ReadTx(ctx, db, func(tx *ent.Tx, _ store.Revision) error {
		cps, err := checkpoints(ctx, tx, orgID, "ORDER BY seq")
		if err != nil {
			return err
		}
		q, args := "SELECT min(seq) FROM audit_log WHERE org_id IS NULL", []any(nil)
		if orgID != "" {
			q, args = "SELECT min(seq) FROM audit_log WHERE org_id = $1", []any{orgID}
		}
		var first *int64
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		if _, err := scanFirst(rows, &first); err != nil {
			return err
		}
		from, hashes := Head{}, map[int64][]byte{}
		for i, c := range cps {
			if err := trust.VerifySignature(c); err != nil {
				return &ChainError{chain, c.Seq, "checkpoint: " + err.Error()}
			}
			if first == nil || c.Seq == *first-1 {
				from = Head{Chain: chain, Seq: c.Seq, Hash: c.HeadHash}
			}
			last = &cps[i]
		}
		if first != nil && *first > 1 && from.Seq != *first-1 {
			return &ChainError{chain, *first - 1, "entries were removed without a checkpoint"}
		}
		if first == nil && last != nil {
			from = Head{Chain: chain, Seq: last.Seq, Hash: last.HeadHash}
		}
		if head, err = verify(ctx, tx, orgID, from, func(seq int64, hash []byte) { hashes[seq] = hash }); err != nil {
			return err
		}
		for _, c := range cps {
			if h, ok := hashes[c.Seq]; (ok && !bytes.Equal(h, c.HeadHash)) || c.Seq > head.Seq {
				return &ChainError{chain, c.Seq, "the checkpoint does not match the chain"}
			}
		}
		return nil
	})
	return head, last, err
}

// CheckpointLog is the local copy of the checkpoints outside the database: one JSON object per
// line, appended and synced to disk (docs/10-operations.md, "Files").
type CheckpointLog struct {
	Path string
	mu   sync.Mutex
}

type logLine struct {
	Chain       string    `json:"chain"`
	Seq         int64     `json:"seq"`
	HeadHash    []byte    `json:"head_hash"`
	Time        time.Time `json:"time"`
	KeyID       string    `json:"key_id"`
	Signature   []byte    `json:"signature"`
	Certificate []byte    `json:"certificate"`
}

// Append appends checkpoints to the log.
func (l *CheckpointLog) Append(cps []Checkpoint) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640) //nolint:gosec // G302: 0640, as docs/10-operations.md, "Filesystem layout", says
	if err != nil {
		return err
	}
	var b bytes.Buffer
	for _, c := range cps {
		line, err := json.Marshal(logLine{c.Chain(), c.Seq, c.HeadHash, c.Time, c.KeyID, c.Signature, c.Certificate})
		if err != nil {
			_ = f.Close()
			return err
		}
		b.Write(append(line, '\n'))
	}
	_, err = f.Write(b.Bytes())
	return errors.Join(err, f.Sync(), f.Close())
}

// ReadCheckpointLog returns the checkpoints of a local log, in order.
func ReadCheckpointLog(path string) ([]Checkpoint, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the controller's own file
	if err != nil {
		return nil, err
	}
	var out []Checkpoint
	for i, line := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
		var l logLine
		if err := json.Unmarshal(line, &l); err != nil {
			return nil, fmt.Errorf("audit: %s, line %d: %w", path, i+1, err)
		}
		out = append(out, Checkpoint{OrgID: orgOf(l.Chain), Seq: l.Seq, HeadHash: l.HeadHash, Time: l.Time, KeyID: l.KeyID,
			Signature: l.Signature, Certificate: l.Certificate})
	}
	return out, nil
}

// Chains returns the chains that have entries or had them: their orgs, empty for the instance
// chain.
func Chains(ctx context.Context, tx *ent.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT chain FROM audit_heads WHERE seq > 0 ORDER BY chain")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var chain string
		if err := rows.Scan(&chain); err != nil {
			return nil, err
		}
		out = append(out, orgOf(chain))
	}
	return out, rows.Err()
}

// Prune removes, in tx, the entries of the chain of orgID older than cutoff, but only a whole
// prefix up to the newest checkpoint whose entry is older than cutoff, so that the chain verifies
// from that checkpoint; the older checkpoints go too. It returns the last seq removed, 0 for none.
func Prune(ctx context.Context, tx *ent.Tx, orgID string, cutoff time.Time) (int64, error) {
	cutoff = cutoff.UTC() // SQLite compares the stored text
	where, args := "c.org_id IS NULL AND e.org_id IS NULL", []any{cutoff}
	if orgID != "" {
		where, args = "c.org_id = $2 AND e.org_id = $2", []any{cutoff, orgID}
	}
	rows, err := tx.QueryContext(ctx, `SELECT c.seq FROM audit_checkpoints c JOIN audit_log e ON e.seq = c.seq
		WHERE `+where+` AND e.ts < $1 ORDER BY c.seq DESC LIMIT 1`, args...)
	if err != nil {
		return 0, err
	}
	var seq int64
	if found, err := scanFirst(rows, &seq); err != nil || !found {
		return 0, err
	}
	chain, cargs := "org_id IS NULL", []any{seq}
	if orgID != "" {
		chain, cargs = "org_id = $2", []any{seq, orgID}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM audit_log WHERE "+chain+" AND seq <= $1", cargs...); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM audit_checkpoints WHERE "+chain+" AND seq < $1", cargs...); err != nil {
		return 0, err
	}
	return seq, nil
}
