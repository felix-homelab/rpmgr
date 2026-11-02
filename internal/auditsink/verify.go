// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/objstore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/sinkverify"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditsinkcursor"
)

// maxNamed is how many missing items a gap names before it says "and n more".
const maxNamed = 10

// checkBatch is how many entries checkEntries reads from the database at once.
const checkBatch = 200

// VerifyS3 reads an object-storage sink back (docs/04-security.md, "Audit log"): for every chain
// it verifies the chain in the database, lists what the sink holds, reports what the database
// shipped and the sink lacks, and reads every checkpoint the sink holds: each must be what its key says, be signed by a key the CA certified for audit checkpoints, and
// match the entry the database holds at its seq. With entries shipped, the entries after the newest
// checkpoint, which no checkpoint covers, are compared with the database byte for byte. The
// sink's stored verification is output only: it is never read, as whoever can write the database
// can write it too. ctx carries the system scope. A sink that cannot
// be read to the end gives an *UnreachableError and no outcome.
func (r *Runner) VerifyS3(ctx context.Context, s *ent.AuditSink, trust audit.Trust) (*sinkverify.Verification, error) {
	if s.Kind != "s3" {
		return nil, errors.New("only an object-storage sink can be read back")
	}
	if s.SecretEnc == nil || len(*s.SecretEnc) == 0 {
		return nil, errors.New("the object-storage sink has no secret key")
	}
	key, err := r.o.Sealer.Open(secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: s.ID}, *s.SecretEnc)
	if err != nil {
		return nil, errors.New("the object-storage sink's secret key cannot be opened")
	}
	c, err := S3SettingsOf(s.Settings).client(key, r.o.Now)
	if err != nil {
		return nil, fmt.Errorf("the object-storage sink has unusable settings: %w", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(ctx, S3VerifyTimeout)
	defer cancel()
	var heads map[string]int64
	if err := store.ReadTx(ctx, r.o.DB, func(tx *ent.Tx, _ store.Revision) (err error) {
		heads, err = audit.Heads(ctx, tx)
		return err
	}); err != nil {
		return nil, err
	}
	chains := make([]string, 0, len(heads))
	for chain := range heads {
		chains = append(chains, chain)
	}
	sort.Strings(chains)
	out := &sinkverify.Verification{Time: r.o.Now().UTC()}
	for _, chain := range chains {
		v, err := r.verifyChain(ctx, c, s, trust, chain)
		if err != nil {
			if ctx.Err() != nil || objstore.Retryable(err) {
				return nil, &UnreachableError{fmt.Errorf("reading the object store back did not finish: %w", s3Failure(err))}
			}
			return nil, fmt.Errorf("reading the object store back failed: %w", err)
		}
		out.Chains = append(out.Chains, v)
	}
	return out, nil
}

// verifyChain is VerifyS3 for one chain. It starts from nothing: every checkpoint of the sink is
// read and compared, whatever an earlier verification reported.
func (r *Runner) verifyChain(ctx context.Context, c *objstore.Client, s *ent.AuditSink, trust audit.Trust, chain string) (sinkverify.Chain, error) {
	org := orgOfChain(chain)
	out := sinkverify.Chain{Chain: chain}
	// The chain itself first: the stored hash of an entry proves nothing about its content.
	if _, _, err := audit.VerifyChain(ctx, r.o.DB, org, trust); err != nil {
		var broken *audit.ChainError
		if !errors.As(err, &broken) {
			return out, err
		}
		out.Problem = fmt.Sprintf("the chain does not verify in the database at entry %d: %s", broken.Seq, broken.Problem)
	}
	cpSeqs, err := listSeqs(ctx, c, s3Dir(chain, "checkpoints"))
	if err != nil {
		return out, err
	}
	var entrySeqs []int64
	if s.Entries {
		if entrySeqs, err = listSeqs(ctx, c, s3Dir(chain, "entries")); err != nil {
			return out, err
		}
	}
	var cur *ent.AuditSinkCursor
	var local []audit.Checkpoint
	if err := store.ReadTx(ctx, r.o.DB, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		if cur, err = tx.AuditSinkCursor.Query().Where(auditsinkcursor.SinkID(s.ID), auditsinkcursor.Chain(chain)).Only(ctx); ent.IsNotFound(err) {
			cur, err = &ent.AuditSinkCursor{}, nil
		}
		if err != nil {
			return err
		}
		local, err = audit.CheckpointsAfter(ctx, tx, org, 0, 1<<20)
		return err
	}); err != nil {
		return out, err
	}
	out.Gap = gapOf(cpSeqs, entrySeqs, local, cur, s.Entries)

	var held []audit.Checkpoint
	for _, seq := range cpSeqs {
		cp, problem, err := readCheckpoint(ctx, c, chain, org, seq)
		if err != nil {
			return out, err
		}
		if problem == "" {
			if err := trust.VerifySignature(cp); err != nil {
				problem = fmt.Sprintf("the checkpoint at seq %d has no valid signature: %v", seq, err)
			}
		}
		if problem != "" {
			if out.Problem == "" {
				out.Problem = problem
			}
			break
		}
		held = append(held, cp)
	}
	_, err = audit.CheckHeld(ctx, r.o.DB, org, held)
	var broken *audit.ChainError
	switch {
	case errors.As(err, &broken):
		if out.Problem == "" {
			out.Problem = fmt.Sprintf("the checkpoint at seq %d: %s", broken.Seq, broken.Problem)
		}
		held = slices.DeleteFunc(held, func(cp audit.Checkpoint) bool { return cp.Seq >= broken.Seq })
	case err != nil:
		return out, err
	}
	out.Checked = len(held)
	if n := len(held); n > 0 {
		out.CheckpointSeq, out.CheckpointTime = held[n-1].Seq, held[n-1].Time
	}
	if s.Entries && out.Problem == "" {
		problem, err := r.checkEntries(ctx, c, org, chain, entrySeqs, out.CheckpointSeq)
		if err != nil {
			return out, err
		}
		out.Problem = problem
	}
	return out, nil
}

// checkEntries compares the entries the sink holds above seq, which no verified checkpoint
// covers, with the database's: the object must hold the bytes the entry ships as, and the database
// must hold an entry for each object. It returns the first problem, or "".
func (r *Runner) checkEntries(ctx context.Context, c *objstore.Client, org, chain string, sinkSeqs []int64, seq int64) (string, error) {
	want := map[int64]bool{}
	for _, q := range sinkSeqs {
		if q > seq {
			want[q] = true
		}
	}
	for after := seq; ; {
		var es []audit.Entry
		if err := store.ReadTx(ctx, r.o.DB, func(tx *ent.Tx, _ store.Revision) (err error) {
			es, err = audit.EntriesAfter(ctx, tx, org, after, checkBatch)
			return err
		}); err != nil {
			return "", err
		}
		for _, e := range es {
			after = e.Seq
			if !want[e.Seq] {
				continue
			}
			delete(want, e.Seq)
			b, err := c.Get(ctx, s3Key(chain, "entries", e.Seq))
			if err != nil {
				return "", err
			}
			if !bytes.Equal(b, entryItem(e).Body) {
				return fmt.Sprintf("the entry at seq %d is not what the sink holds: it was rewritten", e.Seq), nil
			}
		}
		if len(es) < checkBatch {
			break
		}
	}
	if len(want) > 0 {
		return fmt.Sprintf("the sink holds an entry at seq %d that the database does not: entries were removed", slices.Min(slices.Collect(maps.Keys(want)))), nil
	}
	return "", nil
}

// listSeqs lists the keys under prefix and returns the seqs their last parts name, in order. A key
// that is not a seq is not the sink's and is skipped.
func listSeqs(ctx context.Context, c *objstore.Client, prefix string) ([]int64, error) {
	var seqs []int64
	token := ""
	for {
		p, err := c.List(ctx, prefix, token, objstore.MaxListPage)
		if err != nil {
			return nil, err
		}
		for _, o := range p.Objects {
			if seq, err := strconv.ParseInt(strings.TrimPrefix(o.Key, prefix), 10, 64); err == nil && seq > 0 {
				seqs = append(seqs, seq)
			}
		}
		if p.Next == "" {
			return seqs, nil
		}
		token = p.Next
	}
}

// readCheckpoint reads the checkpoint under its key. A missing object is an error of the read, as
// the listing just named it; one that is not what its key says is a problem.
func readCheckpoint(ctx context.Context, c *objstore.Client, chain, org string, seq int64) (audit.Checkpoint, string, error) {
	key := s3Key(chain, "checkpoints", seq)
	b, err := c.Get(ctx, key)
	if err != nil {
		return audit.Checkpoint{}, "", err
	}
	var v checkpointBody
	if json.Unmarshal(b, &v) != nil {
		return audit.Checkpoint{}, "the object " + key + " is not a checkpoint", nil
	}
	hash, herr := hex.DecodeString(v.HeadHash)
	sig, serr := base64.StdEncoding.DecodeString(v.Signature)
	if v.Type != EventCheckpoint || v.Chain != chain || v.Seq != seq || herr != nil || serr != nil {
		return audit.Checkpoint{}, "the object " + key + " is not the checkpoint its key names", nil
	}
	return audit.Checkpoint{ID: v.ID, OrgID: org, Seq: seq, HeadHash: hash, Time: v.Time, KeyID: v.KeyID, Signature: sig}, "", nil
}

// gapOf names what the database shipped, up to the sink's cursor, and the sink lacks.
func gapOf(cpSeqs, entrySeqs []int64, local []audit.Checkpoint, cur *ent.AuditSinkCursor, entries bool) string {
	var parts []string
	have := map[int64]bool{}
	for _, s := range cpSeqs {
		have[s] = true
	}
	var missing []string
	// What the sink was sent: up to the cursor, and up to the newest checkpoint the sink holds, as
	// the cursor is the database's word and a checkpoint older than one the sink holds was sent.
	sent := cur.CheckpointSeq
	if len(cpSeqs) > 0 {
		sent = max(sent, slices.Max(cpSeqs))
	}
	for _, c := range local {
		if c.Seq <= sent && !have[c.Seq] {
			missing = append(missing, strconv.FormatInt(c.Seq, 10))
		}
	}
	if len(missing) > 0 {
		parts = append(parts, "checkpoints "+named(missing))
	}
	if entries {
		var ranges []string
		for i := 1; i < len(entrySeqs); i++ {
			if entrySeqs[i] > entrySeqs[i-1]+1 {
				ranges = append(ranges, seqRange(entrySeqs[i-1]+1, entrySeqs[i]-1))
			}
		}
		switch last := int64(0); {
		case len(entrySeqs) == 0 && cur.EntrySeq > 0:
			ranges = append(ranges, seqRange(1, cur.EntrySeq))
		case len(entrySeqs) > 0:
			if last = entrySeqs[len(entrySeqs)-1]; last < cur.EntrySeq {
				ranges = append(ranges, seqRange(last+1, cur.EntrySeq))
			}
		}
		if len(ranges) > 0 {
			parts = append(parts, "entries "+named(ranges))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "; ") + " missing from the sink"
}

func seqRange(from, to int64) string {
	if from == to {
		return strconv.FormatInt(from, 10)
	}
	return fmt.Sprintf("%d-%d", from, to)
}

// named lists at most maxNamed of the items.
func named(items []string) string {
	if len(items) <= maxNamed {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:maxNamed], ", "), len(items)-maxNamed)
}
