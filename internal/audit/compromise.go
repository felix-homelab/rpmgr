// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
)

// What the replacement of a compromised root records in every audit chain (docs/04-security.md, "Root
// compromise" and "Audit log"): one entry, whose seq is the anchor that the checkpoints under the replaced
// roots are held to, and whose Diff names those roots.
const (
	// ActionRootCompromised is the action of that entry.
	ActionRootCompromised = "ca.root_compromised"
	rootsDiffPrefix       = "roots:"
)

// RootsDiff is the Diff of the entry of ActionRootCompromised: the SHA-256 hashes of the public keys of the
// roots it replaced.
func RootsDiff(hashes []string) string { return rootsDiffPrefix + strings.Join(hashes, ",") }

// Compromise is a root that was replaced as compromised.
type Compromise struct {
	Root *x509.Certificate
	// Cutoff is, per chain, the seq of the entry that records the replacement: a checkpoint the root vouches
	// for counts only below it. A chain with no entry has no checkpoint that counts.
	Cutoff map[string]int64
}

// WithCompromises returns t with the roots replaced as compromised and their cutoffs, as tx reads them:
// the roots from ca_keys, the cutoffs from root_compromises, the copy of the entries' seqs that audit
// retention never prunes (AnchorCompromise).
func (t Trust) WithCompromises(ctx context.Context, tx *ent.Tx) (Trust, error) {
	// Raw SQL: the verification of an org's chain runs in that org's scope, which sees no CA key through the
	// store's privacy rules, and this reads only certificates, which are public.
	keys, err := tx.QueryContext(ctx, "SELECT certificate, public_key FROM ca_keys WHERE kind = $1 AND status = $2", string(cakey.KindRoot), string(cakey.StatusCompromised))
	if err != nil {
		return t, err
	}
	type replaced struct{ cert, pub []byte }
	var rows []replaced
	for keys.Next() {
		var r replaced
		if err := keys.Scan(&r.cert, &r.pub); err != nil {
			_ = keys.Close()
			return t, err
		}
		rows = append(rows, r)
	}
	if err := errors.Join(keys.Err(), keys.Close()); err != nil || len(rows) == 0 {
		return t, err
	}
	cuts := map[string]map[string]int64{} // root hash -> chain -> seq
	res, err := tx.QueryContext(ctx, "SELECT chain, root_hash, seq FROM root_compromises")
	if err != nil {
		return t, err
	}
	defer func() { _ = res.Close() }()
	for res.Next() {
		var chain, hash string
		var seq int64
		if err := res.Scan(&chain, &hash, &seq); err != nil {
			return t, err
		}
		if cuts[hash] == nil {
			cuts[hash] = map[string]int64{}
		}
		cuts[hash][chain] = seq
	}
	if err := res.Err(); err != nil {
		return t, err
	}
	out := t
	out.Compromised = nil
	for _, r := range rows {
		cert, err := x509.ParseCertificate(r.cert)
		if err != nil {
			return t, fmt.Errorf("audit: certificate of a replaced root: %w", err)
		}
		out.Compromised = append(out.Compromised, Compromise{Root: cert, Cutoff: cuts[pki.PublicKeyHash(r.pub)]})
	}
	return out, nil
}

// AnchorCompromise records the replacement of the roots with the given hashes in the chain of orgID (empty:
// the instance chain): the audit entry, which is the audited record, and the row of root_compromises that
// holds its seq for every root, which VerifyChain and the sink verification hold the checkpoints under
// those roots to. It returns the entry.
func AnchorCompromise(ctx context.Context, tx *ent.Tx, orgID string, hashes []string, reason string) (Entry, error) {
	e, err := Append(ctx, tx, Entry{OrgID: orgID, ActorType: ActorSystem, ActorID: "local-cli", Action: ActionRootCompromised,
		TargetType: "ca", Result: Success, Diff: RootsDiff(hashes), Reason: reason})
	if err != nil {
		return e, err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO root_compromises (id, chain, root_hash, seq, created_at) VALUES ($1, $2, $3, $4, $5)`,
			ids.New("rcp"), chainOf(orgID), h, e.Seq, e.Time.UTC()); err != nil {
			return e, fmt.Errorf("audit: record the cutoff of a replaced root: %w", err)
		}
	}
	return e, nil
}

// withoutReplaced drops from cps, the checkpoints of chain in seq order, those that a root replaced as compromised
// certifies, when a checkpoint of another root at or after the latest replacement's entry anchors the chain;
// the one just before the first entry left, which anchors a chain that retention cut, stays.
func (t Trust) withoutReplaced(cps []Checkpoint, chain string, first *int64) []Checkpoint {
	var cut int64
	for _, k := range t.Compromised {
		cut = max(cut, k.Cutoff[chain])
	}
	if cut == 0 {
		return cps
	}
	anchored := false
	for _, c := range cps {
		if c.Seq >= cut && !t.underReplaced(c) {
			anchored = true
		}
	}
	if !anchored {
		return cps
	}
	return slices.DeleteFunc(slices.Clone(cps), func(c Checkpoint) bool {
		return t.underReplaced(c) && (first == nil || c.Seq != *first-1)
	})
}
