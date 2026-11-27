// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

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
// the roots from ca_keys, the cutoffs from the audit entries of ActionRootCompromised, which the hash
// chain protects, so that removing one breaks the chain.
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
	res, err := tx.QueryContext(ctx, "SELECT org_id, seq, diff FROM audit_log WHERE action = $1 ORDER BY seq", ActionRootCompromised)
	if err != nil {
		return t, err
	}
	defer func() { _ = res.Close() }()
	for res.Next() {
		var org *string
		var seq int64
		var diff string
		if err := res.Scan(&org, &seq, &diff); err != nil {
			return t, err
		}
		chain := InstanceChain
		if org != nil {
			chain = *org
		}
		list, _ := strings.CutPrefix(diff, rootsDiffPrefix)
		for _, h := range strings.Split(list, ",") {
			if cuts[h] == nil {
				cuts[h] = map[string]int64{}
			}
			if _, seen := cuts[h][chain]; !seen {
				cuts[h][chain] = seq
			}
		}
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
