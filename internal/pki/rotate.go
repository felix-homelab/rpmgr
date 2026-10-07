// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
)

// The rotation schedule of the CA's keys (docs/04-security.md, "CA hierarchy", "CA rotation").
const (
	// SignerNextBefore is how long before the active signing key's certificate expires the next
	// key is created; agents receive its certificate in every Welcome from then on.
	SignerNextBefore = 90 * 24 * time.Hour
	// SignerPromoteBefore is how long before it expires the next key replaces it. The replaced key
	// stays verifiable until its certificate expires.
	SignerPromoteBefore = 60 * 24 * time.Hour
)

// Rotate brings the CA's keys up to the schedule at now, in tx, and returns what it changed:
//   - the intermediate is replaced at half its lifetime; the old one is retired and keeps
//     verifying the leaves it issued until it expires;
//   - the config-signing and the audit-checkpoint key each get a next key SignerNextBefore their
//     certificate expires, which replaces them SignerPromoteBefore it does.
//
// Every new key is sealed under s. Rotate needs the system scope; the caller runs it as a
// singleton job and reloads the CA afterwards.
func Rotate(ctx context.Context, tx *ent.Tx, s *secret.Sealer, now time.Time) ([]string, error) {
	rows, err := tx.CAKey.Query().Where(cakey.StatusIn(cakey.StatusActive, cakey.StatusNext)).All(ctx)
	if err != nil {
		return nil, err
	}
	active, next := map[cakey.Kind]*ent.CAKey{}, map[cakey.Kind]*ent.CAKey{}
	for _, r := range rows {
		if r.Status == cakey.StatusActive {
			active[r.Kind] = r
		} else {
			next[r.Kind] = r
		}
	}
	if active[cakey.KindRoot] == nil || active[cakey.KindIntermediate] == nil {
		return nil, fmt.Errorf("pki: the database holds no active root or intermediate")
	}
	var done []string
	root, err := x509.ParseCertificate(active[cakey.KindRoot].Certificate)
	if err != nil {
		return nil, err
	}
	old := active[cakey.KindIntermediate]
	var inter KeyPair
	if !now.Before(old.NotBefore.Add(old.NotAfter.Sub(old.NotBefore) / 2)) {
		rootKP, err := openKey(s, active[cakey.KindRoot])
		if err != nil {
			return nil, err
		}
		if inter, err = NewIntermediate(rootKP, now); err != nil {
			return nil, err
		}
		if err := tx.CAKey.UpdateOne(old).SetStatus(cakey.StatusRetired).Exec(ctx); err != nil {
			return nil, err
		}
		if err := saveKey(ctx, tx, s, cakey.KindIntermediate, inter, cakey.StatusActive); err != nil {
			return nil, err
		}
		done = append(done, "intermediate rotated")
	} else if inter, err = openKey(s, old); err != nil {
		return nil, err
	}
	is, err := NewIssuer(root, inter, func() time.Time { return now })
	if err != nil {
		return nil, err
	}
	for kind, purpose := range map[cakey.Kind]Purpose{
		cakey.KindConfigSigning: PurposeConfigSigning, cakey.KindAuditCheckpoint: PurposeAuditCheckpoint,
	} {
		a, n := active[kind], next[kind]
		if a == nil {
			return nil, fmt.Errorf("pki: the database holds no active %s key", kind)
		}
		switch {
		case n != nil && !now.Before(a.NotAfter.Add(-SignerPromoteBefore)):
			if err := tx.CAKey.UpdateOne(a).SetStatus(cakey.StatusRetired).Exec(ctx); err != nil {
				return nil, err
			}
			if err := tx.CAKey.UpdateOne(n).SetStatus(cakey.StatusActive).Exec(ctx); err != nil {
				return nil, err
			}
			done = append(done, string(kind)+" key replaced by the next one")
		case n == nil && !now.Before(a.NotAfter.Add(-SignerNextBefore)):
			key, err := NewKey()
			if err != nil {
				return nil, err
			}
			cert, err := is.IssueSigner(&key.PublicKey, purpose)
			if err != nil {
				return nil, err
			}
			if err := saveKey(ctx, tx, s, kind, KeyPair{Cert: cert, Key: key}, cakey.StatusNext); err != nil {
				return nil, err
			}
			done = append(done, "next "+string(kind)+" key created")
		}
	}
	return done, nil
}
