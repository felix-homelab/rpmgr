// SPDX-License-Identifier: Apache-2.0

package castore

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
)

// The replacement of a compromised root (docs/04-security.md, "Root compromise"): `ca new-root
// --compromised` makes a new root in the same trust domain, with no cross-certificate, and ends every key
// the old one had. Like a rotation it is a plan, made and sealed outside the transaction, and applied in one.

// ReasonCACompromised is the revocation reason of every certificate the replacement revokes.
const ReasonCACompromised = "ca_compromised"

// A CompromisePlan is the replacement of a compromised root, worked out before its transaction: the new
// root, intermediate and signing keys are made and sealed here, which may wait for a key service. Apply
// writes it and fails with ErrRotated if the keys are not the ones it was made from.
type CompromisePlan struct {
	seen    string
	lock    string
	now     time.Time
	newRoot *x509.Certificate
	keys    []*newKey
	// replaced are the SHA-256 hashes of the public keys of the roots that were in service or waiting: the
	// issuing root, the old root of a rotation's overlap and a new root that waited for its signature.
	replaced []string
	audit    pki.KeyPair
}

// CompromiseResult is what Apply changed.
type CompromiseResult struct {
	Keys         int // the keys of the CA that were ended, of every status
	Certificates int // the certificates revoked
	Tokens       int // the enrollment tokens invalidated
}

// PlanCompromisedRoot makes the new root, its intermediate and the two signing keys, all active, in the
// trust domain of the active root, and seals their keys with s. It works in any state of the CA, also
// during a root rotation, and with the old root online or offline. It needs the system scope.
func PlanCompromisedRoot(ctx context.Context, c *ent.CAKeyClient, s *secret.Sealer, now time.Time) (*CompromisePlan, error) {
	rows, err := readActive(ctx, c)
	if err != nil {
		return nil, err
	}
	r := sortRows(rows)
	r1 := r.active[cakey.KindRoot]
	if r1 == nil {
		return nil, errors.New("pki: the database holds no active root")
	}
	r1cert, err := x509.ParseCertificate(r1.Certificate)
	if err != nil {
		return nil, err
	}
	td, err := pki.TrustDomainOf(r1cert)
	if err != nil {
		return nil, err
	}
	p := &CompromisePlan{seen: keysSeen(rows), lock: r1.ID, now: now}
	for _, row := range rows {
		if row.Kind == cakey.KindRoot {
			p.replaced = append(p.replaced, pki.PublicKeyHash(row.PublicKey))
		}
	}
	r2, err := pki.NewRoot(td, now)
	if err != nil {
		return nil, err
	}
	i2, err := pki.NewIntermediate(r2, now)
	if err != nil {
		return nil, err
	}
	is, err := pki.NewIssuer(r2.Cert, i2, func() time.Time { return now })
	if err != nil {
		return nil, err
	}
	p.newRoot = r2.Cert
	made := map[cakey.Kind]pki.KeyPair{cakey.KindRoot: r2, cakey.KindIntermediate: i2}
	for kind, purpose := range map[cakey.Kind]pki.Purpose{cakey.KindConfigSigning: pki.PurposeConfigSigning, cakey.KindAuditCheckpoint: pki.PurposeAuditCheckpoint} {
		key, err := pki.NewKey()
		if err != nil {
			return nil, err
		}
		cert, err := is.IssueSigner(&key.PublicKey, purpose)
		if err != nil {
			return nil, err
		}
		made[kind] = pki.KeyPair{Cert: cert, Key: key}
	}
	for _, kind := range []cakey.Kind{cakey.KindRoot, cakey.KindIntermediate, cakey.KindConfigSigning, cakey.KindAuditCheckpoint} {
		nk, err := sealNew(ctx, s, kind, made[kind], cakey.StatusActive)
		if err != nil {
			return nil, err
		}
		p.keys = append(p.keys, nk)
	}
	p.audit = made[cakey.KindAuditCheckpoint]
	return p, nil
}

// NewRoot returns the new root.
func (p *CompromisePlan) NewRoot() *x509.Certificate { return p.newRoot }

// Replaced returns the SHA-256 hashes of the public keys of the roots the replacement ends, for its
// revocation-log markers and its audit entries.
func (p *CompromisePlan) Replaced() []string { return p.replaced }

// AuditSigner returns the new audit-checkpoint key, which signs the checkpoints that anchor the audit chains
// at the moment of the replacement (docs/04-security.md, "Audit log").
func (p *CompromisePlan) AuditSigner() pki.KeyPair { return p.audit }

// Apply writes the replacement in tx, which must be a configuration transaction: every key of the CA, of
// any status, becomes `compromised` with its sealed key wiped; the new keys become the active ones; every
// certificate not yet revoked or expired is revoked with ReasonCACompromised; and every unused enrollment
// token is invalidated, so that the tokens made afterwards are the only ones. It takes the root row's lock
// first and repeats the check of the keys, so two runs take turns and the second finds ErrRotated.
func (p *CompromisePlan) Apply(ctx context.Context, tx *ent.Tx) (CompromiseResult, error) {
	var res CompromiseResult
	if err := lockRoot(ctx, tx, p.lock); err != nil {
		return res, err
	}
	rows, err := readActive(ctx, tx.CAKey)
	if err != nil {
		return res, err
	}
	if keysSeen(rows) != p.seen {
		return res, ErrRotated
	}
	if res.Keys, err = tx.CAKey.Update().Where(cakey.StatusNEQ(cakey.StatusCompromised)).SetStatus(cakey.StatusCompromised).
		SetRotatedAt(p.now).ClearKeyEnc().Save(ctx); err != nil {
		return res, err
	}
	for _, k := range p.keys {
		if err := createKey(ctx, tx, k); err != nil {
			return res, err
		}
	}
	if res.Certificates, err = tx.IssuedCertificate.Update().Where(issuedcertificate.RevokedAtIsNil(), issuedcertificate.NotAfterGT(p.now)).
		SetRevokedAt(p.now).SetRevocationReason(ReasonCACompromised).Save(ctx); err != nil {
		return res, err
	}
	res.Tokens, err = tx.EnrollmentToken.Update().Where(enrollmenttoken.RevokedAtIsNil()).SetRevokedAt(p.now).Save(ctx)
	return res, err
}
