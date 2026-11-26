// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
)

// ACMERow returns org's ACME certificate row for a hostname, or nil: ACME certificates have
// exactly that one name.
func ACMERow(ctx context.Context, tx *ent.Tx, org, name string) (*ent.Certificate, error) {
	return ACMEOf(ctx, tx.Certificate, org, name)
}

// ACMEOf is ACMERow on any certificate client, in a transaction or not.
func ACMEOf(ctx context.Context, cc *ent.CertificateClient, org, name string) (*ent.Certificate, error) {
	rows, err := cc.Query().Where(certificate.OrgID(org), certificate.SourceEQ(certificate.SourceAcme)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if len(r.Sans) == 1 && r.Sans[0] == name {
			return r, nil
		}
	}
	return nil, nil
}

// SealedKey is a certificate's private key sealed before the transaction that writes it, for the
// row ID the seal is bound to.
type SealedKey struct {
	ID  string
	Enc []byte
}

// ErrStaleKey is returned by RecordACMESealed when the certificate row is not the one the key was
// sealed for, because it was created or replaced meanwhile; the caller seals again.
var ErrStaleKey = errors.New("certs: the certificate row changed while its key was sealed")

// SealACMEKey seals key for the ACME certificate row of org and name, or for the row that a
// first certificate creates. A key service can take long, so the caller seals before the write
// transaction, and RecordACMESealed checks inside it that the row is the same.
func SealACMEKey(ctx context.Context, c *ent.CertificateClient, s *secret.Sealer, org, name string, key crypto.Signer) (*SealedKey, error) {
	row, err := ACMEOf(ctx, c, org, name)
	if err != nil {
		return nil, err
	}
	id := ids.New("crt")
	if row != nil {
		id = row.ID
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	enc, err := s.Seal(ctx, keyContext(id), secret.FromBytes(der))
	clear(der)
	if err != nil {
		return nil, err
	}
	return &SealedKey{ID: id, Enc: enc}, nil
}

// RecordACMESealed is RecordACME with the key sealed by SealACMEKey; it seals nothing in tx.
func RecordACMESealed(ctx context.Context, tx *ent.Tx, sk *SealedKey, org, name string, chain []*x509.Certificate, key crypto.Signer,
	attempt error) (*ent.Certificate, bool, error) {
	return recordACME(ctx, tx, nil, sk, org, name, chain, key, attempt)
}

// RecordACME writes the outcome of obtaining or renewing org's ACME certificate for name. With
// a chain and key the row gets them, active, unless it holds them already; attempt, if not nil,
// is the error of the last attempt, kept in last_error. A row without a certificate is failed.
// changed reports whether the certificate itself changed, so gateways need a new snapshot.
func RecordACME(ctx context.Context, tx *ent.Tx, s *secret.Sealer, org, name string, chain []*x509.Certificate, key crypto.Signer,
	attempt error) (*ent.Certificate, bool, error) {
	return recordACME(ctx, tx, s, nil, org, name, chain, key, attempt)
}

// recordACME seals the key with s inside tx, or, with sk, uses the key sealed before it.
func recordACME(ctx context.Context, tx *ent.Tx, s *secret.Sealer, sk *SealedKey, org, name string, chain []*x509.Certificate, key crypto.Signer,
	attempt error) (row *ent.Certificate, changed bool, err error) {
	row, err = ACMERow(ctx, tx, org, name)
	if err != nil {
		return nil, false, err
	}
	lastError := ""
	if attempt != nil {
		lastError = attempt.Error()
		if len(lastError) > 1000 {
			lastError = lastError[:1000]
		}
	}
	if len(chain) == 0 || key == nil {
		status := certificate.StatusFailed
		if row != nil && len(row.ContentSha256) > 0 {
			status = row.Status // the certificate it has serves on
		}
		if row == nil {
			row, err = tx.Certificate.Create().SetOrgID(org).SetSource(certificate.SourceAcme).SetSans([]string{name}).
				SetStatus(status).SetLastError(lastError).Save(ctx)
			return row, false, err
		}
		row, err = row.Update().SetStatus(status).SetLastError(lastError).Save(ctx)
		return row, false, err
	}
	p := &Parsed{Chain: chain, Key: key, SANs: []string{name}}
	item, err := p.Item()
	if err != nil {
		return nil, false, err
	}
	sum := sha256.Sum256(item)
	clear(item)
	if row != nil && bytes.Equal(row.ContentSha256, sum[:]) {
		row, err = row.Update().SetStatus(certificate.StatusActive).SetLastError(lastError).Save(ctx)
		return row, false, err
	}
	id := ids.New("crt")
	switch {
	case row != nil:
		id = row.ID
	case sk != nil:
		id = sk.ID // the first certificate: the row is made for the ID the key was sealed for
	}
	var sealed []byte
	if sk != nil {
		if sk.ID != id {
			return nil, false, ErrStaleKey
		}
		sealed = sk.Enc
	} else {
		if s == nil { // sealed outside, but the row needs a key that was not
			return nil, false, ErrStaleKey
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, false, err
		}
		sealed, err = s.Seal(ctx, keyContext(id), secret.FromBytes(der))
		clear(der)
		if err != nil {
			return nil, false, err
		}
	}
	if err := store.RecordSealed(ctx, tx, keyContext(id), sealed); err != nil {
		return nil, false, err
	}
	var raw []byte
	for _, c := range chain {
		raw = append(raw, c.Raw...)
	}
	leaf := chain[0]
	if row == nil {
		row, err = tx.Certificate.Create().SetID(id).SetOrgID(org).SetSource(certificate.SourceAcme).SetSans([]string{name}).
			SetNotBefore(leaf.NotBefore).SetNotAfter(leaf.NotAfter).SetChain(raw).SetKeyEnc(sealed).SetContentSha256(sum[:]).
			SetIssuer(leaf.Issuer.String()).SetStatus(certificate.StatusActive).SetLastError(lastError).Save(ctx)
		return row, true, err
	}
	row, err = row.Update().SetNotBefore(leaf.NotBefore).SetNotAfter(leaf.NotAfter).SetChain(raw).SetKeyEnc(sealed).
		SetContentSha256(sum[:]).SetIssuer(leaf.Issuer.String()).SetStatus(certificate.StatusActive).SetLastError(lastError).
		AddVersion(1).Save(ctx)
	return row, true, err
}
