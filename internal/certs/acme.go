// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
)

// ACMERow returns org's ACME certificate row for a hostname, or nil: ACME certificates have
// exactly that one name.
func ACMERow(ctx context.Context, tx *ent.Tx, org, name string) (*ent.Certificate, error) {
	rows, err := tx.Certificate.Query().Where(certificate.OrgID(org), certificate.SourceEQ(certificate.SourceAcme)).All(ctx)
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

// RecordACME writes the outcome of obtaining or renewing org's ACME certificate for name. With
// a chain and key the row gets them, active, unless it holds them already; attempt, if not nil,
// is the error of the last attempt, kept in last_error. A row without a certificate is failed.
// changed reports whether the certificate itself changed, so gateways need a new snapshot.
func RecordACME(ctx context.Context, tx *ent.Tx, s *secret.Sealer, org, name string, chain []*x509.Certificate, key crypto.Signer,
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
	if row != nil {
		id = row.ID
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, false, err
	}
	sealed, err := store.Seal(ctx, tx, s, keyContext(id), secret.FromBytes(der))
	clear(der)
	if err != nil {
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
