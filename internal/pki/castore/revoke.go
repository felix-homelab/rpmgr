// SPDX-License-Identifier: Apache-2.0

package castore

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/revokedidentity"
	"github.com/felix-homelab/rpmgr/internal/store/ent/revokedserial"
)

// Revocation (docs/04-security.md, "Revocation"): issued_certificates and revoked_identities are
// the source of the deny-list, with revoked_serials after a restore.

// ErrIdentityRevoked is returned for a certificate of a revoked identity.
var ErrIdentityRevoked = errors.New("pki: the identity is revoked")

// RevokeCertificate revokes the certificate with serial at now. changed is false if it was
// revoked already; the first revocation's time and reason stay.
func RevokeCertificate(ctx context.Context, tx *ent.Tx, serial, reason string, now time.Time) (row *ent.IssuedCertificate, changed bool, err error) {
	row, err = tx.IssuedCertificate.Get(ctx, serial)
	if ent.IsNotFound(err) {
		return nil, false, pki.ErrNotIssued
	}
	if err != nil || row.RevokedAt != nil {
		return row, false, err
	}
	row, err = tx.IssuedCertificate.UpdateOne(row).SetRevokedAt(now).SetRevocationReason(reason).Save(ctx)
	return row, err == nil, err
}

// RevokeReplaced revokes, by serial, every certificate of id that is neither revoked nor expired
// at now, except the one with serial keep: what a re-enrollment replaces (docs/04-security.md,
// "Tokens"). The identity itself stays valid, so keep and later renewals of it work. It returns
// the certificates it revoked.
func RevokeReplaced(ctx context.Context, tx *ent.Tx, id pki.Identity, keep, reason string, now time.Time) ([]*ent.IssuedCertificate, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	old, err := tx.IssuedCertificate.Query().Where(issuedcertificate.SubjectID(id.ID), issuedcertificate.SpiffeID(id.String()),
		issuedcertificate.IDNEQ(keep), issuedcertificate.RevokedAtIsNil(), issuedcertificate.NotAfterGT(now)).
		Order(ent.Asc(issuedcertificate.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*ent.IssuedCertificate, 0, len(old))
	for _, c := range old {
		row, err := tx.IssuedCertificate.UpdateOne(c).SetRevokedAt(now).SetRevocationReason(reason).Save(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}

// RevokeIdentity revokes id at now: every certificate of it is refused from then on, also one
// issued later, and the deny-list names it until its last certificate expires. changed is false
// if it was revoked already.
func RevokeIdentity(ctx context.Context, tx *ent.Tx, id pki.Identity, reason string, now time.Time) (row *ent.RevokedIdentity, changed bool, err error) {
	if err := id.Validate(); err != nil {
		return nil, false, err
	}
	row, err = tx.RevokedIdentity.Get(ctx, id.String())
	if err == nil {
		return row, false, nil
	}
	if !ent.IsNotFound(err) {
		return nil, false, err
	}
	notAfter := now
	certs, err := tx.IssuedCertificate.Query().Where(issuedcertificate.SubjectID(id.ID), issuedcertificate.SpiffeID(id.String())).All(ctx)
	if err != nil {
		return nil, false, err
	}
	for _, c := range certs {
		if c.NotAfter.After(notAfter) {
			notAfter = c.NotAfter
		}
	}
	create := tx.RevokedIdentity.Create().SetID(id.String()).SetSubjectType(revokedidentity.SubjectType(id.Kind)).
		SetSubjectID(id.ID).SetRevokedAt(now).SetReason(reason).SetNotAfter(notAfter)
	if id.Org != "" {
		create.SetOrgID(id.Org)
	}
	row, err = create.Save(ctx)
	return row, err == nil, err
}

// DenyList returns the deny-list at now: every revoked certificate that has not expired, and every
// revoked identity with a certificate that has not expired, serials first, each sorted.
func DenyList(ctx context.Context, c *ent.Client, now time.Time) ([]*agentv1.DenyEntry, error) {
	certs, err := c.IssuedCertificate.Query().
		Where(issuedcertificate.RevokedAtNotNil(), issuedcertificate.NotAfterGT(now)).All(ctx)
	if err != nil {
		return nil, err
	}
	ids, err := c.RevokedIdentity.Query().Where(revokedidentity.NotAfterGT(now)).All(ctx)
	if err != nil {
		return nil, err
	}
	serials, err := c.RevokedSerial.Query().Where(revokedserial.NotAfterGT(now)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*agentv1.DenyEntry, 0, len(certs)+len(ids)+len(serials))
	for _, r := range certs {
		out = append(out, &agentv1.DenyEntry{Subject: &agentv1.DenyEntry_Serial{Serial: r.ID}, NotAfter: timestamppb.New(r.NotAfter)})
	}
	for _, r := range serials {
		out = append(out, &agentv1.DenyEntry{Subject: &agentv1.DenyEntry_Serial{Serial: r.ID}, NotAfter: timestamppb.New(r.NotAfter)})
	}
	for _, r := range ids {
		out = append(out, &agentv1.DenyEntry{Subject: &agentv1.DenyEntry_Identity{Identity: r.ID}, NotAfter: timestamppb.New(r.NotAfter)})
	}
	pki.SortDenyEntries(out)
	return out, nil
}
