// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/revokedidentity"
)

// Revocation (docs/04-security.md, "Revocation"): issued_certificates and revoked_identities are
// the source of the deny-list.

// ErrIdentityRevoked is returned for a certificate of a revoked identity.
var ErrIdentityRevoked = errors.New("pki: the identity is revoked")

// RevokeCertificate revokes the certificate with serial at now. changed is false if it was
// revoked already; the first revocation's time and reason stay.
func RevokeCertificate(ctx context.Context, tx *ent.Tx, serial, reason string, now time.Time) (row *ent.IssuedCertificate, changed bool, err error) {
	row, err = tx.IssuedCertificate.Get(ctx, serial)
	if ent.IsNotFound(err) {
		return nil, false, ErrNotIssued
	}
	if err != nil || row.RevokedAt != nil {
		return row, false, err
	}
	row, err = tx.IssuedCertificate.UpdateOne(row).SetRevokedAt(now).SetRevocationReason(reason).Save(ctx)
	return row, err == nil, err
}

// RevokeIdentity revokes id at now: every certificate of it is refused from then on, also one
// issued later, and the deny-list names it until its last certificate expires. changed is false
// if it was revoked already.
func RevokeIdentity(ctx context.Context, tx *ent.Tx, id Identity, reason string, now time.Time) (row *ent.RevokedIdentity, changed bool, err error) {
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
	out := make([]*agentv1.DenyEntry, 0, len(certs)+len(ids))
	for _, r := range certs {
		out = append(out, &agentv1.DenyEntry{Subject: &agentv1.DenyEntry_Serial{Serial: r.ID}, NotAfter: timestamppb.New(r.NotAfter)})
	}
	for _, r := range ids {
		out = append(out, &agentv1.DenyEntry{Subject: &agentv1.DenyEntry_Identity{Identity: r.ID}, NotAfter: timestamppb.New(r.NotAfter)})
	}
	SortDenyEntries(out)
	return out, nil
}

// SortDenyEntries orders a deny-list: serials before identities, each in ascending order.
func SortDenyEntries(es []*agentv1.DenyEntry) {
	slices.SortFunc(es, func(a, b *agentv1.DenyEntry) int { return strings.Compare(denyKey(a), denyKey(b)) })
}

// denyKey is an entry's place in the order and its identity in the digest.
func denyKey(e *agentv1.DenyEntry) string {
	if s := e.GetSerial(); s != "" {
		return "1 serial " + s
	}
	return "2 identity " + e.GetIdentity()
}

// DenyDigest is the digest of a deny-list that an agent sends in Hello: SHA-256 over the sorted,
// distinct entries, serial or identity, each followed by a newline, and then the line
// "key <keyID>" of the key that signed the list; nothing for an empty list. Expiry times are not
// part of it, so a controller and an agent that prune at slightly different times still agree; the
// key is, so that after a key rotation every agent receives the list signed by the new key.
func DenyDigest(es []*agentv1.DenyEntry, keyID string) []byte {
	if len(es) == 0 {
		return nil
	}
	keys := make([]string, 0, len(es))
	for _, e := range es {
		keys = append(keys, denyKey(e))
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k + "\n"))
	}
	h.Write([]byte("key " + keyID + "\n"))
	return h.Sum(nil)
}
