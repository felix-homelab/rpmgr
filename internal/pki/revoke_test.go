// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func serialEntry(s string) *agentv1.DenyEntry {
	return &agentv1.DenyEntry{Subject: &agentv1.DenyEntry_Serial{Serial: s}}
}

func identityEntry(s string) *agentv1.DenyEntry {
	return &agentv1.DenyEntry{Subject: &agentv1.DenyEntry_Identity{Identity: s}}
}

// TestRevoke: revoking a certificate or an identity is recorded once; the deny-list holds what has
// not expired, serials first, sorted; a revoked identity gets no new certificate and none of its
// certificates is renewable.
func TestRevoke(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, _ secret.KEK, ca *pki.CA) {
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "org-a")
		issue := func(id pki.Identity) (cert *x509.Certificate, err error) {
			err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
				var err error
				cert, err = ca.Issue(sys, tx, csrFor(t, newKey(t), nil), id, pki.DefaultLeafLifetime)
				return err
			})
			return cert, err
		}
		write := func(f func(tx *ent.Tx) error) {
			t.Helper()
			if err := store.WriteTx(sys, db, f); err != nil {
				t.Fatal(err)
			}
		}
		a, b := connector(org, ids.New("con")), connector(org, ids.New("con"))
		certA, _ := issue(a)
		certB1, _ := issue(b)
		certB2, _ := issue(b)

		write(func(tx *ent.Tx) error {
			if _, _, err := pki.RevokeCertificate(sys, tx, "ffff", "test", t0); !errors.Is(err, pki.ErrNotIssued) {
				t.Errorf("an unknown serial: %v", err)
			}
			row, changed, err := pki.RevokeCertificate(sys, tx, pki.SerialHex(certA.SerialNumber), "key lost", t0)
			if err != nil || !changed || row.RevocationReason != "key lost" {
				t.Errorf("first revocation: %+v %v %v", row, changed, err)
			}
			row, changed, err = pki.RevokeCertificate(sys, tx, pki.SerialHex(certA.SerialNumber), "again", t0.Add(time.Hour))
			if err != nil || changed || row.RevocationReason != "key lost" || !row.RevokedAt.Equal(t0) {
				t.Errorf("second revocation: %+v %v %v", row, changed, err)
			}
			idRow, changed, err := pki.RevokeIdentity(sys, tx, b, "decommissioned", t0)
			if err != nil || !changed || !idRow.NotAfter.Equal(certB2.NotAfter) && !idRow.NotAfter.Equal(certB1.NotAfter) {
				t.Errorf("identity revocation: %+v %v %v", idRow, changed, err)
			}
			if _, changed, err := pki.RevokeIdentity(sys, tx, b, "again", t0); err != nil || changed {
				t.Errorf("second identity revocation: %v %v", changed, err)
			}
			if _, _, err := pki.RevokeIdentity(sys, tx, pki.Identity{TrustDomain: td, Kind: pki.KindConnector, ID: "nope"}, "", t0); err == nil {
				t.Error("an invalid identity was revoked")
			}
			return nil
		})

		list, err := pki.DenyList(sys, db.Client(), t0)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0].GetSerial() != pki.SerialHex(certA.SerialNumber) || list[1].GetIdentity() != b.String() ||
			!list[0].GetNotAfter().AsTime().Equal(certA.NotAfter) {
			t.Fatalf("deny-list %v", list)
		}
		if later, _ := pki.DenyList(sys, db.Client(), certA.NotAfter.Add(time.Second)); len(later) != 0 {
			t.Fatalf("expired entries stay on the deny-list: %v", later)
		}

		for name, cert := range map[string]*x509.Certificate{"revoked serial": certA, "revoked identity": certB1} {
			if err := pki.CheckRenewable(sys, db.Client(), cert); err == nil {
				t.Errorf("%s is renewable", name)
			}
		}
		if err := pki.CheckRenewable(sys, db.Client(), certB2); !errors.Is(err, pki.ErrIdentityRevoked) {
			t.Errorf("another certificate of the revoked identity: %v", err)
		}
		if _, err := issue(b); !errors.Is(err, pki.ErrIdentityRevoked) {
			t.Errorf("a new certificate for a revoked identity: %v", err)
		}
	})
}

// TestDenyDigest: the digest ignores order, duplicates and expiry times, but not the signing key;
// an empty list has none.
func TestDenyDigest(t *testing.T) {
	const k1, k2 = "key-1", "key-2"
	a, b := serialEntry("0a"), identityEntry("spiffe://rpmgr-x/org/o/connector/c")
	withTime := identityEntry("spiffe://rpmgr-x/org/o/connector/c")
	withTime.NotAfter = timestamppb.New(t0)
	d1 := pki.DenyDigest([]*agentv1.DenyEntry{a, b}, k1)
	for name, es := range map[string][]*agentv1.DenyEntry{
		"reversed": {b, a}, "duplicate": {a, b, a}, "expiry time": {a, withTime},
	} {
		if !bytes.Equal(pki.DenyDigest(es, k1), d1) {
			t.Errorf("%s: another digest", name)
		}
	}
	if bytes.Equal(pki.DenyDigest([]*agentv1.DenyEntry{a}, k1), d1) || pki.DenyDigest(nil, k1) != nil {
		t.Error("the digest does not tell the lists apart")
	}
	// A serial and an identity with the same text are different entries.
	if bytes.Equal(pki.DenyDigest([]*agentv1.DenyEntry{a, b}, k2), d1) {
		t.Error("another signing key gives the same digest")
	}
	if bytes.Equal(pki.DenyDigest([]*agentv1.DenyEntry{serialEntry("x")}, k1), pki.DenyDigest([]*agentv1.DenyEntry{identityEntry("x")}, k1)) {
		t.Error("a serial and an identity with the same text have the same digest")
	}
}

// TestRevokeReplaced: a replacement revokes every live certificate of the identity but the one it
// keeps; it leaves expired and already revoked ones as they were, other identities alone, and the
// identity valid.
func TestRevokeReplaced(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, _ secret.KEK, ca *pki.CA) {
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "org-a")
		a, other := connector(org, ids.New("con")), connector(org, ids.New("con"))
		var serials []string
		for _, id := range []pki.Identity{a, a, a, other} {
			if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				cert, err := ca.Issue(sys, tx, csrFor(t, newKey(t), nil), id, pki.DefaultLeafLifetime)
				if err == nil {
					serials = append(serials, pki.SerialHex(cert.SerialNumber))
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		// serials[0] was revoked before, serials[2] is the one kept.
		db.Client().IssuedCertificate.UpdateOneID(serials[0]).SetRevokedAt(t0.Add(-time.Hour)).SetRevocationReason("key lost").ExecX(sys)
		var got []*ent.IssuedCertificate
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			if _, err := pki.RevokeReplaced(sys, tx, pki.Identity{TrustDomain: a.TrustDomain, Kind: pki.KindConnector, ID: "Bad ID"}, "", "x", t0); err == nil {
				t.Error("an invalid identity was accepted")
			}
			// Once every certificate has expired there is nothing to revoke.
			if late, err := pki.RevokeReplaced(sys, tx, a, serials[2], "replaced", t0.Add(pki.DefaultLeafLifetime+time.Hour)); err != nil || len(late) != 0 {
				t.Errorf("after expiry: %v %v", late, err)
			}
			var err error
			got, err = pki.RevokeReplaced(sys, tx, a, serials[2], "replaced", t0)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ID != serials[1] || got[0].RevocationReason != "replaced" || !got[0].RevokedAt.Equal(t0) {
			t.Fatalf("revoked %+v, want only %s", got, serials[1])
		}
		c := db.Client().IssuedCertificate
		if r := c.GetX(sys, serials[0]); r.RevocationReason != "key lost" || !r.RevokedAt.Equal(t0.Add(-time.Hour)) {
			t.Errorf("an earlier revocation changed: %+v", r)
		}
		for _, s := range []string{serials[2], serials[3]} {
			if c.GetX(sys, s).RevokedAt != nil {
				t.Errorf("%s was revoked", s)
			}
		}
		if n := db.Client().RevokedIdentity.Query().CountX(sys); n != 0 {
			t.Errorf("%d identities revoked", n)
		}
	})
}
