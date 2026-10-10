// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"crypto/x509"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

const day = 24 * time.Hour

// TestRotate follows the CA through a year: nothing changes early; the intermediate is replaced at
// half its lifetime and the old one keeps verifying its leaves, also for Reauth after they expired;
// the signing keys get a next key 90 days before they expire, which is delivered and then replaces
// them 60 days before; a second replica's CA picks every change up with Reload.
func TestRotate(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *pki.CA) {
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "org-a")
		s := sealer(t, kek)
		now := t0
		clock := func() time.Time { return now }
		ca, err := pki.LoadCA(sys, db, s, clock)
		if err != nil {
			t.Fatal(err)
		}
		other, err := pki.LoadCA(sys, db, s, clock) // another replica
		if err != nil {
			t.Fatal(err)
		}
		rotate := func(at time.Time) []string {
			t.Helper()
			now = at
			var done []string
			if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				var err error
				done, err = pki.Rotate(sys, tx, s, at)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := ca.Reload(sys, db, s, clock); err != nil {
				t.Fatal(err)
			}
			return done
		}
		issue := func() *x509.Certificate {
			t.Helper()
			var cert *x509.Certificate
			if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				var err error
				cert, err = ca.Issue(sys, tx, csrFor(t, newKey(t), nil), connector(org, ids.New("con")), pki.DefaultLeafLifetime)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return cert
		}

		if done := rotate(t0.Add(30 * day)); len(done) != 0 {
			t.Fatalf("rotated early: %v", done)
		}
		firstInter := ca.Intermediate()
		half := firstInter.NotBefore.Add(firstInter.NotAfter.Sub(firstInter.NotBefore) / 2)
		before := func() *x509.Certificate { now = half.Add(-time.Hour); return issue() }()
		if done := rotate(half); !slices.Equal(done, []string{"intermediate rotated"}) {
			t.Fatalf("at half the intermediate's lifetime: %v", done)
		}
		if ca.Intermediate().Equal(firstInter) {
			t.Fatal("the intermediate did not change")
		}
		after := issue()
		if after.CheckSignatureFrom(ca.Intermediate()) != nil || len(ca.Chain(before)) != 2 || len(ca.Chain(after)) != 2 ||
			!slices.Equal(ca.Chain(before)[1], firstInter.Raw) {
			t.Fatal("leaves do not chain to the intermediates that issued them")
		}
		// The old intermediate still verifies its leaf after the leaf expired plus the grace period.
		now = before.NotAfter.Add(30 * day)
		if _, err := ca.IdentityOf(before, before.NotBefore.Add(pki.Backdate)); err != nil {
			t.Fatalf("a leaf of the retired intermediate: %v", err)
		}
		if _, err := ca.Reload(sys, db, s, clock); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.IdentityOf(before, before.NotBefore.Add(pki.Backdate)); err != nil {
			t.Fatalf("after a reload, a leaf of the retired intermediate: %v", err)
		}
		if changed, err := other.Reload(sys, db, s, clock); err != nil || !changed || !other.Intermediate().Equal(ca.Intermediate()) {
			t.Fatalf("the other replica: changed %v, %v", changed, err)
		}
		if changed, _ := other.Reload(sys, db, s, clock); changed {
			t.Fatal("a reload without a change reported one")
		}

		signer := ca.ConfigSigner()
		audit := ca.AuditSigner()
		if done := rotate(signer.Cert.NotAfter.Add(-pki.SignerNextBefore - time.Hour)); len(done) != 0 {
			t.Fatalf("before the next-key time: %v", done)
		}
		done := rotate(signer.Cert.NotAfter.Add(-pki.SignerNextBefore))
		slices.Sort(done)
		if !slices.Equal(done, []string{"next audit_checkpoint key created", "next config_signing key created"}) {
			t.Fatalf("at the next-key time: %v", done)
		}
		if !ca.ConfigSigner().Cert.Equal(signer.Cert) || len(ca.SigningChain()) != 2+2 {
			t.Fatalf("the next key is used already, or not delivered: %d certificates", len(ca.SigningChain()))
		}
		if done := rotate(signer.Cert.NotAfter.Add(-pki.SignerPromoteBefore)); len(done) != 2 {
			t.Fatalf("at the promotion time: %v", done)
		}
		if ca.ConfigSigner().Cert.Equal(signer.Cert) || ca.AuditSigner().Cert.Equal(audit.Cert) {
			t.Fatal("the next keys did not replace the active ones")
		}
		chain := ca.SigningChain()
		if !slices.ContainsFunc(chain, func(b []byte) bool { return slices.Equal(b, signer.Cert.Raw) }) {
			t.Fatal("the replaced config-signing certificate is no longer delivered")
		}
		var certs []*x509.Certificate
		for _, b := range chain {
			c, _ := x509.ParseCertificate(b)
			certs = append(certs, c)
		}
		if err := pki.VerifySigner(ca.ConfigSigner().Cert, certs, ca.Root(), pki.PurposeConfigSigning, now); err != nil {
			t.Fatalf("the new config-signing key does not chain with what agents get: %v", err)
		}
		n := db.Client().CAKey.Query().Where(cakey.StatusEQ(cakey.StatusActive)).CountX(sys)
		if n != 4 {
			t.Fatalf("%d active keys", n)
		}
	})
}

// TestRotateIntermediate: the intermediate is replaced on request before its half-life, and the
// old one is retired; a rotation that started from an intermediate another rotation has retired
// meanwhile fails with ErrRotated and leaves one active intermediate.
func TestRotateIntermediate(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *pki.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		active := func() []*ent.CAKey {
			return db.Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusActive)).AllX(sys)
		}
		before := active()[0]
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error { return pki.RotateIntermediate(sys, tx, s, t0.Add(day)) }); err != nil {
			t.Fatal(err)
		}
		after := active()
		if len(after) != 1 || after[0].ID == before.ID || after[0].NotBefore.After(t0.Add(day)) || after[0].NotBefore.Before(t0.Add(day-time.Hour)) ||
			db.Client().CAKey.GetX(sys, before.ID).Status != cakey.StatusRetired {
			t.Fatalf("after a rotation on request: %v, the old one %s", after, db.Client().CAKey.GetX(sys, before.ID).Status)
		}
		root := db.Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot)).OnlyX(sys)
		err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			_, err := pki.ReplaceIntermediate(sys, tx, s, root, before, t0.Add(2*day))
			return err
		})
		if !errors.Is(err, pki.ErrRotated) || len(active()) != 1 || active()[0].ID != after[0].ID {
			t.Fatalf("a rotation from a retired intermediate: %v, active %v", err, active())
		}
	})
}
