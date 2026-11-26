// SPDX-License-Identifier: Apache-2.0

package castore_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func chainPool(t *testing.T, chain [][]byte) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	inters := x509.NewCertPool()
	var leaf *x509.Certificate
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			leaf = c
			continue
		}
		inters.AddCert(c)
	}
	return leaf, inters
}

// verifies reports whether the chain a holder presents verifies under roots at at, as a peer that
// trusts only roots does it.
func verifies(t *testing.T, chain [][]byte, roots *x509.CertPool, at time.Time) bool {
	t.Helper()
	leaf, inters := chainPool(t, chain)
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err == nil
}

func rowsOf(t *testing.T, db *store.DB, kind cakey.Kind) []*ent.CAKey {
	t.Helper()
	rows, err := db.ReadClient().CAKey.Query().Where(cakey.KindEQ(kind)).Order(ent.Asc(cakey.FieldID)).All(storetest.SystemCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func newRoot(t *testing.T, db *store.DB, s *secret.Sealer, now time.Time) (*castore.RootRequests, error) {
	t.Helper()
	sys := storetest.SystemCtx(t)
	var req *castore.RootRequests
	err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
		var err error
		_, req, err = castore.NewRoot(sys, tx, s, now)
		return err
	})
	return req, err
}

// TestNewRoot: with the old root online, `ca new-root` makes the new root, signs its
// cross-certificate and the certificate of its intermediate, and moves issuing at once. The bundle is
// {R1, R2, X}; the chain of a new leaf carries I2 and Y, so that a verifier that knows only R1 and one
// that knows only R2 both accept it; a leaf of the old intermediate still verifies; the signing
// certificates chain to the new root too; and a leaf renewed after an agent was offline through the
// switch chains to the old root it knows.
func TestNewRoot(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "org-a")
		s := sealer(t, kek)
		now := t0
		clock := func() time.Time { return now }
		ca, err := castore.LoadCA(sys, db, s, clock)
		if err != nil {
			t.Fatal(err)
		}
		r1 := ca.Root()
		issue := func() ([]*x509.Certificate, [][]byte) {
			t.Helper()
			var leaf *x509.Certificate
			if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				var err error
				leaf, err = ca.Issue(sys, tx, csrFor(t, newKey(t), nil), connector(org, ids.New("con")), pki.DefaultLeafLifetime)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return []*x509.Certificate{leaf}, ca.Chain(leaf)
		}
		before, beforeChain := issue()

		now = t0.Add(10 * day)
		if req, err := newRoot(t, db, s, now); err != nil || req != nil {
			t.Fatalf("new-root with an online root: requests %v, %v", req, err)
		}
		if changed, err := ca.Reload(sys, db, s, clock); err != nil || !changed {
			t.Fatalf("reload: %v, %v", changed, err)
		}
		r2 := ca.Root()
		if r2.Equal(r1) || ca.Intermediate().CheckSignatureFrom(r2) != nil {
			t.Fatal("issuing did not move to the new root")
		}
		if !slices.EqualFunc(ca.Roots(), []*x509.Certificate{r2, r1}, (*x509.Certificate).Equal) || len(ca.TrustBundle()) != 3 {
			t.Fatalf("the bundle holds %d certificates, the roots %d, want {R2, R1} and X", len(ca.TrustBundle()), len(ca.Roots()))
		}
		x := ca.TrustBundle()[2]
		if err := pki.VerifyCrossRoot(x, r1, r2, now); err != nil {
			t.Fatalf("the cross-certificate: %v", err)
		}
		if der, err := ca.TrustRoots(); err != nil || len(der) != 3 {
			t.Fatalf("trust roots: %d, %v", len(der), err)
		}
		// A snapshot reads the same bundle from the database, in the transaction of its revision.
		if got, err := castore.BundleOf(sys, db.ReadClient().CAKey); err != nil || !slices.EqualFunc(got, ca.TrustBundle(), (*x509.Certificate).Equal) {
			t.Fatalf("the bundle read from the database differs from the CA's: %d certificates, %v", len(got), err)
		}
		if der, err := castore.TrustRootsOf(sys, db.ReadClient().CAKey); err != nil || len(der) != 3 {
			t.Fatalf("trust roots of the database: %d, %v", len(der), err)
		}
		if !ca.EnrollmentRoot().Equal(r1) {
			t.Fatal("an agent enrolled in the overlap must pin the old root")
		}

		// A leaf issued now verifies under R1 alone, through Y, and under R2 alone.
		_, chain := issue()
		if len(chain) != 3 {
			t.Fatalf("a new leaf's chain holds %d certificates, want the leaf, I2 and Y", len(chain))
		}
		if !verifies(t, chain, pool(r1), now) || !verifies(t, chain, pool(r2), now) {
			t.Fatal("a new leaf does not verify under both roots")
		}
		// The old intermediate's leaf verifies under R1 only, as before, and the controller still knows it.
		at := before[0].NotBefore.Add(time.Hour) // while it was valid
		if len(beforeChain) != 2 || !verifies(t, beforeChain, pool(r1), at) || verifies(t, beforeChain, pool(r2), at) {
			t.Fatalf("a leaf of the old intermediate is not R1's alone: chain %d, under R1 %v, under R2 %v", len(beforeChain),
				verifies(t, beforeChain, pool(r1), at), verifies(t, beforeChain, pool(r2), at))
		}
		if _, err := ca.IdentityOf(before[0], at); err != nil {
			t.Fatalf("the controller refuses a leaf of the old intermediate: %v", err)
		}
		// The active signing key still chains to the old root, so that connected agents, which know it, verify
		// the snapshots; the next one, which Welcome delivers with the intermediates, chains to both roots, and
		// replaces it with the drop.
		var inters, signers []*x509.Certificate
		for _, der := range ca.SigningChain() {
			c, _ := x509.ParseCertificate(der)
			if c.IsCA {
				inters = append(inters, c)
			} else {
				signers = append(signers, c)
			}
		}
		active := ca.ConfigSigner().Cert
		if len(signers) != 2 || !signers[0].Equal(active) {
			t.Fatalf("%d signing certificates delivered, the active one first", len(signers))
		}
		if pki.VerifySigner(active, inters, r1, pki.PurposeConfigSigning, now) != nil || pki.VerifySigner(active, inters, r2, pki.PurposeConfigSigning, now) == nil {
			t.Error("the active signing certificate does not chain to the old root alone")
		}
		for name, root := range map[string]*x509.Certificate{"R1": r1, "R2": r2} {
			if err := pki.VerifySigner(signers[1], inters, root, pki.PurposeConfigSigning, now); err != nil {
				t.Errorf("the next config-signing certificate under %s: %v", name, err)
			}
		}

		// An agent that was offline through the switch re-authenticates: its leaf expired, the grace
		// period has not, and the leaf it gets back chains to R1, the only root it knows.
		now = before[0].NotAfter.Add(20 * day)
		var renewed *x509.Certificate
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			var err error
			renewed, err = ca.Renew(sys, tx, before[0], csrFor(t, newKey(t), nil), pki.DefaultLeafLifetime)
			return err
		}); err != nil {
			t.Fatalf("renewing an old leaf in the overlap: %v", err)
		}
		if got := ca.Chain(renewed); len(got) != 3 || !verifies(t, got, pool(r1), now) {
			t.Fatal("the renewed leaf does not chain to the old root through Y")
		}
		// And it verifies the controller's own certificate, issued under I2, with R1 alone.
		if node, err := ca.NodeCertificate(sys, db, ids.New("ctn")); err != nil || !verifies(t, node.Certificate, pool(r1), now) {
			t.Fatalf("the controller's certificate under the old root: %v", err)
		}

		// A second rotation, and a rotation of the intermediate, are refused while this one runs.
		if _, err := newRoot(t, db, s, now); !errors.Is(err, castore.ErrRotationInProgress) {
			t.Fatalf("a second new-root = %v, want ErrRotationInProgress", err)
		}
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error { return castore.RotateIntermediate(sys, tx, s, now) }); !errors.Is(err, castore.ErrRotationInProgress) {
			t.Fatalf("rotate-intermediate in the overlap = %v, want ErrRotationInProgress", err)
		}
	})
}

// exportOffline takes the root offline and returns what the offline host has: the root as read from its file.
func exportOffline(t *testing.T, db *store.DB, s *secret.Sealer) pki.KeyPair {
	t.Helper()
	sys := storetest.SystemCtx(t)
	var file []byte
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
		_, err := castore.ExportRootOffline(sys, tx, s, rootPass, func(f []byte) ([]byte, error) {
			file = append([]byte(nil), f...)
			return f, nil
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	root, err := pki.OpenRootFile(file, rootPass)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func importDER(t *testing.T, db *store.DB, der []byte, now time.Time) error {
	t.Helper()
	sys := storetest.SystemCtx(t)
	return store.WriteTx(sys, db, func(tx *ent.Tx) error { return castore.ImportIntermediate(sys, tx, der, now) })
}

func rotate(t *testing.T, db *store.DB, s *secret.Sealer, now time.Time) []string {
	t.Helper()
	sys := storetest.SystemCtx(t)
	var done []string
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
		var err error
		done, err = castore.Rotate(sys, tx, s, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return done
}

// TestNewRootOffline: the offline-root path. The old root's key is not in the database, so `ca
// new-root` makes the new root and its intermediate and the two requests the offline host signs; the
// requests wait, are returned again when asked for again, and change nothing until both certificates are
// imported; the rotation job then moves issuing, and the old root's key is never in the database.
func TestNewRootOffline(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		now := t0.Add(day)
		clock := func() time.Time { return now }
		ca, err := castore.LoadCA(sys, db, s, clock)
		if err != nil {
			t.Fatal(err)
		}
		r1 := ca.Root()
		offline := exportOffline(t, db, s)

		req, err := newRoot(t, db, s, now)
		if err != nil || req == nil {
			t.Fatalf("new-root with an offline root: %v, %v", req, err)
		}
		if _, err := castore.RootKeyForTest(sys, db, s); err == nil {
			t.Fatal("the old root's key is in the database")
		}
		roots := rowsOf(t, db, cakey.KindRoot)
		if len(roots) != 2 {
			t.Fatalf("%d root rows, want the old root and the new one", len(roots))
		}
		var next *ent.CAKey
		for _, r := range roots {
			if r.Status == cakey.StatusNext {
				next = r
			}
		}
		if next == nil || next.KeyEnc == nil || len(*next.KeyEnc) == 0 || len(next.CrossCertificate) != 0 || pki.PublicKeyHash(next.PublicKey) != req.CrossKeyHash {
			t.Fatalf("the new root is %+v; want a sealed next key with no cross-certificate, the key of the request", next)
		}
		// The requests wait: the job changes nothing, and asking again returns them and writes nothing.
		if done := rotate(t, db, s, now); len(done) != 0 {
			t.Fatalf("the job changed %v before the old root signed", done)
		}
		again, err := newRoot(t, db, s, now)
		if err != nil || again == nil || string(again.Cross) != string(req.Cross) || string(again.Intermediate) != string(req.Intermediate) {
			t.Fatalf("new-root again: %v, %v; want the same requests", again, err)
		}
		if len(rowsOf(t, db, cakey.KindRoot)) != 2 || len(rowsOf(t, db, cakey.KindIntermediate)) != 2 {
			t.Fatal("asking again made more keys")
		}

		x, err := pki.SignCrossRoot(offline, req.Cross, now)
		if err != nil {
			t.Fatal(err)
		}
		y, err := pki.SignIntermediate(offline, req.Intermediate, now)
		if err != nil {
			t.Fatal(err)
		}
		// Only the two certificates for the two keys are taken, each against the old root.
		other := newKey(t)
		for name, bad := range map[string][]byte{
			"a cross-certificate that another key signed": forgeCross(t, newKey(t), r1, next.PublicKey, now),
			"a cross-certificate with another subject":    forgeCrossSubject(t, offline, next.PublicKey, now),
			"a certificate for an unrelated key":          forge(t, td, r1, offline.Key, &other.PublicKey, nil),
		} {
			if err := importDER(t, db, bad, now); err == nil {
				t.Errorf("imported %s", name)
			}
		}
		if err := importDER(t, db, x.Raw, now.Add(-100*day)); !errors.Is(err, pki.ErrCrossRootRefused) {
			t.Fatalf("a cross-certificate that is not valid yet = %v, want ErrCrossRootRefused", err)
		}
		if done := rotate(t, db, s, now); len(done) != 0 {
			t.Fatalf("the job changed %v after refused imports", done)
		}
		if err := importDER(t, db, y.Raw, now); err != nil {
			t.Fatal(err)
		}
		if done := rotate(t, db, s, now); len(done) != 0 {
			t.Fatalf("the job moved issuing with only Y imported: %v", done)
		}
		if err := importDER(t, db, x.Raw, now); err != nil {
			t.Fatal(err)
		}
		done := rotate(t, db, s, now)
		if len(done) < 2 || done[0] != "root rotated: the new root issues and the old one stays in the bundle" {
			t.Fatalf("the job did not move issuing: %v", done)
		}
		if changed, err := ca.Reload(sys, db, s, clock); err != nil || !changed {
			t.Fatalf("reload: %v, %v", changed, err)
		}
		r2 := ca.Root()
		if r2.Equal(r1) || len(ca.TrustBundle()) != 3 {
			t.Fatalf("issuing did not move: bundle %d", len(ca.TrustBundle()))
		}
		org := storetest.Org(t, db, "org-a")
		var chain [][]byte
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			c, err := ca.Issue(sys, tx, csrFor(t, newKey(t), nil), connector(org, ids.New("con")), pki.DefaultLeafLifetime)
			chain = ca.Chain(c)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if !verifies(t, chain, pool(r1), now) || !verifies(t, chain, pool(r2), now) {
			t.Fatal("a leaf issued after the switch does not verify under both roots")
		}
		for _, r := range rowsOf(t, db, cakey.KindRoot) {
			if r.Status == cakey.StatusOverlap && r.KeyEnc != nil && len(*r.KeyEnc) != 0 {
				t.Fatal("the old root's key is in the database")
			}
		}
		// A rotation of the intermediate asks for a signature of nobody now: the overlap holds it back.
		if _, err := newRoot(t, db, s, now); !errors.Is(err, castore.ErrRotationInProgress) {
			t.Fatalf("new-root in the overlap = %v", err)
		}
	})
}

// forgeCross makes a cross-certificate for the key pubDER that signer, not the old root, signed.
func forgeCross(t *testing.T, signer *ecdsa.PrivateKey, r1 *x509.Certificate, pubDER []byte, now time.Time) []byte {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatal(err)
	}
	// A stand-in for the old root with its name and key id but another key.
	fake := &x509.Certificate{Subject: r1.Subject, SubjectKeyId: r1.SubjectKeyId}
	return crossWith(t, signer, fake, pub.(*ecdsa.PublicKey), pkix.Name{CommonName: "rpmgr root CA " + td}, now)
}

// forgeCrossSubject makes a cross-certificate that the old root signed, with another subject.
func forgeCrossSubject(t *testing.T, root pki.KeyPair, pubDER []byte, now time.Time) []byte {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatal(err)
	}
	return crossWith(t, root.Key, root.Cert, pub.(*ecdsa.PublicKey), pkix.Name{CommonName: "another root"}, now)
}

func crossWith(t *testing.T, signer *ecdsa.PrivateKey, parent *x509.Certificate, pub *ecdsa.PublicKey, subject pkix.Name, now time.Time) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: bigSerial(t), Subject: subject, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(365 * day), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign}, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
