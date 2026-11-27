// SPDX-License-Identifier: Apache-2.0

package castore_test

import (
	"context"
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

// overlapDays is the overlap the tests give the drop: the defaults' 7 + 30 days.
const overlap = 37 * day

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

func dropRoot(t *testing.T, db *store.DB, now time.Time, o castore.DropOptions) error {
	t.Helper()
	sys := storetest.SystemCtx(t)
	return store.WriteTx(sys, db, func(tx *ent.Tx) error {
		_, err := castore.DropRoot(sys, tx, now, o)
		return err
	})
}

func stragglers(n int) castore.StragglerCount {
	return func(context.Context, *ent.Tx, time.Time) (int, error) { return n, nil }
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

// TestDropRoot: the old root leaves the bundle only after the overlap, or earlier with --force while no
// agent is a straggler; with stragglers it stays unless they are stranded on purpose, which is possible
// only after the overlap; and what it needs is checked again where it is written. Afterwards the bundle is
// the new root, a certificate under the old chain no longer verifies and the signing certificates under the
// old root are no longer delivered.
func TestDropRoot(t *testing.T) {
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
		oldLeaf, oldChain := issue()
		r1 := ca.Root()
		opts := castore.DropOptions{Overlap: overlap}

		if err := dropRoot(t, db, now, opts); !errors.Is(err, castore.ErrNoRotation) {
			t.Fatalf("a drop with no rotation = %v, want ErrNoRotation", err)
		}
		now = t0.Add(day)
		if _, err := newRoot(t, db, s, now); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Reload(sys, db, s, clock); err != nil {
			t.Fatal(err)
		}
		r2 := ca.Root()
		earliest := now.Add(overlap)

		// Early: refused, with the date.
		var early *castore.DropEarlyError
		if err := dropRoot(t, db, now.Add(overlap-time.Minute), opts); !errors.As(err, &early) || !early.Earliest.Equal(earliest) {
			t.Fatalf("a drop before the overlap = %v, want DropEarlyError for %v", err, earliest)
		}
		// --force while agents lack the new root: refused as a force, not as a date.
		var st *castore.StragglersError
		withStragglers := castore.DropOptions{Overlap: overlap, Force: true, Stragglers: stragglers(2)}
		if err := dropRoot(t, db, now.Add(day), withStragglers); !errors.As(err, &st) || !st.Force || st.N != 2 {
			t.Fatalf("--force with stragglers = %v, want a forced StragglersError of 2", err)
		}
		// --strand-stragglers is for after the overlap only.
		if err := dropRoot(t, db, now.Add(day), castore.DropOptions{Overlap: overlap, Strand: true, Stragglers: stragglers(2)}); !errors.As(err, &early) {
			t.Fatalf("--strand-stragglers before the overlap = %v, want DropEarlyError", err)
		}
		// After the overlap, stragglers hold it back, unless they are stranded on purpose.
		if err := dropRoot(t, db, earliest, castore.DropOptions{Overlap: overlap, Stragglers: stragglers(1)}); !errors.As(err, &st) || st.Force {
			t.Fatalf("a drop with stragglers = %v, want StragglersError", err)
		}
		if got := rowsOf(t, db, cakey.KindRoot); !slices.ContainsFunc(got, func(r *ent.CAKey) bool { return r.Status == cakey.StatusOverlap }) {
			t.Fatal("a refused drop changed the old root")
		}

		// What the plan found is checked again in the transaction: a drop that ran first wins, and the
		// plan made before it fails with ErrRotated.
		plan, err := castore.PlanDropRoot(sys, db.ReadClient().CAKey, earliest, castore.DropOptions{Overlap: overlap})
		if err != nil {
			t.Fatal(err)
		}
		if err := dropRoot(t, db, earliest, castore.DropOptions{Overlap: overlap, Strand: true, Stragglers: stragglers(3)}); err != nil {
			t.Fatalf("--strand-stragglers after the overlap: %v", err)
		}
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error { _, err := plan.Apply(sys, tx); return err }); !errors.Is(err, castore.ErrRotated) {
			t.Fatalf("a plan applied after another drop = %v, want ErrRotated", err)
		}

		// The new state.
		now = earliest
		if changed, err := ca.Reload(sys, db, s, clock); err != nil || !changed {
			t.Fatalf("reload: %v, %v", changed, err)
		}
		if got := ca.TrustBundle(); len(got) != 1 || !got[0].Equal(r2) {
			t.Fatalf("the bundle after the drop holds %d certificates, want R2 alone", len(got))
		}
		at := oldLeaf[0].NotBefore.Add(time.Hour)
		if _, err := ca.IdentityOf(oldLeaf[0], at); err == nil {
			t.Fatal("a leaf under the dropped root still verifies")
		}
		_ = oldChain
		_, chain := issue()
		if len(chain) != 2 || !verifies(t, chain, pool(r2), now) || verifies(t, chain, pool(r1), now) {
			t.Fatalf("a leaf after the drop: chain %d certificates", len(chain))
		}
		for _, der := range ca.SigningChain() {
			c, _ := x509.ParseCertificate(der)
			if !c.IsCA && c.CheckSignatureFrom(ca.Intermediate()) != nil {
				t.Fatal("a signing certificate that chains to the dropped root is still delivered")
			}
		}
		if err := dropRoot(t, db, now, opts); !errors.Is(err, castore.ErrNoRotation) {
			t.Fatalf("a second drop = %v, want ErrNoRotation", err)
		}
		// The next rotation can start again.
		if _, err := newRoot(t, db, s, now); err != nil {
			t.Fatalf("a rotation after a finished one: %v", err)
		}
	})
}

// TestDropRootForce: --force drops before the overlap when no agent is a straggler.
func TestDropRootForce(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		s := sealer(t, kek)
		if _, err := newRoot(t, db, s, t0); err != nil {
			t.Fatal(err)
		}
		if err := dropRoot(t, db, t0.Add(day), castore.DropOptions{Overlap: overlap, Force: true, Stragglers: stragglers(0)}); err != nil {
			t.Fatalf("--force with no stragglers: %v", err)
		}
	})
}

// TestCA_RotationChainsVerifyWithOldRootOnly (docs/12-testing-and-quality.md): after issuing moves to the
// new root, an agent that holds only the old root verifies the controller's chain and a peer's chain
// (leaf <- Y <- R1), with Go's chain verification and the real path-length constraint of the root, and
// never leaf <- I2 <- X <- R1, which Go refuses for the path length; an agent that holds only the new root
// verifies leaf <- I2 <- R2; after the old root is dropped the old-only agent is refused.
func TestCA_RotationChainsVerifyWithOldRootOnly(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "org-a")
		s := sealer(t, kek)
		now := t0.Add(day)
		clock := func() time.Time { return now }
		ca, err := castore.LoadCA(sys, db, s, clock)
		if err != nil {
			t.Fatal(err)
		}
		r1 := ca.Root()
		if r1.MaxPathLen != 1 {
			t.Fatalf("the old root's path length is %d; the test needs the real constraint of 1", r1.MaxPathLen)
		}
		if _, err := newRoot(t, db, s, now); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Reload(sys, db, s, clock); err != nil {
			t.Fatal(err)
		}
		r2 := ca.Root()
		var peer *x509.Certificate
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			var err error
			peer, err = ca.Issue(sys, tx, csrFor(t, newKey(t), nil), connector(org, ids.New("con")), pki.DefaultLeafLifetime)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		node, err := ca.NodeCertificate(sys, db, ids.New("ctn"))
		if err != nil {
			t.Fatal(err)
		}
		chains := map[string][][]byte{"the peer's": ca.Chain(peer), "the controller's": node.Certificate}
		for name, chain := range chains {
			if !verifies(t, chain, pool(r1), now) {
				t.Errorf("%s chain does not verify under the old root alone", name)
			}
			if !verifies(t, chain, pool(r2), now) {
				t.Errorf("%s chain does not verify under the new root alone", name)
			}
			// Under R1 the path is through Y, which is a certificate of R1's: leaf, I2's key, R1.
			leaf, inters := chainPool(t, chain)
			paths, err := leaf.Verify(x509.VerifyOptions{Roots: pool(r1), Intermediates: inters, CurrentTime: now,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
			if err != nil || len(paths) == 0 || len(paths[0]) != 3 || paths[0][1].CheckSignatureFrom(r1) != nil {
				t.Errorf("%s chain under R1: %v, %d paths", name, err, len(paths))
			}
		}
		// leaf <- I2 <- X <- R1 has one intermediate too many for R1's path length of 1.
		x := ca.TrustBundle()[2]
		leaf, _ := chainPool(t, chains["the peer's"])
		_, err = leaf.Verify(x509.VerifyOptions{Roots: pool(r1), Intermediates: pool(ca.Intermediate(), x), CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		var invalid x509.CertificateInvalidError
		if !errors.As(err, &invalid) || invalid.Reason != x509.TooManyIntermediates {
			// Y is not in this pool, so the only path is the one through X.
			t.Fatalf("leaf <- I2 <- X <- R1 = %v, want too many intermediates", err)
		}

		// The old root is dropped: an agent that holds only it is refused, one with the new root is not.
		if err := dropRoot(t, db, now.Add(overlap), castore.DropOptions{Overlap: overlap}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(overlap)
		if _, err := ca.Reload(sys, db, s, clock); err != nil {
			t.Fatal(err)
		}
		var fresh *x509.Certificate
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			var err error
			fresh, err = ca.Issue(sys, tx, csrFor(t, newKey(t), nil), connector(org, ids.New("con")), pki.DefaultLeafLifetime)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		chain := ca.Chain(fresh)
		if verifies(t, chain, pool(r1), now) || !verifies(t, chain, pool(r2), now) {
			t.Fatal("after the drop the chain must verify under the new root alone")
		}
		nodeAfter, err := ca.NodeCertificate(sys, db, ids.New("ctn"))
		if err != nil || verifies(t, nodeAfter.Certificate, pool(r1), now) || !verifies(t, nodeAfter.Certificate, pool(r2), now) {
			t.Fatalf("the controller's chain after the drop: %v", err)
		}
	})
}

// TestDropRootNeedsANextSigner: the old root is not dropped while an active signing key chains to it and
// no next key under the new intermediate can replace it, which would leave agents with snapshots they
// cannot verify.
func TestDropRootNeedsANextSigner(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		if _, err := newRoot(t, db, sealer(t, kek), t0); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Client().CAKey.Update().Where(cakey.KindEQ(cakey.KindConfigSigning), cakey.StatusEQ(cakey.StatusNext)).
			SetStatus(cakey.StatusRetired).Save(sys); err != nil {
			t.Fatal(err)
		}
		if err := dropRoot(t, db, t0.Add(overlap), castore.DropOptions{Overlap: overlap}); !errors.Is(err, castore.ErrNoSigner) {
			t.Fatalf("a drop with no next signing key = %v, want ErrNoSigner", err)
		}
	})
}
