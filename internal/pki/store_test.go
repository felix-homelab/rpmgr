// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/secretmeta"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func newKEK(t *testing.T) secret.KEK {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	k, err := secret.NewKEK(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sealer(t *testing.T, current secret.KEK, previous ...secret.KEK) *secret.Sealer {
	t.Helper()
	s, err := secret.NewSealer(current, previous...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func clock() time.Time { return t0 }

// initCA creates a CA in a fresh database of each dialect and loads it.
func withCA(t *testing.T, f func(t *testing.T, db *store.DB, kek secret.KEK, ca *pki.CA)) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		kek := newKEK(t)
		sys := storetest.SystemCtx(t)
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			return pki.InitCA(sys, tx, sealer(t, kek), td, t0)
		}); err != nil {
			t.Fatal(err)
		}
		ca, err := pki.LoadCA(sys, db, sealer(t, kek), clock)
		if err != nil {
			t.Fatal(err)
		}
		f(t, db, kek, ca)
	})
}

func TestInitAndLoadCA(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, ca *pki.CA) {
		sys := storetest.SystemCtx(t)
		if ca.TrustDomain() != td || ca.Root().MaxPathLen != 1 || ca.Intermediate().CheckSignatureFrom(ca.Root()) != nil {
			t.Fatal("the loaded CA is not the one created")
		}
		chain := []*x509.Certificate{ca.Intermediate()}
		if err := pki.VerifySigner(ca.ConfigSigner().Cert, chain, ca.Root(), pki.PurposeConfigSigning, t0); err != nil {
			t.Error(err)
		}
		if err := pki.VerifySigner(ca.AuditSigner().Cert, chain, ca.Root(), pki.PurposeAuditCheckpoint, t0); err != nil {
			t.Error(err)
		}
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			return pki.InitCA(sys, tx, sealer(t, kek), td, t0)
		}); !errors.Is(err, pki.ErrCAExists) {
			t.Errorf("a second InitCA: %v, want ErrCAExists", err)
		}
		metas := db.Client().SecretMeta.Query().Where(secretmeta.TableName("ca_keys")).AllX(sys)
		if len(metas) != 4 {
			t.Fatalf("%d secrets_meta rows for ca_keys, want 4", len(metas))
		}
		for _, m := range metas {
			if m.ColumnName != "key_enc" || m.KekVersion != kek.Version() || !ids.Valid("cak", m.RowID) {
				t.Errorf("secrets_meta row %+v", m)
			}
		}
		// A database dump holds no private key in the clear.
		var dump []byte
		for _, k := range db.Client().CAKey.Query().AllX(sys) {
			dump = append(append(append(dump, *k.KeyEnc...), k.Certificate...), k.PublicKey...)
		}
		for name, kp := range map[string]pki.KeyPair{"config-signing": ca.ConfigSigner(), "audit": ca.AuditSigner()} {
			d, err := kp.Key.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(dump, d[len(d)-32:]) {
				t.Errorf("the %s private key is in the database in the clear", name)
			}
		}
	})
}

func TestLoadCA_Refusals(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *pki.CA) {
		sys := storetest.SystemCtx(t)
		if _, err := pki.LoadCA(sys, db, sealer(t, newKEK(t)), clock); err == nil {
			t.Error("loaded with another KEK")
		}
		if _, err := pki.LoadCA(sys, db, sealer(t, newKEK(t), kek), clock); err != nil {
			t.Errorf("loading with the old KEK as previous: %v", err)
		}
		org := storetest.Org(t, db, "org-a")
		if _, err := pki.LoadCA(storetest.OrgCtx(t, org), db, sealer(t, kek), clock); err == nil {
			t.Error("loaded in an org scope")
		}
		if _, err := pki.LoadCA(context.Background(), db, sealer(t, kek), clock); err == nil {
			t.Error("loaded without a scope")
		}
		if n, err := db.Client().CAKey.Query().Count(storetest.OrgCtx(t, org)); err == nil {
			t.Errorf("an org scope counted %d CA keys", n)
		}
		root := db.Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot)).OnlyX(sys)
		dup := db.Client().CAKey.Create().SetKind(root.Kind).SetAlgorithm(root.Algorithm).SetPublicKey(root.PublicKey).
			SetCertificate(root.Certificate).SetNotBefore(root.NotBefore).SetNotAfter(root.NotAfter).
			SetStatus(cakey.StatusActive).SaveX(sys)
		if _, err := pki.LoadCA(sys, db, sealer(t, kek), clock); err == nil {
			t.Error("loaded with two active roots")
		}
		db.Client().CAKey.DeleteOne(dup).ExecX(sys)
		// A sealed key copied to another row does not open there.
		if _, err := db.Writer.ExecContext(context.Background(),
			"UPDATE ca_keys SET key_enc = (SELECT key_enc FROM ca_keys WHERE kind = 'config_signing') WHERE kind = 'audit_checkpoint'"); err != nil {
			t.Fatal(err)
		}
		if _, err := pki.LoadCA(sys, db, sealer(t, kek), clock); err == nil {
			t.Error("loaded with a key copied between rows")
		}
	})
}

func TestCA_EmptyDatabaseAndOrgScope(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		sys := storetest.SystemCtx(t)
		if _, err := pki.LoadCA(sys, db, sealer(t, newKEK(t)), clock); err == nil {
			t.Error("loaded from an empty database")
		}
		org := storetest.Org(t, db, "org-a")
		ctx := storetest.OrgCtx(t, org)
		if err := store.WriteTx(ctx, db, func(tx *ent.Tx) error {
			return pki.InitCA(ctx, tx, sealer(t, newKEK(t)), td, t0)
		}); err == nil {
			t.Error("InitCA in an org scope")
		}
	})
}

// TestIssue_Records: every leaf is recorded with its identity, key fingerprint and validity, in
// its org; an org scope neither sees nor creates another org's records, and a refused CSR records
// nothing.
func TestIssue_Records(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, _ secret.KEK, ca *pki.CA) {
		a, b := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		ctxA, ctxB, sys := storetest.OrgCtx(t, a), storetest.OrgCtx(t, b), storetest.SystemCtx(t)
		id := connector(a, ids.New("con"))
		issue := func(ctx context.Context, csr *x509.CertificateRequest, id pki.Identity) (*x509.Certificate, error) {
			var cert *x509.Certificate
			err := store.WriteTx(ctx, db, func(tx *ent.Tx) error {
				var err error
				cert, err = ca.Issue(ctx, tx, csr, id, pki.DefaultLeafLifetime)
				return err
			})
			return cert, err
		}
		cert, err := issue(ctxA, csrFor(t, newKey(t), nil), id)
		if err != nil {
			t.Fatal(err)
		}
		row := db.Client().IssuedCertificate.GetX(ctxA, pki.SerialHex(cert.SerialNumber))
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if row.OrgID == nil || *row.OrgID != a || row.SubjectType != issuedcertificate.SubjectTypeConnector ||
			row.SubjectID != id.ID || row.SpiffeID != id.String() || row.PubkeySha256 != hex.EncodeToString(sum[:]) ||
			!row.NotAfter.Equal(cert.NotAfter) {
			t.Errorf("recorded %+v", row)
		}
		if n := db.Client().IssuedCertificate.Query().CountX(ctxB); n != 0 {
			t.Errorf("org B sees %d of org A's certificates", n)
		}
		if _, err := issue(ctxB, csrFor(t, newKey(t), nil), id); err == nil {
			t.Error("org B recorded a certificate for org A")
		}
		broken := csrFor(t, newKey(t), nil)
		broken.Signature[0] ^= 1
		if _, err := issue(ctxA, broken, id); err == nil {
			t.Error("a broken CSR was issued")
		}
		var renewed *x509.Certificate
		if err := store.WriteTx(ctxA, db, func(tx *ent.Tx) error {
			var err error
			renewed, err = ca.Renew(ctxA, tx, cert, csrFor(t, newKey(t), nil), pki.DefaultLeafLifetime)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if n := db.Client().IssuedCertificate.Query().CountX(sys); n != 2 {
			t.Fatalf("%d certificates recorded, want the leaf and its renewal", n)
		}
		if got := db.Client().IssuedCertificate.GetX(sys, pki.SerialHex(renewed.SerialNumber)); got.SubjectID != id.ID {
			t.Errorf("renewal recorded for %s", got.SubjectID)
		}

		node, err := ca.NodeCertificate(sys, db, ids.New("ctn"))
		if err != nil {
			t.Fatal(err)
		}
		roots, inters := x509.NewCertPool(), x509.NewCertPool()
		roots.AddCert(ca.Root())
		inters.AddCert(ca.Intermediate())
		if _, err := node.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "controller." + td,
			CurrentTime: t0, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("node certificate: %v", err)
		}
		if len(node.Certificate) != 2 || !bytes.Equal(node.Certificate[1], ca.Intermediate().Raw) {
			t.Error("the node certificate is not sent with its intermediate")
		}
		nodeRow := db.Client().IssuedCertificate.GetX(sys, pki.SerialHex(node.Leaf.SerialNumber))
		if nodeRow.OrgID != nil || nodeRow.SubjectType != issuedcertificate.SubjectTypeController {
			t.Errorf("node certificate recorded as %+v", nodeRow)
		}
		if n := db.Client().IssuedCertificate.Query().CountX(ctxA); n != 2 {
			t.Errorf("org A sees %d certificates, want its 2 and not the node's", n)
		}
		if _, err := ca.NodeCertificate(ctxA, db, ids.New("ctn")); err == nil {
			t.Error("an org scope issued a controller node certificate")
		}
	})
}

// TestSeal_RecordsKEKVersion: sealing a column again after a KEK rotation updates its one
// secrets_meta row.
func TestSeal_RecordsKEKVersion(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		k1, k2 := newKEK(t), newKEK(t)
		c := secret.Context{Table: "users", Column: "totp_seed_enc", RowID: ids.New("usr")}
		for _, s := range []*secret.Sealer{sealer(t, k1), sealer(t, k2, k1)} {
			if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				_, err := store.Seal(sys, tx, s, c, secret.New("seed"))
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		rows := db.Client().SecretMeta.Query().AllX(sys)
		if len(rows) != 1 || rows[0].KekVersion != k2.Version() || rows[0].RowID != c.RowID {
			t.Fatalf("secrets_meta after a rotation: %+v", rows)
		}
		if err := store.WriteTx(context.Background(), db, func(tx *ent.Tx) error {
			_, err := store.Seal(context.Background(), tx, sealer(t, k1), c, secret.New("seed"))
			return err
		}); err == nil {
			t.Error("sealed without a scope")
		}
	})
}

// TestMarkSeenAndCheckRenewable: using a certificate supersedes the older certificates of its
// identity but not a newer one, records its first use once, and leaves other identities alone;
// unknown, revoked and superseded certificates are not renewable.
func TestMarkSeenAndCheckRenewable(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *pki.CA) {
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "org-a")
		now := t0
		ca, err := pki.LoadCA(sys, db, sealer(t, kek), func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		issueAt := func(id pki.Identity, at time.Time) *x509.Certificate {
			now = at
			var cert *x509.Certificate
			if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				var err error
				cert, err = ca.Issue(sys, tx, csrFor(t, newKey(t), nil), id, pki.DefaultLeafLifetime)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return cert
		}
		seen := func(cert *x509.Certificate, at time.Time) {
			if err := store.WriteTx(sys, db, func(tx *ent.Tx) error { _, err := pki.MarkSeen(sys, tx, cert, at); return err }); err != nil {
				t.Fatal(err)
			}
		}
		check := func(cert *x509.Certificate) error { return pki.CheckRenewable(sys, db.Client(), cert) }
		id, other := connector(org, ids.New("con")), connector(org, ids.New("con"))
		a := issueAt(id, t0)
		b := issueAt(id, t0.Add(time.Hour))
		c := issueAt(id, t0.Add(2*time.Hour)) // issued, never used: a lost Renew response
		o := issueAt(other, t0)

		seen(b, t0.Add(3*time.Hour))
		if err := check(a); !errors.Is(err, pki.ErrSuperseded) {
			t.Errorf("an older certificate: %v", err)
		}
		for name, cert := range map[string]*x509.Certificate{"the one used": b, "a newer one": c, "another identity": o} {
			if err := check(cert); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		seen(b, t0.Add(4*time.Hour))
		if row := db.Client().IssuedCertificate.GetX(sys, pki.SerialHex(b.SerialNumber)); row.FirstSeenAt == nil ||
			!row.FirstSeenAt.Equal(t0.Add(3*time.Hour)) {
			t.Errorf("first use %v, want the first time it was seen", row.FirstSeenAt)
		}

		db.Client().IssuedCertificate.UpdateOneID(pki.SerialHex(c.SerialNumber)).SetRevokedAt(t0).ExecX(sys)
		if err := check(c); !errors.Is(err, pki.ErrCertRevoked) {
			t.Errorf("a revoked certificate: %v", err)
		}

		// A certificate without a record: not renewable, and nothing to mark.
		foreign, _ := newCA(t, td).leaf(t, connector(org, ids.New("con")))
		if err := check(foreign); !errors.Is(err, pki.ErrNotIssued) {
			t.Errorf("a certificate without a record: %v", err)
		}
		seen(foreign, t0)
	})
}
