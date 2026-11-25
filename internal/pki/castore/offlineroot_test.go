// SPDX-License-Identifier: Apache-2.0

package castore_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
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

const rootPass = "correct horse battery staple 42"

// offlineEnv is a CA whose root went offline: its file, and the request for the next intermediate.
type offlineEnv struct {
	db   *store.DB
	s    *secret.Sealer
	file []byte
	root pki.KeyPair // as read from the file
	csr  []byte
	pub  *ecdsa.PublicKey
}

func goOffline(t *testing.T, db *store.DB, kek secret.KEK) *offlineEnv {
	t.Helper()
	sys := storetest.SystemCtx(t)
	e := &offlineEnv{db: db, s: sealer(t, kek)}
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
		_, err := castore.ExportRootOffline(sys, tx, e.s, rootPass, func(f []byte) ([]byte, error) {
			e.file = bytes.Clone(f)
			return f, nil
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var err error
	if e.root, err = pki.OpenRootFile(e.file, rootPass); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
		var err error
		e.csr, err = castore.RequestIntermediateSigning(sys, tx, e.s, t0)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(e.csr)
	req, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	e.pub = req.PublicKey.(*ecdsa.PublicKey)
	return e
}

func (e *offlineEnv) importDER(t *testing.T, der []byte, now time.Time) error {
	t.Helper()
	sys := storetest.SystemCtx(t)
	return store.WriteTx(sys, e.db, func(tx *ent.Tx) error { return castore.ImportIntermediate(sys, tx, der, now) })
}

func (e *offlineEnv) pending(t *testing.T) *ent.CAKey {
	t.Helper()
	r, err := e.db.ReadClient().CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusNext)).Only(storetest.SystemCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func rootRow(t *testing.T, db *store.DB) *ent.CAKey {
	t.Helper()
	r, err := db.ReadClient().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot)).Only(storetest.SystemCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// forge signs an intermediate for pub with signer under parent; mutate changes the template first.
func bigSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

func forge(t *testing.T, td string, parent *x509.Certificate, signer *ecdsa.PrivateKey, pub *ecdsa.PublicKey, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: bigSerial(t), Subject: pkix.Name{CommonName: "rpmgr issuing CA " + td},
		NotBefore: t0.Add(-time.Minute), NotAfter: t0.Add(pki.IntermediateLifetime),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{td}, PermittedURIDomains: []string{td},
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestCA_OfflineRootNeverStored covers what the store layer does of the test in
// docs/12-testing-and-quality.md: the key is in no column of ca_keys and not in the raw database
// file, its log or a new backup, nor in an error; key_enc is null; the CA loads and issues without
// the root. The command, the KEK rotation of the ceremony and the restore are slice 8.11 and the
// backup slices.
func TestCA_OfflineRootNeverStored(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, ca *castore.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		before := rootRow(t, db)
		if keyOffline(before) {
			t.Fatal("the online root has no sealed key")
		}
		rootKP, err := castore.RootKeyForTest(sys, db, s)
		if err != nil {
			t.Fatal(err)
		}
		der, _ := x509.MarshalPKCS8PrivateKey(rootKP.Key)
		scalar := rootKP.Key.D.FillBytes(make([]byte, 32))
		secrets := [][]byte{der, scalar, []byte(rootPass)}

		var errTexts []string
		var exp castore.RootExport
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			var err error
			exp, err = castore.ExportRootOffline(sys, tx, s, rootPass, func(f []byte) ([]byte, error) { return f, nil })
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if exp.Pin != pki.RootPin(ca.Root()) || len(exp.PublicKeyHash) != 64 || len(exp.FileSHA256) != 64 {
			t.Fatalf("export report = %+v", exp)
		}
		if r := rootRow(t, db); !keyOffline(r) {
			t.Fatal("key_enc of the root is not null after the export")
		}
		// An export of a root that is offline, and a wrong passphrase, fail without the key in the error.
		err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
			_, err := castore.ExportRootOffline(sys, tx, s, rootPass, func(f []byte) ([]byte, error) { return f, nil })
			return err
		})
		if !errors.Is(err, castore.ErrRootOffline) {
			t.Fatalf("a second export = %v, want ErrRootOffline", err)
		}
		errTexts = append(errTexts, err.Error())
		_, err = pki.OpenRootFile([]byte("age-encryption.org/v1\n"), rootPass)
		errTexts = append(errTexts, err.Error())
		err = store.WriteTx(sys, db, func(tx *ent.Tx) error { return castore.RotateIntermediate(sys, tx, s, t0.Add(day)) })
		if !errors.Is(err, castore.ErrRootOffline) {
			t.Fatalf("RotateIntermediate with an offline root = %v, want ErrRootOffline", err)
		}
		errTexts = append(errTexts, err.Error())

		// The CA starts and issues without the root's key.
		fresh, err := castore.LoadCA(sys, db, s, clock)
		if err != nil {
			t.Fatalf("the CA does not load with an offline root: %v", err)
		}
		org := storetest.Org(t, db, "org-a")
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			_, err := fresh.Issue(sys, tx, csrFor(t, newKey(t), nil), connector(org, ids.New("con")), pki.DefaultLeafLifetime)
			return err
		}); err != nil {
			t.Fatalf("the CA does not issue with an offline root: %v", err)
		}

		// Nothing in ca_keys, in an error, or in the database file.
		rows, err := db.ReadClient().CAKey.Query().All(sys)
		if err != nil {
			t.Fatal(err)
		}
		var dump bytes.Buffer
		for _, r := range rows {
			dump.WriteString(r.ID + string(r.Kind) + string(r.Status))
			dump.Write(r.PublicKey)
			dump.Write(r.Certificate)
			dump.Write(r.Csr)
			if !keyOffline(r) && r.Kind != cakey.KindRoot {
				dump.Write(*r.KeyEnc)
			}
		}
		dump.WriteString(strings.Join(errTexts, "\n"))
		for _, sec := range secrets {
			if bytes.Contains(dump.Bytes(), sec) {
				t.Fatal("secret bytes of the root are in ca_keys or an error")
			}
		}
		if db.Dialect == store.SQLite {
			backup := t.TempDir() + "/backup.db"
			if err := db.VacuumInto(sys, backup); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{db.Path, db.Path + "-wal", backup} {
				raw, err := os.ReadFile(path)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, sec := range secrets {
					if bytes.Contains(raw, sec) {
						t.Fatalf("secret bytes of the root are in %s", path)
					}
				}
			}
			raw, _ := os.ReadFile(backup)
			if bytes.Contains(raw, before.PublicKey) == false {
				t.Fatal("the backup lost the root's public key; the scan is not looking at the right file")
			}
		}
	})
}

func TestExportRootOffline(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		export := func(pass string, persist func([]byte) ([]byte, error)) error {
			return store.WriteTx(sys, db, func(tx *ent.Tx) error {
				_, err := castore.ExportRootOffline(sys, tx, s, pass, persist)
				return err
			})
		}
		keep := func(f []byte) ([]byte, error) { return f, nil }
		// A file that cannot be written, or reads back wrong, leaves the key where it is.
		if err := export(rootPass, func([]byte) ([]byte, error) { return nil, errors.New("disk full") }); err == nil {
			t.Fatal("an unwritable file was accepted")
		}
		for name, f := range map[string]func([]byte) ([]byte, error){
			"truncated": func(b []byte) ([]byte, error) { return b[:len(b)-5], nil },
			"empty":     func([]byte) ([]byte, error) { return nil, nil },
			"tampered": func(b []byte) ([]byte, error) {
				c := bytes.Clone(b)
				c[len(c)-3] ^= 1
				return c, nil
			},
			"another root": func([]byte) ([]byte, error) {
				other, _ := pki.NewRoot(td, t0)
				return pki.SealRootFile(other, rootPass)
			},
		} {
			if err := export(rootPass, f); !errors.Is(err, castore.ErrRootExport) {
				t.Fatalf("%s read-back: err = %v, want ErrRootExport", name, err)
			}
		}
		if keyOffline(rootRow(t, db)) {
			t.Fatal("a failed export removed the key")
		}
		if err := export(rootPass, keep); err != nil {
			t.Fatal(err)
		}
		if !keyOffline(rootRow(t, db)) {
			t.Fatal("key_enc is not null")
		}
		if err := export(rootPass, keep); !errors.Is(err, castore.ErrRootOffline) {
			t.Fatalf("export of an offline root = %v, want ErrRootOffline", err)
		}
	})
}

func TestOfflineRootSigning(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		// While the root is online no request is made.
		err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			_, err := castore.RequestIntermediateSigning(sys, tx, sealer(t, kek), t0)
			return err
		})
		if !errors.Is(err, castore.ErrRootOnline) {
			t.Fatalf("a request with an online root = %v, want ErrRootOnline", err)
		}
		e := goOffline(t, db, kek)
		p := e.pending(t)
		if len(p.Certificate) != 0 || keyOffline(p) || !bytes.Equal(p.Csr, e.csr) {
			t.Fatal("the pending intermediate has a certificate, no key or another request")
		}
		// One request waits: a second call returns it.
		var again []byte
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			var err error
			again, err = castore.RequestIntermediateSigning(sys, tx, e.s, t0)
			return err
		}); err != nil || !bytes.Equal(again, e.csr) {
			t.Fatalf("second request = %v, %v", err, bytes.Equal(again, e.csr))
		}
		// The CA still loads and issues with the pending key.
		if _, err := castore.LoadCA(sys, db, e.s, clock); err != nil {
			t.Fatalf("the CA does not load with a pending intermediate: %v", err)
		}
		// Signing with the root online is refused; the schedule asks for a signature instead.
		err = store.WriteTx(sys, db, func(tx *ent.Tx) error { return castore.RotateIntermediate(sys, tx, e.s, t0) })
		if !errors.Is(err, castore.ErrRootOffline) {
			t.Fatalf("RotateIntermediate = %v, want ErrRootOffline", err)
		}
		// Import, then the schedule activates the signed key at the active one's half-life.
		cert, err := pki.SignIntermediate(e.root, e.csr, t0)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.importDER(t, cert.Raw, t0); err != nil {
			t.Fatal(err)
		}
		if p := e.pending(t); !bytes.Equal(p.Certificate, cert.Raw) || p.Status != cakey.StatusNext || !p.NotAfter.Equal(cert.NotAfter) {
			t.Fatal("the import did not store the certificate on the next key")
		}
		if err := e.importDER(t, cert.Raw, t0); !errors.Is(err, castore.ErrNoRequest) {
			t.Fatalf("a second import = %v, want ErrNoRequest", err)
		}
		rotate := func(at time.Time) []string {
			var done []string
			if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				var err error
				done, err = castore.Rotate(sys, tx, e.s, at)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return done
		}
		if done := rotate(t0.Add(30 * day)); len(done) != 0 {
			t.Fatalf("early rotation changed %v", done)
		}
		if done := rotate(t0.Add(200 * day)); len(done) != 1 || !strings.Contains(done[0], "replaced") {
			t.Fatalf("rotation at half-life = %v", done)
		}
		ca, err := castore.LoadCA(sys, db, e.s, func() time.Time { return t0.Add(200 * day) })
		if err != nil {
			t.Fatal(err)
		}
		if !ca.Intermediate().Equal(cert) {
			t.Fatal("the imported intermediate is not the active one")
		}
	})
}

// With an offline root the rotation does not sign: it makes a request, once, and keeps the old
// intermediate.
func TestRotateOfflineRootAsksForSignature(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			_, err := castore.ExportRootOffline(sys, tx, s, rootPass, func(f []byte) ([]byte, error) { return f, nil })
			return err
		}); err != nil {
			t.Fatal(err)
		}
		half := t0.Add(pki.IntermediateLifetime / 2)
		for i := range 2 {
			var done []string
			if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				var err error
				done, err = castore.Rotate(sys, tx, s, half.Add(time.Duration(i)*time.Hour))
				return err
			}); err != nil {
				t.Fatalf("Rotate with an offline root: %v", err)
			}
			if (i == 0) != (len(done) == 1 && done[0] == "intermediate needs signing") {
				t.Fatalf("run %d changed %v", i, done)
			}
		}
		n, _ := db.ReadClient().CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate)).Count(sys)
		if n != 2 {
			t.Fatalf("%d intermediates, want the active one and one waiting", n)
		}
	})
}

// TestCA_ImportedIntermediateMustChainAndConstrain: every refusal names its reason, changes nothing,
// and the valid certificate is imported.
func TestCA_ImportedIntermediateMustChainAndConstrain(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		e := goOffline(t, db, kek)
		rootCert, rootKey := e.root.Cert, e.root.Key
		otherRoot, err := pki.NewRoot(td, t0) // the same subject, another key
		if err != nil {
			t.Fatal(err)
		}
		foreignRoot, err := pki.NewRoot("rpmgr-other222", t0)
		if err != nil {
			t.Fatal(err)
		}
		otherPub := &newKey(t).PublicKey
		signed := func(m func(*x509.Certificate)) []byte { return forge(t, td, rootCert, rootKey, e.pub, m) }
		good := signed(nil)
		brokenSig := bytes.Clone(good)
		brokenSig[len(brokenSig)-1] ^= 1
		type tc struct {
			name   string
			der    []byte
			reason string
		}
		for _, c := range []tc{
			{"another root", forge(t, td, foreignRoot.Cert, foreignRoot.Key, e.pub, nil), "not issued by the root"},
			{"same subject, another key", forge(t, td, otherRoot.Cert, otherRoot.Key, e.pub, nil), "did not sign"},
			{"broken signature", brokenSig, "did not sign"},
			{"another key than the request", forge(t, td, rootCert, rootKey, otherPub, nil), "not for the key"},
			{"no name constraints", signed(func(c *x509.Certificate) {
				c.PermittedDNSDomains, c.PermittedURIDomains, c.PermittedDNSDomainsCritical = nil, nil, false
			}), "not critical"},
			{"constraints not critical", signed(func(c *x509.Certificate) { c.PermittedDNSDomainsCritical = false }), "not critical"},
			{"constraints widened", signed(func(c *x509.Certificate) {
				c.PermittedDNSDomains = []string{td, "example.com"}
			}), "not exactly"},
			{"constraints widened to a subdomain scope", signed(func(c *x509.Certificate) {
				c.PermittedURIDomains = []string{"." + td, td}
			}), "not exactly"},
			{"constraints narrowed", signed(func(c *x509.Certificate) { c.PermittedURIDomains = nil }), "not exactly"},
			{"another domain", signed(func(c *x509.Certificate) {
				c.PermittedDNSDomains, c.PermittedURIDomains = []string{"rpmgr-other222"}, []string{"rpmgr-other222"}
			}), "not exactly"},
			{"an exclusion", signed(func(c *x509.Certificate) { c.ExcludedDNSDomains = []string{"bad." + td} }), "not exactly"},
			{"path length 1", signed(func(c *x509.Certificate) { c.MaxPathLen = 1 }), "path length"},
			{"no path length", signed(func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = -1, false }), "path length"},
			{"not a CA", signed(func(c *x509.Certificate) { c.IsCA, c.MaxPathLen, c.MaxPathLenZero = false, -1, false }), "not a CA"},
			{"no certSign", signed(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }), "not a CA"},
			{"expired", signed(func(c *x509.Certificate) {
				c.NotBefore, c.NotAfter = t0.Add(-2*day), t0.Add(-day)
			}), "not valid now"},
			{"not yet valid", signed(func(c *x509.Certificate) {
				c.NotBefore, c.NotAfter = t0.Add(day), t0.Add(2*day)
			}), "not valid now"},
			{"outliving the root", signed(func(c *x509.Certificate) { c.NotAfter = rootCert.NotAfter.Add(time.Hour) }), "outlasts"},
			{"garbage", []byte{1, 2, 3}, "pki: the intermediate is refused"},
		} {
			t.Run(c.name, func(t *testing.T) {
				err := e.importDER(t, c.der, t0)
				if !errors.Is(err, pki.ErrIntermediateRefused) || !strings.Contains(err.Error(), c.reason) {
					t.Fatalf("import = %v, want a refusal containing %q", err, c.reason)
				}
				if p := e.pending(t); len(p.Certificate) != 0 {
					t.Fatal("a refused import changed the row")
				}
			})
		}
		if err := e.importDER(t, good, t0); err != nil {
			t.Fatalf("a valid intermediate was refused: %v", err)
		}
		// The imported certificate chains to the root and constrains.
		cert, _ := x509.ParseCertificate(e.pending(t).Certificate)
		if err := cert.CheckSignatureFrom(rootCert); err != nil || cert.MaxPathLen != 0 || !cert.PermittedDNSDomainsCritical {
			t.Fatal("the imported certificate does not chain or constrain")
		}
	})
}

func TestIntermediateSigningAlert(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		alert := func(now time.Time) castore.SigningAlert {
			t.Helper()
			a, err := castore.IntermediateSigningAlert(sys, db, now)
			if err != nil {
				t.Fatal(err)
			}
			return a
		}
		if a := alert(t0); a != castore.AlertNone {
			t.Fatalf("an online root alerts: %q", a)
		}
		e := goOffline(t, db, kek)
		expires := t0.Add(pki.IntermediateLifetime) // the active intermediate's not_after, as InitCA made it
		active, _ := db.ReadClient().CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusActive)).Only(sys)
		expires = active.NotAfter
		for _, tc := range []struct {
			name string
			at   time.Time
			want castore.SigningAlert
		}{
			{"early", t0, castore.AlertNeedsSigning},
			{"31 days before", expires.Add(-31 * day), castore.AlertNeedsSigning},
			{"30 days before", expires.Add(-30 * day), castore.AlertCritical},
			{"29 days before", expires.Add(-29 * day), castore.AlertCritical},
			{"one second over 30 days", expires.Add(-30*day - time.Second), castore.AlertNeedsSigning},
		} {
			if a := alert(tc.at); a != tc.want {
				t.Errorf("%s: alert = %q, want %q", tc.name, a, tc.want)
			}
		}
		// A signed, imported intermediate ends the alert.
		cert, err := pki.SignIntermediate(e.root, e.csr, t0)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.importDER(t, cert.Raw, t0); err != nil {
			t.Fatal(err)
		}
		if a := alert(expires.Add(-day)); a != castore.AlertNone {
			t.Fatalf("an imported intermediate still alerts: %q", a)
		}
	})
}

func keyOffline(r *ent.CAKey) bool { return r.KeyEnc == nil || len(*r.KeyEnc) == 0 }
