// SPDX-License-Identifier: Apache-2.0

package certs_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

// issued is a certificate with its key.
type issued struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func ecKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// issue signs tmpl with parent (self-signed when parent is nil).
func issue(t *testing.T, tmpl *x509.Certificate, key crypto.Signer, parent *issued) issued {
	t.Helper()
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl.SerialNumber = serial
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore, tmpl.NotAfter = now.Add(-time.Hour), now.Add(90*24*time.Hour)
	}
	signer, issuer := key, tmpl
	if parent != nil {
		signer, issuer = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return issued{c, key}
}

func ca(t *testing.T, name string, parent *issued) issued {
	t.Helper()
	return issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, ecKey(t), parent)
}

func leafTmpl(names ...string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
}

func pemOf(cs ...issued) []byte {
	var out []byte
	for _, c := range cs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})...)
	}
	return out
}

func keyPEM(t *testing.T, k crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// TestParse: a chain and key that a gateway can serve, and every one it cannot.
func TestParse(t *testing.T) {
	root := ca(t, "root", nil)
	inter := ca(t, "inter", &root)
	leaf := issue(t, leafTmpl("App.Example.com", "*.example.com", "app.example.com"), ecKey(t), &inter)
	p, err := certs.Parse(pemOf(leaf, inter), keyPEM(t, leaf.key), now)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.SANs, []string{"*.example.com", "app.example.com"}) || len(p.Chain) != 2 {
		t.Fatalf("SANs %v, chain %d", p.SANs, len(p.Chain))
	}
	// The other key encodings and an RSA leaf.
	ec := leaf.key.(*ecdsa.PrivateKey)
	sec1, _ := x509.MarshalECPrivateKey(ec)
	if _, err := certs.Parse(pemOf(leaf), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}), now); err != nil {
		t.Errorf("a SEC 1 key: %v", err)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rleaf := issue(t, leafTmpl("rsa.example.com"), rk, &inter)
	if _, err := certs.Parse(pemOf(rleaf), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)}), now); err != nil {
		t.Errorf("an RSA 2048 key: %v", err)
	}

	small, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: the test checks that a small key is refused
	smallLeaf := issue(t, leafTmpl("rsa.example.com"), small, &inter)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	p521Leaf := issue(t, leafTmpl("ec.example.com"), p521, &inter)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edLeaf := issue(t, leafTmpl("ed.example.com"), edPriv, &inter)
	expired := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "old"}, DNSNames: []string{"old.example.com"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now}, ecKey(t), &inter)
	future := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "new"}, DNSNames: []string{"new.example.com"},
		NotBefore: now.Add(time.Minute), NotAfter: now.Add(time.Hour)}, ecKey(t), &inter)
	clientOnly := leafTmpl("client.example.com")
	clientOnly.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	client := issue(t, clientOnly, ecKey(t), &inter)
	noDNS := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "x.example.com"}}, ecKey(t), &inter)
	badName := issue(t, leafTmpl("under_score.example.com"), ecKey(t), &inter)
	other := ca(t, "other", nil)
	long := []issued{leaf}
	for range certs.MaxChain {
		long = append(long, inter)
	}
	for _, tc := range []struct {
		name       string
		chain, key []byte
		want       string
	}{
		{"no certificate", nil, keyPEM(t, leaf.key), "no certificate"},
		{"garbage", []byte("hello"), keyPEM(t, leaf.key), "not PEM"},
		{"text after the chain", append(pemOf(leaf), "trailer"...), keyPEM(t, leaf.key), "not PEM"},
		{"a key in the chain", append(pemOf(leaf), keyPEM(t, leaf.key)...), keyPEM(t, leaf.key), "PRIVATE KEY block"},
		{"chain too long", pemOf(long...), keyPEM(t, leaf.key), "longer than 10"},
		{"chain out of order", pemOf(leaf, root, inter), keyPEM(t, leaf.key), "not signed by certificate 2"},
		{"a foreign intermediate", pemOf(leaf, other), keyPEM(t, leaf.key), "not signed"},
		{"a CA first", pemOf(inter, root), keyPEM(t, inter.key), "a CA"},
		{"expired", pemOf(expired), keyPEM(t, expired.key), "expired"},
		{"not yet valid", pemOf(future), keyPEM(t, future.key), "valid only from"},
		{"client EKU only", pemOf(client), keyPEM(t, client.key), "not for TLS servers"},
		{"no DNS name", pemOf(noDNS), keyPEM(t, noDNS.key), "no DNS name"},
		{"an invalid DNS name", pemOf(badName), keyPEM(t, badName.key), "under_score"},
		{"another key", pemOf(leaf), keyPEM(t, ecKey(t)), "does not belong"},
		{"a P-384 key of another leaf", pemOf(leaf), keyPEM(t, p384), "does not belong"},
		{"P-521", pemOf(p521Leaf), keyPEM(t, p521), "P-521"},
		{"RSA 1024", pemOf(smallLeaf), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)}), "1024 bits"},
		{"Ed25519", pemOf(edLeaf), keyPEM(t, edPriv), "ECDSA or RSA only"},
		{"no key", pemOf(leaf), nil, "not one PEM block"},
		{"two keys", pemOf(leaf), append(keyPEM(t, leaf.key), keyPEM(t, leaf.key)...), "not one PEM block"},
		{"a certificate as the key", pemOf(leaf), pemOf(leaf), "CERTIFICATE block"},
		{"a broken key", pemOf(leaf), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), "the key"},
	} {
		_, err := certs.Parse(tc.chain, tc.key, now)
		if !errors.Is(err, certs.ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want ErrInvalid about %q", tc.name, err, tc.want)
		}
	}
}

// TestCovers: certificate names match route hostnames as TLS clients match them.
func TestCovers(t *testing.T) {
	for _, tc := range []struct {
		san, host string
		want      bool
	}{
		{"app.example.com", "app.example.com", true},
		{"app.example.com", "www.example.com", false},
		{"*.example.com", "app.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", "*.example.com", true},
		{"*.example.com", "*.app.example.com", false},
		{"app.example.com", "*.example.com", false},
		{"*.example.com", "badexample.com", false},
		{"*.example.com", ".example.com", false},
	} {
		if got := certs.Covers(tc.san, tc.host); got != tc.want {
			t.Errorf("%s covers %s: %v, want %v", tc.san, tc.host, got, tc.want)
		}
	}
}

func sealer(t *testing.T) *secret.Sealer {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	k, err := secret.NewKEK(b)
	if err != nil {
		t.Fatal(err)
	}
	s, err := secret.NewSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestUploadAndItem: an uploaded certificate is stored with its key sealed, never in plain, and
// its item carries the chain and key with the stored hash; a refused one stores nothing; a row
// changed behind the package's back does not produce an item.
func TestUploadAndItem(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "org-a")
		s := sealer(t)
		root := ca(t, "root", nil)
		leaf := issue(t, leafTmpl("app.example.com"), ecKey(t), &root)
		upload := func(chain, key []byte) (*ent.Certificate, error) {
			var c *ent.Certificate
			err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				var err error
				c, err = certs.Upload(sys, tx, s, org, chain, key, now)
				return err
			})
			return c, err
		}
		c, err := upload(pemOf(leaf, root), keyPEM(t, leaf.key))
		if err != nil {
			t.Fatal(err)
		}
		der, _ := x509.MarshalPKCS8PrivateKey(leaf.key)
		if c.Source != "uploaded" || c.Status != "active" || !c.NotAfter.Equal(leaf.cert.NotAfter) ||
			!slices.Equal(c.Sans, []string{"app.example.com"}) || strings.Contains(string(c.KeyEnc), string(der)) {
			t.Fatalf("stored %+v", c)
		}
		item, err := certs.Item(c, s)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(item); !slices.Equal(sum[:], c.ContentSha256) {
			t.Fatal("the item does not match the stored hash")
		}
		var got agentv1.CertificateItem
		if err := proto.Unmarshal(item, &got); err != nil || len(got.GetChain()) != 2 || !slices.Equal(got.GetChain()[0], leaf.cert.Raw) ||
			!slices.Equal(got.GetPrivateKey(), der) {
			t.Fatalf("item %v %v", &got, err)
		}

		if _, err := upload(pemOf(leaf), keyPEM(t, ecKey(t))); !errors.Is(err, certs.ErrInvalid) {
			t.Fatalf("a mismatched key: %v", err)
		}
		if n := db.Client().Certificate.Query().CountX(sys); n != 1 {
			t.Fatalf("%d certificates after a refused upload", n)
		}

		// Another row's sealed key, or a changed chain, does not pass for this certificate.
		c2, err := upload(pemOf(leaf), keyPEM(t, leaf.key))
		if err != nil {
			t.Fatal(err)
		}
		swapped := *c2
		swapped.KeyEnc = c.KeyEnc
		if _, err := certs.Item(&swapped, s); err == nil {
			t.Fatal("a key sealed for another row opened")
		}
		changed := *c
		changed.Chain = leaf.cert.Raw
		if _, err := certs.Item(&changed, s); err == nil {
			t.Fatal("a changed chain passed the content hash")
		}
		if _, err := certs.Item(c, sealer(t)); err == nil {
			t.Fatal("another KEK opened the key")
		}
	})
}

// TestCheckBundle: a CA bundle holds certificates only, at least one and at most MaxBundle; a
// self-signed server certificate counts.
func TestCheckBundle(t *testing.T) {
	root := ca(t, "root", nil)
	leaf := issue(t, leafTmpl("self.example.com"), ecKey(t), nil)
	if cs, err := certs.CheckBundle(pemOf(root, leaf)); err != nil || len(cs) != 2 {
		t.Fatalf("%d %v", len(cs), err)
	}
	many := make([]issued, certs.MaxBundle+1)
	for i := range many {
		many[i] = root
	}
	if cs, err := certs.CheckBundle(pemOf(many[:certs.MaxBundle]...)); err != nil || len(cs) != certs.MaxBundle {
		t.Fatalf("exactly %d: %d %v", certs.MaxBundle, len(cs), err)
	}
	for name, bundle := range map[string][]byte{
		"empty":      nil,
		"blank":      []byte("  \n"),
		"garbage":    []byte("not pem"),
		"a key":      keyPEM(t, root.key),
		"trailing":   append(pemOf(root), "x"...),
		"too many":   pemOf(many...),
		"unparsable": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
	} {
		if _, err := certs.CheckBundle(bundle); !errors.Is(err, certs.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}
