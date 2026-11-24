// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/pki"
)

func newRootPair(t *testing.T) pki.KeyPair {
	t.Helper()
	r, err := pki.NewRoot(td, t0)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newRoot(t *testing.T) *x509.Certificate { return newRootPair(t).Cert }

// crossCert is a certificate for newer's key and subject that older signs.
func crossCert(t *testing.T, older pki.KeyPair, newer *x509.Certificate) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: serial(), Subject: newer.Subject, SubjectKeyId: newer.SubjectKeyId,
		NotBefore: t0, NotAfter: t0.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, URIs: newer.URIs}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, older.Cert, newer.PublicKey, older.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestRootsDigest: the digest is the SHA-256 of length-prefixed DER in the order of the public key
// hashes, whatever order the roots come in; cross-certificates do not count; another set of roots
// has another digest.
func TestRootsDigest(t *testing.T) {
	k1 := newRootPair(t)
	r1, r2 := k1.Cert, newRoot(t)
	sorted := []*x509.Certificate{r1, r2}
	slices.SortFunc(sorted, func(a, b *x509.Certificate) int {
		ka, kb := sha256.Sum256(a.RawSubjectPublicKeyInfo), sha256.Sum256(b.RawSubjectPublicKeyInfo)
		return bytes.Compare(ka[:], kb[:])
	})
	h := sha256.New()
	for _, r := range sorted {
		h.Write(binary.AppendUvarint(nil, uint64(len(r.Raw))))
		h.Write(r.Raw)
	}
	want := h.Sum(nil)

	if got := pki.RootsDigest([]*x509.Certificate{r1, r2}); !bytes.Equal(got, want) || len(got) != pki.RootsDigestSize {
		t.Errorf("digest %x, want %x", got, want)
	}
	if got := pki.RootsDigest([]*x509.Certificate{r2, r1}); !bytes.Equal(got, want) {
		t.Error("the digest depends on the order of the roots")
	}
	x := crossCert(t, k1, r2)
	if got := pki.RootsDigest([]*x509.Certificate{r1, r2, x}); !bytes.Equal(got, want) {
		t.Error("a cross-certificate changed the digest")
	}
	if bytes.Equal(pki.RootsDigest([]*x509.Certificate{r1}), want) {
		t.Error("one root and two have the same digest")
	}
	if bytes.Equal(pki.RootsDigest(nil), pki.RootsDigest([]*x509.Certificate{r1})) {
		t.Error("no root and one root have the same digest")
	}
}

// TestTrustRootsDER: the roots first, the cross-certificates after them, each group by the hash of
// its public key; the limits refuse a bundle past them.
func TestTrustRootsDER(t *testing.T) {
	k1 := newRootPair(t)
	r2 := newRoot(t)
	x := crossCert(t, k1, r2)

	got, err := pki.TrustRootsDER([]*x509.Certificate{x, r2, k1.Cert})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !bytes.Equal(got[2], x.Raw) {
		t.Fatalf("got %d certificates; the cross-certificate must come last", len(got))
	}
	again, _ := pki.TrustRootsDER([]*x509.Certificate{k1.Cert, x, r2})
	if !slices.EqualFunc(got, again, bytes.Equal) {
		t.Error("the order depends on the order of the bundle")
	}

	var five []*x509.Certificate
	for range pki.MaxTrustRoots + 1 {
		five = append(five, newRoot(t))
	}
	for name, bundle := range map[string][]*x509.Certificate{
		"empty":           nil,
		"cross only":      {x},
		"five roots":      five,
		"nine in all":     append(five[:4:4], x, x, x, x, x),
		"a large root":    {bigRoot(t)},
		"duplicate roots": {k1.Cert, k1.Cert, k1.Cert, k1.Cert, k1.Cert},
	} {
		if _, err := pki.TrustRootsDER(bundle); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// Exactly at the limits: 4 roots and 4 cross-certificates, each below 2 KiB.
	if _, err := pki.TrustRootsDER(append(five[:4:4], x, x, x, x)); err != nil {
		t.Errorf("at the limits: %v", err)
	}
}

// bigRoot is a self-signed certificate above the size limit of one trust certificate.
func bigRoot(t *testing.T) *x509.Certificate {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: serial(), Subject: newRoot(t).Subject, NotBefore: t0, NotAfter: t0.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, DNSNames: []string{strings.Repeat("a", 60) + ".example"}}
	for len(tmpl.DNSNames) < 40 {
		tmpl.DNSNames = append(tmpl.DNSNames, strings.Repeat("b", 60)+string(rune('a'+len(tmpl.DNSNames)%26))+".example")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Raw) <= pki.MaxTrustCertBytes {
		t.Fatalf("the test certificate has only %d bytes", len(c.Raw))
	}
	return c
}
