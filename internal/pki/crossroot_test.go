// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/pki"
)

// crossEnv is a root R1, a new root R2 and the request for R2's cross-certificate.
type crossEnv struct {
	r1, r2 pki.KeyPair
	csr    []byte
	now    time.Time
}

func newCrossEnv(t *testing.T) crossEnv {
	t.Helper()
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	r1, err := pki.NewRoot("rpmgr-7f3k2q6m", now)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := pki.NewRoot("rpmgr-7f3k2q6m", now)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.RequestFor(r2.Key)
	if err != nil {
		t.Fatal(err)
	}
	return crossEnv{r1: r1, r2: r2, csr: csr, now: now}
}

// TestCrossRoot: the cross-certificate has the new root's key, Subject and SubjectKeyId byte for
// byte, is signed by the old root, and passes the check an import makes.
func TestCrossRoot(t *testing.T) {
	e := newCrossEnv(t)
	x, err := pki.SignCrossRoot(e.r1, e.csr, e.now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x.RawSubject, e.r2.Cert.RawSubject) || !bytes.Equal(x.SubjectKeyId, e.r2.Cert.SubjectKeyId) ||
		!bytes.Equal(x.RawSubjectPublicKeyInfo, e.r2.Cert.RawSubjectPublicKeyInfo) || len(x.SubjectKeyId) == 0 {
		t.Fatal("X does not carry R2's subject, key id and key")
	}
	if err := pki.VerifyCrossRoot(x, e.r1.Cert, e.r2.Cert, e.now); err != nil {
		t.Fatalf("a good cross-certificate: %v", err)
	}
	if x.CheckSignatureFrom(e.r1.Cert) != nil || x.Equal(e.r2.Cert) || !x.IsCA || x.MaxPathLen != 1 {
		t.Fatal("X is not a CA of the old root with a path length of 1")
	}
	// X is how an agent learns R2, no link of a chain: R1 allows one intermediate.
	inter, err := pki.NewIntermediate(e.r2, e.now)
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueLeaf(t, inter, e.now)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: poolOf(e.r1.Cert), Intermediates: poolOf(inter.Cert, x), CurrentTime: e.now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err == nil {
		t.Fatal("leaf <- I2 <- X <- R1 verifies; the doc says it has too many intermediates")
	}
}

func TestSignCrossRootRefusals(t *testing.T) {
	e := newCrossEnv(t)
	selfCSR, err := pki.RequestFor(e.r1.Key)
	if err != nil {
		t.Fatal(err)
	}
	for name, csr := range map[string][]byte{"the old root's own key": selfCSR, "garbage": []byte("nothing"), "a certificate, not a request": e.r2.Cert.Raw} {
		if _, err := pki.SignCrossRoot(e.r1, csr, e.now); !errors.Is(err, pki.ErrBadCSR) {
			t.Errorf("signing a request with %s = %v, want ErrBadCSR", name, err)
		}
	}
}

// TestVerifyCrossRootRefusals: each premise of an import fails alone.
func TestVerifyCrossRootRefusals(t *testing.T) {
	e := newCrossEnv(t)
	good, err := pki.SignCrossRoot(e.r1, e.csr, e.now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := pki.NewRoot("rpmgr-7f3k2q6m", e.now)
	if err != nil {
		t.Fatal(err)
	}
	otherX, err := pki.SignCrossRoot(other, e.csr, e.now) // signed by a root that is not R1
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		x, root, r2 *x509.Certificate
		now         time.Time
	}{
		"another root signed it":      {otherX, e.r1.Cert, e.r2.Cert, e.now},
		"it is for another new root":  {good, e.r1.Cert, other.Cert, e.now},
		"not valid yet":               {good, e.r1.Cert, e.r2.Cert, e.now.Add(-time.Hour)},
		"expired":                     {good, e.r1.Cert, e.r2.Cert, good.NotAfter.Add(time.Second)},
		"the old root is no root":     {good, good, e.r2.Cert, e.now},
		"the new root has no key id":  {good, e.r1.Cert, withoutKeyID(e.r2.Cert), e.now},
		"the certificate is the root": {e.r2.Cert, e.r1.Cert, e.r2.Cert, e.now},
	} {
		if err := pki.VerifyCrossRoot(c.x, c.root, c.r2, c.now); err == nil {
			t.Errorf("accepted a cross-certificate when %s", name)
		}
	}
}

func withoutKeyID(c *x509.Certificate) *x509.Certificate {
	d := *c
	d.SubjectKeyId = nil
	return &d
}

// TestCrossSign: with the old root online, X and Y come from the same path as with it offline, and Y
// is an ordinary intermediate of the old root for the new intermediate's key.
func TestCrossSign(t *testing.T) {
	e := newCrossEnv(t)
	i2, err := pki.NewIntermediate(e.r2, e.now)
	if err != nil {
		t.Fatal(err)
	}
	x, y, err := pki.CrossSign(e.r1, e.r2.Key, i2.Key, e.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.VerifyCrossRoot(x, e.r1.Cert, e.r2.Cert, e.now); err != nil {
		t.Fatal(err)
	}
	if err := pki.VerifyIntermediate(y, e.r1.Cert, &i2.Key.PublicKey, e.now); err != nil {
		t.Fatal(err)
	}
	// leaf <- Y <- R1 and leaf <- I2 <- R2 both verify, with the same intermediate key.
	leaf := issueLeaf(t, i2, e.now)
	for name, c := range map[string]struct{ root, inter *x509.Certificate }{"Y under R1": {e.r1.Cert, y}, "I2 under R2": {e.r2.Cert, i2.Cert}} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(c.root), Intermediates: poolOf(c.inter), CurrentTime: e.now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestNewIssuerRoots: leaves of both roots verify, an intermediate that no root signed is refused.
func TestNewIssuerRoots(t *testing.T) {
	e := newCrossEnv(t)
	i1, _ := pki.NewIntermediate(e.r1, e.now)
	i2, _ := pki.NewIntermediate(e.r2, e.now)
	stray, _ := pki.NewRoot("rpmgr-7f3k2q6m", e.now)
	strayInter, _ := pki.NewIntermediate(stray, e.now)
	clock := func() time.Time { return e.now }
	is, err := pki.NewIssuerRoots([]*x509.Certificate{e.r2.Cert, e.r1.Cert}, i2, clock, nil, i1.Cert)
	if err != nil {
		t.Fatal(err)
	}
	for name, inter := range map[string]pki.KeyPair{"R1's leaf": i1, "R2's leaf": i2} {
		if _, err := is.IdentityOf(issueLeaf(t, inter, e.now), e.now); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := pki.NewIssuerRoots([]*x509.Certificate{e.r2.Cert, e.r1.Cert}, i2, clock, nil, strayInter.Cert); err == nil {
		t.Error("an intermediate no root signed was taken")
	}
	if _, err := pki.NewIssuerRoots([]*x509.Certificate{e.r2.Cert}, i1, clock, nil); err == nil {
		t.Error("an issuing intermediate that the issuing root did not sign was taken")
	}
	if _, err := pki.NewIssuerRoots(nil, i2, clock, nil); err == nil {
		t.Error("an issuer without a root")
	}
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// issueLeaf makes a connector leaf under inter's key.
func issueLeaf(t *testing.T, inter pki.KeyPair, now time.Time) *x509.Certificate {
	t.Helper()
	key := newKey(t)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), NotBefore: now.Add(-pki.Backdate), NotAfter: now.Add(pki.DefaultLeafLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{connector(orgA, con1).SPIFFE()}, DNSNames: connector(orgA, con1).DNSNames(),
	}, inter.Cert, &key.PublicKey, inter.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
