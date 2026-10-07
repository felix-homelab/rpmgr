// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

const td = "rpmgr-7f3k2q6m"

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// ca is a root, an intermediate and an Issuer on a settable clock.
type ca struct {
	root, inter pki.KeyPair
	is          *pki.Issuer
	now         time.Time
}

func newCA(t *testing.T, trustDomain string) *ca {
	t.Helper()
	c := &ca{now: t0}
	var err error
	if c.root, err = pki.NewRoot(trustDomain, t0); err != nil {
		t.Fatal(err)
	}
	if c.inter, err = pki.NewIntermediate(c.root, t0); err != nil {
		t.Fatal(err)
	}
	if c.is, err = pki.NewIssuer(c.root.Cert, c.inter, func() time.Time { return c.now }); err != nil {
		t.Fatal(err)
	}
	return c
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func csrFor(t *testing.T, key any, tmpl *x509.CertificateRequest) *x509.CertificateRequest {
	t.Helper()
	if tmpl == nil {
		tmpl = &x509.CertificateRequest{}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func connector(org, id string) pki.Identity {
	return pki.Identity{TrustDomain: td, Org: org, Kind: pki.KindConnector, ID: id}
}

var (
	orgA = ids.New("org")
	con1 = ids.New("con")
	gw1  = ids.New("gw")
	ctn1 = ids.New("ctn")
)

func (c *ca) leaf(t *testing.T, id pki.Identity) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := newKey(t)
	cert, err := c.is.IssueLeaf(csrFor(t, k, nil), id, pki.DefaultLeafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return cert, k
}

func TestIdentityNames(t *testing.T) {
	cases := []struct {
		id        pki.Identity
		uri       string
		dnsNames  []string
		parseable bool
	}{
		{connector(orgA, con1), "spiffe://" + td + "/org/" + orgA + "/connector/" + con1, []string{con1 + ".connector." + td}, true},
		{pki.Identity{TrustDomain: td, Org: orgA, Kind: pki.KindGateway, ID: gw1}, "spiffe://" + td + "/org/" + orgA + "/gateway/" + gw1, []string{gw1 + ".gateway." + td}, true},
		{pki.Identity{TrustDomain: td, Kind: pki.KindController, ID: ctn1}, "spiffe://" + td + "/controller/" + ctn1,
			[]string{ctn1 + ".controller." + td, "controller." + td, "reauth.controller." + td}, true},
	}
	for _, c := range cases {
		if got := c.id.String(); got != c.uri {
			t.Errorf("SPIFFE ID %s, want %s", got, c.uri)
		}
		if !slices.Equal(c.id.DNSNames(), c.dnsNames) {
			t.Errorf("DNS names %v, want %v", c.id.DNSNames(), c.dnsNames)
		}
		got, err := pki.ParseSPIFFE(c.id.SPIFFE(), td)
		if err != nil || got != c.id {
			t.Errorf("ParseSPIFFE(%s) = %+v, %v", c.uri, got, err)
		}
	}
}

func TestParseSPIFFE_Strict(t *testing.T) {
	base := "spiffe://" + td + "/org/" + orgA + "/connector/" + con1
	bad := map[string]string{
		"other trust domain":      "spiffe://rpmgr-aaaaaaaa/org/" + orgA + "/connector/" + con1,
		"sub-domain":              "spiffe://evil." + td + "/org/" + orgA + "/connector/" + con1,
		"upper-case host":         "spiffe://" + strings.ToUpper(td) + "/org/" + orgA + "/connector/" + con1,
		"scheme":                  "https://" + td + "/org/" + orgA + "/connector/" + con1,
		"user info":               "spiffe://u@" + td + "/org/" + orgA + "/connector/" + con1,
		"port":                    "spiffe://" + td + ":443/org/" + orgA + "/connector/" + con1,
		"query":                   base + "?x=1",
		"empty query":             base + "?",
		"fragment":                base + "#x",
		"escaped slash":           "spiffe://" + td + "/org/" + orgA + "%2Fconnector/" + con1,
		"empty segment":           "spiffe://" + td + "/org//connector/" + con1,
		"dot-dot":                 "spiffe://" + td + "/org/" + orgA + "/connector/../" + con1,
		"extra segment":           base + "/x",
		"trailing slash":          base + "/",
		"unknown kind":            "spiffe://" + td + "/org/" + orgA + "/user/" + con1,
		"gateway ID as connector": "spiffe://" + td + "/org/" + orgA + "/connector/" + gw1,
		"connector ID in org":     "spiffe://" + td + "/org/" + con1 + "/connector/" + con1,
		"controller with org":     "spiffe://" + td + "/org/" + orgA + "/controller/" + ctn1,
		"controller with con ID":  "spiffe://" + td + "/controller/" + con1,
		"config-signing key":      pki.SignerURI(td, pki.PurposeConfigSigning).String(),
		"audit-checkpoint key":    pki.SignerURI(td, pki.PurposeAuditCheckpoint).String(),
		"trust domain only":       "spiffe://" + td,
	}
	for name, raw := range bad {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if id, err := pki.ParseSPIFFE(u, td); !errors.Is(err, pki.ErrNotIdentity) {
			t.Errorf("%s: %+v, %v; want ErrNotIdentity", name, id, err)
		}
	}
	if _, err := pki.ParseSPIFFE(nil, td); err == nil {
		t.Error("nil URI accepted")
	}
}

func TestTrustDomain(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		d, err := pki.NewTrustDomain()
		if err != nil {
			t.Fatal(err)
		}
		if !pki.ValidTrustDomain(d) {
			t.Fatalf("generated %q is not valid", d)
		}
		seen[d] = true
	}
	if len(seen) < 999 { // 40 bits: a collision among 1000 has probability below 1e-6
		t.Fatalf("only %d distinct trust domains of 1000", len(seen))
	}
	for _, d := range []string{"", "rpmgr-", "rpmgr-abcdefg", "rpmgr-abcdefghi", "rpmgr-ABCDEFGH", "rpmgr-abcdefg1", "rpmgr-abcdefg8", "xrpmgr-abcdefgh", "rpmgr-abcdefgh.example"} {
		if pki.ValidTrustDomain(d) {
			t.Errorf("%q accepted", d)
		}
	}
}

func TestRootAndIntermediate(t *testing.T) {
	c := newCA(t, td)
	r, i := c.root.Cert, c.inter.Cert
	if !r.IsCA || r.MaxPathLen != 1 || !r.NotAfter.Equal(t0.Add(pki.RootLifetime)) || !r.NotBefore.Equal(t0.Add(-pki.Backdate)) {
		t.Errorf("root: CA %v, path length %d, validity %v – %v", r.IsCA, r.MaxPathLen, r.NotBefore, r.NotAfter)
	}
	if got, err := pki.TrustDomainOf(r); err != nil || got != td {
		t.Errorf("trust domain of the root: %q, %v", got, err)
	}
	if !i.IsCA || i.MaxPathLen != 0 || !i.MaxPathLenZero || !i.PermittedDNSDomainsCritical ||
		!slices.Equal(i.PermittedDNSDomains, []string{td}) || !slices.Equal(i.PermittedURIDomains, []string{td}) {
		t.Errorf("intermediate: path length %d, constraints %v %v critical %v", i.MaxPathLen, i.PermittedDNSDomains, i.PermittedURIDomains, i.PermittedDNSDomainsCritical)
	}
	if !i.NotAfter.Equal(t0.Add(pki.IntermediateLifetime)) || i.CheckSignatureFrom(r) != nil {
		t.Errorf("intermediate validity %v, or not signed by the root", i.NotAfter)
	}
	// An intermediate created near the root's end does not outlive it.
	late, err := pki.NewIntermediate(c.root, r.NotAfter.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !late.Cert.NotAfter.Equal(r.NotAfter) {
		t.Errorf("late intermediate ends %v, after the root's %v", late.Cert.NotAfter, r.NotAfter)
	}
	if _, err := pki.NewRoot("example.com", t0); err == nil {
		t.Error("a root for a name that is no trust domain")
	}
	if _, err := pki.NewIntermediate(c.inter, t0); err == nil {
		t.Error("an intermediate under an intermediate")
	}
}

func TestNewIssuer_Refusals(t *testing.T) {
	c := newCA(t, td)
	other := newCA(t, td)
	now := func() time.Time { return t0 }
	if _, err := pki.NewIssuer(c.root.Cert, pki.KeyPair{Cert: c.inter.Cert, Key: other.inter.Key}, now); err == nil {
		t.Error("an intermediate with another key")
	}
	if _, err := pki.NewIssuer(c.root.Cert, other.inter, now); err == nil {
		t.Error("an intermediate of another root")
	}
	if _, err := pki.NewIssuer(c.root.Cert, c.inter, now, other.inter.Cert); err == nil {
		t.Error("an older intermediate of another root")
	}
	unconstrained := forgeCA(t, c.root)
	if _, err := pki.NewIssuer(c.root.Cert, unconstrained, now); err == nil {
		t.Error("an intermediate without name constraints")
	}
	if _, err := pki.NewIssuer(c.inter.Cert, c.inter, now); err == nil {
		t.Error("an intermediate as root")
	}
}

// forgeCA signs an intermediate without name constraints under root.
func forgeCA(t *testing.T, root pki.KeyPair) pki.KeyPair {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "unconstrained"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(pki.IntermediateLifetime), IsCA: true,
		BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Cert, &k.PublicKey, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pki.KeyPair{Cert: cert, Key: k}
}

var serialN int64 = 1000

func serial() *big.Int {
	serialN++
	return big.NewInt(serialN)
}

// TestIssueLeaf: the CA assigns the identity and ignores what the CSR asks for; it refuses keys
// other than P-256, broken CSRs, lifetimes outside 1–30 days and identities of another domain.
func TestIssueLeaf(t *testing.T) {
	c := newCA(t, td)
	id := connector(orgA, con1)
	k := newKey(t)
	spoof, _ := url.Parse("spiffe://" + td + "/controller/" + ctn1)
	csr := csrFor(t, k, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "admin"},
		DNSNames: []string{"evil.example", "controller." + td}, URIs: []*url.URL{spoof}})
	cert, err := c.is.IssueLeaf(csr, id, pki.DefaultLeafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != id.String() || !slices.Equal(cert.DNSNames, id.DNSNames()) ||
		cert.Subject.CommonName != "" {
		t.Fatalf("CSR names leaked into the certificate: URIs %v, DNS %v, CN %q", cert.URIs, cert.DNSNames, cert.Subject.CommonName)
	}
	if !cert.NotBefore.Equal(t0.Add(-pki.Backdate)) || !cert.NotAfter.Equal(t0.Add(pki.DefaultLeafLifetime)) {
		t.Errorf("validity %v – %v", cert.NotBefore, cert.NotAfter)
	}
	if cert.IsCA || cert.KeyUsage != x509.KeyUsageDigitalSignature ||
		!slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		t.Errorf("CA %v, key usage %v, EKU %v", cert.IsCA, cert.KeyUsage, cert.ExtKeyUsage)
	}
	if cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 128 {
		t.Errorf("serial %v", cert.SerialNumber)
	}
	if got, err := c.is.IdentityOf(cert, t0); err != nil || got != id {
		t.Errorf("IdentityOf: %+v, %v", got, err)
	}
	ctl := pki.Identity{TrustDomain: td, Kind: pki.KindController, ID: ctn1}
	node, err := c.is.IssueLeaf(csrFor(t, newKey(t), nil), ctl, pki.ControllerLifetime)
	if err != nil || !slices.Contains(node.DNSNames, "reauth.controller."+td) {
		t.Fatalf("controller node certificate: %v, %v", node, err)
	}

	for _, lt := range []time.Duration{0, 23 * time.Hour, 31 * 24 * time.Hour} {
		if _, err := c.is.IssueLeaf(csrFor(t, newKey(t), nil), id, lt); !errors.Is(err, pki.ErrLifetime) {
			t.Errorf("lifetime %v: %v, want ErrLifetime", lt, err)
		}
	}
	for _, lt := range []time.Duration{pki.MinLeafLifetime, pki.MaxLeafLifetime} {
		if _, err := c.is.IssueLeaf(csrFor(t, newKey(t), nil), id, lt); err != nil {
			t.Errorf("lifetime %v: %v", lt, err)
		}
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	broken := csrFor(t, newKey(t), nil)
	broken.Signature = slices.Clone(broken.Signature)
	broken.Signature[len(broken.Signature)-1] ^= 0xff
	for name, csr := range map[string]*x509.CertificateRequest{
		"RSA key": csrFor(t, rsaKey, nil), "P-384 key": csrFor(t, p384, nil), "broken signature": broken, "no CSR": nil,
	} {
		if _, err := c.is.IssueLeaf(csr, id, pki.DefaultLeafLifetime); !errors.Is(err, pki.ErrBadCSR) {
			t.Errorf("%s: %v, want ErrBadCSR", name, err)
		}
	}
	for name, bad := range map[string]pki.Identity{
		"other trust domain": {TrustDomain: "rpmgr-aaaaaaaa", Org: orgA, Kind: pki.KindConnector, ID: con1},
		"bad ID":             connector(orgA, "con_1"),
		"bad org":            connector("org_a", con1),
		"unknown kind":       {TrustDomain: td, Org: orgA, Kind: "user", ID: con1},
		"node with org":      {TrustDomain: td, Org: orgA, Kind: pki.KindController, ID: ctn1},
	} {
		if _, err := c.is.IssueLeaf(csrFor(t, newKey(t), nil), bad, pki.DefaultLeafLifetime); err == nil {
			t.Errorf("%s: issued", name)
		}
	}
}

func TestIssueLeaf_CappedAtIntermediate(t *testing.T) {
	c := newCA(t, td)
	c.now = c.inter.Cert.NotAfter.Add(-48 * time.Hour)
	cert, _ := c.leaf(t, connector(orgA, con1))
	if !cert.NotAfter.Equal(c.inter.Cert.NotAfter) {
		t.Fatalf("leaf ends %v, after its intermediate's %v", cert.NotAfter, c.inter.Cert.NotAfter)
	}
}

// TestRenewLeaf: a renewal keeps the identity, needs a new key and a certificate of this CA, works
// for an expired certificate, and never reuses a serial over 200 renewals.
func TestRenewLeaf(t *testing.T) {
	c := newCA(t, td)
	id := connector(orgA, con1)
	c1, k1 := c.leaf(t, id)
	c.now = t0.Add(pki.DefaultLeafLifetime / 2)
	c2, err := c.is.RenewLeaf(c1, csrFor(t, newKey(t), nil), pki.DefaultLeafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if c2.SerialNumber.Cmp(c1.SerialNumber) == 0 || c2.URIs[0].String() != id.String() ||
		c2.PublicKey.(*ecdsa.PublicKey).Equal(c1.PublicKey) {
		t.Fatal("the renewal kept the serial or the key, or changed the identity")
	}
	if _, err := c.is.RenewLeaf(c1, csrFor(t, k1, nil), pki.DefaultLeafLifetime); !errors.Is(err, pki.ErrSameKey) {
		t.Errorf("renewal with the same key: %v, want ErrSameKey", err)
	}
	foreign, _ := newCA(t, td).leaf(t, id)
	if _, err := c.is.RenewLeaf(foreign, csrFor(t, newKey(t), nil), pki.DefaultLeafLifetime); !errors.Is(err, pki.ErrNotIssued) {
		t.Errorf("renewal of another CA's certificate: %v, want ErrNotIssued", err)
	}
	signer, err := c.is.IssueSigner(&newKey(t).PublicKey, pki.PurposeConfigSigning)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.is.RenewLeaf(signer, csrFor(t, newKey(t), nil), pki.DefaultLeafLifetime); err == nil {
		t.Error("a signing certificate was renewed as a leaf")
	}
	c.now = c1.NotAfter.Add(20 * 24 * time.Hour) // expired: Reauth decides on the grace period
	if _, err := c.is.RenewLeaf(c1, csrFor(t, newKey(t), nil), pki.DefaultLeafLifetime); err != nil {
		t.Errorf("renewal of an expired certificate: %v", err)
	}
	seen := map[string]bool{c1.SerialNumber.String(): true, c2.SerialNumber.String(): true}
	cur := c2
	for i := 0; i < 200; i++ {
		next, err := c.is.RenewLeaf(cur, csrFor(t, newKey(t), nil), pki.DefaultLeafLifetime)
		if err != nil {
			t.Fatal(err)
		}
		if seen[next.SerialNumber.String()] {
			t.Fatalf("serial reused after %d renewals", i)
		}
		seen[next.SerialNumber.String()] = true
		cur = next
	}
}

// TestNameConstraints: leaves forged with the intermediate's key, bypassing IssueLeaf, are refused
// by Go's verifier when their names leave the trust domain, and by ParseSPIFFE when the verifier
// admits a name that is not exactly an identity.
func TestNameConstraints(t *testing.T) {
	c := newCA(t, td)
	good := connector(orgA, con1)
	cases := []struct {
		name       string
		uris, dns  []string
		x509OK     bool
		identityOK bool
	}{
		{"in the domain", []string{good.String()}, good.DNSNames(), true, true},
		{"URI in another trust domain", []string{"spiffe://rpmgr-aaaaaaaa/org/" + orgA + "/connector/" + con1}, good.DNSNames(), false, false},
		{"URI host with the domain as a non-label suffix", []string{"spiffe://x" + td + "/org/" + orgA + "/connector/" + con1}, nil, false, false},
		{"URI host a sub-domain", []string{"spiffe://evil." + td + "/org/" + orgA + "/connector/" + con1}, nil, true, false},
		{"URI host in upper case", []string{"spiffe://" + strings.ToUpper(td) + "/org/" + orgA + "/connector/" + con1}, nil, true, false},
		{"URI with an empty host", []string{"spiffe:///org/" + orgA + "/connector/" + con1}, nil, false, false},
		{"URI with an IP host", []string{"spiffe://127.0.0.1/org/" + orgA + "/connector/" + con1}, nil, false, false},
		{"DNS name in another domain", []string{good.String()}, []string{con1 + ".connector.rpmgr-aaaaaaaa"}, false, true},
		{"DNS name with the domain as a non-label suffix", []string{good.String()}, []string{con1 + ".connector.x" + td}, false, true},
		{"no SAN", nil, nil, true, false},
		{"two URI SANs", []string{good.String(), "spiffe://" + td + "/controller/" + ctn1}, nil, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := forgeLeaf(t, c.inter, tc.uris, tc.dns)
			_, idErr := c.is.IdentityOf(cert, t0)
			var cie x509.CertificateInvalidError
			x509Refused := errors.As(idErr, &cie) && cie.Reason == x509.CANotAuthorizedForThisName
			if x509Refused == tc.x509OK {
				t.Fatalf("name constraints: %v, want accepted=%v", idErr, tc.x509OK)
			}
			if (idErr == nil) != (tc.x509OK && tc.identityOK) {
				t.Fatalf("IdentityOf: %v", idErr)
			}
		})
	}
}

// forgeLeaf signs a leaf with arbitrary names with the intermediate's key: what a bug in issuance
// or a stolen intermediate key could produce.
func forgeLeaf(t *testing.T, inter pki.KeyPair, uris, dns []string) *x509.Certificate {
	t.Helper()
	cert, _ := forgeLeafWithKey(t, inter, uris, dns)
	return cert
}

// forgeLeafWithKey is forgeLeaf, and also returns the leaf's key.
func forgeLeafWithKey(t *testing.T, inter pki.KeyPair, uris, dns []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: serial(), NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dns,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, inter.Cert, &k.PublicKey, inter.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, k
}

// TestSigner: a signing certificate verifies only for its purpose, chained to the pinned root; a
// TLS leaf is no signer, and a signer is no TLS identity.
func TestSigner(t *testing.T) {
	c := newCA(t, td)
	cert, err := c.is.IssueSigner(&newKey(t).PublicKey, pki.PurposeConfigSigning)
	if err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{c.inter.Cert}
	if err := pki.VerifySigner(cert, chain, c.root.Cert, pki.PurposeConfigSigning, t0); err != nil {
		t.Fatal(err)
	}
	if len(cert.ExtKeyUsage) != 0 || !cert.NotAfter.Equal(t0.Add(pki.SignerLifetime)) {
		t.Errorf("EKU %v, NotAfter %v", cert.ExtKeyUsage, cert.NotAfter)
	}
	if err := pki.VerifySigner(cert, chain, c.root.Cert, pki.PurposeAuditCheckpoint, t0); err == nil {
		t.Error("a config-signing certificate verified as audit-checkpoint key")
	}
	if err := pki.VerifySigner(cert, chain, c.root.Cert, pki.PurposeConfigSigning, cert.NotAfter.Add(time.Second)); err == nil {
		t.Error("an expired signing certificate verified")
	}
	other := newCA(t, td)
	if err := pki.VerifySigner(cert, chain, other.root.Cert, pki.PurposeConfigSigning, t0); err == nil {
		t.Error("a signing certificate verified under another root")
	}
	if err := pki.VerifySigner(cert, nil, c.root.Cert, pki.PurposeConfigSigning, t0); err == nil {
		t.Error("a signing certificate verified without its intermediate")
	}
	leaf, _ := c.leaf(t, pki.Identity{TrustDomain: td, Kind: pki.KindController, ID: ctn1})
	if err := pki.VerifySigner(leaf, chain, c.root.Cert, pki.PurposeConfigSigning, t0); err == nil {
		t.Error("a TLS leaf verified as signing certificate")
	}
	forged := forgeLeaf(t, c.inter, []string{pki.SignerURI(td, pki.PurposeConfigSigning).String()}, nil)
	if err := pki.VerifySigner(forged, chain, c.root.Cert, pki.PurposeConfigSigning, t0); err == nil {
		t.Error("a signing certificate with TLS EKUs verified")
	}
	if _, err := c.is.IdentityOf(cert, t0); !errors.Is(err, pki.ErrNotIdentity) {
		t.Errorf("a signing certificate as TLS identity: %v, want ErrNotIdentity", err)
	}
	if _, err := c.is.IssueSigner(&newKey(t).PublicKey, "release"); err == nil {
		t.Error("a signing certificate for an unknown purpose")
	}
	if _, err := c.is.IssueSigner(nil, pki.PurposeAuditCheckpoint); err == nil {
		t.Error("a signing certificate without a key")
	}
}

func TestSelectPinnedRoot(t *testing.T) {
	c := newCA(t, td)
	attacker := newCA(t, td)
	bundle := []*x509.Certificate{attacker.root.Cert, c.inter.Cert, c.root.Cert}
	root, gotTD, err := pki.SelectPinnedRoot(bundle, pki.RootPin(c.root.Cert))
	if err != nil || root != c.root.Cert || gotTD != td {
		t.Fatalf("selected the pinned root: %v, %q, %v", root == c.root.Cert, gotTD, err)
	}
	if _, _, err := pki.SelectPinnedRoot(bundle[:2], pki.RootPin(c.root.Cert)); !errors.Is(err, pki.ErrPinNotFound) {
		t.Errorf("bundle without the pinned root: %v, want ErrPinNotFound", err)
	}
	if _, _, err := pki.SelectPinnedRoot(bundle, pki.RootPin(c.inter.Cert)); err == nil || errors.Is(err, pki.ErrPinNotFound) {
		t.Errorf("pin of the intermediate: %v, want a refusal of a non-root", err)
	}
	pin := pki.RootPin(c.root.Cert)
	for _, bad := range []string{"", pin[7:], "sha1:" + pin[7:], pin[:len(pin)-4], pin + "=", "sha256:" + strings.Repeat("A", 43) + "B"} {
		if pki.ValidPin(bad) {
			t.Errorf("pin %q has a valid form", bad)
		}
		if _, _, err := pki.SelectPinnedRoot(bundle, bad); err == nil {
			t.Errorf("pin %q selected a root", bad)
		}
	}
	unknown := "sha256:" + strings.Repeat("A", 43) + "="
	if _, _, err := pki.SelectPinnedRoot(bundle, unknown); !pki.ValidPin(unknown) || !errors.Is(err, pki.ErrPinNotFound) {
		t.Errorf("well-formed unknown pin: %v, want ErrPinNotFound", err)
	}
}
