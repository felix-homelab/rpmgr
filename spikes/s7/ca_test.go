// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"
)

// Criterion 1: issue and renew 7-day leaf certificates with new keys.
func TestLeafIssueAndRenew(t *testing.T) {
	clk := newClock()
	ca := newCA(t, clk)
	id := connectorID("org_a", "con_nas")
	t0 := clk.Now()

	// The CSR asks for other names; the CA ignores subject and SANs and assigns the identity.
	k1 := newKey(t)
	spoof, _ := url.Parse("spiffe://" + td + "/controller/ctl_1")
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "admin"}, DNSNames: []string{"evil.example"}, URIs: []*url.URL{spoof},
	}, k1)
	if err != nil {
		t.Fatal(err)
	}
	csr1, _ := x509.ParseCertificateRequest(der)
	c1, err := ca.Issue(csr1, id, ProfileConnector, AgentLeafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if !c1.NotBefore.Equal(t0.Add(-5*time.Minute)) || !c1.NotAfter.Equal(t0.Add(7*24*time.Hour)) {
		t.Fatalf("validity %v – %v", c1.NotBefore, c1.NotAfter)
	}
	if len(c1.URIs) != 1 || c1.URIs[0].String() != id.String() || !slices.Equal(c1.DNSNames, []string{"con_nas.connector." + td}) {
		t.Fatalf("SANs: URIs %v DNS %v", c1.URIs, c1.DNSNames)
	}
	if c1.Subject.CommonName != "" || c1.IsCA || c1.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("subject %q, IsCA %v, key usage %v", c1.Subject.CommonName, c1.IsCA, c1.KeyUsage)
	}
	if !slices.Equal(c1.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		t.Fatalf("EKU %v", c1.ExtKeyUsage)
	}
	if c1.SerialNumber.Sign() <= 0 || c1.SerialNumber.BitLen() > 128 {
		t.Fatalf("serial %v", c1.SerialNumber)
	}
	verify := func(c *x509.Certificate, at time.Time) error {
		inter := x509.NewCertPool()
		inter.AddCert(ca.Intermediate)
		_, err := c.Verify(x509.VerifyOptions{Roots: ca.Roots(), Intermediates: inter, CurrentTime: at,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		return err
	}
	if err := verify(c1, clk.Now()); err != nil {
		t.Fatal(err)
	}

	// Renewal at 50 % of the lifetime: new key, new serial, same identity.
	clk.Advance(AgentLeafLifetime / 2)
	k2 := newKey(t)
	c2, err := ca.Renew(c1, plainCSR(t, k2), ProfileConnector, AgentLeafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if c2.SerialNumber.Cmp(c1.SerialNumber) == 0 || c2.URIs[0].String() != c1.URIs[0].String() ||
		!slices.Equal(c2.DNSNames, c1.DNSNames) {
		t.Fatal("renewal changed the identity or kept the serial")
	}
	if c2.PublicKey.(*ecdsa.PublicKey).Equal(c1.PublicKey) {
		t.Fatal("renewal kept the key")
	}
	if !c2.NotBefore.Equal(clk.Now().Add(-Backdate)) {
		t.Fatalf("renewed NotBefore %v", c2.NotBefore)
	}
	if err := verify(c1, clk.Now()); err != nil {
		t.Fatalf("old certificate must stay valid until its NotAfter: %v", err)
	}
	if err := verify(c1, c1.NotAfter.Add(time.Second)); err == nil {
		t.Fatal("old certificate verified after NotAfter")
	}
	if err := verify(c2, c1.NotAfter.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	// Error cases.
	if _, err := ca.Renew(c2, plainCSR(t, k2), ProfileConnector, AgentLeafLifetime); !errors.Is(err, ErrSameKey) {
		t.Fatalf("renewal with the same key: %v", err)
	}
	other, err := NewCA(td, clk.Now, true)
	if err != nil {
		t.Fatal(err)
	}
	foreign := issue(t, other, id, ProfileConnector, AgentLeafLifetime)
	if _, err := ca.Renew(foreign.cert, plainCSR(t, newKey(t)), ProfileConnector, AgentLeafLifetime); !errors.Is(err, ErrUnknownCert) {
		t.Fatalf("renewal of a foreign certificate: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, rsaKey)
	rsaCSR, _ := x509.ParseCertificateRequest(rsaDER)
	if _, err := ca.Issue(rsaCSR, id, ProfileConnector, AgentLeafLifetime); !errors.Is(err, ErrBadCSR) {
		t.Fatalf("RSA CSR: %v", err)
	}
	bad := plainCSR(t, newKey(t))
	bad.Signature = slices.Clone(bad.Signature)
	bad.Signature[len(bad.Signature)-1] ^= 0xff
	if _, err := ca.Issue(bad, id, ProfileConnector, AgentLeafLifetime); !errors.Is(err, ErrBadCSR) {
		t.Fatalf("CSR with a broken signature: %v", err)
	}
	for _, lt := range []time.Duration{0, 23 * time.Hour, 31 * 24 * time.Hour} {
		if _, err := ca.Issue(plainCSR(t, newKey(t)), id, ProfileConnector, lt); !errors.Is(err, ErrLifetime) {
			t.Fatalf("lifetime %v: %v", lt, err)
		}
	}
	for _, lt := range []time.Duration{24 * time.Hour, 30 * 24 * time.Hour} {
		if _, err := ca.Issue(plainCSR(t, newKey(t)), id, ProfileConnector, lt); err != nil {
			t.Fatalf("lifetime %v: %v", lt, err)
		}
	}

	// Serials stay unique over many renewals.
	seen := map[string]bool{}
	cur := c2
	for i := 0; i < 200; i++ {
		next, err := ca.Renew(cur, plainCSR(t, newKey(t)), ProfileConnector, AgentLeafLifetime)
		if err != nil {
			t.Fatal(err)
		}
		if seen[next.SerialNumber.String()] {
			t.Fatal("serial reused")
		}
		seen[next.SerialNumber.String()] = true
		cur = next
	}
}

func TestProfilesAndControllerNames(t *testing.T) {
	clk := newClock()
	ca := newCA(t, clk)
	gs := issue(t, ca, gatewayID("org_a", "gw_1"), ProfileGatewayServer, AgentLeafLifetime)
	gc := issue(t, ca, gatewayID("org_a", "gw_1"), ProfileGatewayClient, AgentLeafLifetime)
	ctl := issue(t, ca, controllerID("node_1"), ProfileController, ControllerLifetime)
	if !slices.Equal(gs.cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) ||
		!slices.Equal(gc.cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Fatalf("gateway EKUs %v / %v", gs.cert.ExtKeyUsage, gc.cert.ExtKeyUsage)
	}
	want := []string{"node_1.controller." + td, "controller." + td, "reauth.controller." + td}
	if !slices.Equal(ctl.cert.DNSNames, want) || ctl.cert.NotAfter.Sub(clk.Now()) != ControllerLifetime {
		t.Fatalf("controller names %v, lifetime %v", ctl.cert.DNSNames, ctl.cert.NotAfter.Sub(clk.Now()))
	}
	// The intermediate's name constraints are marked critical (RFC 5280, 4.2.1.10).
	nc := asn1.ObjectIdentifier{2, 5, 29, 30}
	found := false
	for _, e := range ca.Intermediate.Extensions {
		if e.Id.Equal(nc) {
			found = e.Critical
		}
	}
	if !found || ca.Intermediate.MaxPathLen != 0 || !ca.Intermediate.MaxPathLenZero {
		t.Fatal("intermediate: name constraints not critical or pathlen not 0")
	}
}

func TestSelectPinnedRoot(t *testing.T) {
	clk := newClock()
	ca := newCA(t, clk)
	attacker, err := NewCA(td, clk.Now, true)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []*x509.Certificate{attacker.Root, ca.Intermediate, ca.Root}
	root, gotTD, err := SelectPinnedRoot(bundle, ca.RootPin())
	if err != nil || root != ca.Root || gotTD != td {
		t.Fatalf("root %v td %q err %v", root == ca.Root, gotTD, err)
	}
	if _, _, err := SelectPinnedRoot([]*x509.Certificate{attacker.Root, ca.Intermediate}, ca.RootPin()); !errors.Is(err, ErrPinNotFound) {
		t.Fatalf("missing pinned root: %v", err)
	}
	if _, _, err := SelectPinnedRoot(bundle, "sha256:"+ca.RootPin()[8:12]+"AAAA"); !errors.Is(err, ErrPinNotFound) {
		t.Fatalf("wrong pin: %v", err)
	}
	// Pinning the intermediate's key is refused: it is not an rpmgr root.
	other := &CA{Root: ca.Intermediate}
	if _, _, err := SelectPinnedRoot(bundle, other.RootPin()); err == nil {
		t.Fatal("intermediate accepted as root")
	}
}
