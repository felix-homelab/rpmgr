// SPDX-License-Identifier: Apache-2.0

package castore_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/pki"
)

const td = "rpmgr-7f3k2q6m"

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

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

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func connector(org, id string) pki.Identity {
	return pki.Identity{TrustDomain: td, Org: org, Kind: pki.KindConnector, ID: id}
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

// ca is a root, an intermediate and an Issuer on a settable clock.
type ca struct {
	root, inter pki.KeyPair
	is          *pki.Issuer
	now         time.Time
}

func (c *ca) leaf(t *testing.T, id pki.Identity) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := newKey(t)
	cert, err := c.is.IssueLeaf(csrFor(t, k, nil), id, pki.DefaultLeafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return cert, k
}
