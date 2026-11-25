// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Certificates under which no real leaf of the CA verifies must not be imported, and the probe
// must catch what the field checks do not.
func TestVerifyIntermediateRefusesWhatNoLeafSurvives(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	const td = "rpmgr-7f3k2q6m"
	root, err := NewRoot(td, now)
	if err != nil {
		t.Fatal(err)
	}
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/8")
	for name, m := range map[string]func(*x509.Certificate){
		"EKU serverAuth only": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"EKU codeSigning":     func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning} },
		"unknown critical extension": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{5, 0}}}
		},
		"extra key usages":    func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment },
		"no CRL sign":         func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCertSign },
		"permitted IP range":  func(c *x509.Certificate) { c.PermittedIPRanges = []*net.IPNet{ipnet} },
		"excluded IP range":   func(c *x509.Certificate) { c.ExcludedIPRanges = []*net.IPNet{ipnet} },
		"permitted email":     func(c *x509.Certificate) { c.PermittedEmailAddresses = []string{"example.com"} },
		"excluded email":      func(c *x509.Certificate) { c.ExcludedEmailAddresses = []string{"example.com"} },
		"excluded URI domain": func(c *x509.Certificate) { c.ExcludedURIDomains = []string{"bad." + td} },
		"excluded DNS domain": func(c *x509.Certificate) { c.ExcludedDNSDomains = []string{"bad." + td} },
	} {
		t.Run(name, func(t *testing.T) {
			key, _ := NewKey()
			tmpl := intermediateTemplate(td, root.Cert, now)
			m(tmpl)
			cert, err := create(tmpl, root.Cert, &key.PublicKey, root.Key)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyIntermediate(cert, root.Cert, &key.PublicKey, now); !errors.Is(err, ErrIntermediateRefused) {
				t.Fatalf("VerifyIntermediate = %v, want a refusal", err)
			}
		})
	}
}

// probe is the last line of defence, so it is tested alone with certificates built by hand, as the
// field checks do not reach it for these.
func TestProbe(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	const td = "rpmgr-7f3k2q6m"
	good := func() *x509.Certificate {
		return &x509.Certificate{
			Subject: pkix.Name{CommonName: "x"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
			PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{td}, PermittedURIDomains: []string{td},
		}
	}
	if err := probe(good(), td, now); err != nil {
		t.Fatalf("probe of a good certificate: %v", err)
	}
	for name, tc := range map[string]struct {
		m    func(*x509.Certificate)
		want string
	}{
		"no constraints": {func(c *x509.Certificate) { c.PermittedDNSDomains, c.PermittedURIDomains = nil, nil }, "another domain"},
		"wide constraints": {func(c *x509.Certificate) {
			c.PermittedURIDomains = []string{td, "other.example", "probe-" + td}
		}, "another domain"},
		"other domain": {func(c *x509.Certificate) { c.PermittedURIDomains = []string{"rpmgr-other222"} }, "does not verify"},
		"serverAuth only": {func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}, "does not verify"},
		"codeSigning only": {func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		}, "does not verify"},
		"not valid at now": {func(c *x509.Certificate) { c.NotAfter = now.Add(-time.Minute) }, "does not verify"},
	} {
		t.Run(name, func(t *testing.T) {
			c := good()
			tc.m(c)
			if err := probe(c, td, now); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("probe = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
