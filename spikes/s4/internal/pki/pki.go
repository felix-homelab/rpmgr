// SPDX-License-Identifier: Apache-2.0

// Package pki builds a throw-away test CA in the shape of docs/04-security.md, "PKI and identity":
// a P-256 root carrying the trust domain as its URI SAN, one issuing intermediate, and leaf
// certificates with a SPIFFE URI SAN and the DNS SAN derived from it. Spike S4 needs it only to
// run mutual TLS without InsecureSkipVerify; spike S7 tests the PKI itself.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// CA is a root plus one issuing intermediate for one trust domain.
type CA struct {
	TrustDomain string
	Root        *x509.Certificate
	Roots       *x509.CertPool
	inter       *x509.Certificate
	interKey    *ecdsa.PrivateKey
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}

// NewCA creates the root and the intermediate for td.
func NewCA(td string) (*CA, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tdURI := &url.URL{Scheme: "spiffe", Host: td}
	rootTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "rpmgr root " + td},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		URIs:                  []*url.URL{tdURI},
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "rpmgr issuing " + td},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		PermittedDNSDomains:   []string{td},
		PermittedURIDomains:   []string{td},
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &CA{TrustDomain: td, Root: root, Roots: pool, inter: inter, interKey: interKey}, nil
}

// Leaf issues a 7-day certificate for the SPIFFE path (e.g. "/controller/n1") with the given DNS
// names and returns it as a tls.Certificate whose chain includes the intermediate.
func (ca *CA) Leaf(path string, dnsNames []string, server, client bool) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	var eku []x509.ExtKeyUsage
	if server {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	if client {
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		DNSNames:     dnsNames,
		URIs:         []*url.URL{{Scheme: "spiffe", Host: ca.TrustDomain, Path: path}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.inter, &key.PublicKey, ca.interKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.inter.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// SPIFFEID returns the single SPIFFE URI SAN of cert if it belongs to td.
func SPIFFEID(cert *x509.Certificate, td string) (*url.URL, error) {
	if len(cert.URIs) != 1 {
		return nil, fmt.Errorf("want exactly one URI SAN, got %d", len(cert.URIs))
	}
	u := cert.URIs[0]
	if u.Scheme != "spiffe" || u.Host != td {
		return nil, fmt.Errorf("URI SAN %q is not in trust domain %q", u, td)
	}
	return u, nil
}

// Role returns the role segment of a SPIFFE path: "connector", "gateway" or "controller".
func Role(u *url.URL) (string, error) {
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	switch {
	case len(parts) == 4 && parts[0] == "org" && (parts[2] == "connector" || parts[2] == "gateway"):
		return parts[2], nil
	case len(parts) == 2 && parts[0] == "controller":
		return "controller", nil
	}
	return "", errors.New("unknown SPIFFE path " + u.Path)
}
