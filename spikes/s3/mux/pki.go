// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

// CA is a minimal test certificate authority. The spike uses two: the installation's internal CA
// (pinned by agents, SPIFFE URI SAN spiffe://<td>) and a "public" test CA that stands in for ACME
// certificates of route and UI hostnames.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}

// NewCA creates a self-signed ECDSA P-256 root. uri, if not empty, is added as URI SAN.
func NewCA(name, uri string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// Pool returns a pool containing only this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Leaf issues a leaf certificate with the given DNS names and optional SPIFFE URI.
func (ca *CA) Leaf(dnsNames []string, spiffe string, usages ...x509.ExtKeyUsage) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: firstOr(dnsNames, spiffe)},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
	}
	if spiffe != "" {
		u, err := url.Parse(spiffe)
		if err != nil {
			return tls.Certificate{}, err
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// SPKIHash returns the base64 SHA-256 of the certificate's SubjectPublicKeyInfo, the format of
// Chromium's --ignore-certificate-errors-spki-list.
func SPKIHash(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// KeyPEM encodes the private key of a leaf as PKCS#8 PEM.
func KeyPEM(c tls.Certificate) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// CertPEM encodes the leaf certificate as PEM.
func CertPEM(c tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
}

func randSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return n
}

func firstOr(s []string, alt string) string {
	if len(s) > 0 {
		return s[0]
	}
	return alt
}
