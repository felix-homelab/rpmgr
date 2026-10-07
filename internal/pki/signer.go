// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// Purpose names one of the controller's signing keys (docs/04-security.md, "CA hierarchy").
type Purpose string

// The signing keys. Their certificates come from the issuing intermediate, so that the root can
// go offline without blocking their yearly rotation.
const (
	PurposeConfigSigning   Purpose = "config-signing"
	PurposeAuditCheckpoint Purpose = "audit-checkpoint"
)

// SignerURI is the URI SAN of a signing key's certificate: spiffe://<td>/controller/<purpose>.
// It is not an identity, so ParseSPIFFE refuses it and the certificate never authenticates a TLS
// peer.
func SignerURI(td string, p Purpose) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: td, Path: "/controller/" + string(p)}
}

// IssueSigner certifies a signing key: key usage digitalSignature, no extended key usage, and the
// purpose's URI as the only SAN.
func (is *Issuer) IssueSigner(pub *ecdsa.PublicKey, p Purpose) (*x509.Certificate, error) {
	if p != PurposeConfigSigning && p != PurposeAuditCheckpoint {
		return nil, fmt.Errorf("pki: unknown signing purpose %q", p)
	}
	if pub == nil {
		return nil, errors.New("pki: no public key")
	}
	return is.sign(pub, SignerLifetime, &x509.Certificate{
		KeyUsage: x509.KeyUsageDigitalSignature,
		URIs:     []*url.URL{SignerURI(is.td, p)},
	})
}

// VerifySigner checks that cert certifies a signing key for purpose p at time at: it chains to
// root through intermediates, carries no extended key usage, and its only SAN is the purpose's URI
// in root's trust domain. Agents accept a snapshot or deny-list signature only from such a key.
func VerifySigner(cert *x509.Certificate, intermediates []*x509.Certificate, root *x509.Certificate, p Purpose, at time.Time) error {
	td, err := TrustDomainOf(root)
	if err != nil {
		return err
	}
	if cert == nil {
		return errors.New("pki: no signing certificate")
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, c := range intermediates {
		inters.AddCert(c)
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return fmt.Errorf("pki: signing certificate: %w", err)
	}
	want := SignerURI(td, p).String()
	switch {
	case len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 0:
		return errors.New("pki: a signing certificate has no extended key usage")
	case cert.KeyUsage != x509.KeyUsageDigitalSignature:
		return errors.New("pki: a signing certificate has key usage digitalSignature only")
	case len(cert.URIs) != 1 || cert.URIs[0].String() != want || len(cert.DNSNames) != 0 ||
		len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0:
		return fmt.Errorf("pki: the signing certificate is not for %s", want)
	}
	return nil
}
