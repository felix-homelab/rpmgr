// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"time"
)

// Lifetimes and backdating of docs/04-security.md ("CA hierarchy", "Leaf certificates"). No
// certificate outlives its issuer: NotAfter is capped at the issuer's.
const (
	RootLifetime         = 10 * 365 * 24 * time.Hour
	IntermediateLifetime = 365 * 24 * time.Hour
	SignerLifetime       = 365 * 24 * time.Hour // config-signing and audit-checkpoint keys
	ControllerLifetime   = 30 * 24 * time.Hour
	DefaultLeafLifetime  = 7 * 24 * time.Hour // agents; Settings → PKI allows 1–30 days
	MinLeafLifetime      = 24 * time.Hour
	MaxLeafLifetime      = 30 * 24 * time.Hour
	Backdate             = 5 * time.Minute
)

// Errors of issuance. Every refusal of a CSR wraps ErrBadCSR.
var (
	ErrBadCSR    = errors.New("pki: bad certificate request")
	ErrSameKey   = errors.New("pki: a renewal needs a new key")
	ErrLifetime  = errors.New("pki: leaf lifetime outside 1–30 days")
	ErrNotIssued = errors.New("pki: certificate not issued by this CA")
)

// KeyPair is a certificate and its private key.
type KeyPair struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewKey returns a new ECDSA P-256 key, the algorithm of every rpmgr certificate.
func NewKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// NewRoot creates the root CA of trust domain td: 10 years, path length 1, and the trust domain as
// its only URI SAN, from which agents read it after selecting the root by its pin.
func NewRoot(td string, now time.Time) (KeyPair, error) {
	if !ValidTrustDomain(td) {
		return KeyPair{}, fmt.Errorf("pki: %q is not a trust domain", td)
	}
	key, err := NewKey()
	if err != nil {
		return KeyPair{}, err
	}
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "rpmgr root CA " + td},
		NotBefore:             now.Add(-Backdate),
		NotAfter:              now.Add(RootLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: td}},
	}
	cert, err := create(tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Cert: cert, Key: key}, nil
}

// NewIntermediate creates an issuing intermediate under root: 1 year, path length 0, and name
// constraints (critical) that permit only the URI and DNS domain of the trust domain, which Go's
// verifier enforces.
func NewIntermediate(root KeyPair, now time.Time) (KeyPair, error) {
	td, err := TrustDomainOf(root.Cert)
	if err != nil {
		return KeyPair{}, err
	}
	key, err := NewKey()
	if err != nil {
		return KeyPair{}, err
	}
	tmpl := &x509.Certificate{
		Subject:                     pkix.Name{CommonName: "rpmgr issuing CA " + td},
		NotBefore:                   now.Add(-Backdate),
		NotAfter:                    capAt(now.Add(IntermediateLifetime), root.Cert),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{td},
		PermittedURIDomains:         []string{td},
	}
	cert, err := create(tmpl, root.Cert, &key.PublicKey, root.Key)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Cert: cert, Key: key}, nil
}

// TrustDomainOf returns the trust domain of a root: its only URI SAN, spiffe://<td>.
func TrustDomainOf(root *x509.Certificate) (string, error) {
	if root == nil || !root.IsCA || len(root.URIs) != 1 {
		return "", errors.New("pki: not an rpmgr root")
	}
	u := root.URIs[0]
	if u.Scheme != "spiffe" || !ValidTrustDomain(u.Host) || (u.Path != "" && u.Path != "/") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("pki: root URI %v is not a trust domain", u)
	}
	return u.Host, nil
}

// Issuer issues certificates with the current intermediate, and verifies certificates issued by
// it or by an older intermediate that is still trusted (rotation overlap).
type Issuer struct {
	td            string
	root          *x509.Certificate
	inter         KeyPair
	roots, inters *x509.CertPool
	now           func() time.Time
}

// NewIssuer checks that inter is a name-constrained intermediate of root with its key, and returns
// an Issuer that also verifies certificates of the older intermediates.
func NewIssuer(root *x509.Certificate, inter KeyPair, now func() time.Time, older ...*x509.Certificate) (*Issuer, error) {
	td, err := TrustDomainOf(root)
	if err != nil {
		return nil, err
	}
	if inter.Cert == nil || inter.Key == nil || !inter.Key.PublicKey.Equal(inter.Cert.PublicKey) {
		return nil, errors.New("pki: the intermediate's key does not match its certificate")
	}
	if !inter.Cert.IsCA || inter.Cert.MaxPathLen != 0 || !inter.Cert.PermittedDNSDomainsCritical ||
		!slices.Equal(inter.Cert.PermittedDNSDomains, []string{td}) ||
		!slices.Equal(inter.Cert.PermittedURIDomains, []string{td}) {
		return nil, errors.New("pki: the intermediate is not constrained to the trust domain")
	}
	is := &Issuer{td: td, root: root, inter: inter, roots: x509.NewCertPool(), inters: x509.NewCertPool(), now: now}
	is.roots.AddCert(root)
	for _, c := range append([]*x509.Certificate{inter.Cert}, older...) {
		if err := c.CheckSignatureFrom(root); err != nil {
			return nil, fmt.Errorf("pki: intermediate %s is not signed by the root: %w", c.Subject, err)
		}
		is.inters.AddCert(c)
	}
	return is, nil
}

// TrustDomain returns the issuer's trust domain.
func (is *Issuer) TrustDomain() string { return is.td }

// Root returns the root certificate, the trust anchor agents pin.
func (is *Issuer) Root() *x509.Certificate { return is.root }

// Intermediate returns the certificate of the current intermediate, sent with every leaf.
func (is *Issuer) Intermediate() *x509.Certificate { return is.inter.Cert }

// IssueLeaf issues a TLS leaf for id from a CSR, which is only proof of possession of a P-256 key:
// its subject and SANs are ignored, and the identity comes from the caller. Every leaf has the EKUs
// clientAuth and serverAuth (D42).
func (is *Issuer) IssueLeaf(csr *x509.CertificateRequest, id Identity, lifetime time.Duration) (*x509.Certificate, error) {
	if lifetime < MinLeafLifetime || lifetime > MaxLeafLifetime {
		return nil, ErrLifetime
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if id.TrustDomain != is.td {
		return nil, fmt.Errorf("pki: identity in trust domain %s, not %s", id.TrustDomain, is.td)
	}
	pub, err := checkCSR(csr)
	if err != nil {
		return nil, err
	}
	return is.sign(pub, lifetime, &x509.Certificate{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{id.SPIFFE()},
		DNSNames:    id.DNSNames(),
	})
}

// RenewLeaf issues a new leaf for the identity of presented, a leaf of this CA, for a CSR with a
// new key. presented may have expired: its chain is checked at a time inside its validity; whether
// it may still be renewed (revoked, superseded, the Reauth grace period) the caller decides from
// issued_certificates.
func (is *Issuer) RenewLeaf(presented *x509.Certificate, csr *x509.CertificateRequest, lifetime time.Duration) (*x509.Certificate, error) {
	id, err := is.IdentityOf(presented, presented.NotBefore.Add(Backdate))
	if err != nil {
		return nil, err
	}
	if pub, err := checkCSR(csr); err == nil && pub.Equal(presented.PublicKey) {
		return nil, ErrSameKey
	}
	return is.IssueLeaf(csr, id, lifetime)
}

// IdentityOf verifies that cert is a TLS leaf of this CA at time at and returns its identity.
func (is *Issuer) IdentityOf(cert *x509.Certificate, at time.Time) (Identity, error) {
	if cert == nil {
		return Identity{}, ErrNotIssued
	}
	_, err := cert.Verify(x509.VerifyOptions{Roots: is.roots, Intermediates: is.inters, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrNotIssued, err)
	}
	if len(cert.URIs) != 1 {
		return Identity{}, fmt.Errorf("%w: %d URI SANs", ErrNotIdentity, len(cert.URIs))
	}
	return ParseSPIFFE(cert.URIs[0], is.td)
}

func (is *Issuer) sign(pub *ecdsa.PublicKey, lifetime time.Duration, tmpl *x509.Certificate) (*x509.Certificate, error) {
	t := is.now()
	tmpl.NotBefore = t.Add(-Backdate)
	tmpl.NotAfter = capAt(t.Add(lifetime), is.inter.Cert)
	return create(tmpl, is.inter.Cert, pub, is.inter.Key)
}

// checkCSR checks the CSR's signature, its proof of possession, and that its key is ECDSA P-256.
func checkCSR(csr *x509.CertificateRequest) (*ecdsa.PublicKey, error) {
	if csr == nil {
		return nil, ErrBadCSR
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCSR, err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: the key is not ECDSA P-256", ErrBadCSR)
	}
	return pub, nil
}

// create gives tmpl a random serial, signs it and parses the result.
func create(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// randomSerial returns 128 random bits, positive and non-zero (RFC 5280 allows up to 20 octets).
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// capAt returns t, or the issuer's NotAfter if that is earlier.
func capAt(t time.Time, issuer *x509.Certificate) time.Time {
	if issuer.NotAfter.Before(t) {
		return issuer.NotAfter
	}
	return t
}
