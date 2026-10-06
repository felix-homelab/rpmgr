// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sync"
	"time"
)

// Values from docs/04-security.md ("CA hierarchy", "Leaf certificates").
const (
	RootLifetime         = 10 * 365 * 24 * time.Hour
	IntermediateLifetime = 365 * 24 * time.Hour
	AgentLeafLifetime    = 7 * 24 * time.Hour
	ControllerLifetime   = 30 * 24 * time.Hour
	Backdate             = 5 * time.Minute
	DefaultGrace         = 30 * 24 * time.Hour
	MinLeafLifetime      = 24 * time.Hour      // Settings → PKI: 1–30 days
	MaxLeafLifetime      = 30 * 24 * time.Hour //
)

// Profile selects the extended key usages of a leaf.
type Profile int

const (
	ProfileConnector     Profile = iota // clientAuth + serverAuth (server in rpmgr-e2e / rpmgr-p2p)
	ProfileGatewayClient                // clientAuth (control session to the controller)
	ProfileGatewayServer                // serverAuth (<gateway-id>.gateway.<td> for data sessions)
	ProfileController                   // serverAuth + clientAuth (HA replicas call each other)
)

func (p Profile) ekus() []x509.ExtKeyUsage {
	switch p {
	case ProfileConnector, ProfileController:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case ProfileGatewayClient:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
}

// CA is the internal CA of one installation: a root and one name-constrained issuing
// intermediate. The registry plays the role of the issued_certificates table.
type CA struct {
	TD           string
	Root         *x509.Certificate
	Intermediate *x509.Certificate
	rootKey      *ecdsa.PrivateKey
	interKey     *ecdsa.PrivateKey
	Now          func() time.Time

	mu     sync.Mutex
	issued map[string]*Issued // by serial (hex)
	// revokedIdentities holds SPIFFE IDs revoked as a whole.
	revokedIdentities map[string]bool
}

// Issued is one row of issued_certificates.
type Issued struct {
	Serial     *big.Int
	Identity   Identity
	NotBefore  time.Time
	NotAfter   time.Time
	SeenAt     time.Time // first seen in an authenticated session; zero if never used
	Superseded bool
	Revoked    bool
}

func randomSerial() (*big.Int, error) {
	// 128 random bits, positive and non-zero (RFC 5280 allows up to 20 octets).
	for {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// NewCA creates a root and an issuing intermediate for trust domain td. If constrain is false,
// the intermediate carries no name constraints (used only by the control test that proves the
// constraints are what blocks a forged leaf).
func NewCA(td string, now func() time.Time, constrain bool) (*CA, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	t := now()
	rs, err := randomSerial()
	if err != nil {
		return nil, err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          rs,
		Subject:               pkix.Name{CommonName: "rpmgr root CA " + td},
		NotBefore:             t.Add(-Backdate),
		NotAfter:              t.Add(RootLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: td}},
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}
	is, err := randomSerial()
	if err != nil {
		return nil, err
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          is,
		Subject:               pkix.Name{CommonName: "rpmgr issuing CA " + td},
		NotBefore:             t.Add(-Backdate),
		NotAfter:              t.Add(IntermediateLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if constrain {
		interTmpl.PermittedDNSDomainsCritical = true
		interTmpl.PermittedDNSDomains = []string{td}
		interTmpl.PermittedURIDomains = []string{td}
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, err
	}
	return &CA{
		TD: td, Root: root, Intermediate: inter, rootKey: rootKey, interKey: interKey, Now: now,
		issued: map[string]*Issued{}, revokedIdentities: map[string]bool{},
	}, nil
}

// Roots returns a pool with the root only: the pinned trust anchor.
func (ca *CA) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Root)
	return p
}

// RootPin is the --ca-pin value: sha256 of the root's SubjectPublicKeyInfo.
func (ca *CA) RootPin() string {
	sum := sha256.Sum256(ca.Root.RawSubjectPublicKeyInfo)
	return "sha256:" + base64.StdEncoding.EncodeToString(sum[:])
}

var (
	ErrBadCSR       = errors.New("bad CSR")
	ErrSameKey      = errors.New("renewal must use a new key")
	ErrLifetime     = errors.New("leaf lifetime outside 1–30 days")
	ErrUnknownCert  = errors.New("certificate not issued by this CA")
	ErrRevoked      = errors.New("certificate or identity revoked")
	ErrSuperseded   = errors.New("certificate superseded by a newer serial")
	ErrExpiredGrace = errors.New("certificate expired beyond the grace period")
)

// Issue checks the CSR (proof of possession, P-256) and issues a leaf for id. The CSR's subject
// and SANs are ignored: the CA assigns the identity.
func (ca *CA) Issue(csr *x509.CertificateRequest, id Identity, p Profile, lifetime time.Duration) (*x509.Certificate, error) {
	if lifetime < MinLeafLifetime || lifetime > MaxLeafLifetime {
		if !(p == ProfileController && lifetime == ControllerLifetime) {
			return nil, ErrLifetime
		}
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCSR, err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: key is not ECDSA P-256", ErrBadCSR)
	}
	return ca.sign(pub, id, p, lifetime)
}

func (ca *CA) sign(pub *ecdsa.PublicKey, id Identity, p Profile, lifetime time.Duration) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	t := ca.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    t.Add(-Backdate),
		NotAfter:     t.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  p.ekus(),
		URIs:         []*url.URL{id.SPIFFE()},
		DNSNames:     id.DNSNames(),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Intermediate, pub, ca.interKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ca.mu.Lock()
	ca.issued[serial.Text(16)] = &Issued{Serial: serial, Identity: id, NotBefore: tmpl.NotBefore, NotAfter: tmpl.NotAfter}
	ca.mu.Unlock()
	return cert, nil
}

// Renew issues a new certificate for the identity of the presented (valid) certificate. The CSR
// must carry a new key; its subject and SANs are ignored.
func (ca *CA) Renew(presented *x509.Certificate, csr *x509.CertificateRequest, p Profile, lifetime time.Duration) (*x509.Certificate, error) {
	id, err := ca.identityOf(presented)
	if err != nil {
		return nil, err
	}
	if old, ok := presented.PublicKey.(*ecdsa.PublicKey); ok {
		if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); ok && pub.Equal(old) {
			return nil, ErrSameKey
		}
	}
	return ca.Issue(csr, id, p, lifetime)
}

func (ca *CA) identityOf(cert *x509.Certificate) (Identity, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	row, ok := ca.issued[cert.SerialNumber.Text(16)]
	if !ok {
		return Identity{}, ErrUnknownCert
	}
	return row.Identity, nil
}

// MarkSeen records that a serial was used in an authenticated session (control session or
// Renew). Every older serial of the same identity becomes superseded (docs/04, "Leaf
// certificates").
func (ca *CA) MarkSeen(serial *big.Int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	row, ok := ca.issued[serial.Text(16)]
	if !ok {
		return
	}
	if row.SeenAt.IsZero() {
		row.SeenAt = ca.Now()
	}
	for _, other := range ca.issued {
		if other != row && other.Identity == row.Identity && other.NotBefore.Before(row.NotBefore) {
			other.Superseded = true
		}
	}
}

// RevokeSerial and RevokeIdentity are the two kinds of deny-list entry.
func (ca *CA) RevokeSerial(serial *big.Int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if row, ok := ca.issued[serial.Text(16)]; ok {
		row.Revoked = true
	}
}

func (ca *CA) RevokeIdentity(id Identity) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.revokedIdentities[id.String()] = true
}

// CheckReauthable applies the database checks of Reauth to a chain-verified certificate: expired
// at most grace ago (grace 0 disables Reauth for expired certificates), issued by this CA,
// neither its serial nor its identity revoked, and not superseded.
func (ca *CA) CheckReauthable(cert *x509.Certificate, grace time.Duration) error {
	if ca.Now().After(cert.NotAfter.Add(grace)) {
		return ErrExpiredGrace
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	row, ok := ca.issued[cert.SerialNumber.Text(16)]
	switch {
	case !ok:
		return ErrUnknownCert
	case row.Revoked || ca.revokedIdentities[row.Identity.String()]:
		return ErrRevoked
	case row.Superseded:
		return ErrSuperseded
	}
	return nil
}

// DenyList is what relying parties receive in DenyListUpdate: revoked serials and identities.
type DenyList struct {
	mu         sync.RWMutex
	serials    map[string]bool
	identities map[string]bool
}

func NewDenyList() *DenyList {
	return &DenyList{serials: map[string]bool{}, identities: map[string]bool{}}
}

func (d *DenyList) AddSerial(s *big.Int) { d.mu.Lock(); d.serials[s.Text(16)] = true; d.mu.Unlock() }
func (d *DenyList) AddIdentity(id string) {
	d.mu.Lock()
	d.identities[id] = true
	d.mu.Unlock()
}

// Denied reports whether a certificate is on the list, by serial or by identity.
func (d *DenyList) Denied(cert *x509.Certificate) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.serials[cert.SerialNumber.Text(16)] {
		return true
	}
	for _, u := range cert.URIs {
		if d.identities[u.String()] {
			return true
		}
	}
	return false
}
