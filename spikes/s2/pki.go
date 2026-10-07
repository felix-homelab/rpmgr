// SPDX-License-Identifier: Apache-2.0

// Package s2 is the throw-away prototype of spike S2: reverse HTTP/2 as the TCP transport of a
// data session (docs/13-roadmap.md, S2; docs/adr/0005-reverse-http2-fallback.md).
package s2

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

// ALPN of the TCP transport (docs/03-connections.md, "Versioning and capabilities").
const ALPN = "rpmgr-tunnel-h2/1"

// TestPKI is a throw-away CA for the spike. rpmgr's real CA has an intermediate and name
// constraints (spike S7); S2 only needs mutual TLS 1.3 with SPIFFE identities.
type TestPKI struct {
	TrustDomain string
	root        *x509.Certificate
	rootKey     *ecdsa.PrivateKey
	Pool        *x509.CertPool
}

// NewTestPKI creates a root CA for the trust domain td.
func NewTestPKI(td string) (*TestPKI, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse("spiffe://" + td)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rpmgr test root " + td},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &TestPKI{TrustDomain: td, root: root, rootKey: key, Pool: pool}, nil
}

// Identity is an agent identity: its SPIFFE ID and the DNS SAN derived from it.
type Identity struct {
	Role string // "connector" or "gateway"
	Org  string
	ID   string
}

// SPIFFE returns spiffe://<td>/org/<org>/<role>/<id>.
func (i Identity) SPIFFE(td string) string {
	return fmt.Sprintf("spiffe://%s/org/%s/%s/%s", td, i.Org, i.Role, i.ID)
}

// DNSName returns <id>.<role>.<td>.
func (i Identity) DNSName(td string) string {
	return fmt.Sprintf("%s.%s.%s", i.ID, i.Role, td)
}

// Issue issues a leaf certificate for id with a fresh P-256 key.
func (p *TestPKI) Issue(id Identity) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	u, err := url.Parse(id.SPIFFE(p.TrustDomain))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{u},
		DNSNames:     []string{id.DNSName(p.TrustDomain)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.root, &key.PublicKey, p.rootKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// peerSPIFFE returns the single URI SAN of the verified peer certificate.
func peerSPIFFE(cs tls.ConnectionState) (string, error) {
	if len(cs.PeerCertificates) == 0 {
		return "", errors.New("no peer certificate")
	}
	leaf := cs.PeerCertificates[0]
	if len(leaf.URIs) != 1 {
		return "", fmt.Errorf("peer certificate has %d URI SANs, want 1", len(leaf.URIs))
	}
	return leaf.URIs[0].String(), nil
}

// GatewayTLS is the gateway's TLS server configuration for data sessions: TLS 1.3 only, a
// client certificate from the pinned CA is required, and the peer must be a connector of the
// trust domain.
func (p *TestPKI) GatewayTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.Pool,
		NextProtos:   []string{ALPN},
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, err := peerSPIFFE(cs)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(id, "spiffe://"+p.TrustDomain+"/org/") || !strings.Contains(id, "/connector/") {
				return fmt.Errorf("peer %q is not a connector of trust domain %s", id, p.TrustDomain)
			}
			return nil
		},
	}
}

// ConnectorTLS is the connector's TLS client configuration for a data session to the gateway
// with the given identity: ServerName is the expected gateway's DNS name, and the SPIFFE ID is
// checked as well (docs/04-security.md, "Trust domain and identities").
func (p *TestPKI) ConnectorTLS(cert tls.Certificate, gateway Identity) *tls.Config {
	want := gateway.SPIFFE(p.TrustDomain)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      p.Pool,
		ServerName:   gateway.DNSName(p.TrustDomain),
		NextProtos:   []string{ALPN},
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, err := peerSPIFFE(cs)
			if err != nil {
				return err
			}
			if id != want {
				return fmt.Errorf("gateway identity %q, want %q", id, want)
			}
			return nil
		},
	}
}
