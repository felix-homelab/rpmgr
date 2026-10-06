// SPDX-License-Identifier: Apache-2.0

// Package pki creates the test PKI of the S1 benchmark: one root CA and leaf certificates for a
// gateway and a connector with SPIFFE URI SANs and identity DNS SANs, as in docs/04-security.md.
// Benchmarks do not exercise the PKI; it exists so that the tunnels run with the same mutual
// TLS 1.3 handshakes as the design, never with verification disabled.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Files in a certificate directory.
const (
	CAFile        = "ca.pem"
	GatewayCert   = "gateway.pem"
	GatewayKey    = "gateway-key.pem"
	ConnectorCert = "connector.pem"
	ConnectorKey  = "connector-key.pem"
)

// Identity names one tunnel endpoint.
type Identity struct {
	TrustDomain string
	Role        string // "gateway" or "connector"
	ID          string
}

// DNSName is the identity's DNS SAN, e.g. "gw1.gateway.rpmgr-bench".
func (i Identity) DNSName() string { return i.ID + "." + i.Role + "." + i.TrustDomain }

// SPIFFE is the identity's URI SAN.
func (i Identity) SPIFFE() *url.URL {
	return &url.URL{Scheme: "spiffe", Host: i.TrustDomain, Path: "/org/org_bench/" + i.Role + "/" + i.ID}
}

// Generate writes a root CA, a gateway and a connector certificate into dir.
func Generate(dir, trustDomain, gatewayID, connectorID string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "rpmgr S1 benchmark root"},
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: trustDomain}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, CAFile), "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	leaves := []struct {
		id          Identity
		cert, key   string
		extKeyUsage []x509.ExtKeyUsage
	}{
		{Identity{trustDomain, "gateway", gatewayID}, GatewayCert, GatewayKey,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}},
		{Identity{trustDomain, "connector", connectorID}, ConnectorCert, ConnectorKey,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}},
	}
	for _, l := range leaves {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial(),
			DNSNames:     []string{l.id.DNSName()},
			URIs:         []*url.URL{l.id.SPIFFE()},
			NotBefore:    now.Add(-5 * time.Minute),
			NotAfter:     now.Add(7 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  l.extKeyUsage,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, l.cert), "CERTIFICATE", der, 0o644); err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, l.key), "EC PRIVATE KEY", keyDER, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

// Load reads the CA and one role's key pair from dir.
func Load(dir, role string) (*x509.CertPool, tls.Certificate, error) {
	caPEM, err := os.ReadFile(filepath.Join(dir, CAFile))
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, tls.Certificate{}, errors.New("pki: no CA certificate in " + CAFile)
	}
	certFile, keyFile := GatewayCert, GatewayKey
	if role == "connector" {
		certFile, keyFile = ConnectorCert, ConnectorKey
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, certFile), filepath.Join(dir, keyFile))
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	return pool, pair, nil
}

// ServerConfig is the gateway's TLS configuration: TLS 1.3 only, client certificates required
// and verified against the pinned CA, and the peer must be a connector of the trust domain.
func ServerConfig(pool *x509.CertPool, cert tls.Certificate, trustDomain string, alpn ...string) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        pool,
		NextProtos:       alpn,
		VerifyConnection: requirePeerRole(trustDomain, "connector"),
	}
}

// ClientConfig is the connector's TLS configuration: TLS 1.3 only, the pinned CA as the only
// root, ServerName set to the expected gateway's DNS SAN and its SPIFFE role checked.
func ClientConfig(pool *x509.CertPool, cert tls.Certificate, gateway Identity, alpn ...string) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		RootCAs:          pool,
		ServerName:       gateway.DNSName(),
		NextProtos:       alpn,
		VerifyConnection: requirePeerRole(gateway.TrustDomain, "gateway"),
	}
}

func requirePeerRole(trustDomain, role string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("pki: no peer certificate")
		}
		uris := cs.PeerCertificates[0].URIs
		if len(uris) != 1 || uris[0].Scheme != "spiffe" || uris[0].Host != trustDomain {
			return fmt.Errorf("pki: peer has no SPIFFE ID in trust domain %q", trustDomain)
		}
		if !strings.Contains(uris[0].Path, "/"+role+"/") {
			return fmt.Errorf("pki: peer %s is not a %s", uris[0], role)
		}
		return nil
	}
}
