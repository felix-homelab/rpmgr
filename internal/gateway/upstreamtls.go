// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// UpstreamVerify is how the gateway checks an HTTPS upstream's certificate (docs/04-security.md,
// "HTTPS upstreams"; ADR-0017).
type UpstreamVerify int

const (
	// VerifyChain checks the chain against the CA bundle or the host's trust store, the server
	// name, and the pin if one is set.
	VerifyChain UpstreamVerify = iota
	// VerifyNothing checks nothing: the target's user marked it unverified (D82).
	VerifyNothing
)

// UpstreamTLS is how the gateway verifies the HTTPS upstream of one route target.
type UpstreamTLS struct {
	// ServerName is the name sent to the upstream (SNI) and, when verified, the name its
	// certificate must hold.
	ServerName string
	// CAPEM verifies the upstream's chain; empty is the host's trust store.
	CAPEM []byte
	// SPKISHA256, if set, must be the SHA-256 of the leaf's SubjectPublicKeyInfo.
	SPKISHA256 []byte
	Verify     UpstreamVerify
}

// config returns the TLS configuration of a connection to the upstream: TLS 1.2 or later, the
// server name, ALPN for HTTP/2, and the checks of its mode: the CA bundle or the host's trust store
// and the pin, or none.
//
// It is the only place in rpmgr that turns crypto/tls's own verification off, and only for a
// target its user marked unverified; tools/bannedapi and .golangci.yml allow InsecureSkipVerify
// in this function alone (ADR-0017). rpmgr's own sessions never skip verification.
func (u UpstreamTLS) config() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.ServerName, NextProtos: []string{"h2", "http/1.1"}}
	if u.Verify == VerifyNothing {
		cfg.InsecureSkipVerify = true
		return cfg, nil
	}
	if len(u.CAPEM) > 0 {
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(u.CAPEM) {
			return nil, errors.New("the CA bundle holds no certificate")
		}
	}
	if pin := u.SPKISHA256; len(pin) > 0 {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if !bytes.Equal(sum[:], pin) {
				return errors.New("the upstream's key does not match its pin")
			}
			return nil
		}
	}
	return cfg, nil
}
