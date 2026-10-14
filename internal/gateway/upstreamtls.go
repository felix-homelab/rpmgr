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
// "HTTPS upstreams"; ADR-0017, ADR-0018).
type UpstreamVerify int

const (
	// VerifyChain checks the chain against the CA bundle or the host's trust store, the server
	// name, and the pin if one is set.
	VerifyChain UpstreamVerify = iota
	// VerifyNothing checks nothing: the target's user marked it unverified (D82).
	VerifyNothing
	// VerifyPinnedKey checks only the key, against SPKISHA256: the target's user pinned the key
	// it presented (D82).
	VerifyPinnedKey
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
	// Connector is the target's connector: its settings apply only to the streams that connector
	// answers. "" from a controller that names none.
	Connector string
}

// config returns the TLS configuration of a connection to the upstream: TLS 1.2 or later, the
// server name, ALPN for HTTP/2, and the checks of its mode: the CA bundle or the host's trust store
// and the pin; the pin alone; or none.
//
// It turns crypto/tls's own verification off for a target its user marked unverified or pinned by
// key only; tools/bannedapi allows InsecureSkipVerify in this function and in the connector's
// certificate probe alone, and .golangci.yml lets forbidigo skip this file, where bannedapi still
// reports any other use (ADR-0017, ADR-0018). rpmgr's own sessions never skip verification.
func (u UpstreamTLS) config() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.ServerName, NextProtos: []string{"h2", "http/1.1"}}
	switch u.Verify {
	case VerifyNothing:
		cfg.InsecureSkipVerify = true
		return cfg, nil
	case VerifyPinnedKey:
		if len(u.SPKISHA256) != sha256.Size {
			return nil, errors.New("a pinned-key upstream has no pin")
		}
		cfg.InsecureSkipVerify = true // the pin below is the whole check
		cfg.VerifyConnection = pinned(u.SPKISHA256,
			"the upstream's key is not the pinned one; trust the certificate it presents now if it is the target's")
		return cfg, nil
	}
	if len(u.CAPEM) > 0 {
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(u.CAPEM) {
			return nil, errors.New("the CA bundle holds no certificate")
		}
	}
	if pin := u.SPKISHA256; len(pin) > 0 {
		cfg.VerifyConnection = pinned(pin, "the upstream's key does not match its pin")
	}
	return cfg, nil
}

// pinned is a VerifyConnection that accepts only a leaf with the SHA-256 pin of its
// SubjectPublicKeyInfo, and fails with message otherwise.
func pinned(pin []byte, message string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("the upstream presented no certificate")
		}
		sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if !bytes.Equal(sum[:], pin) {
			return errors.New(message)
		}
		return nil
	}
}
