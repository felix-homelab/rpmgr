// SPDX-License-Identifier: Apache-2.0

// Package upstreamtls is how rpmgr checks the certificate of an HTTPS route target
// (docs/04-security.md, "HTTPS upstreams"; ADR-0017, ADR-0018): the gateway for the route's
// traffic, and the connector for the target's HTTPS health check, which must succeed or fail
// as the traffic does. It is a package of its own so that the connector-only build, which links no
// gateway code (D119), shares the one function that may turn crypto/tls's verification off.
package upstreamtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// Verify is how an HTTPS upstream's certificate is checked.
type Verify int

const (
	// Chain checks the chain against the CA bundle or the host's trust store, the server name,
	// and the pin if one is set.
	Chain Verify = iota
	// Nothing checks nothing: the target's user marked it unverified (D82).
	Nothing
	// PinnedKey checks only the key, against SPKISHA256: the target's user pinned the key it
	// presented (D82).
	PinnedKey
)

// Settings are how one route target's certificate is checked.
type Settings struct {
	// ServerName is the name sent to the upstream (SNI) and, when verified, the name its
	// certificate must hold.
	ServerName string
	// CAPEM verifies the upstream's chain; empty is the host's trust store.
	CAPEM []byte
	// SPKISHA256, if set, must be the SHA-256 of the leaf's SubjectPublicKeyInfo.
	SPKISHA256 []byte
	Verify     Verify
}

// Config returns the TLS configuration of a connection to the upstream: TLS 1.2 or later, the
// server name, ALPN for HTTP/2, and the checks of its mode: the CA bundle or the host's trust store
// and the pin; the pin alone; or none.
//
// It turns crypto/tls's own verification off for a target its user marked unverified or pinned by
// key only; tools/bannedapi allows InsecureSkipVerify in this function and in the connector's
// certificate probe alone, and .golangci.yml lets forbidigo skip this file, where bannedapi still
// reports any other use (ADR-0017, ADR-0018). rpmgr's own sessions never skip verification.
func (s Settings) Config() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.ServerName, NextProtos: []string{"h2", "http/1.1"}}
	switch s.Verify {
	case Nothing:
		cfg.InsecureSkipVerify = true
		return cfg, nil
	case PinnedKey:
		if len(s.SPKISHA256) != sha256.Size {
			return nil, errors.New("a pinned-key upstream has no pin")
		}
		cfg.InsecureSkipVerify = true // the pin below is the whole check
		cfg.VerifyConnection = pinned(s.SPKISHA256,
			"the upstream's key is not the pinned one; trust the certificate it presents now if it is the target's")
		return cfg, nil
	}
	if len(s.CAPEM) > 0 {
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(s.CAPEM) {
			return nil, errors.New("the CA bundle holds no certificate")
		}
	}
	if pin := s.SPKISHA256; len(pin) > 0 {
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
