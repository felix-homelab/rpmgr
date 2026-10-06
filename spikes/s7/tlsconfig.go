// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// Counters records how often the verification callbacks ran, and on which kind of handshake.
type Counters struct {
	VerifyConnection        atomic.Int32
	VerifyConnectionResumed atomic.Int32
	VerifyPeerCertificate   atomic.Int32
}

// Expect describes the peer a TLS endpoint accepts.
type Expect struct {
	TrustDomain string
	Kinds       []Kind    // accepted roles
	Exact       *Identity // if set, exactly this identity (clients always know their peer)
	Deny        *DenyList
	Counters    *Counters
}

var (
	ErrNoPeerCert    = errors.New("no peer certificate")
	ErrWrongIdentity = errors.New("peer identity not accepted")
	ErrDenied        = errors.New("peer certificate is on the deny-list")
)

// VerifyConnection is the rpmgr check that runs after Go's chain verification on every
// handshake, full or resumed: exactly one SPIFFE URI SAN in the trust domain, an accepted role
// and identity, and not on the deny-list.
func (e Expect) VerifyConnection(cs tls.ConnectionState) error {
	if e.Counters != nil {
		e.Counters.VerifyConnection.Add(1)
		if cs.DidResume {
			e.Counters.VerifyConnectionResumed.Add(1)
		}
	}
	if len(cs.PeerCertificates) == 0 {
		return ErrNoPeerCert
	}
	leaf := cs.PeerCertificates[0]
	if len(leaf.URIs) != 1 {
		return fmt.Errorf("%w: %d URI SANs", ErrWrongIdentity, len(leaf.URIs))
	}
	id, err := ParseSPIFFE(leaf.URIs[0], e.TrustDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWrongIdentity, err)
	}
	if e.Exact != nil && id != *e.Exact {
		return fmt.Errorf("%w: got %s, want %s", ErrWrongIdentity, id, e.Exact)
	}
	kindOK := len(e.Kinds) == 0
	for _, k := range e.Kinds {
		kindOK = kindOK || k == id.Kind
	}
	if !kindOK {
		return fmt.Errorf("%w: role %s", ErrWrongIdentity, id.Kind)
	}
	if e.Deny != nil && e.Deny.Denied(leaf) {
		return ErrDenied
	}
	return nil
}

// countPeerCertificate only counts; rpmgr never relies on VerifyPeerCertificate, because Go does
// not call it on resumed connections.
func (e Expect) countPeerCertificate(_ [][]byte, _ [][]*x509.Certificate) error {
	if e.Counters != nil {
		e.Counters.VerifyPeerCertificate.Add(1)
	}
	return nil
}

// ClientConfig is the constructor for every rpmgr-internal TLS client: TLS 1.3 only, the pinned
// root only, ServerName of the expected peer, no InsecureSkipVerify, no 0-RTT (crypto/tls has
// none on TCP). sessions may be nil to disable resumption.
func ClientConfig(own tls.Certificate, roots *x509.CertPool, serverName string, e Expect,
	now func() time.Time, sessions tls.ClientSessionCache) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{own},
		RootCAs:               roots,
		ServerName:            serverName,
		VerifyConnection:      e.VerifyConnection,
		VerifyPeerCertificate: e.countPeerCertificate,
		Time:                  now,
		ClientSessionCache:    sessions,
	}
}

// ServerConfig is the constructor for rpmgr-internal TLS servers that require a verified client
// certificate chaining to the pinned root.
func ServerConfig(own tls.Certificate, roots *x509.CertPool, e Expect, now func() time.Time) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{own},
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             roots,
		VerifyConnection:      e.VerifyConnection,
		VerifyPeerCertificate: e.countPeerCertificate,
		Time:                  now,
	}
}
