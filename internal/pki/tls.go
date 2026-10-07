// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The TLS configurations of every rpmgr-internal session (docs/03-connections.md, "Properties
// common to all rpmgr-internal sessions"): TLS 1.3 only, the pinned root only, a ServerName for the
// expected peer, and every rpmgr check in VerifyConnection, which Go runs on full and resumed
// handshakes alike. Session tickets keep crypto/tls's automatic keys, which it rotates daily.

// Errors of VerifyConnection.
var (
	ErrNoPeerCert    = errors.New("pki: no peer certificate")
	ErrWrongIdentity = errors.New("pki: peer identity not accepted")
	ErrDenied        = errors.New("pki: peer certificate is on the deny-list")
	ErrExpiredGrace  = errors.New("pki: certificate expired beyond the Reauth grace period")
)

// Expect describes the peer a TLS endpoint accepts.
type Expect struct {
	TrustDomain string
	Kinds       []Kind    // accepted roles; empty accepts every role
	Exact       *Identity // if set, exactly this identity: a client always knows its peer
	// Denied reports whether a certificate is on the deny-list, by serial or by identity.
	Denied func(*x509.Certificate) bool
}

// VerifyConnection checks the peer after Go has verified its chain, on every handshake, full or
// resumed: exactly one URI SAN, an identity of the trust domain (ParseSPIFFE: the host must equal
// it), an accepted role or the exact identity, and not on the deny-list.
func (e Expect) VerifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return ErrNoPeerCert
	}
	leaf := cs.PeerCertificates[0]
	if len(leaf.URIs) != 1 {
		return fmt.Errorf("%w: %d URI SANs", ErrWrongIdentity, len(leaf.URIs))
	}
	id, err := ParseSPIFFE(leaf.URIs[0], e.TrustDomain)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrWrongIdentity, err)
	}
	if e.Exact != nil && id != *e.Exact {
		return fmt.Errorf("%w: %s, want %s", ErrWrongIdentity, id, e.Exact)
	}
	if len(e.Kinds) > 0 && !slices.Contains(e.Kinds, id.Kind) {
		return fmt.Errorf("%w: role %s", ErrWrongIdentity, id.Kind)
	}
	if e.Denied != nil && e.Denied(leaf) {
		return ErrDenied
	}
	return nil
}

// ClientConfig returns the configuration of an rpmgr-internal TLS client. serverName is the
// expected peer's DNS name; crypto/tls refuses to handshake without one. sessions may be nil,
// which disables resumption.
func ClientConfig(own tls.Certificate, roots *x509.CertPool, serverName string, e Expect, now func() time.Time,
	sessions tls.ClientSessionCache) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{own},
		RootCAs:            roots,
		ServerName:         serverName,
		VerifyConnection:   e.VerifyConnection,
		Time:               now,
		ClientSessionCache: sessions,
	}
}

// ServerConfig returns the configuration of an rpmgr-internal TLS server, which requires a client
// certificate that chains to the pinned root.
func ServerConfig(own tls.Certificate, roots *x509.CertPool, e Expect, now func() time.Time) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{own},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        roots,
		VerifyConnection: e.VerifyConnection,
		Time:             now,
	}
}

// Reauth configures the verifier of reauth.controller.<td> (docs/04-security.md, "Leaf
// certificates").
type Reauth struct {
	// Grace returns the current grace period; 0 refuses every expired certificate.
	Grace func() time.Duration
	// Check runs the database checks on the presented leaf: issued by this CA, neither its serial
	// nor its identity revoked, not superseded. Without it, every Reauth is refused.
	Check func(leaf *x509.Certificate) error
}

// AgentEndpointConfig returns the controller's configuration for the agent names on one listener:
// mutual TLS as ServerConfig for controller.<td>, and for SNI reauth.controller.<td> a verifier
// that also accepts a client certificate that expired at most the grace period ago. The Reauth
// configuration neither issues nor accepts session tickets: it shares the parent's ticket keys,
// so a ticket from controller.<td> would otherwise resume there and skip the verifier.
func AgentEndpointConfig(own tls.Certificate, roots *x509.CertPool, e Expect, now func() time.Time, r Reauth) *tls.Config {
	if now == nil {
		now = time.Now
	}
	base := ServerConfig(own, roots, e, now)
	reauth := base.Clone()
	// crypto/tls would refuse the expired certificate, so the chain is verified in
	// VerifyConnection; crypto/tls still checks CertificateVerify, the proof of possession.
	reauth.ClientAuth = tls.RequireAnyClientCert
	reauth.ClientCAs = nil
	reauth.SessionTicketsDisabled = true
	reauth.VerifyConnection = func(cs tls.ConnectionState) error { return r.verify(cs, roots, e, now()) }
	name := "reauth.controller." + e.TrustDomain
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if strings.EqualFold(hello.ServerName, name) {
			return reauth, nil
		}
		return nil, nil // the base configuration
	}
	return base
}

func (r Reauth) verify(cs tls.ConnectionState, roots *x509.CertPool, e Expect, now time.Time) error {
	if len(cs.PeerCertificates) == 0 {
		return ErrNoPeerCert
	}
	if r.Grace == nil || r.Check == nil {
		return errors.New("pki: Reauth is not configured")
	}
	leaf := cs.PeerCertificates[0]
	if now.Before(leaf.NotBefore) {
		return errors.New("pki: Reauth certificate is not yet valid")
	}
	if now.After(leaf.NotAfter.Add(r.Grace())) {
		return ErrExpiredGrace
	}
	at := now
	if at.After(leaf.NotAfter) {
		at = leaf.NotAfter // inside the validity, so an expired leaf still chains
	}
	inters := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inters.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("pki: Reauth chain: %w", err)
	}
	if err := e.VerifyConnection(cs); err != nil {
		return err
	}
	return r.Check(leaf)
}
