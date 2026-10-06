// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// ControllerConfig returns the controller's TLS configuration for the agent endpoints on one
// listener. SNI controller.<td> gets the normal mutual-TLS verifier; SNI reauth.controller.<td>
// gets a verifier that also accepts client certificates expired at most grace ago, selected with
// GetConfigForClient (docs/04-security.md, "Leaf certificates").
func ControllerConfig(own tls.Certificate, ca *CA, normal Expect, grace time.Duration) *tls.Config {
	base := ServerConfig(own, ca.Roots(), normal, ca.Now)
	reauthName := "reauth.controller." + ca.TD

	reauth := base.Clone()
	reauth.GetConfigForClient = nil
	// No chain verification by crypto/tls (it would reject the expired certificate); the chain,
	// the grace period and the database checks run in VerifyConnection. CertificateVerify, the
	// client's proof of possession of the key, is still checked by crypto/tls.
	reauth.ClientAuth = tls.RequireAnyClientCert
	reauth.ClientCAs = nil
	// A Reauth session is never resumable, in either direction: no tickets are issued and none is
	// accepted. (A ticket from the normal endpoint would otherwise skip this verifier.)
	reauth.SessionTicketsDisabled = true
	reauth.VerifyPeerCertificate = nil
	reauth.VerifyConnection = func(cs tls.ConnectionState) error {
		if normal.Counters != nil {
			normal.Counters.VerifyConnection.Add(1)
		}
		if len(cs.PeerCertificates) == 0 {
			return ErrNoPeerCert
		}
		leaf := cs.PeerCertificates[0]
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		// Verify the chain at a time inside the leaf's validity, so an expired leaf still
		// chains; the grace period is checked separately below.
		at := ca.Now()
		if at.After(leaf.NotAfter) {
			at = leaf.NotAfter.Add(-time.Second)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: ca.Roots(), Intermediates: inter, CurrentTime: at,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			return fmt.Errorf("reauth: chain: %w", err)
		}
		if ca.Now().Before(leaf.NotBefore) {
			return fmt.Errorf("reauth: certificate not yet valid")
		}
		if err := (Expect{TrustDomain: ca.TD, Kinds: normal.Kinds}).VerifyConnection(cs); err != nil {
			return fmt.Errorf("reauth: %w", err)
		}
		if err := ca.CheckReauthable(leaf, grace); err != nil {
			return fmt.Errorf("reauth: %w", err)
		}
		return nil
	}

	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName == reauthName {
			return reauth, nil
		}
		return nil, nil // keep the base configuration
	}
	return base
}
