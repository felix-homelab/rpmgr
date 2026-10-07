// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/pki"
)

// TestHolder: the agent endpoint presents the holder's current certificate at every handshake.
func TestHolder(t *testing.T) {
	c := newCA(t, td)
	first := c.agent(t, node(ctn1), pki.ControllerLifetime).tls
	second := c.agent(t, node(ctn1), pki.ControllerLifetime).tls
	h := pki.NewHolder(first)
	srv := pki.AgentEndpointConfig(h, c.pool(), pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}}, c.clock, pki.Reauth{})
	served := func() []byte {
		t.Helper()
		a, b := net.Pipe()
		defer func() { _ = a.Close(); _ = b.Close() }()
		go func() { _ = tls.Server(a, srv).Handshake() }()
		cli := pki.ClientConfig(tls.Certificate{}, c.pool(), "controller."+td,
			pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindController}}, c.clock, nil)
		conn := tls.Client(b, cli)
		if err := conn.Handshake(); err != nil {
			t.Fatal(err)
		}
		return conn.ConnectionState().PeerCertificates[0].Raw
	}
	if string(served()) != string(first.Certificate[0]) {
		t.Fatal("not the first certificate")
	}
	h.Set(second)
	if string(served()) != string(second.Certificate[0]) {
		t.Fatal("a handshake after Set did not present the new certificate")
	}
}
