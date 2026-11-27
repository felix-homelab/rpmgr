// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"crypto/tls"
	"crypto/x509"
	"sync/atomic"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/pki"
)

// TestFollowRoots: a listener whose client CAs follow a root rotation accepts a client under the new
// root as soon as the pool has it, with no restart, keeps accepting the old root while both are in the pool,
// and refuses the old root once it is dropped; the configuration it hands out is the same one between
// changes, so that session tickets keep working.
func TestFollowRoots(t *testing.T) {
	c1, c2 := newCA(t, td), newCA(t, td) // the old and the new root of one trust domain
	gwID, conID := gateway(orgA, gw1), connector(orgA, con1)
	gw := c1.agent(t, gwID, pki.MaxLeafLifetime)
	old, fresh := c1.agent(t, conID, pki.DefaultLeafLifetime), c2.agent(t, conID, pki.DefaultLeafLifetime)

	var pool atomic.Pointer[x509.CertPool]
	set := func(cs ...*ca) {
		p := x509.NewCertPool()
		for _, c := range cs {
			p.AddCert(c.root.Cert)
		}
		pool.Store(p)
	}
	set(c1)
	srv := pki.FollowRoots(pki.ServerConfig(gw.tls, c1.pool(), pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}}, c1.clock),
		func() *x509.CertPool { return pool.Load() })
	// The client trusts both roots, and its own certificate chains to whichever it has.
	both := x509.NewCertPool()
	both.AddCert(c1.root.Cert)
	both.AddCert(c2.root.Cert)
	client := func(own agent) *tls.Config {
		return pki.ClientConfig(own.tls, both, gwID.DNSName(), pki.Expect{TrustDomain: td, Exact: &gwID}, c1.clock, nil)
	}

	if r := run(t, srv, client(old)); !r.ok() {
		t.Fatalf("the old root's client: %v %v", r.srvErr, r.cliErr)
	}
	if r := run(t, srv, client(fresh)); r.srvErr == nil {
		t.Fatal("a client under a root the listener does not know was accepted")
	}
	set(c1, c2) // the overlap: the listener learned the new root
	for name, a := range map[string]agent{"old": old, "new": fresh} {
		if r := run(t, srv, client(a)); !r.ok() {
			t.Fatalf("%s client in the overlap: %v %v", name, r.srvErr, r.cliErr)
		}
	}
	set(c2) // the drop
	if r := run(t, srv, client(old)); r.srvErr == nil {
		t.Fatal("a client under the dropped root was accepted")
	}
	if r := run(t, srv, client(fresh)); !r.ok() {
		t.Fatalf("the new root's client after the drop: %v %v", r.srvErr, r.cliErr)
	}
}

// TestAgentEndpointConfigFollowing: the controller's listener takes the same pool at each handshake,
// also for Reauth, whose chain it verifies itself.
func TestAgentEndpointConfigFollowing(t *testing.T) {
	c1, c2 := newCA(t, td), newCA(t, td)
	ctl := c1.agent(t, node(ctn1), pki.ControllerLifetime)
	fresh := c2.agent(t, connector(orgA, con1), pki.DefaultLeafLifetime)
	var pool atomic.Pointer[x509.CertPool]
	pool.Store(c1.pool())
	srv := pki.AgentEndpointConfigFollowing(pki.NewHolder(ctl.tls), func() *x509.CertPool { return pool.Load() },
		pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}}, c1.clock, pki.Reauth{})
	both := x509.NewCertPool()
	both.AddCert(c1.root.Cert)
	both.AddCert(c2.root.Cert)
	cli := pki.ClientConfig(fresh.tls, both, "controller."+td, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindController}}, c1.clock, nil)
	if r := run(t, srv, cli); r.srvErr == nil {
		t.Fatal("an agent under an unknown root was accepted")
	}
	both2 := x509.NewCertPool()
	both2.AddCert(c1.root.Cert)
	both2.AddCert(c2.root.Cert)
	pool.Store(both2)
	if r := run(t, srv, cli); !r.ok() {
		t.Fatalf("after the roots changed: %v %v", r.srvErr, r.cliErr)
	}
}
