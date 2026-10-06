// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// Criterion 4: VerifyConnection runs on resumed TLS 1.3 sessions, on both sides, and rejects an
// identity revoked after the first handshake.
func TestResumptionRunsVerifyConnection(t *testing.T) {
	clk := newClock()
	ca := newCA(t, clk)
	conID := connectorID("org_a", "con_1")
	gwID := gatewayID("org_a", "gw_1")
	con := issue(t, ca, conID, ProfileConnector, AgentLeafLifetime)
	gw := issue(t, ca, gwID, ProfileGatewayServer, MaxLeafLifetime)

	setup := func() (*tls.Config, *tls.Config, *Counters, *Counters, *DenyList, *DenyList) {
		sc, cc := &Counters{}, &Counters{}
		sd, cd := NewDenyList(), NewDenyList()
		srv := ServerConfig(gw.tls, ca.Roots(), Expect{TrustDomain: td, Kinds: []Kind{KindConnector}, Deny: sd, Counters: sc}, clk.Now)
		cli := ClientConfig(con.tls, ca.Roots(), gwID.DNSName(), Expect{TrustDomain: td, Exact: &gwID, Deny: cd, Counters: cc},
			clk.Now, tls.NewLRUClientSessionCache(8))
		return srv, cli, sc, cc, sd, cd
	}

	t.Run("resumed handshake runs VerifyConnection on both sides", func(t *testing.T) {
		srv, cli, sc, cc, _, _ := setup()
		r1 := run(t, srv, cli, nil, nil)
		r2 := run(t, srv, cli, nil, nil)
		if !r1.ok() || !r2.ok() {
			t.Fatalf("%v %v %v %v", r1.srvErr, r1.cliErr, r2.srvErr, r2.cliErr)
		}
		if r1.srv.DidResume || !r2.srv.DidResume || !r2.cli.DidResume {
			t.Fatalf("DidResume: first %v, second server %v client %v", r1.srv.DidResume, r2.srv.DidResume, r2.cli.DidResume)
		}
		if len(r2.srv.PeerCertificates) == 0 || len(r2.srv.VerifiedChains) == 0 || len(r2.cli.PeerCertificates) == 0 {
			t.Fatal("resumed state lacks the peer certificates or verified chains")
		}
		for name, c := range map[string]*Counters{"server": sc, "client": cc} {
			if c.VerifyConnection.Load() != 2 || c.VerifyConnectionResumed.Load() != 1 {
				t.Fatalf("%s: VerifyConnection %d (resumed %d), want 2 (1)", name, c.VerifyConnection.Load(), c.VerifyConnectionResumed.Load())
			}
			// VerifyPeerCertificate does not run on resumption: rpmgr must not rely on it.
			if c.VerifyPeerCertificate.Load() != 1 {
				t.Fatalf("%s: VerifyPeerCertificate %d, want 1", name, c.VerifyPeerCertificate.Load())
			}
		}
	})
	t.Run("connector revoked after the first handshake", func(t *testing.T) {
		srv, cli, sc, _, sd, _ := setup()
		if r := run(t, srv, cli, nil, nil); !r.ok() {
			t.Fatal(r.srvErr, r.cliErr)
		}
		sd.AddIdentity(conID.String())
		r := run(t, srv, cli, nil, nil)
		if !errIs(r.srvErr, ErrDenied) || r.cliErr == nil {
			t.Fatalf("server %v, client %v", r.srvErr, r.cliErr)
		}
		if sc.VerifyConnectionResumed.Load() != 1 {
			t.Fatalf("the rejected handshake was not a resumption (resumed count %d)", sc.VerifyConnectionResumed.Load())
		}
	})
	t.Run("gateway revoked after the first handshake", func(t *testing.T) {
		srv, cli, _, cc, _, cd := setup()
		if r := run(t, srv, cli, nil, nil); !r.ok() {
			t.Fatal(r.srvErr, r.cliErr)
		}
		cd.AddSerial(gw.cert.SerialNumber)
		r := run(t, srv, cli, nil, nil)
		if !errIs(r.cliErr, ErrDenied) {
			t.Fatalf("client %v", r.cliErr)
		}
		if cc.VerifyConnectionResumed.Load() != 1 {
			t.Fatalf("the rejected handshake was not a resumption (resumed count %d)", cc.VerifyConnectionResumed.Load())
		}
	})
	t.Run("ticket of an expired client certificate is not resumed", func(t *testing.T) {
		start := clk.Now()
		defer clk.Set(start)
		// A 1-day certificate, so the ticket (7 days) and the ticket keys outlive it.
		short := issue(t, ca, conID, ProfileConnector, MinLeafLifetime)
		sc := &Counters{}
		srv := ServerConfig(gw.tls, ca.Roots(), Expect{TrustDomain: td, Kinds: []Kind{KindConnector}, Counters: sc}, clk.Now)
		cli := ClientConfig(short.tls, ca.Roots(), gwID.DNSName(), Expect{TrustDomain: td, Exact: &gwID}, clk.Now,
			tls.NewLRUClientSessionCache(8))
		if r := run(t, srv, cli, nil, nil); !r.ok() {
			t.Fatal(r.srvErr, r.cliErr)
		}
		clk.Set(short.cert.NotAfter.Add(-time.Minute))
		if r := run(t, srv, cli, nil, nil); !r.ok() || !r.srv.DidResume {
			t.Fatalf("control: resumption before expiry failed: %v %v %v", r.srvErr, r.cliErr, r.srv.DidResume)
		}
		clk.Set(short.cert.NotAfter.Add(time.Minute))
		r := run(t, srv, cli, nil, nil)
		if r.ok() || r.srv.DidResume || sc.VerifyConnectionResumed.Load() != 1 {
			t.Fatalf("server %v, client %v, resumed %v", r.srvErr, r.cliErr, r.srv.DidResume)
		}
		var cie x509.CertificateInvalidError
		if !errors.As(r.srvErr, &cie) || cie.Reason != x509.Expired {
			t.Fatalf("server error %v, want an expiry error from the full handshake", r.srvErr)
		}
	})
}
