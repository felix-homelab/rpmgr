// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

// Criterion 3: per-identity DNS SANs with ServerName per peer; a valid certificate of another
// gateway is rejected; VerifyConnection checks the SPIFFE ID and the deny-list.
func TestServerNamePerPeer(t *testing.T) {
	clk := newClock()
	ca := newCA(t, clk)
	conID := connectorID("org_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R", "con_01JA2Z8Q6W7Y3V9K4M5N6P7Q8S")
	g1ID := gatewayID("org_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R", "gw_01JA2Z8Q6W7Y3V9K4M5N6P7Q8T")
	g2ID := gatewayID("org_01JB000000000000000000000B", "gw_01JB000000000000000000000C")
	con := issue(t, ca, conID, ProfileConnector, AgentLeafLifetime)
	g1 := issue(t, ca, g1ID, ProfileGatewayServer, AgentLeafLifetime)
	g2 := issue(t, ca, g2ID, ProfileGatewayServer, AgentLeafLifetime)

	gwSide := func(cert tls.Certificate, deny *DenyList) *tls.Config {
		return ServerConfig(cert, ca.Roots(), Expect{TrustDomain: td, Kinds: []Kind{KindConnector}, Deny: deny}, clk.Now)
	}
	conSide := func(deny *DenyList) *tls.Config {
		return ClientConfig(con.tls, ca.Roots(), g1ID.DNSName(), Expect{TrustDomain: td, Exact: &g1ID, Deny: deny}, clk.Now, nil)
	}

	t.Run("expected gateway", func(t *testing.T) {
		r := run(t, gwSide(g1.tls, nil), conSide(nil), nil, nil)
		if !r.ok() {
			t.Fatalf("server %v, client %v", r.srvErr, r.cliErr)
		}
		if r.cli.Version != tls.VersionTLS13 || r.cli.ServerName != g1ID.DNSName() {
			t.Fatalf("version %x, SNI %q", r.cli.Version, r.cli.ServerName)
		}
		t.Logf("ServerName %s accepted; IDs with upper-case base32 and '_' work in DNS SANs", g1ID.DNSName())
	})
	t.Run("valid certificate of another gateway", func(t *testing.T) {
		r := run(t, gwSide(g2.tls, nil), conSide(nil), nil, nil)
		var he x509.HostnameError
		if !errors.As(r.cliErr, &he) {
			t.Fatalf("client error %v, want a hostname error", r.cliErr)
		}
		t.Logf("client: %v", r.cliErr)
	})
	t.Run("right DNS name, wrong SPIFFE ID", func(t *testing.T) {
		f := forge(t, ca, []string{g2ID.String()}, []string{g1ID.DNSName()}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		r := run(t, gwSide(f.tls, nil), conSide(nil), nil, nil)
		if !errIs(r.cliErr, ErrWrongIdentity) {
			t.Fatalf("client error %v", r.cliErr)
		}
	})
	t.Run("gateway serial on the connector's deny-list", func(t *testing.T) {
		d := NewDenyList()
		d.AddSerial(g1.cert.SerialNumber)
		if r := run(t, gwSide(g1.tls, nil), conSide(d), nil, nil); !errIs(r.cliErr, ErrDenied) {
			t.Fatalf("client error %v", r.cliErr)
		}
	})
	t.Run("gateway identity on the connector's deny-list", func(t *testing.T) {
		d := NewDenyList()
		d.AddIdentity(g1ID.String())
		if r := run(t, gwSide(g1.tls, nil), conSide(d), nil, nil); !errIs(r.cliErr, ErrDenied) {
			t.Fatalf("client error %v", r.cliErr)
		}
	})
	t.Run("connector on the gateway's deny-list", func(t *testing.T) {
		d := NewDenyList()
		d.AddIdentity(conID.String())
		r := run(t, gwSide(g1.tls, d), conSide(nil), nil, nil)
		if !errIs(r.srvErr, ErrDenied) || r.cliErr == nil {
			t.Fatalf("server %v, client %v", r.srvErr, r.cliErr)
		}
	})
	t.Run("gateway client certificate used to open a data session", func(t *testing.T) {
		gc := issue(t, ca, g2ID, ProfileGatewayClient, AgentLeafLifetime)
		cli := ClientConfig(gc.tls, ca.Roots(), g1ID.DNSName(), Expect{TrustDomain: td, Exact: &g1ID}, clk.Now, nil)
		if r := run(t, gwSide(g1.tls, nil), cli, nil, nil); !errIs(r.srvErr, ErrWrongIdentity) {
			t.Fatalf("server %v", r.srvErr)
		}
	})
	t.Run("server-only certificate used as a client certificate", func(t *testing.T) {
		cli := ClientConfig(g2.tls, ca.Roots(), g1ID.DNSName(), Expect{TrustDomain: td, Exact: &g1ID}, clk.Now, nil)
		r := run(t, gwSide(g1.tls, nil), cli, nil, nil)
		if r.srvErr == nil || !strings.Contains(r.srvErr.Error(), "key usage") {
			t.Fatalf("server %v", r.srvErr)
		}
	})
	t.Run("no ServerName", func(t *testing.T) {
		cli := ClientConfig(con.tls, ca.Roots(), "", Expect{TrustDomain: td, Exact: &g1ID}, clk.Now, nil)
		r := run(t, gwSide(g1.tls, nil), cli, nil, nil)
		if r.cliErr == nil || !strings.Contains(r.cliErr.Error(), "either ServerName or InsecureSkipVerify") {
			t.Fatalf("client %v", r.cliErr)
		}
	})
	t.Run("TLS 1.2 client", func(t *testing.T) {
		cli := ClientConfig(con.tls, ca.Roots(), g1ID.DNSName(), Expect{TrustDomain: td, Exact: &g1ID}, clk.Now, nil)
		cli.MinVersion, cli.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		if r := run(t, gwSide(g1.tls, nil), cli, nil, nil); r.ok() {
			t.Fatal("TLS 1.2 handshake succeeded")
		}
	})
	t.Run("controller names", func(t *testing.T) {
		ctl := issue(t, ca, controllerID("node_1"), ProfileController, ControllerLifetime)
		srv := ServerConfig(ctl.tls, ca.Roots(), Expect{TrustDomain: td, Kinds: []Kind{KindConnector, KindGateway}}, clk.Now)
		for _, sni := range []string{"controller." + td, "reauth.controller." + td, "node_1.controller." + td} {
			cli := ClientConfig(con.tls, ca.Roots(), sni, Expect{TrustDomain: td, Kinds: []Kind{KindController}}, clk.Now, nil)
			if r := run(t, srv, cli, nil, nil); !r.ok() {
				t.Fatalf("%s: server %v, client %v", sni, r.srvErr, r.cliErr)
			}
		}
		// Another connector's certificate (also serverAuth) cannot pose as the controller.
		other := issue(t, ca, connectorID("org_a", "con_other"), ProfileConnector, AgentLeafLifetime)
		srv = ServerConfig(other.tls, ca.Roots(), Expect{TrustDomain: td}, clk.Now)
		cli := ClientConfig(con.tls, ca.Roots(), "controller."+td, Expect{TrustDomain: td, Kinds: []Kind{KindController}}, clk.Now, nil)
		var he x509.HostnameError
		if r := run(t, srv, cli, nil, nil); !errors.As(r.cliErr, &he) {
			t.Fatalf("client %v", r.cliErr)
		}
	})
}
