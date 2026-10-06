// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

func verifyLeaf(ca *CA, c *x509.Certificate) error {
	inter := x509.NewCertPool()
	inter.AddCert(ca.Intermediate)
	_, err := c.Verify(x509.VerifyOptions{Roots: ca.Roots(), Intermediates: inter, CurrentTime: ca.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// Criterion 2: Go's verifier enforces the intermediate's URI and DNS name constraints.
func TestNameConstraintsEnforced(t *testing.T) {
	clk := newClock()
	ca := newCA(t, clk)
	unconstrained, err := NewCA(td, clk.Now, false)
	if err != nil {
		t.Fatal(err)
	}
	ekus := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	good := "spiffe://" + td + "/org/org_a/connector/con_1"
	cases := []struct {
		name       string
		uris, dns  []string
		x509OK     bool // passes Go's chain verification under the constrained intermediate
		identityOK bool // passes rpmgr's VerifyConnection identity check
	}{
		{"in domain", []string{good}, []string{"con_1.connector." + td}, true, true},
		{"URI in another trust domain", []string{"spiffe://rpmgr-otherdom/org/org_a/connector/con_1"}, []string{"con_1.connector." + td}, false, false},
		{"URI host with the domain as a non-label suffix", []string{"spiffe://x" + td + "/org/org_a/connector/con_1"}, nil, false, false},
		{"URI host a sub-domain of the trust domain", []string{"spiffe://evil." + td + "/org/org_a/connector/con_1"}, nil, true, false},
		{"URI host in upper case", []string{"spiffe://" + strings.ToUpper(td) + "/org/org_a/connector/con_1"}, nil, true, false},
		{"URI with empty host", []string{"spiffe:///org/org_a/connector/con_1"}, nil, false, false},
		{"URI with an IP host", []string{"spiffe://127.0.0.1/org/org_a/connector/con_1"}, nil, false, false},
		{"DNS name in another domain", []string{good}, []string{"con_1.connector.rpmgr-otherdom"}, false, true},
		{"DNS name with the domain as a non-label suffix", []string{good}, []string{"con_1.connector.x" + td}, false, true},
		{"DNS name equal to the trust domain", []string{good}, []string{td}, true, true},
		{"no SAN at all", nil, nil, true, false},
		{"two URI SANs", []string{good, "spiffe://" + td + "/controller/ctl_1"}, nil, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := forge(t, ca, c.uris, c.dns, ekus)
			err := verifyLeaf(ca, l.cert)
			if (err == nil) != c.x509OK {
				t.Fatalf("x509.Verify: %v (want ok=%v)", err, c.x509OK)
			}
			var cie x509.CertificateInvalidError
			if err != nil && !(errors.As(err, &cie) && cie.Reason == x509.CANotAuthorizedForThisName) {
				t.Fatalf("x509.Verify error is not CANotAuthorizedForThisName: %v", err)
			}
			if err != nil {
				t.Logf("rejected by name constraints: %v", err)
			}
			idErr := Expect{TrustDomain: td}.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{l.cert}})
			if (idErr == nil) != c.identityOK {
				t.Fatalf("VerifyConnection: %v (want ok=%v)", idErr, c.identityOK)
			}
			// Control: the same names under an intermediate without constraints chain fine, so the
			// constraints are what rejects them (URIs that cannot be matched at all excepted).
			if !c.x509OK && c.uris != nil && !strings.HasPrefix(c.uris[0], "spiffe:///") && !strings.Contains(c.uris[0], "127.0.0.1") {
				if err := verifyLeaf(unconstrained, forge(t, unconstrained, c.uris, c.dns, ekus).cert); err != nil {
					t.Fatalf("control without constraints: %v", err)
				}
			}
		})
	}
}

// The constraints also stop a forged server certificate in a real handshake.
func TestNameConstraintsInHandshake(t *testing.T) {
	clk := newClock()
	ca := newCA(t, clk)
	con := issue(t, ca, connectorID("org_a", "con_1"), ProfileConnector, AgentLeafLifetime)
	gw := gatewayID("org_a", "gw_1")
	// Right DNS name and an out-of-domain URI.
	forged := forge(t, ca, []string{"spiffe://rpmgr-otherdom/org/org_a/gateway/gw_1"}, []string{gw.DNSName()},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	srv := ServerConfig(forged.tls, ca.Roots(), Expect{TrustDomain: td, Kinds: []Kind{KindConnector}}, clk.Now)
	cli := ClientConfig(con.tls, ca.Roots(), gw.DNSName(), Expect{TrustDomain: td, Exact: &gw}, clk.Now, nil)
	r := run(t, srv, cli, nil, nil)
	var cie x509.CertificateInvalidError
	if r.cliErr == nil || !errors.As(r.cliErr, &cie) || cie.Reason != x509.CANotAuthorizedForThisName {
		t.Fatalf("client error %v", r.cliErr)
	}
	t.Logf("client: %v", r.cliErr)
}
