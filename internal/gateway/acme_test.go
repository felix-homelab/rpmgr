// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"strconv"
	"testing"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/tlspeek"
)

func challenge(action agentv1.AcmeAction, typ agentv1.AcmeChallengeType, id, token, ka string) *agentv1.AcmeChallenge {
	return &agentv1.AcmeChallenge{OpId: "op_1", Action: action, Type: typ, Identifier: id, Token: token, KeyAuthorization: ka}
}

const (
	add, remove = agentv1.AcmeAction_ACME_ACTION_ADD, agentv1.AcmeAction_ACME_ACTION_REMOVE
	http01      = agentv1.AcmeChallengeType_ACME_CHALLENGE_TYPE_HTTP_01
	alpn01      = agentv1.AcmeChallengeType_ACME_CHALLENGE_TYPE_TLS_ALPN_01
)

// TestChallenges: HTTP-01 and TLS-ALPN-01 challenges are added and removed by host; invalid ones
// are refused.
func TestChallenges(t *testing.T) {
	c := gateway.NewChallenges()
	if err := c.Apply(challenge(add, http01, "App.Example.test", "tok", "tok.ka")); err != nil {
		t.Fatal(err)
	}
	if ka, ok := c.HTTP01("app.example.test", "tok"); !ok || ka != "tok.ka" {
		t.Fatalf("HTTP-01: %q %v", ka, ok)
	}
	if _, ok := c.HTTP01("other.example.test", "tok"); ok {
		t.Fatal("a token answered for another host")
	}
	if err := c.Apply(challenge(add, alpn01, "app.example.test", "", "ka")); err != nil {
		t.Fatal(err)
	}
	cert := c.ALPN("APP.example.test.")
	if cert == nil || cert.Leaf == nil && len(cert.Certificate) == 0 {
		t.Fatal("no TLS-ALPN-01 certificate")
	}
	if c.Len() != 2 {
		t.Fatalf("%d challenges", c.Len())
	}
	_ = c.Apply(challenge(remove, http01, "app.example.test", "tok", ""))
	_ = c.Apply(challenge(remove, alpn01, "app.example.test", "", ""))
	if c.Len() != 0 || c.ALPN("app.example.test") != nil {
		t.Fatal("removed challenges still answer")
	}
	for name, ch := range map[string]*agentv1.AcmeChallenge{
		"no action":            challenge(agentv1.AcmeAction_ACME_ACTION_UNSPECIFIED, http01, "a.example.test", "t", "k"),
		"no key authorization": challenge(add, http01, "a.example.test", "t", ""),
		"a path in the token":  challenge(add, http01, "a.example.test", "../t", "k"),
		"no token":             challenge(add, http01, "a.example.test", "", "k"),
		"an IP address":        challenge(add, http01, "192.0.2.1", "t", "k"),
		"a wildcard":           challenge(add, alpn01, "*.example.test", "", "k"),
		"DNS-01":               challenge(add, agentv1.AcmeChallengeType_ACME_CHALLENGE_TYPE_UNSPECIFIED, "a.example.test", "t", "k"),
	} {
		if err := c.Apply(ch); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestChallenges_Limit: a gateway keeps at most 1000 challenges of both types together; a
// challenge it keeps can be replaced at the limit, and a removal makes room.
func TestChallenges_Limit(t *testing.T) {
	c := gateway.NewChallenges()
	for i := range 999 {
		if err := c.Apply(challenge(add, http01, "a.example.test", "t"+strconv.Itoa(i), "k")); err != nil {
			t.Fatalf("challenge %d: %v", i, err)
		}
	}
	if err := c.Apply(challenge(add, alpn01, "a.example.test", "", "k")); err != nil {
		t.Fatalf("the 1000th challenge: %v", err)
	}
	if err := c.Apply(challenge(add, http01, "a.example.test", "more", "k")); err == nil {
		t.Fatal("a 1001st HTTP-01 challenge")
	}
	if err := c.Apply(challenge(add, alpn01, "b.example.test", "", "k")); err == nil {
		t.Fatal("a 1001st TLS-ALPN-01 challenge")
	}
	if err := c.Apply(challenge(add, http01, "a.example.test", "t0", "k2")); err != nil {
		t.Fatalf("replacing an HTTP-01 challenge at the limit: %v", err)
	}
	if err := c.Apply(challenge(add, alpn01, "a.example.test", "", "k2")); err != nil {
		t.Fatalf("replacing a TLS-ALPN-01 challenge at the limit: %v", err)
	}
	if err := c.Apply(challenge(remove, http01, "a.example.test", "t0", "")); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(challenge(add, http01, "a.example.test", "more", "k")); err != nil || c.Len() != 1000 {
		t.Fatalf("after a removal: %v, %d challenges", err, c.Len())
	}
}

// TestRouter_TLSALPN01: a ClientHello with ALPN acme-tls/1 for a name with a TLS-ALPN-01
// challenge is answered with the challenge certificate, before any route of the name; without the
// ALPN, or without a challenge, the name is routed as usual. The certificate has the name and a
// critical acmeIdentifier extension with the key authorization's digest (RFC 8737). A real CA's
// validation of the handshake runs in internal/acme (TestACME_ValidationWaitsForEveryGateway).
func TestRouter_TLSALPN01(t *testing.T) {
	c := gateway.NewChallenges()
	if err := c.Apply(challenge(add, alpn01, "app.example.com", "", "ka")); err != nil {
		t.Fatal(err)
	}
	r := &gateway.Router{TrustDomain: td, GatewayID: "gw_01", ACME: c.ALPN,
		Routes: fakeRoutes{pass: map[string]bool{"app.example.com": true}, http: map[string]bool{}}}
	for _, tc := range []struct {
		sni  string
		alpn []string
		want gateway.Decision
	}{
		{"app.example.com", []string{"acme-tls/1"}, gateway.DecideACME},
		{"APP.example.com.", []string{"acme-tls/1"}, gateway.DecideACME},
		{"app.example.com", []string{"h2"}, gateway.DecidePassthrough},
		{"other.example.com", []string{"acme-tls/1"}, gateway.DecideDefault},
	} {
		if got := r.Decide(&tlspeek.ClientHello{ServerName: tc.sni, ALPN: tc.alpn}); got != tc.want {
			t.Errorf("%s %v: %s, want %s", tc.sni, tc.alpn, got, tc.want)
		}
	}
	cert, err := x509.ParseCertificate(c.ALPN("app.example.com").Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("ka"))
	want, _ := asn1.Marshal(digest[:])
	found := false
	for _, e := range cert.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}) {
			found = e.Critical && bytes.Equal(e.Value, want)
		}
	}
	if !found || len(cert.DNSNames) != 1 || cert.DNSNames[0] != "app.example.com" {
		t.Fatalf("challenge certificate: %v %v", cert.DNSNames, found)
	}
}
