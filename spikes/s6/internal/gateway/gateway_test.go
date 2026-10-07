// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/asn1"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
)

func start(t *testing.T) (*Gateway, string, string) {
	t.Helper()
	h, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := New("gw1", h, s)
	t.Cleanup(g.Close)
	return g, h.Addr().String(), s.Addr().String()
}

func get(t *testing.T, addr, host, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestHTTP01OnlyForPushedChallenge(t *testing.T) {
	g, httpAddr, _ := start(t)
	ch := acme.Challenge{Type: acme.ChallengeTypeHTTP01, Token: "tok", KeyAuthorization: "tok.thumb",
		Identifier: acme.Identifier{Type: "dns", Value: "App.Example.test"}}
	if code, _ := get(t, httpAddr, "app.example.test", "/.well-known/acme-challenge/tok"); code != 404 {
		t.Fatalf("before the push: HTTP %d, want 404", code)
	}
	if err := g.ApplyChallenge(context.Background(), ChallengeUpdate{Challenge: ch}); err != nil {
		t.Fatal(err)
	}
	if code, body := get(t, httpAddr, "app.example.test:80", "/.well-known/acme-challenge/tok"); code != 200 || body != "tok.thumb" {
		t.Fatalf("pushed challenge: HTTP %d %q", code, body)
	}
	for _, tc := range []struct{ host, path string }{
		{"app.example.test", "/.well-known/acme-challenge/other"}, // wrong token
		{"other.example.test", "/.well-known/acme-challenge/tok"}, // wrong host
		{"app.example.test", "/"},                                 // not a challenge path
	} {
		if code, _ := get(t, httpAddr, tc.host, tc.path); code != 404 {
			t.Errorf("%s%s: HTTP %d, want 404", tc.host, tc.path, code)
		}
	}
	// Removal with another token does not remove the current challenge; with the token it does.
	_ = g.ApplyChallenge(context.Background(), ChallengeUpdate{Remove: true, Challenge: acme.Challenge{
		Token: "old", Identifier: ch.Identifier}})
	if !g.HasChallenge("app.example.test") {
		t.Fatal("removal of a stale token removed the current challenge")
	}
	_ = g.ApplyChallenge(context.Background(), ChallengeUpdate{Remove: true, Challenge: ch})
	if code, _ := get(t, httpAddr, "app.example.test", "/.well-known/acme-challenge/tok"); code != 404 {
		t.Fatalf("after removal: HTTP %d, want 404", code)
	}
}

func TestApplyChallengeRejectsInvalidUpdates(t *testing.T) {
	g, _, _ := start(t)
	for _, ch := range []acme.Challenge{
		{Type: acme.ChallengeTypeHTTP01, Token: "t", KeyAuthorization: "k"},                  // no identifier
		{Type: acme.ChallengeTypeDNS01, Token: "t", KeyAuthorization: "k", Identifier: id()}, // not for gateways
		{Type: acme.ChallengeTypeHTTP01, Token: "", KeyAuthorization: "k", Identifier: id()}, // no token
		{Type: acme.ChallengeTypeHTTP01, Token: "t", KeyAuthorization: "", Identifier: id()}, // no key auth
	} {
		if err := g.ApplyChallenge(context.Background(), ChallengeUpdate{Challenge: ch}); err == nil {
			t.Errorf("ApplyChallenge(%+v) succeeded", ch)
		}
	}
}

func id() acme.Identifier { return acme.Identifier{Type: "dns", Value: "a.example.test"} }

func TestTLSALPN01OnlyForPushedChallenge(t *testing.T) {
	g, _, tlsAddr := start(t)
	dial := func() error {
		c, err := tls.Dial("tcp", tlsAddr, &tls.Config{ServerName: "a.example.test",
			NextProtos: []string{acmez.ACMETLS1Protocol}, InsecureSkipVerify: true}) //nolint:gosec // the TLS-ALPN-01 certificate is self-signed by design; the test checks its extension below
		if err != nil {
			return err
		}
		defer c.Close()
		if c.ConnectionState().NegotiatedProtocol != acmez.ACMETLS1Protocol {
			t.Errorf("negotiated %q", c.ConnectionState().NegotiatedProtocol)
		}
		// RFC 8737: the validator checks the acmeIdentifier extension, an OCTET STRING holding
		// SHA-256 of the key authorization, not the certificate chain.
		leaf := c.ConnectionState().PeerCertificates[0]
		sum := sha256.Sum256([]byte("t.k"))
		want, _ := asn1.Marshal(sum[:])
		found := false
		for _, ext := range leaf.Extensions {
			if ext.Id.String() == "1.3.6.1.5.5.7.1.31" { // id-pe-acmeIdentifier
				found = ext.Critical && bytes.Equal(ext.Value, want)
			}
		}
		if !found || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "a.example.test" {
			t.Errorf("challenge certificate without the right acmeIdentifier, or with wrong names: %v", leaf.DNSNames)
		}
		return nil
	}
	if err := dial(); err == nil {
		t.Fatal("TLS-ALPN-01 handshake succeeded before the push")
	}
	ch := acme.Challenge{Type: acme.ChallengeTypeTLSALPN01, Token: "t", KeyAuthorization: "t.k", Identifier: id()}
	if err := g.ApplyChallenge(context.Background(), ChallengeUpdate{Challenge: ch}); err != nil {
		t.Fatal(err)
	}
	if err := dial(); err != nil {
		t.Fatalf("TLS-ALPN-01 handshake after the push: %v", err)
	}
	if g.ALPNAnswered.Load() != 1 {
		t.Fatalf("ALPNAnswered = %d", g.ALPNAnswered.Load())
	}
}
