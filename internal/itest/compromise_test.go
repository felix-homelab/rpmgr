// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// refusedAfterHandshake dials addr with cfg and reports whether the peer refused: the handshake failed, or,
// as TLS 1.3 reports a refused client certificate only once the client reads, the first read was an alert.
func refusedAfterHandshake(t *testing.T, addr string, cfg *tls.Config) bool {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return true
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	_, err = conn.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false // the server waits for a request: it accepted
	}
	return err != nil
}

// serveTLS serves cfg on a loopback port, accepting and completing handshakes until the test ends.
func serveTLS(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				if tc, ok := conn.(*tls.Conn); ok && tc.Handshake() == nil {
					_, _ = conn.Read(make([]byte, 1)) // holds a session that was accepted open until the client leaves
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// TestCA_CompromisedRootRefusedEverywhere: after `ca new-root --compromised` a controller, a gateway and an
// agent that trust the new root refuse every certificate of the old chain, on control sessions, Reauth, the
// data plane in both directions and the controller-to-controller listener's configuration; the trust bundle
// holds the new root alone; enrolling with the old pin fails and uses no token; every certificate is
// revoked; and the single-use tokens, written to a file of mode 0600 and logged nowhere, enroll each agent
// again under its old identity, gateway first.
func TestCA_CompromisedRootRefusedEverywhere(t *testing.T) {
	ctx := context.Background()
	c := itest.StartController(t, itest.Options{})
	dir := t.TempDir()
	td := c.CA.TrustDomain()
	oldRoot, oldPin := c.CA.Root(), pki.RootPin(c.CA.Root())
	gw := c.EnrollGateway(t, filepath.Join(dir, "gw"), c.GatewayGroup(t, "edge"), []string{"127.0.0.1:1"})
	con := c.EnrollConnector(t, filepath.Join(dir, "con"))
	oldNode, err := c.CA.NodeCertificate(c.Sys, c.DB, ids.New("ctn"))
	if err != nil {
		t.Fatal(err)
	}

	// The controller host: every controller stopped, the command run, the new keys loaded, a controller started.
	c.Stop()
	tokensFile := filepath.Join(dir, "tokens")
	res, err := controller.ReplaceCompromisedRoot(ctx, controller.CompromiseOptions{ConfigPath: c.BootFile(t), TokensOut: tokensFile,
		Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CA.Reload(c.Sys, c.DB, c.Sealer(), time.Now); err != nil {
		t.Fatal(err)
	}
	newRoot := c.CA.Root()
	if newRoot.Equal(oldRoot) || res.Pin != pki.RootPin(newRoot) || res.Pin == oldPin {
		t.Fatalf("the new root: pin %q, old %q", res.Pin, oldPin)
	}
	// Every certificate is revoked, before the new controller issues its own node certificate.
	if n := c.DB.Client().IssuedCertificate.Query().Where(issuedcertificate.RevokedAtIsNil(), issuedcertificate.NotAfterGT(time.Now())).CountX(c.Sys); n != 0 {
		t.Fatalf("%d certificates are not revoked", n)
	}
	if n := c.DB.Client().IssuedCertificate.Query().Where(issuedcertificate.RevocationReason("ca_compromised")).CountX(c.Sys); n < 3 {
		t.Fatalf("%d certificates revoked as ca_compromised, want the gateway's, the connector's and the node's", n)
	}

	url2, sessions2 := c.StartReplica(t)
	addr2 := strings.TrimPrefix(url2, "https://")

	// The tokens: a file of mode 0600 with one single-use token per agent, none in any log.
	if st, err := os.Stat(tokensFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("tokens file: %v, %v", st, err)
	}
	raw, err := os.ReadFile(tokensFile)
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{} // agent ID -> token
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if f := strings.Split(l, "\t"); !strings.HasPrefix(l, "#") && len(f) == 5 {
			tokens[f[2]] = f[4]
			c.Logs.Secret(f[4]) // any line of any log that holds it fails the test
		}
	}
	if len(tokens) != 2 || tokens[gw.AgentID] == "" || tokens[con.AgentID] == "" {
		t.Fatalf("%d tokens, want one for the gateway %s and one for the connector %s", len(tokens), gw.AgentID, con.AgentID)
	}

	// The trust bundle the controller serves holds the new root alone.
	web := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: c.UIRoots, MinVersion: tls.VersionTLS13}}}
	resp, err := web.Get(url2 + "/.well-known/rpmgr/trust-bundle")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var served []*x509.Certificate
	for rest := body; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		served = append(served, cert)
	}
	if len(served) != 1 || !served[0].Equal(newRoot) {
		t.Fatalf("the trust bundle holds %d certificates, want the new root alone", len(served))
	}

	// Enrollment with the old pin fails, and leaves the token unused; with the new pin it succeeds.
	enrollWith := func(id agent.Loaded, pin string) error {
		_, err := agent.Enroll(ctx, agent.EnrollOptions{Controller: url2, Pin: pin, Token: tokens[id.AgentID], IdentityDir: id.Dir, Replace: true, HTTPClient: web,
			Host: &agentv1.HostFacts{Hostname: "itest"}, Version: "0.1.0"})
		return err
	}
	if err := enrollWith(gw, oldPin); err == nil {
		t.Fatal("enrollment with the old pin succeeded")
	}
	if row := c.DB.Client().EnrollmentToken.Query().Where(enrollmenttoken.TokenHash(token.Hash(tokens[gw.AgentID]))).OnlyX(c.Sys); row.UseCount != 0 || row.RevokedAt != nil {
		t.Fatalf("the refused enrollment used the token: %+v", row)
	}

	// Control sessions and Reauth: the old chain is refused by the new controller; a real agent that holds the
	// old identity gets no session.
	toController := func(cert tls.Certificate, sni string) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.CA.RootsPool(), ServerName: sni, Certificates: []tls.Certificate{cert}}
	}
	for _, sni := range []string{"controller." + td, "reauth.controller." + td} {
		if !refusedAfterHandshake(t, addr2, toController(con.Certificate, sni)) {
			t.Errorf("the controller accepted the old connector certificate for %s", sni)
		}
		if !refusedAfterHandshake(t, addr2, toController(gw.Certificate, sni)) {
			t.Errorf("the controller accepted the old gateway certificate for %s", sni)
		}
	}
	oldClient, _, _ := run(t, agent.ClientOptions{Identity: con, Endpoints: []string{url2}, Version: "0.1.0"})
	time.Sleep(500 * time.Millisecond)
	if welcomes(oldClient) != 0 || len(sessions2.Connected()) != 0 {
		t.Fatal("an agent with the old identity has a control session")
	}

	// Re-enrollment under the old identities, gateway first; a token is single-use.
	for _, id := range []agent.Loaded{gw, con} {
		if err := enrollWith(id, res.Pin); err != nil {
			t.Fatalf("re-enrolling %s: %v", id.AgentID, err)
		}
	}
	if err := enrollWith(con, res.Pin); err == nil {
		t.Fatal("a token enrolled twice")
	}
	newGW, err := agent.Load(gw.Dir)
	if err != nil {
		t.Fatal(err)
	}
	newCon, err := agent.Load(con.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]agent.Loaded{{gw, newGW}, {con, newCon}} {
		old, now := pair[0], pair[1]
		if now.AgentID != old.AgentID || now.Certificate.Leaf.URIs[0].String() != old.Certificate.Leaf.URIs[0].String() ||
			now.Certificate.Leaf.SerialNumber.Cmp(old.Certificate.Leaf.SerialNumber) == 0 {
			t.Errorf("%s: the new certificate %s is not a new one under the old identity %s", old.AgentID, now.Certificate.Leaf.URIs[0], old.Certificate.Leaf.URIs[0])
		}
		if len(now.RootCerts) != 1 || !now.RootCerts[0].Equal(newRoot) {
			t.Errorf("%s holds %d roots after re-enrolling, want the new root alone", old.AgentID, len(now.RootCerts))
		}
	}
	_, _, _ = run(t, agent.ClientOptions{Identity: newCon, Endpoints: []string{url2}, Version: "0.1.0"})
	waitFor(t, "a session of the re-enrolled connector", func() bool { return slices.Contains(sessions2.Connected(), newCon.AgentID) })

	// The gateway, as the connectors' dial meets it: its listener takes the roots the agent holds, which
	// refuses a connector of the old chain and accepts one of the new; a connector refuses a gateway of the old
	// chain.
	expectConnector := pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}}
	gwAddr := serveTLS(t, pki.ServerConfig(newGW.Certificate, newGW.Roots, expectConnector, nil))
	toGateway := func(own tls.Certificate, roots *x509.CertPool) *tls.Config {
		return pki.ClientConfig(own, roots, newGW.Certificate.Leaf.DNSNames[0], pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindGateway}}, nil, nil)
	}
	if refusedAfterHandshake(t, gwAddr, toGateway(newCon.Certificate, newCon.Roots)) {
		t.Error("the gateway refused a connector of the new chain")
	}
	if !refusedAfterHandshake(t, gwAddr, toGateway(con.Certificate, newCon.Roots)) {
		t.Error("the gateway accepted a connector of the old chain")
	}
	oldGWAddr := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{gw.Certificate}, MinVersion: tls.VersionTLS13})
	if !refusedAfterHandshake(t, oldGWAddr, toGateway(newCon.Certificate, newCon.Roots)) {
		t.Error("a connector of the new chain accepted a gateway of the old chain")
	}

	// The controller-to-controller listener takes the controller's roots at each handshake.
	newNode, err := c.CA.NodeCertificate(c.Sys, c.DB, ids.New("ctn"))
	if err != nil {
		t.Fatal(err)
	}
	peer := pki.FollowRoots(pki.ServerConfig(newNode, c.CA.RootsPool(), pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindController}}, nil), c.CA.RootsPool)
	peerAddr := serveTLS(t, peer)
	toPeer := func(own tls.Certificate) *tls.Config {
		return pki.ClientConfig(own, c.CA.RootsPool(), newNode.Leaf.DNSNames[0], pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindController}}, nil, nil)
	}
	if refusedAfterHandshake(t, peerAddr, toPeer(newNode)) {
		t.Error("a controller of the new chain was refused by its peer")
	}
	if !refusedAfterHandshake(t, peerAddr, toPeer(oldNode)) {
		t.Error("a controller node of the old chain was accepted")
	}
}
