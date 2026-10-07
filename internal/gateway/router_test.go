// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/tlspeek"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

const td = "rpmgr-7f3k2q6m"

// world is a test CA with a gateway and a connector.
type world struct {
	roots     *x509.CertPool
	gw, con   pki.Identity
	tunnelTLS *tls.Config // the gateway's mutual TLS
	conTLS    func(serverName string, alpn ...string) *tls.Config
}

func newWorld(t *testing.T) *world {
	t.Helper()
	now := time.Now()
	root, _ := pki.NewRoot(td, now)
	inter, _ := pki.NewIntermediate(root, now)
	is, err := pki.NewIssuer(root.Cert, inter, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	org := ids.New("org")
	w := &world{roots: x509.NewCertPool(), gw: pki.Identity{TrustDomain: td, Org: org, Kind: pki.KindGateway, ID: ids.New("gw")},
		con: pki.Identity{TrustDomain: td, Org: org, Kind: pki.KindConnector, ID: ids.New("con")}}
	w.roots.AddCert(root.Cert)
	leaf := func(id pki.Identity) tls.Certificate {
		key, _ := pki.NewKey()
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		csr, _ := x509.ParseCertificateRequest(der)
		c, err := is.IssueLeaf(csr, id, pki.DefaultLeafLifetime)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{c.Raw, inter.Cert.Raw}, PrivateKey: key, Leaf: c}
	}
	w.tunnelTLS = pki.ServerConfig(leaf(w.gw), w.roots, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}}, nil)
	conCert := leaf(w.con)
	w.conTLS = func(serverName string, alpn ...string) *tls.Config {
		c := pki.ClientConfig(conCert, w.roots, serverName, pki.Expect{TrustDomain: td, Exact: &w.gw}, nil, nil)
		c.NextProtos = alpn
		return c
	}
	return w
}

type fakeRoutes struct{ pass, http map[string]bool }

func (f fakeRoutes) Passthrough(sni string) (func(net.Conn), bool) {
	return func(c net.Conn) { _ = c.Close() }, f.pass[sni]
}
func (f fakeRoutes) HTTP(sni string) bool { return f.http[sni] }

func TestDecide(t *testing.T) {
	r := &gateway.Router{TrustDomain: td, GatewayID: "gw_01ABC", ControllerNames: []string{"panel.example.com"},
		Routes: fakeRoutes{pass: map[string]bool{"db.example.com": true}, http: map[string]bool{"app.example.com": true}}}
	own := "gw_01ABC.gateway." + td
	for _, tc := range []struct {
		sni  string
		alpn []string
		want gateway.Decision
	}{
		{"controller." + td, nil, gateway.DecideController},
		{"reauth.controller." + td, nil, gateway.DecideController},
		{"PANEL.example.com", nil, gateway.DecideController},
		{own, []string{tunnel.ALPNH2}, gateway.DecideTunnelH2},
		{strings.ToLower(own) + ".", []string{"h2", tunnel.ALPNH2}, gateway.DecideTunnelH2},
		{own, []string{"h2"}, gateway.DecideDefault},                               // the tunnel name without the tunnel ALPN
		{"gw_02XYZ.gateway." + td, []string{tunnel.ALPNH2}, gateway.DecideDefault}, // another gateway's name
		{"app.example.com", []string{tunnel.ALPNH2}, gateway.DecideHTTP},           // the tunnel ALPN on another name
		{"db.example.com", nil, gateway.DecidePassthrough},
		{"app.example.com", []string{"h2", "http/1.1"}, gateway.DecideHTTP},
		{"unknown.example.com", nil, gateway.DecideDefault},
		{"", nil, gateway.DecideDefault},
	} {
		if got := r.Decide(&tlspeek.ClientHello{ServerName: tc.sni, ALPN: tc.alpn}); got != tc.want {
			t.Errorf("%q %v: %s, want %s", tc.sni, tc.alpn, got, tc.want)
		}
	}
}

// serve runs the router on a loopback port.
func serve(t *testing.T, r *gateway.Router) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = r.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func TestRouter(t *testing.T) {
	w := newWorld(t)
	def, err := gateway.DefaultTLS()
	if err != nil {
		t.Fatal(err)
	}
	controller := make(chan []byte, 1)
	tunnels := make(chan error, 1)
	r := &gateway.Router{TrustDomain: td, GatewayID: w.gw.ID, TunnelTLS: w.tunnelTLS, DefaultTLS: def,
		Controller: func(c net.Conn) {
			b := make([]byte, 1)
			_, _ = io.ReadFull(c, b)
			controller <- b
			_ = c.Close()
		},
		Tunnel: func(c *tls.Conn) {
			tunnels <- c.Handshake()
			_ = c.Close()
		}}
	addr := serve(t, r)

	// The controller's names reach its handler with the ClientHello replayed.
	go func() {
		c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "controller." + td, RootCAs: w.roots, MinVersion: tls.VersionTLS13})
		if err == nil {
			_ = c.Close()
		}
	}()
	if b := <-controller; b[0] != 0x16 {
		t.Fatalf("the controller got %x first, not the replayed handshake record", b)
	}

	// This gateway's tunnel name with the tunnel ALPN: a mutual TLS data session.
	c, err := tls.Dial("tcp", addr, w.conTLS(w.gw.DNSName(), tunnel.ALPNH2))
	if err != nil {
		t.Fatalf("the tunnel handshake: %v", err)
	}
	_ = c.Close()
	if err := <-tunnels; err != nil {
		t.Fatalf("the gateway's side of the tunnel handshake: %v", err)
	}

	// Unknown names get the default certificate, then the connection closes.
	pool := x509.NewCertPool()
	defLeaf, _ := x509.ParseCertificate(def.Certificates[0].Certificate[0])
	pool.AddCert(defLeaf)
	for _, sni := range []string{"unknown.example.com", "gw_other.gateway." + td} {
		_, err := tls.Dial("tcp", addr, &tls.Config{ServerName: sni, RootCAs: pool, MinVersion: tls.VersionTLS13, NextProtos: []string{tunnel.ALPNH2}})
		var hostErr x509.HostnameError
		if !errors.As(err, &hostErr) || hostErr.Certificate.Subject.CommonName != "default.invalid" {
			t.Errorf("%s: %v, want the default certificate", sni, err)
		}
	}

	// Not TLS: closed without an answer.
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = raw.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := raw.Read(make([]byte, 64)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("plain HTTP: %d bytes, %v; want a close", n, err)
	}
	_ = raw.Close()
}

// TestQUICTLS: the UDP listener completes a handshake only for this gateway's tunnel name with the
// tunnel ALPN; h3 and other names are refused.
func TestQUICTLS(t *testing.T) {
	w := newWorld(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() { _ = tr.Close() })
	ln, err := tr.Listen(gateway.QUICTLS(td, w.gw.ID, w.tunnelTLS), tunnel.QUICConfig(false, tunnel.NewBudget(tunnel.DefaultWindowBudget)))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			_ = c.CloseWithError(0, "")
		}
	}()
	cpc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	ctr := &quic.Transport{Conn: cpc}
	t.Cleanup(func() { _ = ctr.Close() })
	dial := func(cfg *tls.Config) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := ctr.Dial(ctx, pc.LocalAddr(), cfg, tunnel.QUICConfig(true, tunnel.NewBudget(tunnel.DefaultWindowBudget)))
		if err == nil {
			_ = c.CloseWithError(0, "")
		}
		return err
	}
	if err := dial(w.conTLS(w.gw.DNSName(), tunnel.ALPNQUIC)); err != nil {
		t.Fatalf("the tunnel: %v", err)
	}
	if err := dial(w.conTLS(w.gw.DNSName(), "h3")); err == nil {
		t.Fatal("h3 was accepted")
	}
	if err := dial(w.conTLS("gw_other.gateway."+td, tunnel.ALPNQUIC)); err == nil {
		t.Fatal("another gateway's name was accepted")
	}
}
