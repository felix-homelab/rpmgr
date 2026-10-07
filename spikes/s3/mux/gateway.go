// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Names used by the test gateway. The gateway ID has the real ID format (prefix, underscore,
// upper-case Crockford base32), because it appears in a DNS SAN and in the SNI.
const (
	TestTrustDomain = "rpmgr-s3test01"
	TestOrg         = "org_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R"
	TestGatewayID   = "gw_01JA2Z8Q6W7Y3V9K4M5N6P7Q8S"
	TestConnectorID = "con_01JA2Z8Q6W7Y3V9K4M5N6P7Q8T"
	TestUIHost      = "panel.example.test"
	TestHTTPHost    = "app.example.test"
	TestHTTPHost2   = "api.example.test"
	TestPassHost    = "pass.example.test"
)

// TunnelName returns the gateway's tunnel name <gateway-id>.gateway.<td>.
func TunnelName() string { return TestGatewayID + ".gateway." + TestTrustDomain }

// Certs holds the spike's test PKI.
type Certs struct {
	Internal, Public                *CA
	Controller, Gateway, Connector  tls.Certificate
	UI, HTTP, HTTP2, Pass, Default  tls.Certificate
	ForeignGateway                  tls.Certificate // a valid gateway certificate of another gateway
	ConnectorSPIFFE, GatewaySPIFFE  string
}

// NewCerts creates every certificate the test gateway and its clients need.
func NewCerts() (*Certs, error) {
	var c Certs
	var err error
	td := TestTrustDomain
	if c.Internal, err = NewCA("rpmgr root "+td, "spiffe://"+td); err != nil {
		return nil, err
	}
	if c.Public, err = NewCA("S3 public test CA (stands in for ACME)", ""); err != nil {
		return nil, err
	}
	c.GatewaySPIFFE = fmt.Sprintf("spiffe://%s/org/%s/gateway/%s", td, TestOrg, TestGatewayID)
	c.ConnectorSPIFFE = fmt.Sprintf("spiffe://%s/org/%s/connector/%s", td, TestOrg, TestConnectorID)
	server, client := x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth
	steps := []struct {
		dst  *tls.Certificate
		ca   *CA
		dns  []string
		uri  string
		ekus []x509.ExtKeyUsage
	}{
		{&c.Controller, c.Internal, []string{"controller." + td, "reauth.controller." + td, "node1.controller." + td}, "spiffe://" + td + "/controller/node1", []x509.ExtKeyUsage{server, client}},
		{&c.Gateway, c.Internal, []string{TunnelName()}, c.GatewaySPIFFE, []x509.ExtKeyUsage{server, client}},
		{&c.ForeignGateway, c.Internal, []string{"gw_01JA2Z8Q6W7Y3V9K4M5N6P7Q8Z.gateway." + td}, fmt.Sprintf("spiffe://%s/org/%s/gateway/gw_01JA2Z8Q6W7Y3V9K4M5N6P7Q8Z", td, TestOrg), []x509.ExtKeyUsage{server, client}},
		{&c.Connector, c.Internal, []string{TestConnectorID + ".connector." + td}, c.ConnectorSPIFFE, []x509.ExtKeyUsage{client, server}},
		{&c.UI, c.Public, []string{TestUIHost}, "", []x509.ExtKeyUsage{server}},
		{&c.HTTP, c.Public, []string{TestHTTPHost}, "", []x509.ExtKeyUsage{server}},
		{&c.HTTP2, c.Public, []string{TestHTTPHost2}, "", []x509.ExtKeyUsage{server}},
		{&c.Pass, c.Public, []string{TestPassHost}, "", []x509.ExtKeyUsage{server}},
		{&c.Default, c.Public, []string{"default.invalid"}, "", []x509.ExtKeyUsage{server}},
	}
	for _, s := range steps {
		if *s.dst, err = s.ca.Leaf(s.dns, s.uri, s.ekus...); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

// Gateway wires a Router to an in-process controller, an HTTP engine, a tunnel endpoint and a
// TLS-passthrough backend, the way an all-in-one process would.
type Gateway struct {
	Certs  *Certs
	Router *Router
	UDP    *UDPMux

	httpLn, ctlLn *chanListener
	httpSrv       *http.Server
	ctlSrv        *http.Server
	passLn        net.Listener
	passSrv       *http.Server

	mu     sync.Mutex
	events []Event
	notes  []string
}

// NewGateway builds the test gateway. onEvent may be nil.
func NewGateway(certs *Certs, onEvent func(Event)) (*Gateway, error) {
	g := &Gateway{Certs: certs, httpLn: newChanListener(), ctlLn: newChanListener()}

	// TLS-passthrough backend: terminates TLS itself with a certificate the gateway never has.
	var err error
	if g.passLn, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		return nil, err
	}
	g.passSrv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "passthrough-backend sni=%s proto=%s\n", r.TLS.ServerName, r.Proto)
			g.note(fmt.Sprintf("passthrough-backend served sni=%s proto=%s ua=%q", r.TLS.ServerName, r.Proto, r.UserAgent()))
		}),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{certs.Pass}, NextProtos: []string{"h2", "http/1.1"}},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = g.passSrv.Serve(tls.NewListener(g.passLn, g.passSrv.TLSConfig)) }()

	// HTTP engine: one tls.Config for all http routes; GetConfigForClient picks the certificate.
	byName := map[string]tls.Certificate{TestHTTPHost: certs.HTTP, TestHTTPHost2: certs.HTTP2}
	httpTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			cert, ok := byName[strings.ToLower(chi.ServerName)]
			if !ok {
				return nil, fmt.Errorf("no certificate for %q", chi.ServerName)
			}
			return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}, nil
		},
	}
	g.httpSrv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "http-route host=%s proto=%s\n", r.Host, r.Proto)
			g.note(fmt.Sprintf("http-route served host=%s proto=%s ua=%q", r.Host, r.Proto, r.UserAgent()))
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = g.httpSrv.Serve(g.httpLn) }()

	// In-process controller: the agent name, the Reauth name and the UI on one TLS stack,
	// selected by SNI with GetConfigForClient (docs/04, "Controller certificates").
	td := TestTrustDomain
	internal := certs.Internal.Pool()
	ctlTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			switch strings.ToLower(chi.ServerName) {
			case "controller." + td:
				return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certs.Controller},
					ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: internal, NextProtos: []string{"h2"}}, nil
			case "reauth.controller." + td:
				// The expired-certificate verifier itself is spike S7; here only the selection.
				return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certs.Controller},
					ClientAuth: tls.RequireAnyClientCert, NextProtos: []string{"h2"}}, nil
			case TestUIHost:
				return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certs.UI},
					NextProtos: []string{"h2", "http/1.1"}}, nil
			}
			return nil, fmt.Errorf("controller: unknown name %q", chi.ServerName)
		},
	}
	g.ctlSrv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			endpoint, peer := "ui", ""
			switch strings.ToLower(r.TLS.ServerName) {
			case "controller." + td:
				endpoint = "agent"
			case "reauth.controller." + td:
				endpoint = "reauth"
			}
			if len(r.TLS.PeerCertificates) > 0 && len(r.TLS.PeerCertificates[0].URIs) == 1 {
				peer = r.TLS.PeerCertificates[0].URIs[0].String()
			}
			fmt.Fprintf(w, "controller endpoint=%s peer=%s proto=%s\n", endpoint, peer, r.Proto)
			g.note(fmt.Sprintf("controller served endpoint=%s peer=%s proto=%s ua=%q", endpoint, peer, r.Proto, r.UserAgent()))
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = g.ctlSrv.Serve(g.ctlLn) }()

	tunnelTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certs.Gateway},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    internal,
		NextProtos:   []string{ALPNTunnelH2},
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, err := SPIFFEFromChain(cs.VerifiedChains)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(id, "spiffe://"+td+"/org/") || !strings.Contains(id, "/connector/") {
				return fmt.Errorf("tunnel: %s is not a connector of this trust domain", id)
			}
			return nil
		},
	}

	g.Router = &Router{
		Name:          "tcp443",
		TrustDomain:   td,
		GatewayID:     strings.ToLower(TestGatewayID),
		ControllerUI:  []string{TestUIHost},
		Passthrough:   map[string]string{TestPassHost: g.passLn.Addr().String()},
		HTTPHostnames: map[string]bool{TestHTTPHost: true, TestHTTPHost2: true},
		Controller:    func(c net.Conn) { g.ctlLn.push(tls.Server(c, ctlTLS)) },
		HTTP:          func(c *tls.Conn) { g.httpLn.push(c) },
		Tunnel:        g.serveTunnelH2,
		TunnelTLS:     tunnelTLS,
		HTTPTLS:       httpTLS,
		DefaultTLS:    &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certs.Default}},
		OnEvent: func(ev Event) {
			g.mu.Lock()
			g.events = append(g.events, ev)
			g.mu.Unlock()
			if onEvent != nil {
				onEvent(ev)
			}
		},
	}
	return g, nil
}

// serveTunnelH2 stands in for the reverse-HTTP/2 data session (spike S2): it completes mutual
// TLS, then answers one line with the peer identity and echoes the rest.
func (g *Gateway) serveTunnelH2(c *tls.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if err := c.Handshake(); err != nil {
		g.note("tunnel-h2 handshake failed: " + err.Error())
		return
	}
	cs := c.ConnectionState()
	id, _ := SPIFFEFromChain(cs.VerifiedChains)
	g.note(fmt.Sprintf("tunnel-h2 session alpn=%s peer=%s", cs.NegotiatedProtocol, id))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	fmt.Fprintf(c, "tunnel-h2 peer=%s alpn=%s got=%s", id, cs.NegotiatedProtocol, line)
	_, _ = io.Copy(c, br)
}

// Events returns the routing events recorded so far.
func (g *Gateway) Events() []Event {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Event(nil), g.events...)
}

// Notes returns what the handlers behind the router saw.
func (g *Gateway) Notes() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.notes...)
}

func (g *Gateway) note(s string) {
	g.mu.Lock()
	g.notes = append(g.notes, s)
	g.mu.Unlock()
}

// Close stops the servers behind the router.
func (g *Gateway) Close() {
	_ = g.httpSrv.Close()
	_ = g.ctlSrv.Close()
	_ = g.passSrv.Close()
	if g.UDP != nil {
		_ = g.UDP.Close()
	}
}

// chanListener is a net.Listener fed by the router.
type chanListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{ch: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.closed:
		_ = c.Close()
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

