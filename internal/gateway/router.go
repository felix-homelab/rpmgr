// SPDX-License-Identifier: Apache-2.0

// Package gateway is the gateway role (docs/02-architecture.md): its public listeners on port 443
// and on the routes' ports, the data sessions from connectors, and the relays between them.
package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez/v3"

	"github.com/felix-homelab/rpmgr/internal/tlspeek"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// defaultHandshake bounds the handshake with the default certificate for an unknown name.
const defaultHandshake = 5 * time.Second

// Decision is what the router does with one TCP/443 connection (docs/03-connections.md, "Port 443
// multiplexing").
type Decision string

// The decisions, one per row of 03's table, and the peek failures.
const (
	DecideController  Decision = "controller"  // controller.<td>, reauth.controller.<td>, UI names
	DecideTunnelH2    Decision = "tunnel-h2"   // <this gateway>.gateway.<td> and ALPN rpmgr-tunnel-h2/1
	DecidePassthrough Decision = "passthrough" // the SNI of a TLS-passthrough route
	DecideACME        Decision = "acme"        // ALPN acme-tls/1 for a name with a TLS-ALPN-01 challenge
	DecideHTTP        Decision = "http"        // the SNI of an http route
	DecideWSS         Decision = "wss"         // this gateway's WSS hostname
	DecideDefault     Decision = "default"     // no SNI, or an unknown one
	DecideNotTLS      Decision = "not-tls"     // not a TLS handshake
	DecidePeekFailed  Decision = "peek-failed" // too slow, too large or malformed
)

// Routes answers which routes serve a name; the route table of the gateway's snapshot implements
// it.
type Routes interface {
	// Passthrough returns the handler of the TLS-passthrough route for sni.
	Passthrough(sni string) (func(net.Conn), bool)
	// HTTP reports whether an http route serves sni.
	HTTP(sni string) bool
}

// Router multiplexes TCP/443: it peeks at the ClientHello without consuming it and hands the
// connection, with the recorded bytes replayed, to the handler the table chooses.
type Router struct {
	TrustDomain string
	GatewayID   string
	// ControllerNames are the controller UI hostnames; the agent names controller.<td> and
	// reauth.controller.<td> always go to Controller.
	ControllerNames []string
	// Controller takes the controller's connections, still encrypted: the in-process controller
	// (all-in-one) or the forwarding to a private one (5.12); nil closes them.
	Controller func(net.Conn)
	// Tunnel takes a data session over TLS and reverse HTTP/2, after the mutual TLS handshake
	// with TunnelTLS.
	Tunnel    func(*tls.Conn)
	TunnelTLS *tls.Config
	Routes    Routes
	// HTTP takes the connections of http routes; HTTPTLS picks the certificate per name.
	HTTP    func(*tls.Conn)
	HTTPTLS *tls.Config
	// WSSHostname, if set, returns this gateway's WSS hostname, "" for none; WSS takes its
	// connections over TLS with WSSTLS, which presents the hostname's public certificate.
	WSSHostname func() string
	WSS         func(*tls.Conn)
	WSSTLS      *tls.Config
	// ACME, if set, returns the acme-tls/1 certificate of a pending TLS-ALPN-01 challenge for a
	// name, or nil.
	ACME func(sni string) *tls.Certificate
	// Unrouted, if set, takes the connections of unknown names, or of none, over TLS with
	// UnroutedTLS, and answers them with the gateway's page (D87).
	Unrouted    func(*tls.Conn)
	UnroutedTLS *tls.Config
	// DefaultTLS completes the handshake for an unknown name before the connection is closed,
	// when Unrouted is not set.
	DefaultTLS *tls.Config
	Logger     *slog.Logger

	wg, tunnels sync.WaitGroup
}

// Serve accepts connections until l is closed.
func (r *Router) Serve(l net.Listener) error { return serve(l, &r.wg, r.Handle) }

// ServeTunnels accepts connections until l is closed and serves them as HandleTunnel does.
func (r *Router) ServeTunnels(l net.Listener) error { return serve(l, &r.tunnels, r.HandleTunnel) }

// serve hands every connection l accepts to handle and, once l is closed, waits for them.
func serve(l net.Listener, wg *sync.WaitGroup, handle func(net.Conn)) error {
	for {
		c, err := l.Accept()
		if err != nil {
			wg.Wait()
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wg.Go(func() { handle(c) })
	}
}

// Decide applies 03's table to a ClientHello. Names are compared case-insensitively.
func (r *Router) Decide(ch *tlspeek.ClientHello) Decision {
	sni := strings.ToLower(strings.TrimSuffix(ch.ServerName, "."))
	td := strings.ToLower(r.TrustDomain)
	switch {
	case sni == "":
		return DecideDefault
	case sni == "controller."+td || sni == "reauth.controller."+td || slices.ContainsFunc(r.ControllerNames,
		func(n string) bool { return strings.EqualFold(n, sni) }):
		return DecideController
	case strings.HasSuffix(sni, ".gateway."+td):
		// Only this gateway's own name, and only with the tunnel ALPN; any other name under
		// .gateway.<td> is unknown.
		if sni == strings.ToLower(r.GatewayID)+".gateway."+td && slices.Contains(ch.ALPN, tunnel.ALPNH2) {
			return DecideTunnelH2
		}
		return DecideDefault
	}
	if r.ACME != nil && slices.Contains(ch.ALPN, acmez.ACMETLS1Protocol) && r.ACME(sni) != nil {
		return DecideACME // before the routes: a passthrough route's backend never sees the CA
	}
	if r.WSS != nil && r.WSSHostname != nil {
		if name := r.WSSHostname(); name != "" && sni == name {
			return DecideWSS // no route of the group has the name (routes.SetWSSHostname)
		}
	}
	if r.Routes != nil {
		if _, ok := r.Routes.Passthrough(sni); ok {
			return DecidePassthrough
		}
		if r.Routes.HTTP(sni) {
			return DecideHTTP
		}
	}
	return DecideDefault
}

// Handle peeks at one connection, decides and hands it over.
func (r *Router) Handle(c net.Conn) {
	ch, err := tlspeek.Peek(c, tlspeek.MaxBytes, tlspeek.Timeout)
	if err != nil {
		d := DecidePeekFailed
		if errors.Is(err, tlspeek.ErrNotTLS) {
			d = DecideNotTLS
		}
		r.log().Debug("closing a connection on port 443", "decision", d, "remote", c.RemoteAddr(), "error", err)
		_ = c.Close()
		return
	}
	rc := tlspeek.NewReplayConn(c, ch.Raw)
	switch d := r.Decide(ch); d {
	case DecideController:
		if r.Controller == nil {
			_ = rc.Close()
			return
		}
		r.Controller(rc)
	case DecideTunnelH2:
		r.Tunnel(tls.Server(rc, r.TunnelTLS))
	case DecidePassthrough:
		h, _ := r.Routes.Passthrough(strings.ToLower(strings.TrimSuffix(ch.ServerName, ".")))
		h(rc)
	case DecideHTTP:
		r.HTTP(tls.Server(rc, r.HTTPTLS))
	case DecideWSS:
		r.WSS(tls.Server(rc, r.WSSTLS))
	case DecideACME:
		// RFC 8737: a handshake with the challenge certificate is the answer; nothing follows.
		cert := r.ACME(strings.ToLower(strings.TrimSuffix(ch.ServerName, ".")))
		if cert == nil {
			_ = rc.Close()
			return
		}
		tc := tls.Server(rc, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{acmez.ACMETLS1Protocol},
			Certificates: []tls.Certificate{*cert}})
		_ = tc.SetDeadline(time.Now().Add(defaultHandshake))
		_ = tc.Handshake()
		_ = tc.Close()
	default:
		// There is no fallback route: the page that says so, with a certificate that covers the
		// name or else the default one, after which a browser shows its certificate error first.
		if r.Unrouted != nil {
			r.Unrouted(tls.Server(rc, r.UnroutedTLS))
			return
		}
		tc := tls.Server(rc, r.DefaultTLS)
		_ = tc.SetDeadline(time.Now().Add(defaultHandshake))
		_ = tc.Handshake()
		_ = tc.Close()
	}
}

// HandleTunnel serves a connection that may only be a data session to this gateway: one that
// all-in-one's connector makes in memory. It passes the same ClientHello checks as on port 443 and
// the same mutual TLS handshake; anything else is closed.
func (r *Router) HandleTunnel(c net.Conn) {
	ch, err := tlspeek.Peek(c, tlspeek.MaxBytes, tlspeek.Timeout)
	if err != nil {
		r.log().Debug("closing an in-memory connection", "error", err)
		_ = c.Close()
		return
	}
	if d := r.Decide(ch); d != DecideTunnelH2 {
		r.log().Warn("closing an in-memory connection that is not a data session to this gateway", "decision", d)
		_ = c.Close()
		return
	}
	r.Tunnel(tls.Server(tlspeek.NewReplayConn(c, ch.Raw), r.TunnelTLS))
}

func (r *Router) log() *slog.Logger {
	if r.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return r.Logger
}

// DefaultTLS returns the configuration for unknown names: a certificate for default.invalid that
// the gateway generates at every start (R18), which no client trusts.
func DefaultTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "default.invalid"},
		DNSNames: []string{"default.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, nil
}

// QUICTLS returns the TLS configuration of the gateway's UDP/443 listener: mutual TLS with the
// tunnel configuration for this gateway's tunnel name and ALPN rpmgr-tunnel/1, and a refusal for
// everything else; public HTTP/3 comes in Phase 3.
func QUICTLS(trustDomain, gatewayID string, tunnelTLS *tls.Config) *tls.Config {
	name := strings.ToLower(gatewayID + ".gateway." + trustDomain)
	inner := tunnelTLS.Clone()
	inner.NextProtos = []string{tunnel.ALPNQUIC}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{tunnel.ALPNQUIC},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if strings.EqualFold(hello.ServerName, name) && slices.Contains(hello.SupportedProtos, tunnel.ALPNQUIC) {
				return inner, nil
			}
			return nil, fmt.Errorf("gateway: no QUIC service for %q with %v", hello.ServerName, hello.SupportedProtos)
		},
	}
}
