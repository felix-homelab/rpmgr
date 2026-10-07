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
	DecideHTTP        Decision = "http"        // the SNI of an http route
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
	// DefaultTLS completes the handshake for an unknown name before the connection is closed.
	DefaultTLS *tls.Config
	Logger     *slog.Logger

	wg sync.WaitGroup
}

// Serve accepts connections until l is closed.
func (r *Router) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			r.wg.Wait()
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		r.wg.Go(func() { r.Handle(c) })
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
	default:
		// There is no fallback route: complete the handshake with the default certificate, so a
		// browser shows a certificate error rather than a reset, and close.
		tc := tls.Server(rc, r.DefaultTLS)
		_ = tc.SetDeadline(time.Now().Add(defaultHandshake))
		_ = tc.Handshake()
		_ = tc.Close()
	}
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
