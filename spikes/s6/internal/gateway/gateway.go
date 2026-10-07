// SPDX-License-Identifier: Apache-2.0

// Package gateway is the gateway side of S6: it answers ACME HTTP-01 and TLS-ALPN-01 challenges
// and serves issued certificates, using only what the controller pushed to it over the
// (simulated) control session. It deliberately does not import certmagic and has no access to
// the controller's storage, as in rpmgr, where gateways never read the database
// (docs/04-security.md, "Controller certificates"; ADR-0007).
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
)

// ChallengeUpdate is what the controller pushes for an HTTP-01 or TLS-ALPN-01 challenge.
type ChallengeUpdate struct {
	Remove    bool
	Challenge acme.Challenge // Type, Token, KeyAuthorization and Identifier are used
}

// Gateway answers challenges on its HTTP and TLS listeners.
type Gateway struct {
	ID string

	mu          sync.RWMutex
	challenges  map[string]acme.Challenge   // identifier → active challenge
	alpnCerts   map[string]*tls.Certificate // identifier → TLS-ALPN-01 certificate
	servedCerts map[string]*tls.Certificate // hostname → issued certificate

	HTTPAnswered atomic.Int64 // HTTP-01 requests answered with a key authorization
	ALPNAnswered atomic.Int64 // TLS-ALPN-01 handshakes answered with a challenge certificate
	Pushes       atomic.Int64 // challenge updates applied

	httpLn, tlsLn net.Listener
	httpSrv       *http.Server
	wg            sync.WaitGroup
}

// New starts a gateway on the given listeners: plain HTTP (port 80 in production) and TLS
// (port 443).
func New(id string, httpLn, tlsLn net.Listener) *Gateway {
	g := &Gateway{
		ID:          id,
		challenges:  map[string]acme.Challenge{},
		alpnCerts:   map[string]*tls.Certificate{},
		servedCerts: map[string]*tls.Certificate{},
		httpLn:      httpLn,
		tlsLn:       tlsLn,
	}
	g.httpSrv = &http.Server{Handler: http.HandlerFunc(g.serveHTTP), ReadHeaderTimeout: 10 * time.Second}
	g.wg.Add(2)
	go func() { defer g.wg.Done(); _ = g.httpSrv.Serve(httpLn) }()
	go func() { defer g.wg.Done(); g.serveTLS() }()
	return g
}

// Close stops both listeners.
func (g *Gateway) Close() {
	_ = g.httpSrv.Close()
	_ = g.tlsLn.Close()
	g.wg.Wait()
}

// ApplyChallenge is the receiving end of the control session: it installs or removes a challenge
// and returns only when the gateway can answer it.
func (g *Gateway) ApplyChallenge(_ context.Context, u ChallengeUpdate) error {
	ch := u.Challenge
	id := strings.ToLower(ch.Identifier.Value)
	if id == "" {
		return errors.New("gateway: challenge without identifier")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if u.Remove {
		if cur, ok := g.challenges[id]; ok && cur.Token == ch.Token {
			delete(g.challenges, id)
			delete(g.alpnCerts, id)
		}
		g.Pushes.Add(1)
		return nil
	}
	switch ch.Type {
	case acme.ChallengeTypeHTTP01:
		delete(g.alpnCerts, id)
	case acme.ChallengeTypeTLSALPN01:
		cert, err := acmez.TLSALPN01ChallengeCert(ch)
		if err != nil {
			return fmt.Errorf("gateway: building TLS-ALPN-01 certificate: %w", err)
		}
		g.alpnCerts[id] = cert
	default:
		return fmt.Errorf("gateway: challenge type %q is not answered by gateways", ch.Type)
	}
	if ch.KeyAuthorization == "" || ch.Token == "" {
		return errors.New("gateway: challenge without token or key authorization")
	}
	g.challenges[id] = ch
	g.Pushes.Add(1)
	return nil
}

// ApplyCertificate installs an issued certificate for its names (pushed in snapshots in rpmgr).
func (g *Gateway) ApplyCertificate(cert *tls.Certificate) error {
	if cert == nil || cert.Leaf == nil {
		return errors.New("gateway: certificate without parsed leaf")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, n := range cert.Leaf.DNSNames {
		g.servedCerts[strings.ToLower(n)] = cert
	}
	return nil
}

// HasChallenge reports whether a challenge for identifier is installed.
func (g *Gateway) HasChallenge(identifier string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	_, ok := g.challenges[strings.ToLower(identifier)]
	return ok
}

func (g *Gateway) serveHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	g.mu.RLock()
	ch, ok := g.challenges[strings.ToLower(host)]
	g.mu.RUnlock()
	if !ok || ch.Type != acme.ChallengeTypeHTTP01 || r.URL.Path != prefix+ch.Token {
		http.NotFound(w, r)
		return
	}
	g.HTTPAnswered.Add(1)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(ch.KeyAuthorization))
}

func (g *Gateway) serveTLS() {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12, // public ingress; rpmgr-internal sessions are TLS 1.3 only
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			name := strings.ToLower(hello.ServerName)
			if slices.Contains(hello.SupportedProtos, acmez.ACMETLS1Protocol) {
				g.mu.RLock()
				cert, ok := g.alpnCerts[name]
				g.mu.RUnlock()
				if !ok {
					return nil, fmt.Errorf("gateway: no TLS-ALPN-01 challenge for %q", name)
				}
				g.ALPNAnswered.Add(1)
				return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert},
					NextProtos: []string{acmez.ACMETLS1Protocol}}, nil
			}
			g.mu.RLock()
			cert, ok := g.servedCerts[name]
			if !ok {
				if i := strings.IndexByte(name, '.'); i > 0 {
					cert, ok = g.servedCerts["*"+name[i:]]
				}
			}
			g.mu.RUnlock()
			if !ok {
				return nil, fmt.Errorf("gateway: no certificate for %q", name)
			}
			return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}}, nil
		},
	}
	for {
		c, err := g.tlsLn.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			tc := tls.Server(c, cfg)
			_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
			_ = tc.Handshake() // challenge and certificate tests only need the handshake
		}()
	}
}
