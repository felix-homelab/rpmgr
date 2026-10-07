// SPDX-License-Identifier: Apache-2.0

// Package pebblehost runs Pebble, Let's Encrypt's ACME test server, in-process, wired as its
// cmd/pebble does, and counts the ACME requests the spike's assertions need: new orders per
// identifier and challenge responses. Validation is real: Pebble's VA resolves names through the
// spike's DNS server and connects to the gateways' ports; PEBBLE_VA_ALWAYS_VALID is never set.
package pebblehost

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
)

// Options configure the test CA.
type Options struct {
	HTTPPort, TLSPort int           // where the VA connects for HTTP-01 and TLS-ALPN-01
	Resolver          string        // DNS server for all VA lookups
	Validity          time.Duration // certificate lifetime; 0 = Pebble's default
	Log               io.Writer     // Pebble's log; nil discards it
}

// Pebble is a running test CA.
type Pebble struct {
	DirectoryURL string
	// ServerRoots trusts the ACME server's own TLS certificate (not the issuance root).
	ServerRoots *x509.CertPool

	srv, mgmt *httptest.Server

	mu        sync.Mutex
	newOrders map[string]int // identifier → number of new-order requests naming it

	NewOrders      atomic.Int64
	ChallengePosts atomic.Int64 // POSTs to challenge URLs (responses, i.e. "please validate", and polls)
}

func init() {
	// Deterministic, fast behaviour: no artificial VA sleep, no injected bad nonces, no
	// authorization reuse (renewals must validate again).
	os.Setenv("PEBBLE_VA_NOSLEEP", "1")
	os.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	os.Setenv("PEBBLE_AUTHZREUSE", "0")
	os.Unsetenv("PEBBLE_VA_ALWAYS_VALID")
}

// Start runs Pebble on a free port of 127.0.0.1.
func Start(opts Options) (*Pebble, error) {
	if os.Getenv("PEBBLE_VA_ALWAYS_VALID") != "" {
		return nil, errors.New("pebblehost: PEBBLE_VA_ALWAYS_VALID must not be set")
	}
	w := opts.Log
	if w == nil {
		w = io.Discard
	}
	logger := log.New(w, "pebble ", log.LstdFlags|log.Lmicroseconds)
	validity := uint64(opts.Validity / time.Second)
	profiles := map[string]ca.Profile{"default": {Description: "spike", ValidityPeriod: validity}}
	store := db.NewMemoryStore()
	caImpl := ca.New(logger, store, "", "ecdsa", 0, 1, profiles)
	vaImpl := va.New(logger, opts.HTTPPort, opts.TLSPort, false, opts.Resolver, store)
	wfeImpl := wfe.New(logger, store, vaImpl, caImpl, []string{"pebble.letsencrypt.org"}, false, false, 1, 1)

	p := &Pebble{newOrders: map[string]int{}}
	p.srv = httptest.NewUnstartedServer(p.count(wfeImpl.Handler()))
	p.srv.StartTLS()
	p.mgmt = httptest.NewTLSServer(wfeImpl.ManagementHandler())
	p.DirectoryURL = p.srv.URL + wfe.DirectoryPath
	p.ServerRoots = x509.NewCertPool()
	p.ServerRoots.AddCert(p.srv.Certificate())
	return p, nil
}

// Close stops the servers.
func (p *Pebble) Close() {
	p.srv.Close()
	p.mgmt.Close()
}

// ServerCertPEM returns the ACME server's own TLS certificate (to trust it in another process).
func (p *Pebble) ServerCertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.srv.Certificate().Raw})
}

// OrdersFor returns how many new-order requests named identifier.
func (p *Pebble) OrdersFor(identifier string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.newOrders[strings.ToLower(identifier)]
}

func (p *Pebble) count(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			switch {
			case r.URL.Path == "/order-plz":
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				p.NewOrders.Add(1)
				for _, id := range orderIdentifiers(body) {
					p.mu.Lock()
					p.newOrders[strings.ToLower(id)]++
					p.mu.Unlock()
				}
			case strings.HasPrefix(r.URL.Path, "/chalZ/"):
				p.ChallengePosts.Add(1)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func orderIdentifiers(jws []byte) []string {
	var outer struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(jws, &outer) != nil {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(outer.Payload)
	if err != nil {
		return nil
	}
	var order struct {
		Identifiers []struct {
			Value string `json:"value"`
		} `json:"identifiers"`
	}
	if json.Unmarshal(raw, &order) != nil {
		return nil
	}
	var out []string
	for _, id := range order.Identifiers {
		out = append(out, id.Value)
	}
	return out
}

// IssuanceRoots returns the root that signs issued certificates, from Pebble's management API.
func (p *Pebble) IssuanceRoots(ctx context.Context) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pemBytes, err := p.get(ctx, wfe.RootCertPath+"0")
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("pebblehost: no root in management response")
	}
	return pool, nil
}

func (p *Pebble) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.mgmt.URL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.mgmt.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pebblehost: GET %s: HTTP %d", path, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err == nil {
		if blk, _ := pem.Decode(b); blk == nil {
			return nil, errors.New("pebblehost: management response is not PEM")
		}
	}
	return b, err
}
