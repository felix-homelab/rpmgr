// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
)

// The fetching of route certificates (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	fetchTimeout  = 10 * time.Second // one FetchResource call
	fetchRetryMin = time.Second      // a failed fetch is retried after 1 s, doubling up to 1 min
	fetchRetryMax = time.Minute
)

// CertificateRoute is a certificate as the gateway serves it, from its snapshot.
type CertificateRoute struct {
	ID            string
	ContentSHA256 []byte
	// Hostnames are the route hostnames it serves: names, or "*.name" for every name one label
	// below.
	Hostnames []string
}

// CertificatesOptions configure Certificates.
type CertificatesOptions struct {
	// Dir keeps the fetched items, so a restart while the controller is unreachable serves them;
	// "" keeps them in memory only.
	Dir string
	// Fetch fetches an item by ID and content hash, normally agent.Control.Fetch.
	Fetch  func(ctx context.Context, id string, hash []byte) ([]byte, error)
	Now    func() time.Time
	Logger *slog.Logger
}

// Certificates holds the route certificates of the gateway's snapshot and chooses one for a TLS
// handshake by its server name (docs/04-security.md, "Route certificates"). A certificate the
// gateway cannot load yet is retried in the background.
type Certificates struct {
	o     CertificatesOptions
	retry chan struct{}

	mu      sync.Mutex
	want    []CertificateRoute
	loaded  map[string]*tls.Certificate // by hex content hash
	byHost  map[string][]*tls.Certificate
	missing map[string]CertificateRoute // by hex content hash
}

// NewCertificates returns an empty set; Run retries what Apply could not load.
func NewCertificates(o CertificatesOptions) *Certificates {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Certificates{o: o, retry: make(chan struct{}, 1), loaded: map[string]*tls.Certificate{},
		byHost: map[string][]*tls.Certificate{}, missing: map[string]CertificateRoute{}}
}

// Apply makes routes the served certificates: each comes from memory, from Dir, or from Fetch, and
// is checked against its hash. Those it cannot load are returned not ready and retried by Run;
// items no route names any more are forgotten and removed from Dir.
func (c *Certificates) Apply(ctx context.Context, routes []CertificateRoute) []*agentv1.ResourceStatus {
	c.mu.Lock()
	c.want = slices.Clone(routes)
	c.mu.Unlock()
	var status []*agentv1.ResourceStatus
	for _, r := range routes {
		if err := c.load(ctx, r); err != nil {
			status = append(status, &agentv1.ResourceStatus{ResourceId: r.ID, Reason: agentv1.NotReadyReason_NOT_READY_REASON_ENVIRONMENT,
				Detail: "certificate not loaded: " + err.Error()})
		}
	}
	c.rebuild()
	c.prune()
	return status
}

// load makes one certificate available, or records it as missing.
func (c *Certificates) load(ctx context.Context, r CertificateRoute) error {
	key := hex.EncodeToString(r.ContentSHA256)
	c.mu.Lock()
	_, ok := c.loaded[key]
	c.mu.Unlock()
	if ok {
		return nil
	}
	cert, err := c.read(key, r.ContentSHA256)
	if err != nil && c.o.Fetch != nil {
		fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		var item []byte
		item, err = c.o.Fetch(fctx, r.ID, r.ContentSHA256)
		cancel()
		if err == nil {
			cert, err = parseItem(item, r.ContentSHA256)
		}
		if err == nil {
			c.write(key, item)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.missing[key] = r
		select {
		case c.retry <- struct{}{}:
		default:
		}
		return err
	}
	delete(c.missing, key)
	c.loaded[key] = cert
	return nil
}

// read loads an item from Dir.
func (c *Certificates) read(key string, hash []byte) (*tls.Certificate, error) {
	if c.o.Dir == "" {
		return nil, os.ErrNotExist
	}
	item, err := os.ReadFile(filepath.Join(c.o.Dir, key)) //nolint:gosec // G304: the name is a hex hash
	if err != nil {
		return nil, err
	}
	return parseItem(item, hash)
}

// write keeps an item in Dir, readable by the gateway's user only; a failure is logged, the
// certificate still serves from memory.
func (c *Certificates) write(key string, item []byte) {
	if c.o.Dir == "" {
		return
	}
	err := os.MkdirAll(c.o.Dir, 0o700)
	if err == nil {
		tmp := filepath.Join(c.o.Dir, "."+key+".tmp")
		if err = os.WriteFile(tmp, item, 0o600); err == nil {
			err = os.Rename(tmp, filepath.Join(c.o.Dir, key))
		}
	}
	if err != nil {
		c.o.Logger.Warn("cannot keep a route certificate on disk; it serves from memory", "error", err)
	}
}

// prune forgets the items no route names and removes them from Dir.
func (c *Certificates) prune() {
	c.mu.Lock()
	keep := map[string]bool{}
	for _, r := range c.want {
		keep[hex.EncodeToString(r.ContentSHA256)] = true
	}
	for k := range c.loaded {
		if !keep[k] {
			delete(c.loaded, k)
		}
	}
	for k := range c.missing {
		if !keep[k] {
			delete(c.missing, k)
		}
	}
	c.mu.Unlock()
	if c.o.Dir == "" {
		return
	}
	entries, err := os.ReadDir(c.o.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if b, err := hex.DecodeString(name); err == nil && len(b) == sha256.Size && !keep[name] {
			_ = os.Remove(filepath.Join(c.o.Dir, name))
		}
	}
}

// rebuild maps every route hostname of the snapshot's certificates to those of them that are
// loaded, possibly none.
func (c *Certificates) rebuild() {
	c.mu.Lock()
	defer c.mu.Unlock()
	byHost := map[string][]*tls.Certificate{}
	for _, r := range c.want {
		cert := c.loaded[hex.EncodeToString(r.ContentSHA256)]
		for _, h := range r.Hostnames {
			if cert != nil {
				byHost[h] = append(byHost[h], cert)
			} else if _, ok := byHost[h]; !ok {
				byHost[h] = nil
			}
		}
	}
	c.byHost = byHost
}

// Run retries the certificates Apply could not load, with backoff, until ctx ends.
func (c *Certificates) Run(ctx context.Context) {
	wait := fetchRetryMin
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.retry:
		}
		for {
			c.mu.Lock()
			var missing []CertificateRoute
			for _, r := range c.missing {
				missing = append(missing, r)
			}
			c.mu.Unlock()
			if len(missing) == 0 {
				wait = fetchRetryMin
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			for _, r := range missing {
				if err := c.load(ctx, r); err != nil {
					c.o.Logger.Debug("route certificate still not loaded", "certificate", r.ID, "error", err)
				}
			}
			c.rebuild()
			wait = min(2*wait, fetchRetryMax)
			// Drain the signal the failed loads just sent; the loop goes on while any is missing.
			select {
			case <-c.retry:
			default:
			}
		}
	}
}

// Missing returns how many certificates of the snapshot are not loaded.
func (c *Certificates) Missing() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.missing)
}

// ForName returns the certificate for a TLS server name: one that serves the name as a route
// hostname, or, only if no certificate names it, the wildcard hostname one label up; among
// several, the valid one that expires last. It is nil when none is valid now, so an expired
// certificate for a name never gives way to a wildcard one that may belong to another route.
func (c *Certificates) ForName(serverName string) *tls.Certificate {
	name := strings.ToLower(strings.TrimSuffix(serverName, "."))
	now := c.o.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	candidates, named := c.byHost[name]
	if _, parent, ok := strings.Cut(name, "."); ok && !named {
		candidates = c.byHost["*."+parent]
	}
	var best *tls.Certificate
	for _, cert := range candidates {
		if now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
			continue
		}
		if best == nil || cert.Leaf.NotAfter.After(best.Leaf.NotAfter) {
			best = cert
		}
	}
	return best
}

// parseItem checks an item against its hash and returns the certificate it carries, whose key
// must match its leaf.
func parseItem(item, hash []byte) (*tls.Certificate, error) {
	if sum := sha256.Sum256(item); !bytes.Equal(sum[:], hash) {
		return nil, errors.New("the item does not match its hash")
	}
	var it agentv1.CertificateItem
	if err := proto.Unmarshal(item, &it); err != nil {
		return nil, err
	}
	if len(it.GetChain()) == 0 {
		return nil, errors.New("an item without a certificate")
	}
	leaf, err := x509.ParseCertificate(it.GetChain()[0])
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(it.GetPrivateKey())
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("a %T key", key)
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if pub, isEq := signer.Public().(equaler); !isEq || !pub.Equal(leaf.PublicKey) {
		return nil, fmt.Errorf("the key of certificate %s does not match it", leaf.Subject)
	}
	return &tls.Certificate{Certificate: it.GetChain(), PrivateKey: signer, Leaf: leaf}, nil
}
