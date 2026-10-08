// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// certItem returns a CertificateItem for a self-signed certificate valid from nb to na, with the
// key of another certificate when wrongKey is set, and its hash.
func certItem(t *testing.T, cn string, nb, na time.Time, wrongKey bool) ([]byte, []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}, NotBefore: nb, NotAfter: na}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	if wrongKey {
		k, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(k)
	item, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.CertificateItem{Chain: [][]byte{der}, PrivateKey: pk})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(item)
	return item, sum[:]
}

// fakeFetch serves items by hash and counts the calls; fail makes every call fail.
type fakeFetch struct {
	mu    sync.Mutex
	items map[string][]byte // by string(hash)
	calls atomic.Int64
	fail  atomic.Bool
}

func (f *fakeFetch) add(item, hash []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.items == nil {
		f.items = map[string][]byte{}
	}
	f.items[string(hash)] = item
}

func (f *fakeFetch) fetch(_ context.Context, _ string, hash []byte) ([]byte, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return nil, errors.New("controller unreachable")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if item, ok := f.items[string(hash)]; ok {
		return item, nil
	}
	return nil, errors.New("not found")
}

// TestCertificates_ForName: the certificate for a server name is one that serves it as a route
// hostname, or, if none names it, the wildcard hostname one label up; among several, the valid one
// that expires last; a name whose certificates are all expired or not valid yet gets none.
func TestCertificates_ForName(t *testing.T) {
	now := time.Now()
	f := &fakeFetch{}
	mk := func(cn string, nb, na time.Time) []byte {
		item, hash := certItem(t, cn, nb, na, false)
		f.add(item, hash)
		return hash
	}
	soon := mk("soon", now.Add(-time.Hour), now.Add(time.Hour))
	later := mk("later", now.Add(-time.Hour), now.Add(48*time.Hour))
	expired := mk("expired", now.Add(-48*time.Hour), now.Add(-time.Hour))
	future := mk("future", now.Add(time.Hour), now.Add(96*time.Hour))
	wild := mk("wild", now.Add(-time.Hour), now.Add(24*time.Hour))
	c := gateway.NewCertificates(gateway.CertificatesOptions{Fetch: f.fetch})
	st := c.Apply(t.Context(), []gateway.CertificateRoute{
		{ID: "crt_soon", ContentSHA256: soon, Hostnames: []string{"app.example.com"}},
		{ID: "crt_later", ContentSHA256: later, Hostnames: []string{"app.example.com"}},
		{ID: "crt_expired", ContentSHA256: expired, Hostnames: []string{"app.example.com", "old.example.com"}},
		{ID: "crt_future", ContentSHA256: future, Hostnames: []string{"app.example.com", "new.example.com"}},
		{ID: "crt_wild", ContentSHA256: wild, Hostnames: []string{"*.example.com", "*.api.example.com"}},
	})
	if len(st) != 0 {
		t.Fatal(st)
	}
	cn := func(name string) string {
		if crt := c.ForName(name); crt != nil {
			return crt.Leaf.Subject.CommonName
		}
		return ""
	}
	for name, want := range map[string]string{
		"app.example.com": "later", "APP.Example.com.": "later", "www.example.com": "wild", "x.api.example.com": "wild",
		"a.b.api.example.com": "", "example.com": "", "old.example.com": "", "new.example.com": "",
		"other.net": "", "": "",
	} {
		if got := cn(name); got != want {
			t.Errorf("%q: %q, want %q", name, got, want)
		}
	}
}

// TestCertificates_FetchAndKeep: a certificate is fetched once and kept in the directory, 0600;
// after a restart while the controller is unreachable it serves from there; a tampered copy is
// fetched again; an item that does not match its hash or its key is not loaded.
func TestCertificates_FetchAndKeep(t *testing.T) {
	now := time.Now()
	dir := filepath.Join(t.TempDir(), "resources")
	f := &fakeFetch{}
	item, hash := certItem(t, "app.example.com", now.Add(-time.Hour), now.Add(time.Hour), false)
	f.add(item, hash)
	routes := []gateway.CertificateRoute{{ID: "crt_app", ContentSHA256: hash, Hostnames: []string{"app.example.com"}}}
	c := gateway.NewCertificates(gateway.CertificatesOptions{Dir: dir, Fetch: f.fetch})
	if st := c.Apply(t.Context(), routes); len(st) != 0 || c.ForName("app.example.com") == nil {
		t.Fatalf("apply: %v", st)
	}
	c.Apply(t.Context(), routes)
	if f.calls.Load() != 1 {
		t.Fatalf("%d fetches, want one", f.calls.Load())
	}
	file := filepath.Join(dir, hex.EncodeToString(hash))
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("kept item: %v %v", fi, err)
	}

	f.fail.Store(true)
	restarted := gateway.NewCertificates(gateway.CertificatesOptions{Dir: dir, Fetch: f.fetch})
	if st := restarted.Apply(t.Context(), routes); len(st) != 0 || restarted.ForName("app.example.com") == nil {
		t.Fatalf("a restart without the controller: %v", st)
	}

	if err := os.WriteFile(file, append(item, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	f.fail.Store(false)
	again := gateway.NewCertificates(gateway.CertificatesOptions{Dir: dir, Fetch: f.fetch})
	before := f.calls.Load()
	if st := again.Apply(t.Context(), routes); len(st) != 0 || f.calls.Load() != before+1 {
		t.Fatalf("a tampered copy: %v, %d fetches", st, f.calls.Load()-before)
	}
	if got, _ := os.ReadFile(file); string(got) != string(item) { //nolint:gosec // G304: a test file
		t.Fatal("the tampered copy was not replaced")
	}

	stray := filepath.Join(dir, "README")
	if err := os.WriteFile(stray, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	badKey, badKeyHash := certItem(t, "bad.example.com", now.Add(-time.Hour), now.Add(time.Hour), true)
	f.add(badKey, badKeyHash)
	other, _ := certItem(t, "other.example.com", now.Add(-time.Hour), now.Add(time.Hour), false)
	wrongHash := sha256.Sum256([]byte("another item"))
	f.add(other, wrongHash[:])
	st := again.Apply(t.Context(), []gateway.CertificateRoute{
		{ID: "crt_badkey", ContentSHA256: badKeyHash, Hostnames: []string{"bad.example.com"}},
		{ID: "crt_wronghash", ContentSHA256: wrongHash[:], Hostnames: []string{"other.example.com"}},
	})
	if len(st) != 2 || st[0].GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_ENVIRONMENT || again.ForName("bad.example.com") != nil ||
		again.ForName("other.example.com") != nil {
		t.Fatalf("bad items: %v", st)
	}
	// The snapshot no longer names crt_app: its file went, other files stay.
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an item no route names is still kept: %v", err)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Fatalf("a file that is not an item was removed: %v", err)
	}
	if again.ForName("app.example.com") != nil {
		t.Fatal("a removed certificate still serves")
	}
}

// TestCertificates_Retry: a certificate that cannot be fetched is reported not ready and loaded by
// Run once the controller answers again.
func TestCertificates_Retry(t *testing.T) {
	now := time.Now()
	f := &fakeFetch{}
	f.fail.Store(true)
	item, hash := certItem(t, "app.example.com", now.Add(-time.Hour), now.Add(time.Hour), false)
	f.add(item, hash)
	c := gateway.NewCertificates(gateway.CertificatesOptions{Fetch: f.fetch})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go c.Run(ctx)
	st := c.Apply(t.Context(), []gateway.CertificateRoute{{ID: "crt_app", ContentSHA256: hash, Hostnames: []string{"app.example.com"}}})
	if len(st) != 1 || st[0].GetResourceId() != "crt_app" || c.Missing() != 1 || c.ForName("app.example.com") != nil {
		t.Fatalf("an unreachable controller: %v", st)
	}
	time.Sleep(1500 * time.Millisecond) // at least one failed retry
	f.fail.Store(false)
	eventually(t, "the certificate was never loaded", func() bool { return c.ForName("app.example.com") != nil })
	if c.Missing() != 0 {
		t.Fatalf("%d still missing", c.Missing())
	}
}

// TestApplier_Certificates: a gateway snapshot's certificates need a SHA-256 and normalised
// hostnames; they are loaded on Apply, and one that cannot be fetched is reported.
func TestApplier_Certificates(t *testing.T) {
	a, _ := gateway.NewApplier()
	crt := func(hash []byte, hostnames ...string) *agentv1.Resource {
		return &agentv1.Resource{Id: "crt_1", Kind: &agentv1.Resource_GatewayCertificate{GatewayCertificate: &agentv1.GatewayCertificate{
			ContentSha256: hash, Hostnames: hostnames}}}
	}
	good := make([]byte, 32)
	if errs := a.Validate(gatewaySnapshot(1, crt(good, "app.example.com", "*.example.com"))); len(errs) != 0 {
		t.Fatal(errs)
	}
	for name, res := range map[string]*agentv1.Resource{
		"no hash":            crt(nil, "app.example.com"),
		"a short hash":       crt(make([]byte, 16), "app.example.com"),
		"no hostnames":       crt(good),
		"upper case":         crt(good, "App.example.com"),
		"not a name":         crt(good, "app_1.example.com"),
		"a trailing dot":     crt(good, "app.example.com."),
		"a wildcard inside":  crt(good, "a.*.example.com"),
		"an IP address":      crt(good, "192.0.2.1"),
		"a single label":     crt(good, "localhost"),
		"two wildcard stars": crt(good, "*.*.example.com"),
	} {
		if errs := a.Validate(gatewaySnapshot(1, res)); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	f := &fakeFetch{}
	f.fail.Store(true)
	certs := gateway.NewCertificates(gateway.CertificatesOptions{Fetch: f.fetch})
	a.Bind(gateway.Served{Certificates: certs})
	st := a.Apply(t.Context(), gatewaySnapshot(2, crt(good, "app.example.com")), agent.Changes{})
	if len(st) != 1 || st[0].GetResourceId() != "crt_1" {
		t.Fatalf("status %v", st)
	}
}
