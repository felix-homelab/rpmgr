// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Low-entropy test credentials; none is a real secret.
const (
	testToken    = "test-token-one"
	testRoleID   = "test-role-id"
	testSecretID = "test-secret-id"
)

// testCA is a generated CA and a server certificate for 127.0.0.1 that it signed.
type testCA struct {
	caPEM  []byte
	server tls.Certificate
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kms test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "transit.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		server: tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey},
	}
}

// fakeTransit is an in-process TLS server that follows the documented Transit, AppRole and token
// APIs closely enough for the client: a derived aes256-gcm96 key with versions, and tokens.
type fakeTransit struct {
	t   *testing.T
	ca  testCA
	srv *httptest.Server

	mu       sync.Mutex
	master   []byte
	latest   int
	mount    string
	key      string
	keyType  string
	derived  bool
	tokens   map[string]bool // valid tokens
	calls    map[string]int  // by "METHOD path"
	seen     []string        // token of every request, in order
	roleID   string
	secretID string
	lease    int64 // seconds, of logins and renewals
	renew    bool
	issued   int
	// override handles a request before the fake does, when it returns true.
	override func(w http.ResponseWriter, r *http.Request) bool
	// release ends handlers that wait, when the test is over.
	release chan struct{}
}

func newFakeTransit(t *testing.T) *fakeTransit {
	t.Helper()
	f := &fakeTransit{
		t: t, ca: newTestCA(t), master: bytes.Repeat([]byte{7}, 32), latest: 1, mount: "transit", key: "rpmgr",
		keyType: "aes256-gcm96", derived: true, tokens: map[string]bool{testToken: true},
		calls: map[string]int{}, roleID: testRoleID, secretID: testSecretID, lease: 3600, renew: true,
	}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{f.ca.server}, MinVersion: tls.VersionTLS12}
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.release = make(chan struct{})
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	t.Cleanup(func() { close(f.release) })
	return f
}

func (f *fakeTransit) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[key]
}

func (f *fakeTransit) setLatest(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.latest = n
}

func (f *fakeTransit) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeTransit) fail(w http.ResponseWriter, status int, msg string) {
	f.reply(w, status, map[string]any{"errors": []string{msg}})
}

func (f *fakeTransit) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls[r.Method+" "+r.URL.Path]++
	f.seen = append(f.seen, r.Header.Get("X-Vault-Token"))
	ov := f.override
	f.mu.Unlock()
	if ov != nil && ov(w, r) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case path == "auth/approle/login":
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["role_id"] != f.roleID || in["secret_id"] != f.secretID {
			f.fail(w, http.StatusBadRequest, "invalid role or secret ID")
			return
		}
		f.issued++
		tok := "approle-token-" + strconv.Itoa(f.issued)
		f.tokens[tok] = true
		f.reply(w, 200, map[string]any{"auth": map[string]any{
			"client_token": tok, "lease_duration": f.lease, "renewable": f.renew}})
		return
	case path == "auth/token/renew-self":
		if !f.tokens[r.Header.Get("X-Vault-Token")] {
			f.fail(w, http.StatusForbidden, "permission denied")
			return
		}
		f.reply(w, 200, map[string]any{"auth": map[string]any{
			"client_token": r.Header.Get("X-Vault-Token"), "lease_duration": f.lease, "renewable": f.renew}})
		return
	}
	if !f.tokens[r.Header.Get("X-Vault-Token")] {
		f.fail(w, http.StatusForbidden, "permission denied")
		return
	}
	prefix := f.mount + "/"
	if !strings.HasPrefix(path, prefix) {
		f.fail(w, http.StatusNotFound, "no handler for route "+strconv.Quote(path))
		return
	}
	op, name, _ := strings.Cut(strings.TrimPrefix(path, prefix), "/")
	if name != f.key {
		f.fail(w, http.StatusBadRequest, "encryption key not found")
		return
	}
	if r.Method == http.MethodGet && op == "keys" {
		f.reply(w, 200, map[string]any{"data": map[string]any{
			"type": f.keyType, "derived": f.derived, "latest_version": f.latest}})
		return
	}
	var in map[string]string
	_ = json.NewDecoder(r.Body).Decode(&in)
	ctxBytes, err := base64.StdEncoding.DecodeString(in["context"])
	if err != nil || len(ctxBytes) == 0 {
		f.fail(w, http.StatusBadRequest, "missing or invalid context")
		return
	}
	switch op {
	case "encrypt":
		pt, err := base64.StdEncoding.DecodeString(in["plaintext"])
		if err != nil {
			f.fail(w, http.StatusBadRequest, "plaintext is not base64")
			return
		}
		f.reply(w, 200, map[string]any{"data": map[string]any{"ciphertext": f.seal(f.latest, ctxBytes, pt)}})
	case "decrypt":
		pt, ok := f.open(in["ciphertext"], ctxBytes)
		if !ok {
			f.fail(w, http.StatusBadRequest, "cipher: message authentication failed")
			return
		}
		f.reply(w, 200, map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(pt)}})
	case "rewrap":
		pt, ok := f.open(in["ciphertext"], ctxBytes)
		if !ok {
			f.fail(w, http.StatusBadRequest, "cipher: message authentication failed")
			return
		}
		f.reply(w, 200, map[string]any{"data": map[string]any{"ciphertext": f.seal(f.latest, ctxBytes, pt)}})
	default:
		f.fail(w, http.StatusNotFound, "unsupported path")
	}
}

func (f *fakeTransit) versionKey(version int, ctx []byte) cipher.AEAD {
	h := hmac.New(sha256.New, f.master)
	_, _ = fmt.Fprintf(h, "v%d", version)
	h.Write(ctx)
	blk, err := aes.NewCipher(h.Sum(nil))
	if err != nil {
		f.t.Fatal(err)
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}

func (f *fakeTransit) seal(version int, ctx, pt []byte) string {
	g := f.versionKey(version, ctx)
	nonce := make([]byte, g.NonceSize())
	_, _ = rand.Read(nonce)
	return fmt.Sprintf("vault:v%d:%s", version, base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, pt, nil)))
}

func (f *fakeTransit) open(ct string, ctx []byte) ([]byte, bool) {
	rest, ok := strings.CutPrefix(ct, "vault:v")
	if !ok {
		return nil, false
	}
	vs, b64, ok := strings.Cut(rest, ":")
	v, err := strconv.Atoi(vs)
	raw, err2 := base64.StdEncoding.DecodeString(b64)
	if !ok || err != nil || err2 != nil || v < 1 || v > f.latest {
		return nil, false
	}
	g := f.versionKey(v, ctx)
	if len(raw) < g.NonceSize() {
		return nil, false
	}
	pt, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	return pt, err == nil
}

// writeCred writes a credential file with mode 0600 and returns its path.
func writeCred(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeCA(t *testing.T, pemBytes []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pemBytes, 0o644); err != nil { //nolint:gosec // a CA certificate is public
		t.Fatal(err)
	}
	return p
}

// clock is a settable clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testClient returns a Client for the fake with a token file, the fake's CA, no real sleeping and
// the list of sleeps it would have made.
func testClient(t *testing.T, f *fakeTransit, mutate func(*Config)) (*Client, *[]time.Duration, *clock) {
	t.Helper()
	cfg := Config{
		Address: f.srv.URL, Key: f.key, CAFile: writeCA(t, f.ca.caPEM), TokenFile: writeCred(t, "token", testToken),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var sleeps []time.Duration
	var mu sync.Mutex
	c.sleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		defer mu.Unlock()
		sleeps = append(sleeps, d)
		return nil
	}
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c.now = clk.now
	t.Cleanup(c.http.CloseIdleConnections)
	return c, &sleeps, clk
}

func appRoleCfg(t *testing.T) func(*Config) {
	return func(cfg *Config) {
		cfg.TokenFile = ""
		cfg.AppRole = &AppRole{
			RoleIDFile: writeCred(t, "role", testRoleID), SecretIDFile: writeCred(t, "secret", testSecretID),
		}
	}
}

func writeFileMode(path, content string, mode os.FileMode) error {
	return os.WriteFile(path, []byte(content+"\n"), mode) //nolint:gosec // tests a mode check
}
