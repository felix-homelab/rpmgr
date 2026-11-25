// SPDX-License-Identifier: Apache-2.0

// Package kmstest is a fake Transit for tests of packages that use internal/kms: an in-process TLS
// server with a derived aes256-gcm96 key that has versions, token and AppRole logins, and switches
// to make it fail. It follows the documented API closely enough for the client; it is not Vault.
package kmstest

import (
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
	Token    = "kmstest-token-one" //nolint:gosec // G101: a made-up test credential
	RoleID   = "kmstest-role-id"
	SecretID = "kmstest-secret-id"
	Mount    = "transit"
	Key      = "rpmgr-kek"
)

// Server is a fake Transit with the key Mount/Key.
type Server struct {
	// URL is the address of the server, https://127.0.0.1:<port>.
	URL string

	t      testing.TB
	srv    *httptest.Server
	caPEM  []byte
	master []byte

	mu      sync.Mutex
	latest  int
	minDec  int
	keyType string
	derived bool
	status  int  // if not 0, every call answers with it
	echo    bool // an error body repeats the token and the request body, as a careless service might
	calls   map[string]int
}

// New starts a fake with a key at version 1, a derived aes256-gcm96 key, and the token Token.
func New(t testing.TB) *Server {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	return NewWithMaster(t, master)
}

// NewWithMaster starts a fake whose key is made from master: two fakes with the same master
// unwrap each other's values, as one Transit before and after a restart does.
func NewWithMaster(t testing.TB, master []byte) *Server {
	t.Helper()
	caPEM, server := newCA(t)
	s := &Server{t: t, caPEM: caPEM, master: master, latest: 1, keyType: "aes256-gcm96", derived: true, calls: map[string]int{}}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.handle))
	s.srv.TLS = &tls.Config{Certificates: []tls.Certificate{server}, MinVersion: tls.VersionTLS12}
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	s.URL = s.srv.URL
	return s
}

// Master returns the secret the key is made from, for NewWithMaster.
func (s *Server) Master() []byte { return s.master }

// CAFile writes the CA certificate of the server to a file and returns its path.
func (s *Server) CAFile() string {
	s.t.Helper()
	p := filepath.Join(s.t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, s.caPEM, 0o644); err != nil { //nolint:gosec // a CA certificate is public
		s.t.Fatal(err)
	}
	return p
}

// WriteCredential writes content to a new file of mode 0600 and returns its path.
func (s *Server) WriteCredential(name, content string) string {
	s.t.Helper()
	p := filepath.Join(s.t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content+"\n"), 0o600); err != nil {
		s.t.Fatal(err)
	}
	return p
}

// Rotate makes a new key version, as `vault write -f transit/keys/<key>/rotate` does.
func (s *Server) Rotate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latest++
}

// Latest is the latest key version.
func (s *Server) Latest() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest
}

// SetMinDecryptionVersion refuses ciphertexts of older versions.
func (s *Server) SetMinDecryptionVersion(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.minDec = n
}

// SetKey changes the type and whether the key is derived, which the client checks at start.
func (s *Server) SetKey(keyType string, derived bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyType, s.derived = keyType, derived
}

// FailWith makes every call answer with status, or stop doing so for 0. With echo, the error body
// repeats the token and the request body, so that a client that passes error text on would leak.
func (s *Server) FailWith(status int, echo bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.echo = status, echo
}

// Calls returns how many times "<METHOD> <path after /v1/>" was called.
func (s *Server) Calls(call string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[call]
}

// Close stops the server, so that a call gets a refused connection.
func (s *Server) Close() { s.srv.Close() }

func (s *Server) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, status int, msg string) {
	s.reply(w, status, map[string]any{"errors": []string{msg}})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	s.calls[r.Method+" "+path]++
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if s.status != 0 {
		msg := "service failure"
		if s.echo {
			msg += " token=" + r.Header.Get("X-Vault-Token") + " request=" + string(body)
		}
		if s.status == http.StatusOK { // a malformed answer
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not json " + msg)) //nolint:gosec // G705: a test fake answering a test client
			return
		}
		s.fail(w, s.status, msg)
		return
	}
	var in map[string]string
	_ = json.Unmarshal(body, &in)
	if path == "auth/approle/login" {
		if in["role_id"] != RoleID || in["secret_id"] != SecretID {
			s.fail(w, http.StatusBadRequest, "invalid role or secret ID")
			return
		}
		s.reply(w, 200, map[string]any{"auth": map[string]any{"client_token": Token, "lease_duration": 3600, "renewable": false}})
		return
	}
	if r.Header.Get("X-Vault-Token") != Token {
		s.fail(w, http.StatusForbidden, "permission denied")
		return
	}
	switch path {
	case "auth/token/lookup-self":
		s.reply(w, 200, map[string]any{"data": map[string]any{"ttl": 0}})
		return
	case "auth/token/renew-self":
		s.fail(w, http.StatusBadRequest, "token is not renewable")
		return
	}
	op, name, _ := strings.Cut(strings.TrimPrefix(path, Mount+"/"), "/")
	if !strings.HasPrefix(path, Mount+"/") || name != Key {
		s.fail(w, http.StatusNotFound, "encryption key not found")
		return
	}
	if r.Method == http.MethodGet && op == "keys" {
		s.reply(w, 200, map[string]any{"data": map[string]any{"type": s.keyType, "derived": s.derived, "latest_version": s.latest}})
		return
	}
	ctx, err := base64.StdEncoding.DecodeString(in["context"])
	if err != nil || len(ctx) == 0 {
		s.fail(w, http.StatusBadRequest, "missing or invalid context")
		return
	}
	switch op {
	case "encrypt":
		pt, err := base64.StdEncoding.DecodeString(in["plaintext"])
		if err != nil {
			s.fail(w, http.StatusBadRequest, "plaintext is not base64")
			return
		}
		s.reply(w, 200, map[string]any{"data": map[string]any{"ciphertext": s.seal(s.latest, ctx, pt)}})
	case "decrypt", "rewrap":
		pt, msg := s.open(in["ciphertext"], ctx)
		if msg != "" {
			s.fail(w, http.StatusBadRequest, msg)
			return
		}
		if op == "rewrap" {
			s.reply(w, 200, map[string]any{"data": map[string]any{"ciphertext": s.seal(s.latest, ctx, pt)}})
			return
		}
		s.reply(w, 200, map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(pt)}})
	default:
		s.fail(w, http.StatusNotFound, "unsupported path")
	}
}

func (s *Server) aead(version int, ctx []byte) cipher.AEAD {
	h := hmac.New(sha256.New, s.master)
	_, _ = fmt.Fprintf(h, "v%d", version)
	h.Write(ctx)
	blk, err := aes.NewCipher(h.Sum(nil))
	if err != nil {
		s.t.Fatal(err)
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		s.t.Fatal(err)
	}
	return g
}

func (s *Server) seal(version int, ctx, pt []byte) string {
	g := s.aead(version, ctx)
	nonce := make([]byte, g.NonceSize())
	_, _ = rand.Read(nonce)
	return fmt.Sprintf("vault:v%d:%s", version, base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, pt, nil)))
}

// open returns the plaintext of a ciphertext, or the message Transit gives for why it does not open.
func (s *Server) open(ct string, ctx []byte) ([]byte, string) {
	rest, ok := strings.CutPrefix(ct, "vault:v")
	if !ok {
		return nil, "invalid ciphertext: no prefix"
	}
	vs, b64, ok := strings.Cut(rest, ":")
	v, err := strconv.Atoi(vs)
	raw, err2 := base64.StdEncoding.DecodeString(b64)
	switch {
	case !ok || err != nil || err2 != nil || v < 1:
		return nil, "invalid ciphertext: unable to decode"
	case v > s.latest:
		return nil, "invalid ciphertext: version is too new"
	case v < s.minDec:
		return nil, "ciphertext or signature version is disallowed by policy (too old)"
	}
	g := s.aead(v, ctx)
	if len(raw) < g.NonceSize() {
		return nil, "invalid ciphertext: unable to decode"
	}
	pt, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	if err != nil {
		return nil, "cipher: message authentication failed"
	}
	return pt, ""
}

// newCA returns a generated CA, as PEM, and a server certificate for 127.0.0.1 that it signed.
func newCA(t testing.TB) ([]byte, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kmstest CA"},
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}
}
