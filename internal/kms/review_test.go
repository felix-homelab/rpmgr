// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

// answer makes the fake reply with a fixed 2xx body to calls whose path contains op.
func answer(f *fakeTransit, op, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/"+op+"/") {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
		return true
	}
}

// S1: a 2xx answer that holds no key is a protocol error, not a value that does not open.
func TestEmptyAnswersAreNotErrOpen(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	w, err := c.Wrap(ctxA, dk, aadA)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{``, `{}`, `{"data":{}}`, `{"data":{"plaintext":""}}`, `{"data":{"plaintext":"!!"}}`,
		`{"wrap_info":{"token":"x","ttl":60}}`} {
		answer(f, "decrypt", body)
		got, err := c.Unwrap(ctxA, w, aadA)
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, secret.ErrOpen) || got != nil {
			t.Errorf("decrypt answer %q: %x, %v; want ErrUnavailable", body, got, err)
		}
	}
	for _, body := range []string{``, `{}`, `{"data":{}}`, `{"data":{"ciphertext":""}}`, `{"wrap_info":{"token":"x"}}`} {
		answer(f, "encrypt", body)
		if _, err := c.Wrap(ctxA, dk, aadA); !errors.Is(err, ErrUnavailable) {
			t.Errorf("encrypt answer %q: %v; want ErrUnavailable", body, err)
		}
		answer(f, "rewrap", body)
		if _, err := c.Rewrap(ctxA, w, aadA); !errors.Is(err, ErrUnavailable) || errors.Is(err, secret.ErrOpen) {
			t.Errorf("rewrap answer %q: %v; want ErrUnavailable", body, err)
		}
	}
}

// S2: a key version that Transit refuses is its own error; an invalid ciphertext does not open.
func TestKeyVersionRefusedIsNotErrOpen(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	w1, err := c.Wrap(ctxA, dk, aadA)
	if err != nil {
		t.Fatal(err)
	}
	// The operator raised the minimum decryption version.
	f.mu.Lock()
	f.latest, f.minDec = 2, 2
	f.mu.Unlock()
	for name, call := range map[string]func() error{
		"unwrap": func() error { _, err := c.Unwrap(ctxA, w1, aadA); return err },
		"rewrap": func() error { _, err := c.Rewrap(ctxA, w1, aadA); return err },
	} {
		err := call()
		if !errors.Is(err, ErrKeyVersion) || errors.Is(err, secret.ErrOpen) || errors.Is(err, ErrUnavailable) {
			t.Errorf("%s of a version below the minimum: %v; want ErrKeyVersion alone", name, err)
		}
	}
	// Transit restored from an older backup: the ciphertext is of a version it does not know.
	f.mu.Lock()
	f.latest, f.minDec = 1, 0
	f.mu.Unlock()
	w5 := []byte("vault:v5:" + strings.Repeat("A", 40))
	if _, err := c.Unwrap(ctxA, w5, aadA); !errors.Is(err, ErrKeyVersion) || errors.Is(err, secret.ErrOpen) {
		t.Errorf("unwrap of a version that is too new: %v; want ErrKeyVersion", err)
	}
	// An undecodable ciphertext of a good version does not open.
	if _, err := c.Unwrap(ctxA, []byte("vault:v1:AAAA"), aadA); !errors.Is(err, secret.ErrOpen) {
		t.Errorf("unwrap of an invalid ciphertext: %v; want ErrOpen", err)
	}
}

// N3: an answer of a lower version than the key's latest is refused.
func TestOlderVersionAnswerIsRefused(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	f.setLatest(2)
	if n, err := c.Check(ctxA); err != nil || n != 2 {
		t.Fatalf("Check = %d, %v", n, err)
	}
	f.setLatest(1) // Transit restored from an older state
	if _, err := c.Wrap(ctxA, dk, aadA); !errors.Is(err, ErrKeyVersion) {
		t.Fatalf("Wrap of version 1 after seeing 2: %v", err)
	}
	w := []byte("vault:v1:" + strings.Repeat("A", 40))
	if _, err := c.Rewrap(ctxA, w, aadA); err == nil {
		t.Fatal("Rewrap answered with an older version")
	}
	// Without Check, the first answer teaches the client.
	c2, _, _ := testClient(t, f, nil)
	f.setLatest(3)
	if _, err := c2.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	f.setLatest(2)
	if _, err := c2.Wrap(ctxA, dk, aadA); !errors.Is(err, ErrKeyVersion) {
		t.Fatalf("Wrap of version 2 after seeing 3: %v", err)
	}
}

// N5: the data key is redacted from an error even when Transit echoes it.
func TestDataKeyIsRedactedFromErrors(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.fail(w, http.StatusBadRequest, "cannot encrypt "+in["plaintext"])
		return true
	}
	_, err := c.Wrap(ctxA, dk, aadA)
	if err == nil || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(dk)) ||
		!strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("Wrap = %v", err)
	}
}

// N7: every block of the CA file must be a certificate that parses.
func TestCAFileBlocks(t *testing.T) {
	f := newFakeTransit(t)
	junk := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})
	hdr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"a": "b"}, Bytes: []byte("x")})
	for name, content := range map[string][]byte{
		"valid then junk certificate": append(bytes.Clone(f.ca.caPEM), junk...),
		"junk then valid":             append(bytes.Clone(junk), f.ca.caPEM...),
		"certificate and key":         append(bytes.Clone(f.ca.caPEM), key...),
		"a block with headers":        append(bytes.Clone(f.ca.caPEM), hdr...),
		"empty":                       nil,
	} {
		p := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(Config{Address: f.srv.URL, Key: "k", CAFile: p, TokenFile: writeCred(t, "t", testToken)}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	two := append(bytes.Clone(f.ca.caPEM), newTestCA(t).caPEM...)
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, two, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Address: f.srv.URL, Key: "k", CAFile: p, TokenFile: writeCred(t, "t", testToken)}); err != nil {
		t.Errorf("two certificates: %v", err)
	}
}

// N8 and N2 at the configuration and ciphertext edges.
func TestDotSegmentsAndVersionSpellings(t *testing.T) {
	f := newFakeTransit(t)
	for _, m := range []string{".", "a/./b", "./a", "a/.", "a/..", "a//b"} {
		if _, err := New(Config{Address: f.srv.URL, Key: "k", Mount: m, TokenFile: writeCred(t, "t", testToken)}); err == nil {
			t.Errorf("mount %q accepted", m)
		}
	}
	c, _, _ := testClient(t, f, nil)
	for _, w := range []string{"vault:v0:AAAA", "vault:v01:AAAA", "vault:v12345678901:AAAA"} {
		if _, err := c.Unwrap(ctxA, []byte(w), aadA); !errors.Is(err, secret.ErrOpen) {
			t.Errorf("Unwrap(%q) = %v, want ErrOpen", w, err)
		}
	}
	if n := f.count("POST /v1/transit/decrypt/rpmgr"); n != 0 {
		t.Errorf("%d calls for malformed versions", n)
	}
}
