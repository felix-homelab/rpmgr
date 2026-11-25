// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

var (
	ctxA = context.Background()
	aadA = []byte("\x04user\x03tok\x011")
	aadB = []byte("\x04user\x03tok\x012")
	dk   = bytes.Repeat([]byte{0x42}, 32)
)

func TestWrapUnwrapRoundTrip(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	if c.Kind() != secret.KindTransit || string(c.ID()) != "transit/rpmgr" {
		t.Fatalf("Kind %d, ID %q", c.Kind(), c.ID())
	}
	w, err := c.Wrap(ctxA, dk, aadA)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(w), "vault:v1:") {
		t.Fatalf("wrapped = %q", w)
	}
	got, err := c.Unwrap(ctxA, w, aadA)
	if err != nil || !bytes.Equal(got, dk) {
		t.Fatalf("Unwrap = %x, %v", got, err)
	}
}

func TestSealerOverTransit(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	s, err := secret.NewSealerWith(c)
	if err != nil {
		t.Fatal(err)
	}
	sc := secret.Context{Table: "dns_providers", Column: "credential_enc", RowID: "row-1"}
	sealed, err := s.Seal(sc, secret.New("low-entropy-value"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Open(sc, sealed)
	if err != nil || v.Reveal() != "low-entropy-value" {
		t.Fatalf("Open = %v", err)
	}
	if ver, err := secret.KEKVersion(sealed); err != nil || ver != "transit/rpmgr@v1" {
		t.Fatalf("KEKVersion = %q, %v", ver, err)
	}
	// A value moved to another row does not open: the Transit context differs.
	other := sc
	other.RowID = "row-2"
	if _, err := s.Open(other, sealed); !errors.Is(err, secret.ErrOpen) {
		t.Fatalf("moved value: %v, want ErrOpen", err)
	}
	// Transit down is not ErrOpen.
	f.srv.Close()
	if _, err := s.Open(sc, sealed); errors.Is(err, secret.ErrOpen) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Transit down: %v, want ErrUnavailable and not ErrOpen", err)
	}
}

func TestWrongContextFailsToDecrypt(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	w, err := c.Wrap(ctxA, dk, aadA)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Unwrap(ctxA, w, aadB); !errors.Is(err, secret.ErrOpen) || got != nil {
		t.Fatalf("Unwrap with another AAD = %x, %v; want ErrOpen", got, err)
	}
	if _, err := c.Rewrap(ctxA, w, aadB); !errors.Is(err, secret.ErrOpen) {
		t.Fatalf("Rewrap with another AAD: %v; want ErrOpen", err)
	}
	if n := f.count("POST /v1/transit/decrypt/rpmgr"); n != 1 {
		t.Errorf("a 400 was tried %d times, want once", n)
	}
}

func TestMalformedWrappedKeyIsErrOpenWithoutACall(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	for _, w := range []string{"", "garbage", "vault:v:abc", "vault:v1:", "vault:v1:a b", "vault:v1:abc\n"} {
		if _, err := c.Unwrap(ctxA, []byte(w), aadA); !errors.Is(err, secret.ErrOpen) {
			t.Errorf("Unwrap(%q) = %v, want ErrOpen", w, err)
		}
		if _, err := c.Rewrap(ctxA, []byte(w), aadA); !errors.Is(err, secret.ErrOpen) {
			t.Errorf("Rewrap(%q) = %v, want ErrOpen", w, err)
		}
	}
	if n := f.count("POST /v1/transit/decrypt/rpmgr"); n != 0 {
		t.Errorf("%d calls for malformed values", n)
	}
}

func TestRewrapMovesToLatestVersion(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	w1, err := c.Wrap(ctxA, dk, aadA)
	if err != nil {
		t.Fatal(err)
	}
	f.setLatest(2)
	w2, err := c.Rewrap(ctxA, w1, aadA)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(w2), "vault:v2:") {
		t.Fatalf("rewrapped = %q, want version 2", w2)
	}
	if got, err := c.Unwrap(ctxA, w2, aadA); err != nil || !bytes.Equal(got, dk) {
		t.Fatalf("Unwrap after rewrap = %x, %v", got, err)
	}
	// The old version stays usable until the operator raises the minimum decryption version.
	if got, err := c.Unwrap(ctxA, w1, aadA); err != nil || !bytes.Equal(got, dk) {
		t.Fatalf("Unwrap of the old version = %x, %v", got, err)
	}
}

func TestPermissionDenied(t *testing.T) {
	f := newFakeTransit(t)
	c, sleeps, _ := testClient(t, f, func(cfg *Config) {
		cfg.TokenFile = writeCred(t, "token", "rejected-token")
	})
	_, err := c.Wrap(ctxA, dk, aadA)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Wrap = %v, want ErrPermissionDenied", err)
	}
	var te *Error
	if !errors.As(err, &te) || te.Status != 403 || te.Message != "permission denied" {
		t.Fatalf("error = %#v", err)
	}
	if len(*sleeps) != 0 {
		t.Errorf("a 403 was retried after %v", *sleeps)
	}
	// The token file holds the same token when it is read again, so there is nothing new to try.
	if n := f.count("POST /v1/transit/encrypt/rpmgr"); n != 1 {
		t.Errorf("%d encrypt requests, want 1", n)
	}
}

func TestTokenFileReplacedIsPickedUpAtFirst403(t *testing.T) {
	f := newFakeTransit(t)
	path := writeCred(t, "token", testToken)
	c, _, _ := testClient(t, f, func(cfg *Config) { cfg.TokenFile = path })
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	// The operator replaces the token; the old one stops working.
	f.mu.Lock()
	f.tokens = map[string]bool{"test-token-two": true}
	f.mu.Unlock()
	if err := os.WriteFile(path, []byte("test-token-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatalf("after the token file was replaced: %v", err)
	}
}

func TestServerErrorsAreRetriedThenUnavailable(t *testing.T) {
	f := newFakeTransit(t)
	c, sleeps, _ := testClient(t, f, nil)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/encrypt/") {
			f.fail(w, http.StatusInternalServerError, "internal error")
			return true
		}
		return false
	}
	_, err := c.Wrap(ctxA, dk, aadA)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Wrap = %v, want ErrUnavailable", err)
	}
	if n := f.count("POST /v1/transit/encrypt/rpmgr"); n != 4 {
		t.Errorf("%d requests, want 1 and 3 retries", n)
	}
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}
	if len(*sleeps) != 3 || (*sleeps)[0] != want[0] || (*sleeps)[1] != want[1] || (*sleeps)[2] != want[2] {
		t.Errorf("backoff = %v, want %v", *sleeps, want)
	}
}

func TestRetryRecovers(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	var n atomic.Int32
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/encrypt/") && n.Add(1) <= 2 {
			f.fail(w, http.StatusServiceUnavailable, "Vault is sealed")
			return true
		}
		return false
	}
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatalf("Wrap after two 503: %v", err)
	}
}

func TestRetryAfterIsHonouredUpToFiveSeconds(t *testing.T) {
	f := newFakeTransit(t)
	c, sleeps, _ := testClient(t, f, nil)
	var n atomic.Int32
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/encrypt/") {
			return false
		}
		switch n.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "3")
		case 2:
			w.Header().Set("Retry-After", "600")
		default:
			return false
		}
		f.fail(w, http.StatusTooManyRequests, "rate limited")
		return true
	}
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	if len(*sleeps) != 2 || (*sleeps)[0] != 3*time.Second || (*sleeps)[1] != 5*time.Second {
		t.Errorf("sleeps = %v, want 3 s and 5 s", *sleeps)
	}
}

func TestClientErrorsAreNotRetried(t *testing.T) {
	f := newFakeTransit(t)
	c, sleeps, _ := testClient(t, f, nil)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		f.fail(w, http.StatusBadRequest, "bad request")
		return true
	}
	_, err := c.Wrap(ctxA, dk, aadA)
	var te *Error
	if !errors.As(err, &te) || te.Status != 400 || errors.Is(err, ErrUnavailable) || errors.Is(err, secret.ErrOpen) {
		t.Fatalf("Wrap = %v", err)
	}
	if len(*sleeps) != 0 {
		t.Errorf("retried: %v", *sleeps)
	}
}

func TestTimeout(t *testing.T) {
	f := newFakeTransit(t)
	c, sleeps, _ := testClient(t, f, nil)
	c.reqTTL = 100 * time.Millisecond
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/encrypt/") {
			select {
			case <-f.release:
			case <-r.Context().Done():
			}
			return true
		}
		return false
	}
	_, err := c.Wrap(ctxA, dk, aadA)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("Wrap = %v, want an unavailable timeout", err)
	}
	if len(*sleeps) != 3 {
		t.Errorf("%d retries after a timeout, want 3", len(*sleeps))
	}
}

func TestCancelledContextStopsRetries(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	ctx, cancel := context.WithCancel(ctxA)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/encrypt/") {
			cancel()
			f.fail(w, http.StatusInternalServerError, "x")
			return true
		}
		return false
	}
	if _, err := c.Wrap(ctx, dk, aadA); err == nil {
		t.Fatal("no error")
	}
	if n := f.count("POST /v1/transit/encrypt/rpmgr"); n != 1 {
		t.Errorf("%d requests after cancel, want 1", n)
	}
}

func TestWrongMount(t *testing.T) {
	f := newFakeTransit(t)
	c, sleeps, _ := testClient(t, f, func(cfg *Config) { cfg.Mount = "other" })
	_, err := c.Wrap(ctxA, dk, aadA)
	var te *Error
	if !errors.As(err, &te) || te.Status != 404 || errors.Is(err, ErrUnavailable) {
		t.Fatalf("Wrap on a wrong mount = %v, want a 404", err)
	}
	if len(*sleeps) != 0 {
		t.Errorf("a 404 was retried")
	}
	if _, err := c.Unwrap(ctxA, []byte("vault:v1:AAAA"), aadA); errors.Is(err, secret.ErrOpen) {
		t.Errorf("a wrong mount on decrypt is reported as a value that does not open")
	}
	if _, err := c.Check(ctxA); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("Check on a wrong mount = %v", err)
	}
	if string(c.ID()) != "other/rpmgr" {
		t.Errorf("ID = %q", c.ID())
	}
}

func TestMissingKeyOnDecryptIsNotErrOpen(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, func(cfg *Config) { cfg.Key = "nokey" })
	_, err := c.Unwrap(ctxA, []byte("vault:v1:AAAA"), aadA)
	if err == nil || errors.Is(err, secret.ErrOpen) {
		t.Fatalf("Unwrap with a missing key = %v, want a configuration error", err)
	}
}

func TestResponseLargerThanLimit(t *testing.T) {
	f := newFakeTransit(t)
	c, sleeps, _ := testClient(t, f, nil)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/encrypt/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(append([]byte(`{"data":{"ciphertext":"vault:v1:`), bytes.Repeat([]byte("A"), maxResponse)...))
			return true
		}
		return false
	}
	_, err := c.Wrap(ctxA, dk, aadA)
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("Wrap = %v, want a size error", err)
	}
	if len(*sleeps) != 0 {
		t.Error("an oversized answer was retried")
	}
	// Exactly the limit is accepted by the reader: the answer below is under it and decodes.
	f.override = nil
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatalf("a normal answer after an oversized one: %v", err)
	}
}

func TestUntrustedServerCertificate(t *testing.T) {
	f := newFakeTransit(t)
	other := newTestCA(t) // another CA than the one that signed the server
	c, sleeps, _ := testClient(t, f, func(cfg *Config) { cfg.CAFile = writeCA(t, other.caPEM) })
	_, err := c.Wrap(ctxA, dk, aadA)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "x509") {
		t.Fatalf("Wrap against an untrusted certificate = %v", err)
	}
	if len(*sleeps) != 0 {
		t.Errorf("a failed verification was retried")
	}
	if n := f.count("POST /v1/transit/encrypt/rpmgr"); n != 0 {
		t.Errorf("the request reached the handler %d times", n)
	}
	// Without a CA file the system roots apply, which do not hold the test CA either.
	c2, _, _ := testClient(t, f, func(cfg *Config) { cfg.CAFile = "" })
	if _, err := c2.Wrap(ctxA, dk, aadA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Wrap with the system roots = %v", err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	f := newFakeTransit(t)
	c, sleeps, _ := testClient(t, f, nil)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/encrypt/") {
			http.Redirect(w, r, "https://127.0.0.1:1/elsewhere", http.StatusTemporaryRedirect)
			return true
		}
		return false
	}
	_, err := c.Wrap(ctxA, dk, aadA)
	var te *Error
	if !errors.As(err, &te) || te.Status != http.StatusTemporaryRedirect {
		t.Fatalf("Wrap = %v, want the 307 as an error", err)
	}
	if len(*sleeps) != 0 {
		t.Error("a redirect was retried")
	}
}

func TestNoProxyFromEnvironment(t *testing.T) {
	f := newFakeTransit(t)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	c, _, _ := testClient(t, f, nil)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatalf("Wrap with HTTPS_PROXY set: %v", err)
	}
}

func TestNotJSONAnswer(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/encrypt/") {
			_, _ = w.Write([]byte("<html>hello</html>"))
			return true
		}
		return false
	}
	if _, err := c.Wrap(ctxA, dk, aadA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Wrap = %v, want ErrUnavailable", err)
	}
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/encrypt/") {
			_, _ = w.Write([]byte(`{"data":{"ciphertext":"not-a-transit-ciphertext"}}`))
			return true
		}
		return false
	}
	if _, err := c.Wrap(ctxA, dk, aadA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Wrap with a foreign ciphertext = %v, want ErrUnavailable", err)
	}
}

func TestCheck(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	f.setLatest(3)
	if n, err := c.Check(ctxA); err != nil || n != 3 {
		t.Fatalf("Check = %d, %v", n, err)
	}
	f.mu.Lock()
	f.derived = false
	f.mu.Unlock()
	if _, err := c.Check(ctxA); err == nil || !strings.Contains(err.Error(), "not derived") {
		t.Errorf("Check of a key that is not derived = %v", err)
	}
	f.mu.Lock()
	f.derived, f.keyType = true, "rsa-4096"
	f.mu.Unlock()
	if _, err := c.Check(ctxA); err == nil || !strings.Contains(err.Error(), "rsa-4096") {
		t.Errorf("Check of another type = %v", err)
	}
	f.srv.Close()
	if _, err := c.Check(ctxA); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Check with Transit down = %v", err)
	}
}

func TestTokenRenewalFromFile(t *testing.T) {
	f := newFakeTransit(t)
	f.lease = 100
	c, _, clk := testClient(t, f, nil)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	probe := f.count("POST /v1/auth/token/renew-self")
	if probe != 1 {
		t.Fatalf("%d renew-self calls at first use, want the one probe", probe)
	}
	clk.advance(49 * time.Second)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	if n := f.count("POST /v1/auth/token/renew-self"); n != probe {
		t.Errorf("renewed before half the lease: %d", n)
	}
	clk.advance(2 * time.Second)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	if n := f.count("POST /v1/auth/token/renew-self"); n != probe+1 {
		t.Errorf("%d renew-self calls at half the lease, want %d", n, probe+1)
	}
	// The next renewal is half a lease after this one.
	clk.advance(49 * time.Second)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	if n := f.count("POST /v1/auth/token/renew-self"); n != probe+1 {
		t.Errorf("renewed again too early: %d", n)
	}
}

func TestNonRenewableTokenIsNotRenewed(t *testing.T) {
	f := newFakeTransit(t)
	f.renew = false
	c, _, clk := testClient(t, f, nil)
	for range 3 {
		clk.advance(time.Hour)
		if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count("POST /v1/auth/token/renew-self"); n != 1 {
		t.Errorf("%d renew-self calls for a non-renewable token, want the probe only", n)
	}
}

func TestAppRoleLoginRenewalAndRelogin(t *testing.T) {
	f := newFakeTransit(t)
	f.lease = 100
	c, _, clk := testClient(t, f, appRoleCfg(t))
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	if n := f.count("POST /v1/auth/approle/login"); n != 1 {
		t.Fatalf("%d logins, want 1", n)
	}
	clk.advance(51 * time.Second)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	if n := f.count("POST /v1/auth/token/renew-self"); n != 1 {
		t.Errorf("%d renewals at half the lease, want 1", n)
	}
	if n := f.count("POST /v1/auth/approle/login"); n != 1 {
		t.Errorf("logged in again though the renewal worked: %d", n)
	}
	// The token can no longer be renewed (it ended): the client logs in again.
	f.mu.Lock()
	f.tokens = map[string]bool{}
	f.mu.Unlock()
	clk.advance(51 * time.Second)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatalf("after the token ended: %v", err)
	}
	if n := f.count("POST /v1/auth/approle/login"); n != 2 {
		t.Errorf("%d logins after the token ended, want 2", n)
	}
	f.mu.Lock()
	last := f.seen[len(f.seen)-1]
	f.mu.Unlock()
	if last != "approle-token-2" {
		t.Errorf("last request used %q, want the new token", last)
	}
}

func TestAppRoleNonRenewableLogsInAtHalfLease(t *testing.T) {
	f := newFakeTransit(t)
	f.lease, f.renew = 100, false
	c, _, clk := testClient(t, f, appRoleCfg(t))
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	clk.advance(60 * time.Second)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	if n := f.count("POST /v1/auth/approle/login"); n != 2 {
		t.Errorf("%d logins, want 2", n)
	}
	if n := f.count("POST /v1/auth/token/renew-self"); n != 0 {
		t.Errorf("%d renewals of a non-renewable token", n)
	}
}

func TestAppRoleSecretIDIsReadAtEachLogin(t *testing.T) {
	f := newFakeTransit(t)
	f.renew, f.lease = false, 100
	var secretPath string
	c, _, clk := testClient(t, f, func(cfg *Config) {
		appRoleCfg(t)(cfg)
		secretPath = cfg.AppRole.SecretIDFile
	})
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.secretID = "test-secret-id-two"
	f.mu.Unlock()
	if err := os.WriteFile(secretPath, []byte("test-secret-id-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clk.advance(60 * time.Second)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatalf("login with the replaced secret ID: %v", err)
	}
}

func TestAppRoleLoginFails(t *testing.T) {
	f := newFakeTransit(t)
	f.secretID = "another-secret-id"
	c, _, _ := testClient(t, f, appRoleCfg(t))
	_, err := c.Wrap(ctxA, dk, aadA)
	if err == nil || !strings.Contains(err.Error(), "AppRole login") {
		t.Fatalf("Wrap = %v, want a login error", err)
	}
	if n := f.count("POST /v1/transit/encrypt/rpmgr"); n != 0 {
		t.Errorf("Transit was called %d times without a token", n)
	}
	if strings.Contains(err.Error(), testSecretID) || strings.Contains(err.Error(), testRoleID) {
		t.Errorf("the login error holds a credential: %v", err)
	}
}

func TestConfigErrors(t *testing.T) {
	f := newFakeTransit(t)
	ok := func(cfg *Config) {}
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.WriteFile(loose, []byte(testToken), 0o644); err != nil { //nolint:gosec // the test of a mode check
		t.Fatal(err)
	}
	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	trailing := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(trailing, append(append([]byte{}, f.ca.caPEM...), []byte("\nextra text\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Config){
		"http address":       func(c *Config) { c.Address = "http://127.0.0.1:8200" },
		"no address":         func(c *Config) { c.Address = "" },
		"address credential": func(c *Config) { c.Address = "https://user:pw@127.0.0.1:8200" },
		"address query":      func(c *Config) { c.Address = "https://127.0.0.1:8200/?x=1" },
		"no key":             func(c *Config) { c.Key = "" },
		"key with slash":     func(c *Config) { c.Key = "a/b" },
		"mount with dots":    func(c *Config) { c.Mount = "a/../b" },
		"mount with query":   func(c *Config) { c.Mount = "a?b" },
		"no credential":      func(c *Config) { c.TokenFile = "" },
		"both credentials": func(c *Config) {
			c.AppRole = &AppRole{RoleIDFile: "a", SecretIDFile: "b"}
		},
		"approle one file": func(c *Config) {
			c.TokenFile, c.AppRole = "", &AppRole{RoleIDFile: "a"}
		},
		"ca file missing":  func(c *Config) { c.CAFile = filepath.Join(t.TempDir(), "none") },
		"ca file not PEM":  func(c *Config) { c.CAFile = notPEM },
		"ca file trailing": func(c *Config) { c.CAFile = trailing },
	}
	for name, mut := range cases {
		cfg := Config{Address: f.srv.URL, Key: "rpmgr", CAFile: writeCA(t, f.ca.caPEM), TokenFile: writeCred(t, "token", testToken)}
		ok(&cfg)
		mut(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// A credential file that others can read is refused when it is used, and its content stays out
	// of the error.
	c, _, _ := testClient(t, f, func(cfg *Config) { cfg.TokenFile = loose })
	_, err := c.Wrap(ctxA, dk, aadA)
	if err == nil || !strings.Contains(err.Error(), "0644") || strings.Contains(err.Error(), testToken) {
		t.Errorf("a world-readable token file: %v", err)
	}
	// An empty token file.
	empty := writeCred(t, "empty", "")
	c, _, _ = testClient(t, f, func(cfg *Config) { cfg.TokenFile = empty })
	if _, err := c.Wrap(ctxA, dk, aadA); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("an empty token file: %v", err)
	}
}

func TestMountDefaultsAndNormalisation(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, func(cfg *Config) { cfg.Mount = "/transit/" })
	if string(c.ID()) != "transit/rpmgr" {
		t.Errorf("ID = %q", c.ID())
	}
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
}

func TestTLSMinimumVersion(t *testing.T) {
	f := newFakeTransit(t)
	c, _, _ := testClient(t, f, nil)
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig.MinVersion < 0x0303 || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("TLS config = %+v", tr.TLSClientConfig)
	}
	if tr.Proxy != nil {
		t.Error("a proxy is set")
	}
}
