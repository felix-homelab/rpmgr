// SPDX-License-Identifier: Apache-2.0

package apicli_test

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// TestCredentials: the credentials file is written for the user only and read back; a file other
// users may read or write, an incomplete one and one with unknown keys are refused; without one,
// the commands say to log in.
func TestCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmgr", "credentials.yaml")
	if _, err := apicli.Load(path); !errors.Is(err, apicli.ErrNotLoggedIn) {
		t.Fatalf("no file: %v", err)
	}
	c := &apicli.Credentials{Controller: "https://panel.example.com", Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_x")), CAFile: "/etc/ca.pem"}
	if err := apicli.Save(path, c); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Dir(path)); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("the directory: %v %v", st, err)
	}
	got, err := apicli.Load(path)
	if err != nil || got.Controller != c.Controller || got.Org != c.Org || got.Token.Reveal() != "rpmgr_pat_x" || got.CAFile != c.CAFile { //nolint:forbidigo // the test reads back the token it stored
		t.Fatalf("read back: %+v %v", got, err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := apicli.Load(path); err == nil || !strings.Contains(err.Error(), "open to other users") {
			t.Errorf("mode %04o: %v", mode, err)
		}
	}
	for name, text := range map[string]string{"no token": "controller: https://x\norg: org_1\n", "an unknown key": "controller: https://x\norg: o\ntoken: t\npassword: p\n"} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := apicli.Load(path); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if p, err := apicli.Path(func(string) string { return "/tmp/x.yaml" }); err != nil || p != "/tmp/x.yaml" {
		t.Errorf("RPMGR_CREDENTIALS: %q %v", p, err)
	}
}

// TestControllerURL: only an https URL with a host and no query, fragment or user is a controller.
func TestControllerURL(t *testing.T) {
	if u, err := apicli.ControllerURL("https://panel.example.com/"); err != nil || u != "https://panel.example.com" {
		t.Errorf("a URL: %q %v", u, err)
	}
	for _, bad := range []string{"http://panel.example.com", "panel.example.com", "https://", "https://a@panel.example.com", "https://p?x=1", "https://p#f"} {
		if _, err := apicli.ControllerURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestClient: the client sends the token as a Bearer header and trusts the CA file instead of the
// system's roots; a CA file without a certificate is refused.
func TestClient(t *testing.T) {
	var auth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { auth = r.Header.Get("Authorization") }))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := apicli.Client(&apicli.Credentials{Token: secret.FromBytes([]byte("rpmgr_pat_x")), CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if auth != "Bearer rpmgr_pat_x" {
		t.Errorf("Authorization %q", auth)
	}
	system, err := apicli.Client(&apicli.Credentials{Token: secret.FromBytes([]byte("rpmgr_pat_x"))})
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := system.Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Error("the system's roots trust the test server")
	}
	if err := os.WriteFile(ca, []byte("not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := apicli.Client(&apicli.Credentials{CAFile: ca}); err == nil {
		t.Error("a CA file without a certificate accepted")
	}
}
