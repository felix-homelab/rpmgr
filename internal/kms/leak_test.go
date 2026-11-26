// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a log destination that several goroutines may write.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestKMS_CredentialsNeverLogged provokes every failure of Transit that docs/12 lists, with the
// log at debug, and looks for a token, a role ID, a secret ID, a wrapped key or the data key in a
// log line or an error. The fake puts the credentials into its own error messages and answers,
// which a careless client would pass on.
func TestKMS_CredentialsNeverLogged(t *testing.T) {
	f := newFakeTransit(t)
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfgs := map[string]func(*Config){
		"token file": func(c *Config) { c.Logger = logger },
		"approle":    func(c *Config) { appRoleCfg(t)(c); c.Logger = logger },
	}

	wrapped := ""
	forbidden := func() []string {
		dkB64 := base64.StdEncoding.EncodeToString(dk)
		return []string{testToken, testRoleID, testSecretID, "approle-token-", dkB64, wrapped}
	}
	var errs []string
	record := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	for name, mut := range cfgs {
		t.Run(name, func(t *testing.T) {
			c, _, _ := testClient(t, f, mut)
			c.reqTTL = 100 * time.Millisecond
			w, err := c.Wrap(context.Background(), dk, aadA)
			if err != nil {
				t.Fatal(err)
			}
			if wrapped == "" {
				wrapped = strings.TrimPrefix(string(w), "vault:v1:")
			}
			// An error body that echoes the credentials and a wrapped key, for each status.
			var mode struct {
				sync.Mutex
				status int
				echo   string
			}
			get := func() (int, string) {
				mode.Lock()
				defer mode.Unlock()
				return mode.status, mode.echo
			}
			set := func(status int, echo string) {
				mode.Lock()
				defer mode.Unlock()
				mode.status, mode.echo = status, echo
			}
			f.override = func(rw http.ResponseWriter, r *http.Request) bool {
				status, echo := get()
				if strings.HasPrefix(r.URL.Path, "/v1/auth/") && status != 0 && echo == "login" {
					rw.WriteHeader(status)
					_, _ = fmt.Fprintf(rw, `{"errors":["bad %s and %s\nsecond line"]}`, testSecretID, testRoleID)
					return true
				}
				if !strings.Contains(r.URL.Path, "/transit/") || status == 0 {
					return false
				}
				switch echo {
				case "timeout":
					select {
					case <-r.Context().Done():
					case <-f.release:
					}
				case "malformed":
					rw.WriteHeader(status)
					_, _ = fmt.Fprintf(rw, "<html>%s %s vault:v1:%s</html>", r.Header.Get("X-Vault-Token"), testSecretID, wrapped) //nolint:gosec // G705: a test server that echoes secrets on purpose
				default:
					tok := r.Header.Get("X-Vault-Token")
					body, _ := json.Marshal(map[string]any{"errors": []string{
						"token " + tok + " secret_id " + knownSecret(name) + " key vault:v1:" + wrapped + " done",
					}})
					rw.WriteHeader(status)
					_, _ = rw.Write(body)
				}
				return true
			}
			for _, tc := range []struct {
				status int
				echo   string
			}{{401, "json"}, {403, "json"}, {500, "json"}, {503, "malformed"}, {400, "json"}, {200, "malformed"}, {200, "timeout"}} {
				set(tc.status, tc.echo)
				_, err := c.Wrap(context.Background(), dk, aadA)
				record(err)
				_, err = c.Unwrap(context.Background(), w, aadB)
				record(err)
				_, err = c.Rewrap(context.Background(), w, aadA)
				record(err)
				_, err = c.Check(context.Background())
				record(err)
			}
			if name == "approle" {
				// The login itself fails with a message that echoes the credentials. A new client has
				// no token yet.
				c2, _, _ := testClient(t, f, mut)
				set(400, "login")
				_, err := c2.Wrap(context.Background(), dk, aadA)
				record(err)
			}
			set(0, "")
		})
	}

	// An unreachable host.
	f2 := newFakeTransit(t)
	addr := f2.srv.URL
	f2.srv.Close()
	c, _, _ := testClient(t, f2, func(cfg *Config) { cfg.Address = addr; cfg.Logger = logger })
	_, err := c.Wrap(context.Background(), dk, aadA)
	record(err)

	// Credential files with a mode that others can read.
	loose := t.TempDir() + "/loose"
	if werr := writeLoose(loose, testToken); werr != nil {
		t.Fatal(werr)
	}
	c, _, _ = testClient(t, f, func(cfg *Config) { cfg.TokenFile = loose; cfg.Logger = logger })
	_, err = c.Wrap(context.Background(), dk, aadA)
	record(err)

	if len(errs) < 20 {
		t.Fatalf("only %d errors were provoked", len(errs))
	}
	all := logs.String() + "\n" + strings.Join(errs, "\n")
	if !strings.Contains(logs.String(), "level=DEBUG") || !strings.Contains(logs.String(), "level=WARN") {
		t.Fatalf("the log at debug is missing lines:\n%s", logs.String())
	}
	for _, bad := range forbidden() {
		if bad != "" && strings.Contains(all, bad) {
			i := strings.Index(all, bad)
			t.Errorf("%q appears in a log line or an error: ...%s...", bad, all[max(0, i-100):min(len(all), i+60)])
		}
	}
	for _, e := range errs {
		if len(e) > 600 {
			t.Errorf("an error of %d bytes: %.80s", len(e), e)
		}
		if strings.ContainsAny(e, "\n\r") {
			t.Errorf("an error with a line break: %q", e)
		}
	}
	// The credentials are redacted, not dropped, so an operator sees that something was there.
	if !strings.Contains(strings.Join(errs, "\n"), "[REDACTED]") {
		t.Error("no error shows a redaction")
	}
}

// knownSecret is the secret ID that the client has been given, if any; a client cannot redact one
// it never saw.
func knownSecret(mode string) string {
	if mode == "approle" {
		return testSecretID
	}
	return "unknown"
}

func writeLoose(path, content string) error {
	return writeFileMode(path, content, 0o644)
}
