// SPDX-License-Identifier: Apache-2.0

package telemetrytest_test

import (
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/telemetry/telemetrytest"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// reporter is a test that a Sink reports to.
type reporter struct {
	errs     []string
	cleanups []func()
}

func (r *reporter) Helper() {}
func (r *reporter) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}
func (r *reporter) Cleanup(f func()) { r.cleanups = append(r.cleanups, f) }

// end runs the cleanups as a test's end does and returns the reports.
func (r *reporter) end() []string {
	for i := len(r.cleanups) - 1; i >= 0; i-- {
		r.cleanups[i]()
	}
	return r.errs
}

func TestSink(t *testing.T) {
	tok, err := token.New(token.PersonalAPI)
	if err != nil {
		t.Fatal(err)
	}
	const registered = "kek-material-0123456789"
	key := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not a real key")}))
	for _, tc := range []struct {
		name  string
		write func(s *telemetrytest.Sink)
		leaks int
	}{
		{"ordinary lines", func(s *telemetrytest.Sink) {
			s.Logger().Info("route applied", "route", "rt_1", "revision", 7)
			s.Logger().Debug("dial", "target", "127.0.0.1:8080")
		}, 0},
		{"a token's display prefix", func(s *telemetrytest.Sink) {
			s.Logger().Info("token created", "prefix", tok[:len("rpmgr_pat_")+4])
		}, 0},
		{"a secret.Value", func(s *telemetrytest.Sink) { s.Logger().Info("login", "credential", secret.New(tok)) }, 0},
		{"a denied key", func(s *telemetrytest.Sink) { s.Logger().Info("login", "api_token", tok, "Password", registered) }, 0},
		{"a short registered value", func(s *telemetrytest.Sink) { s.Secret("abc"); s.Logger().Info("id abc") }, 0},
		{"a token in a message", func(s *telemetrytest.Sink) { s.Logger().Info("enrolled with " + tok) }, 1},
		{"a token in an error", func(s *telemetrytest.Sink) {
			s.Logger().Error("enrollment failed", "error", fmt.Errorf("parse %q: %w", tok, errors.New("bad")))
		}, 1},
		{"a truncated token", func(s *telemetrytest.Sink) { s.Logger().Warn("token", "id", tok[:len("rpmgr_pat_")+20]) }, 1},
		{"a private key", func(s *telemetrytest.Sink) { s.Logger().Debug("loaded", "pem", key) }, 1},
		{"a registered value", func(s *telemetrytest.Sink) { s.Secret(registered); s.Logger().Info("kek", "raw", registered) }, 1},
		{"a value split across writes", func(s *telemetrytest.Sink) {
			s.Secret(registered)
			line := `{"msg":"x","v":"` + registered + "\"}\n"
			_, _ = s.Write([]byte(line[:20]))
			_, _ = s.Write([]byte(line[20:]))
		}, 1},
		{"a last line without a newline", func(s *telemetrytest.Sink) { _, _ = s.Write([]byte("tail " + tok)) }, 1},
		{"one finding per line", func(s *telemetrytest.Sink) {
			s.Secret(registered)
			s.Logger().Info(tok, "a", registered, "b", key)
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &reporter{}
			s := telemetrytest.NewSink(r)
			tc.write(s)
			errs := r.end()
			if s.Lines() == 0 {
				t.Fatal("no line was counted")
			}
			if len(errs) != tc.leaks {
				t.Fatalf("%d reports, want %d: %q", len(errs), tc.leaks, errs)
			}
			for _, e := range errs {
				if strings.Contains(e, tok[len("rpmgr_pat_"):len("rpmgr_pat_")+20]) || strings.Contains(e, registered) ||
					strings.Contains(e, "not a real key") {
					t.Errorf("the report repeats the secret: %s", e)
				}
			}
		})
	}
}
