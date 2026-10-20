// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// TestServiceState: rpmgr status says what the admin listener's /readyz answers, the reason it is
// not ready once, without the "not ready:" the answer starts with.
func TestServiceState(t *testing.T) {
	admin := func(t *testing.T, h http.Handler) string {
		t.Helper()
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		return strings.TrimPrefix(srv.URL, "http://")
	}
	answer := func(code int, body string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		})
	}
	ready := func(err error) http.Handler {
		return telemetry.AdminHandler(telemetry.NewRegistry(), func(context.Context) error { return err })
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closedAddr := strings.TrimPrefix(closed.URL, "http://")
	closed.Close()
	for name, tc := range map[string]struct{ admin, want string }{
		"ready":               {admin(t, ready(nil)), "running and ready"},
		"not ready":           {admin(t, ready(errors.New("no control session"))), "running, not ready: no control session"},
		"a reason without it": {admin(t, answer(http.StatusServiceUnavailable, "draining\n")), "running, not ready: draining"},
		"no reason":           {admin(t, answer(http.StatusServiceUnavailable, "not ready: \n")), "running, not ready"},
		"an empty answer":     {admin(t, answer(http.StatusServiceUnavailable, "")), "running, not ready"},
		"no listener":         {"", "unknown: the admin listener is off"},
		"nothing answers":     {closedAddr, "not running (nothing answers on " + closedAddr + ")"},
	} {
		if got := serviceState(context.Background(), tc.admin); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

// TestLoadAgentBoot: a boot file valid for one role only has that role; one valid for both, such
// as the one /install.sh writes for a gateway, has the role its identity records, and the
// connector's without one; a file valid for neither is refused.
func TestLoadAgentBoot(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "identity")
	if err := os.MkdirAll(identity, 0o700); err != nil {
		t.Fatal(err)
	}
	common := "version: 1\ncontroller: {endpoints: ['https://panel.example.com']}\nidentity_dir: " + identity + "\n"
	noEnv := func(string) string { return "" }
	for _, tc := range []struct {
		name, boot, kind, role, admin string
	}{
		{"gateway keys", common + "listen: {tcp: ':443'}\n", "", "gateway", "127.0.0.1:7382"},
		{"connector keys", common + "policy_file: /etc/rpmgr/policy.yaml\n", "", "connector", "127.0.0.1:7383"},
		{"both, a gateway's identity", common, "gateway", "gateway", "127.0.0.1:7382"},
		{"both, a connector's identity", common, "connector", "connector", "127.0.0.1:7383"},
		{"both, the admin address given", common + "listen: {admin: '127.0.0.1:9000'}\n", "gateway", "gateway", "127.0.0.1:9000"},
		{"both, no identity", common, "", "connector", "127.0.0.1:7383"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "boot.yaml")
			if err := os.WriteFile(path, []byte(tc.boot), 0o600); err != nil {
				t.Fatal(err)
			}
			agentFile := filepath.Join(identity, "agent.json")
			_ = os.Remove(agentFile)
			if tc.kind != "" {
				if err := os.WriteFile(agentFile, []byte(`{"agent_id":"x_1","kind":"`+tc.kind+`"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			b, err := loadAgentBoot(path, noEnv)
			if err != nil || b.role != tc.role || b.admin != tc.admin || b.path != path {
				t.Fatalf("%+v, %v; want the role %s, admin %s", b, err, tc.role, tc.admin)
			}
		})
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte(common+"listen: {tcp: ':443'}\npolicy_file: /p.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAgentBoot(bad, noEnv); err == nil {
		t.Error("a boot file valid for neither role was read")
	}
	if b, err := loadAgentBoot("", func(k string) string { return map[string]string{"RPMGR_CONFIG": bad}[k] }); err == nil {
		t.Errorf("$RPMGR_CONFIG: read %+v", b)
	}
}
