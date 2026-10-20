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

// TestUpdaterReady: the updater asks each role's admin listener, at the address its boot file
// names, whether it is ready; a role that is not ready, not running, without a boot file, or not
// one the updater replaces counts as not ready.
func TestUpdaterReady(t *testing.T) {
	dir := t.TempDir()
	common := "version: 1\ncontroller: {endpoints: ['https://panel.example.com']}\n"
	listen := func(t *testing.T, err error) string {
		t.Helper()
		srv := httptest.NewServer(telemetry.AdminHandler(telemetry.NewRegistry(), func(context.Context) error { return err }))
		t.Cleanup(srv.Close)
		return strings.TrimPrefix(srv.URL, "http://")
	}
	boot := func(t *testing.T, role, admin string) {
		t.Helper()
		b := common + "listen: {admin: '" + admin + "'}\n"
		if err := os.WriteFile(filepath.Join(dir, role+".yaml"), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	boot(t, "connector", listen(t, nil))
	if err := ready(context.Background(), dir, "connector"); err != nil {
		t.Errorf("a ready connector: %v", err)
	}
	boot(t, "gateway", listen(t, errors.New("no control session")))
	if err := ready(context.Background(), dir, "gateway"); err == nil || !strings.Contains(err.Error(), "no control session") {
		t.Errorf("a gateway without a control session: %v", err)
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	addr := strings.TrimPrefix(closed.URL, "http://")
	closed.Close()
	boot(t, "connector", addr)
	if err := ready(context.Background(), dir, "connector"); err == nil {
		t.Error("a connector that does not run counted as ready")
	}
	if err := ready(context.Background(), t.TempDir(), "connector"); err == nil {
		t.Error("a role without a boot file counted as ready")
	}
	if err := ready(context.Background(), dir, "controller"); err == nil {
		t.Error("the updater checked a controller, which it never replaces")
	}
}
