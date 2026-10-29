// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/update"
	"github.com/felix-homelab/rpmgr/internal/version"
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
		t.Error("a controller without a boot file counted as ready")
	}
}

// runUpdater runs `rpmgr updater` of a build with the variant, as root unless root is false.
func runUpdater(t *testing.T, variant string, root bool, args ...string) (int, string, string) {
	t.Helper()
	old := isRoot
	t.Cleanup(func() { isRoot = old })
	isRoot = func() bool { return root }
	var out, errOut bytes.Buffer
	tree := &cli.Command{Name: "rpmgr", Sub: []*cli.Command{Updater(variant)}}
	code := cli.Main(context.Background(), tree, append([]string{"updater", "install"}, args...), &cli.Env{
		Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }})
	return code, out.String(), errOut.String()
}

// TestUpdaterInstall: the install scripts' `rpmgr updater install` records the build's variant,
// the given roles and those with a boot file, raises the state to the release's, and writes the
// units; on a host that v0.1.0 installed it turns the single role into a list and raises the
// state, and it never lowers it. Without a seq, a missing state starts at the binary's version
// with seq 0, except on a development build. It refuses to run as another user than root, whose
// files the updater would not trust, and a seq without a floor or the other way round.
func TestUpdaterInstall(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the root updater runs on Linux only")
	}
	base := t.TempDir()
	state, etc, unitDir := filepath.Join(base, "rpmgr-update"), filepath.Join(base, "etc"), filepath.Join(base, "units")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "gateway.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := []string{"--state", state, "--etc", etc, "--units", unitDir, "--path", "/usr/local/bin/rpmgr"}
	code, out, errOut := runUpdater(t, "full", true, append(flags, "--role", "connector", "--seq", "87", "--floor", "1.4.2")...)
	if code != 0 {
		t.Fatalf("updater install: %d %q %q", code, out, errOut)
	}
	for _, want := range []string{"the full build at /usr/local/bin/rpmgr, roles: connector, gateway.", "manifest seq 87, version floor 1.4.2",
		filepath.Join(unitDir, "rpmgr-update.path") + " and " + filepath.Join(unitDir, "rpmgr-update.service")} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in %q", want, out)
		}
	}
	if in, err := update.ReadInstall(state); err != nil || in.Method != "script" || strings.Join(in.Roles, ",") != "connector,gateway" {
		t.Errorf("record %+v, %v", in, err)
	}
	// An older release never lowers the state; without systemd no units are written.
	noUnits := filepath.Join(base, "none")
	code, out, _ = runUpdater(t, "full", true, "--state", state, "--etc", etc, "--units", noUnits, "--no-units", "--seq", "80", "--floor", "1.3.0")
	if st, err := update.ReadState(state); code != 0 || err != nil || st.Seq != 87 || st.Floor != "1.4.2" {
		t.Errorf("an older release: %d %q, state %+v, %v", code, out, st, err)
	}
	if _, err := os.Stat(noUnits); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("--no-units wrote units: %v", err)
	}

	t.Run("host of v0.1.0", func(t *testing.T) {
		state := filepath.Join(t.TempDir(), "rpmgr-update")
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string]string{
			"install.json": `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full","role":"connector"}`,
			"state.json":   `{"seq":1,"floor":"0.1.0"}`,
		} {
			if err := os.WriteFile(filepath.Join(state, name), []byte(body+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		code, out, errOut := runUpdater(t, "full", true, "--state", state, "--etc", t.TempDir(), "--no-units", "--seq", "2", "--floor", "0.2.0")
		in, err := update.ReadInstall(state)
		st, serr := update.ReadState(state)
		if code != 0 || err != nil || serr != nil || strings.Join(in.Roles, ",") != "connector" || in.Role != "" || st.Seq != 2 || st.Floor != "0.2.0" {
			t.Errorf("%d %q %q: record %+v, %v; state %+v, %v", code, out, errOut, in, err, st, serr)
		}
	})
	t.Run("development build without a seq", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "s")
		code, out, _ := runUpdater(t, "connector", true, "--state", dir, "--etc", t.TempDir(), "--no-units")
		if code != 0 || !strings.Contains(out, "roles: none yet") || !strings.Contains(out, "this development build has no release version") {
			t.Errorf("%d %q", code, out)
		}
		if _, err := os.Stat(filepath.Join(dir, "state.json")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a development build wrote a state: %v", err)
		}
	})
	t.Run("release build without a seq", func(t *testing.T) {
		old := version.Version
		t.Cleanup(func() { version.Version = old })
		version.Version = "1.4.2"
		dir := filepath.Join(t.TempDir(), "s")
		code, out, _ := runUpdater(t, "full", true, "--state", dir, "--etc", t.TempDir(), "--no-units")
		if st, err := update.ReadState(dir); code != 0 || err != nil || st != (update.State{Floor: "1.4.2"}) ||
			!strings.Contains(out, "version floor 1.4.2; the first update records the manifest seq") {
			t.Errorf("%d %q: state %+v, %v", code, out, st, err)
		}
		// An existing state stays as it is.
		version.Version = "1.5.0"
		if code, out, _ := runUpdater(t, "full", true, "--state", dir, "--etc", t.TempDir(), "--no-units"); code != 0 {
			t.Fatalf("%d %q", code, out)
		}
		if st, err := update.ReadState(dir); err != nil || st != (update.State{Floor: "1.4.2"}) {
			t.Errorf("state %+v, %v; want it unchanged", st, err)
		}
	})
	t.Run("refusals", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "s")
		if code, _, errOut := runUpdater(t, "full", false, "--state", dir, "--no-units"); code == 0 || !strings.Contains(errOut, "run it as root") {
			t.Errorf("not root: %d %q", code, errOut)
		}
		if code, _, errOut := runUpdater(t, "full", true, "--state", dir, "--no-units", "--seq", "5"); code != cli.ExitUsage {
			t.Errorf("--seq without --floor: %d %q", code, errOut)
		}
		if code, _, errOut := runUpdater(t, "full", true, "--state", dir, "--no-units", "--floor", "1.4.2"); code != cli.ExitUsage {
			t.Errorf("--floor without --seq: %d %q", code, errOut)
		}
		if code, _, errOut := runUpdater(t, "full", true, "--state", dir, "--no-units", "extra"); code != cli.ExitUsage {
			t.Errorf("an argument: %d %q", code, errOut)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a refusal created the state directory: %v", err)
		}
		// Another variant than recorded is refused.
		if code, _, errOut := runUpdater(t, "connector", true, "--state", state, "--etc", etc, "--no-units"); code == 0 ||
			!strings.Contains(errOut, "records the full build") {
			t.Errorf("another variant: %d %q", code, errOut)
		}
	})
}

// TestControlPlane: the updater reads the database driver from the boot file itself, so that a
// PostgreSQL controller is named as one even though its boot file does not load yet.
func TestControlPlane(t *testing.T) {
	dir := t.TempDir()
	write := func(role, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, role+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("controller", "version: 1\npublic_url: https://panel.example.com\n")
	write("all-in-one", "version: 1\ndatabase: {driver: postgres, dsn: 'postgres://x'}\n")
	write("broken", "database: [")
	for role, want := range map[string]string{"controller": "sqlite", "all-in-one": "postgres"} {
		cp, err := controlPlane(dir, role)
		if err != nil || cp.Driver != want || cp.Config != filepath.Join(dir, role+".yaml") {
			t.Errorf("controlPlane(%s) = %+v, %v; want driver %s", role, cp, err, want)
		}
	}
	for _, role := range []string{"broken", "missing"} {
		if _, err := controlPlane(dir, role); err == nil {
			t.Errorf("controlPlane(%s) succeeded", role)
		}
	}
	srv := httptest.NewServer(telemetry.AdminHandler(telemetry.NewRegistry(), func(context.Context) error { return nil }))
	defer srv.Close()
	write("controller", "version: 1\npublic_url: https://panel.example.com\nlisten: {admin: '"+strings.TrimPrefix(srv.URL, "http://")+"'}\n")
	if err := ready(context.Background(), dir, "controller"); err != nil {
		t.Errorf("a ready controller: %v", err)
	}
}
