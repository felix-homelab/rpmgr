// SPDX-License-Identifier: Apache-2.0

package units_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/units"
)

func lines(t *testing.T, role string, o units.Options) map[string]bool {
	t.Helper()
	b, err := units.Render(role, o)
	if err != nil {
		t.Fatalf("%s: %v", role, err)
	}
	out := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		out[l] = true
	}
	return out
}

// TestRender: every role runs as rpmgr with the hardening of docs/10-operations.md; gateways,
// controllers and all-in-one may bind ports below 1024, connectors get no capability; connectors
// reload on SIGHUP (their local policy), gateways and all-in-one reload with a hand-off; only controller and
// all-in-one load the KEK credential, and only when named.
func TestRender(t *testing.T) {
	common := []string{"User=rpmgr", "Group=rpmgr", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
		"PrivateDevices=yes", "RestrictNamespaces=yes", "MemoryDenyWriteExecute=yes", "SystemCallArchitectures=native",
		"StateDirectory=rpmgr", "ReadOnlyPaths=/etc/rpmgr", "Restart=on-failure", "WantedBy=multi-user.target"}
	const cred = "LoadCredentialEncrypted=rpmgr-kek:/etc/rpmgr/credstore/rpmgr-kek" //nolint:gosec // G101: a unit line naming a credential
	for _, tc := range []struct {
		role       string
		credential string
		want, not  []string
	}{
		{"gateway", "rpmgr-kek", []string{"AmbientCapabilities=CAP_NET_BIND_SERVICE", "RuntimeDirectory=rpmgr/gateway",
			"ExecReload=/usr/local/bin/rpmgr handoff gateway"},
			[]string{cred, "ExecReload=/bin/kill -HUP $MAINPID", "Type=notify", "NotifyAccess=all"}},
		{"connector", "rpmgr-kek", []string{"CapabilityBoundingSet=", "ExecReload=/bin/kill -HUP $MAINPID",
			"RuntimeDirectory=rpmgr/connector"}, []string{cred, "AmbientCapabilities=CAP_NET_BIND_SERVICE", "Type=notify", "NotifyAccess=all"}},
		{"controller", "rpmgr-kek", []string{cred, "AmbientCapabilities=CAP_NET_BIND_SERVICE"},
			[]string{"ExecReload=/bin/kill -HUP $MAINPID", "Type=notify", "NotifyAccess=all", "RuntimeDirectory=rpmgr/controller"}},
		{"controller", "", []string{"AmbientCapabilities=CAP_NET_BIND_SERVICE"}, []string{cred}},
		{"all-in-one", "rpmgr-kek", []string{cred, "AmbientCapabilities=CAP_NET_BIND_SERVICE", "ExecReload=/usr/local/bin/rpmgr handoff all-in-one",
			"RuntimeDirectory=rpmgr/all-in-one"}, []string{"ExecReload=/bin/kill -HUP $MAINPID", "Type=notify", "NotifyAccess=all"}},
	} {
		got := lines(t, tc.role, units.Options{Bin: "/usr/local/bin/rpmgr", Credential: tc.credential})
		want := append(append([]string{"ExecStart=/usr/local/bin/rpmgr " + tc.role + " --config /etc/rpmgr/" + tc.role + ".yaml"}, common...), tc.want...)
		for _, l := range want {
			if !got[l] {
				t.Errorf("%s (credential %q): no %q", tc.role, tc.credential, l)
			}
		}
		for _, l := range tc.not {
			if got[l] {
				t.Errorf("%s (credential %q): %q", tc.role, tc.credential, l)
			}
		}
		for l := range got {
			if strings.HasPrefix(l, "ReadWritePaths=") {
				t.Errorf("%s without a writable directory: %q", tc.role, l)
			}
		}
	}
}

// TestRenderWritable: each writable directory, such as the revocation-log sink, becomes its own
// ReadWritePaths= with "-", cleaned of a trailing or doubled slash, after ReadOnlyPaths=/etc/rpmgr,
// so that ProtectSystem=strict leaves it writable and a missing one does not stop the start.
func TestRenderWritable(t *testing.T) {
	for _, role := range []string{"controller", "all-in-one"} {
		b, err := units.Render(role, units.Options{Bin: "/usr/local/bin/rpmgr", Writable: []string{"/mnt/rpmgr-revocations/", "//srv//sink"}})
		if err != nil {
			t.Fatal(err)
		}
		const want = "ReadOnlyPaths=/etc/rpmgr\n" +
			"# Directories the boot file names outside the state directory; \"-\" starts without a missing one.\n" +
			"ReadWritePaths=-/mnt/rpmgr-revocations\nReadWritePaths=-/srv/sink\nLimitNOFILE="
		if !strings.Contains(string(b), want) {
			t.Errorf("%s: no\n%s\nin\n%s", role, want, b)
		}
		if n := strings.Count(string(b), "ReadWritePaths="); n != 2 {
			t.Errorf("%s: %d ReadWritePaths= lines", role, n)
		}
	}
}

// TestForController: the boot file decides the credential and the writable sink; a KEK file needs
// no credential, and without a sink nothing is writable beyond the state directory.
func TestForController(t *testing.T) {
	for name, tc := range map[string]struct {
		c    config.Controller
		want units.Options
	}{
		"credential and sink": {controller(config.KEKSystemdCredential, "rpmgr-kek", "/mnt/sink"),
			units.Options{Credential: "rpmgr-kek", Writable: []string{"/mnt/sink"}}}, //nolint:gosec // G101: a credential's name
		"credential, no sink": {controller(config.KEKSystemdCredential, "kek-2", ""), units.Options{Credential: "kek-2"}},
		"a KEK file, no sink": {controller(config.KEKFile, "", ""), units.Options{}},
		"a KEK file and sink": {controller(config.KEKFile, "", "/srv/revocations"), units.Options{Writable: []string{"/srv/revocations"}}},
	} {
		if got := units.ForController(tc.c); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
}

func controller(source, name, sink string) config.Controller {
	var c config.Controller
	c.KEK.Source, c.KEK.Name, c.RevocationLog.Sink = source, name, sink
	return c
}

// TestRenderRefuses: an unknown role, a binary path that is relative or holds a space, %, $ or a
// backslash (which systemd would expand or split), a credential name systemd refuses, and a
// writable directory that is relative, the root, not normalised, or holds what systemd would
// split, unquote or expand.
func TestRenderRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		role string
		o    units.Options
	}{
		"an unknown role":      {"relay", units.Options{Bin: "/usr/bin/rpmgr"}},
		"a relative binary":    {"gateway", units.Options{Bin: "rpmgr"}},
		"a space":              {"gateway", units.Options{Bin: "/opt/my apps/rpmgr"}},
		"a percent sign":       {"gateway", units.Options{Bin: "/opt/%h/rpmgr"}},
		"a dollar sign":        {"gateway", units.Options{Bin: "/opt/$HOME/rpmgr"}},
		"a backslash":          {"gateway", units.Options{Bin: `/opt/x\nrpmgr`}},
		"no binary":            {"gateway", units.Options{}},
		"a bad credential":     {"controller", units.Options{Bin: "/usr/bin/rpmgr", Credential: "kek/../x"}},                  //nolint:gosec // G101: a credential's name
		"a newline credential": {"all-in-one", units.Options{Bin: "/usr/bin/rpmgr", Credential: "kek\nExecStartPre=/bin/sh"}}, //nolint:gosec // G101: a credential's name
		"a relative sink":      {"controller", sink("mnt/sink")},
		"an empty sink":        {"controller", sink("")},
		"the root as sink":     {"controller", sink("/")},
		"a doubled root":       {"all-in-one", sink("//")},
		"a .. part":            {"controller", sink("/mnt/../etc")},
		"a trailing ..":        {"controller", sink("/mnt/sink/..")},
		"a . part":             {"controller", sink("/mnt/./sink")},
		"a space in a sink":    {"controller", sink("/mnt/my sink")},
		"a tab in a sink":      {"controller", sink("/mnt/my\tsink")},
		"a newline in a sink":  {"all-in-one", sink("/mnt/sink\nExecStartPre=/bin/sh")},
		"a DEL in a sink":      {"controller", sink("/mnt/sink\x7f")},
		"a specifier in sink":  {"controller", sink("/mnt/%h")},
		"a backslash in sink":  {"controller", sink(`/mnt/x\x20y`)},
		"a quote in a sink":    {"controller", sink(`/mnt/"sink"`)},
		"an apostrophe":        {"controller", sink("/mnt/it's")},
		"one bad of two sinks": {"controller", units.Options{Bin: "/usr/bin/rpmgr", Writable: []string{"/mnt/sink", "sink"}}},
	} {
		if _, err := units.Render(tc.role, tc.o); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}

func sink(dir string) units.Options {
	return units.Options{Bin: "/usr/bin/rpmgr", Writable: []string{dir}}
}

// TestRenderUpdater: the updater pair names the binary install.json records in ExecStart, runs
// as root (no User=), may write only the binary's directory and its own state, keeps the status
// file after the run, and runs once at boot.
func TestRenderUpdater(t *testing.T) {
	b, err := units.RenderUpdater("/opt/rpmgr/bin/rpmgr")
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	path, service, ok := strings.Cut(out, "# /etc/systemd/system/rpmgr-update.service\n")
	if !ok || !strings.HasPrefix(path, "# /etc/systemd/system/rpmgr-update.path\n") {
		t.Fatalf("the pair is not two units, each after its file name:\n%s", out)
	}
	for _, want := range []string{"PathChanged=/var/lib/rpmgr/update/manifest.json", "Unit=rpmgr-update.service"} {
		if !strings.Contains(path, want+"\n") {
			t.Errorf("rpmgr-update.path lacks %q", want)
		}
	}
	for _, want := range []string{
		"Type=oneshot",
		"ExecStart=/opt/rpmgr/bin/rpmgr updater apply --staged /var/lib/rpmgr/update --state /var/lib/rpmgr-update",
		"RuntimeDirectory=rpmgr-update", "RuntimeDirectoryPreserve=yes", "ProtectSystem=strict",
		"ReadWritePaths=/opt/rpmgr/bin /var/lib/rpmgr-update -/var/lib/rpmgr -/etc/systemd/system/rpmgr-gateway.service.d -/etc/systemd/system/rpmgr-connector.service.d -/etc/systemd/system/rpmgr-all-in-one.service.d", "ReadOnlyPaths=-/var/lib/rpmgr/update", "NoNewPrivileges=yes",
		// Once at boot, after the roles, to finish an install that a crash or reboot interrupted.
		"After=network-online.target rpmgr-controller.service rpmgr-gateway.service rpmgr-connector.service rpmgr-all-in-one.service", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(service, want+"\n") {
			t.Errorf("rpmgr-update.service lacks %q", want)
		}
	}
	if strings.Contains(service, "User=") {
		t.Error("the updater must run as root")
	}
	for _, bin := range []string{"", "rpmgr", "/usr/local/bin/rp mgr", "/usr/local/bin/%n", "/usr/local//bin/rpmgr", "/usr/local/bin/../rpmgr"} {
		if _, err := units.RenderUpdater(bin); err == nil {
			t.Errorf("RenderUpdater(%q) succeeded", bin)
		}
	}
}

// TestRenderDropIn: Type=notify is in a drop-in, for the roles that restart with a hand-off only.
func TestRenderDropIn(t *testing.T) {
	for _, role := range []string{"gateway", "all-in-one", "connector"} {
		b, err := units.RenderDropIn(role)
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		got := lines(t, role, units.Options{Bin: "/usr/local/bin/rpmgr"})
		if got["Type=notify"] {
			t.Errorf("%s: the unit itself is Type=notify", role)
		}
		for _, l := range []string{"[Service]", "Type=notify", "NotifyAccess=all"} {
			if !strings.Contains("\n"+string(b), "\n"+l+"\n") {
				t.Errorf("%s: no %q in %q", role, l, b)
			}
		}
	}
	// The start timeout of 03 covers a reload, whose hand-off may take the readiness window and more.
	if b, _ := units.RenderDropIn("gateway"); !strings.Contains(string(b), "\nTimeoutStartSec=120\n") {
		t.Errorf("no TimeoutStartSec=120 in %q", b)
	}
	for _, role := range []string{"controller", "update", ""} {
		if b, err := units.RenderDropIn(role); err == nil {
			t.Errorf("%q: drop-in %q", role, b)
		}
	}
}

func TestHasHandoff(t *testing.T) {
	for v, want := range map[string]bool{
		"0.3.0": true, "v0.3.0": true, "0.3.0-rc.1": true, "0.3.1": true, "1.0.0": true,
		"0.2.0": false, "0.2.9": false, "0.1.0": false, "": false, "dev": false,
	} {
		if got := units.HasHandoff(v); got != want {
			t.Errorf("HasHandoff(%q) = %v, want %v", v, got, want)
		}
	}
}
