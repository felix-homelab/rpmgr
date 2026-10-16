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
// and all-in-one, whose connector has a local policy, reload on SIGHUP; only controller and
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
		{"gateway", "rpmgr-kek", []string{"AmbientCapabilities=CAP_NET_BIND_SERVICE"}, []string{cred, "ExecReload=/bin/kill -HUP $MAINPID"}},
		{"connector", "rpmgr-kek", []string{"CapabilityBoundingSet=", "ExecReload=/bin/kill -HUP $MAINPID"},
			[]string{cred, "AmbientCapabilities=CAP_NET_BIND_SERVICE"}},
		{"controller", "rpmgr-kek", []string{cred, "AmbientCapabilities=CAP_NET_BIND_SERVICE"}, []string{"ExecReload=/bin/kill -HUP $MAINPID"}},
		{"controller", "", []string{"AmbientCapabilities=CAP_NET_BIND_SERVICE"}, []string{cred}},
		{"all-in-one", "rpmgr-kek", []string{cred, "AmbientCapabilities=CAP_NET_BIND_SERVICE", "ExecReload=/bin/kill -HUP $MAINPID"}, nil},
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
