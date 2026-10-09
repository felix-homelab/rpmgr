// SPDX-License-Identifier: Apache-2.0

package units_test

import (
	"strings"
	"testing"

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
// controllers and all-in-one may bind ports below 1024, connectors get no capability and reload on
// SIGHUP; only controller and all-in-one load the KEK credential, and only when named.
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
		{"controller", "rpmgr-kek", []string{cred, "AmbientCapabilities=CAP_NET_BIND_SERVICE"}, nil},
		{"controller", "", []string{"AmbientCapabilities=CAP_NET_BIND_SERVICE"}, []string{cred}},
		{"all-in-one", "rpmgr-kek", []string{cred}, nil},
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
	}
}

// TestRenderRefuses: an unknown role, a binary path that is relative or holds a space, %, $ or a
// backslash (which systemd would expand or split), and a credential name systemd refuses.
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
	} {
		if _, err := units.Render(tc.role, tc.o); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}
