// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
