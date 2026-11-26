// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"fmt"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/config"
)

// TestKMSKEK: kek.source kms takes the Transit key and one login, for a controller and for
// all-in-one, and the section reaches the controller part.
func TestKMSKEK(t *testing.T) {
	const kms = "kek: {source: kms, kms: {address: \"https://vault.example:8200\", key: rpmgr-kek, ca_file: /etc/rpmgr/ca.pem, %s}}\n"
	for name, login := range map[string]string{ //nolint:gosec // G101: file names, not credentials
		"token":   "token_file: /etc/rpmgr/token",
		"approle": "approle: {role_id_file: /etc/rpmgr/role, secret_id_file: /etc/rpmgr/secret}",
	} {
		boot := "version: 1\npublic_url: https://p.example\n" + fmt.Sprintf(kms, login)
		var c config.Controller
		if err := config.Parse([]byte(boot), &c); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.KEK.Source != config.KEKKMS || c.KEK.Name != "" || c.KEK.KMS == nil || c.KEK.KMS.Key != "rpmgr-kek" {
			t.Errorf("%s: %+v", name, c.KEK)
		}
		var a config.AllInOne
		if err := config.Parse([]byte(boot), &a); err != nil {
			t.Fatalf("all-in-one with %s: %v", name, err)
		}
		if got := a.Controller().KEK; got.KMS == nil || got.KMS.Address != "https://vault.example:8200" {
			t.Errorf("all-in-one %s: %+v", name, got)
		}
	}
}
