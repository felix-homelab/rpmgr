// SPDX-License-Identifier: Apache-2.0

package objstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKey(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.yaml")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadKeyFile(t *testing.T) {
	c, err := LoadKeyFile(writeKey(t, "access_key_id: AKID\nsecret_access_key: "+testSecret+"\n", 0o600))
	if err != nil || c.AccessKeyID != "AKID" || c.SecretAccessKey.Reveal() != testSecret {
		t.Fatalf("got %+v, %v", c, err)
	}
	if _, err := LoadKeyFile(writeKey(t, "access_key_id: AKID\nsecret_access_key: x\n", 0o400)); err != nil {
		t.Errorf("mode 0400: %v", err)
	}
}

func TestLoadKeyFileRefuses(t *testing.T) {
	good := "access_key_id: AKID\nsecret_access_key: " + testSecret + "\n"
	for name, tc := range map[string]struct {
		content string
		mode    os.FileMode
	}{
		"group readable":  {good, 0o640},
		"world readable":  {good, 0o604},
		"unknown key":     {good + "region: x\n", 0o600},
		"missing secret":  {"access_key_id: AKID\n", 0o600},
		"missing id":      {"secret_access_key: x\n", 0o600},
		"not YAML":        {"{{{ " + testSecret, 0o600},
		"control char":    {"access_key_id: AKID\nsecret_access_key: \"a\\nb\"\n", 0o600},
		"space in secret": {"access_key_id: AKID\nsecret_access_key: \"a b\"\n", 0o600},
		"too large":       {good + "# " + strings.Repeat("x", maxKeyFile), 0o600},
		"empty file":      {"", 0o600},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadKeyFile(writeKey(t, tc.content, tc.mode))
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), testSecret) {
				t.Errorf("error holds the secret: %v", err)
			}
		})
	}
	if _, err := LoadKeyFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("absent file accepted")
	}
	if _, err := LoadKeyFile(t.TempDir()); err == nil {
		t.Error("directory accepted")
	}
}

func TestLoadKeyFileFollowsSymlink(t *testing.T) {
	p := writeKey(t, "access_key_id: AKID\nsecret_access_key: x\n", 0o600)
	l := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(p, l); err != nil {
		t.Skip(err)
	}
	if _, err := LoadKeyFile(l); err != nil {
		t.Error(err)
	}
}
