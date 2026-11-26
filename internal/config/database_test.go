// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/config"
)

// TestLoadDatabase: only the database section is read and checked; other sections, even ones this
// binary would refuse, are not.
func TestLoadDatabase(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "boot.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := map[string]struct {
		body string
		want config.Database
	}{
		"sqlite":      {"database: {driver: sqlite, dsn: /srv/rpmgr/c.db}\n", config.Database{Driver: "sqlite", DSN: "/srv/rpmgr/c.db"}},
		"empty block": {"database: {}\n", config.Database{Driver: "sqlite", DSN: "/var/lib/rpmgr/controller.db"}},
		"postgres with a file": {"database: {driver: postgres, dsn: 'postgres://rpmgr@db.example.com/rpmgr', password_file: /srv/pw}\n",
			config.Database{Driver: "postgres", DSN: "postgres://rpmgr@db.example.com/rpmgr", PasswordFile: "/srv/pw"}},
		"postgres with a credential": {"database: {driver: postgres, dsn: 'host=db dbname=rpmgr', password_credential: dbpw}\nkek: {source: nonsense}\nlisten: {bogus: 1}\n",
			config.Database{Driver: "postgres", DSN: "host=db dbname=rpmgr", PasswordCredential: "dbpw"}},
	}
	for name, c := range ok {
		got, err := config.LoadDatabase(write(c.body))
		if err != nil || got != c.want {
			t.Errorf("%s: %+v, %v; want %+v", name, got, err, c.want)
		}
	}
	bad := map[string]string{
		"unknown key":        "database: {driver: sqlite, dsn: /srv/c.db, extra: 1}\n",
		"relative sqlite":    "database: {driver: sqlite, dsn: c.db}\n",
		"sqlite with query":  "database: {driver: sqlite, dsn: /srv/c.db?mode=ro}\n",
		"sqlite password":    "database: {driver: sqlite, dsn: /srv/c.db, password_credential: x}\n",
		"postgres no dsn":    "database: {driver: postgres}\n",
		"two password kinds": "database: {driver: postgres, dsn: 'postgres://u@h/d', password_file: /srv/a, password_credential: b}\n",
		"another driver":     "database: {driver: mysql, dsn: x}\n",
		"misspelt key":       "databse: {driver: sqlite, dsn: /srv/c.db}\n",
		"no section":         "public_url: https://p.example.com\n",
		"a gateway file":     "version: 1\ncontroller_url: https://p.example.com\n",
		"second document":    "public_url: https://p.example.com\n---\ndatabase: {driver: sqlite, dsn: /srv/c.db}\n",
		"two documents":      "database: {driver: sqlite, dsn: /srv/c.db}\n---\ndatabase: {driver: sqlite, dsn: /srv/d.db}\n",
		"null section":       "database:\n",
		"not yaml":           "database: [\n",
		"database a scalar":  "database: sqlite\n",
	}
	for name, body := range bad {
		if _, err := config.LoadDatabase(write(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := config.LoadDatabase(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file was accepted")
	}
	if _, err := config.LoadDatabase(write("database: {dsn: /srv/c.db}\n# " + strings.Repeat("x", 70<<10))); err == nil {
		t.Error("an oversized file was accepted")
	}
}
