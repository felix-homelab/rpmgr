// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Database is the `database` section of a controller's or all-in-one's boot file.
type Database struct {
	Driver             string `yaml:"driver"`
	DSN                string `yaml:"dsn"`
	PasswordFile       string `yaml:"password_file"`
	PasswordCredential string `yaml:"password_credential"`
}

// LoadDatabase reads only the `database` section of the boot file at path, for `rpmgr migrate-db`,
// which needs no other section: not the KEK, not the listeners. The rest of the file is not
// validated, so a boot file prepared for a PostgreSQL controller can be read before the controller
// itself accepts it. Unknown keys inside the section, a DSN of a SQLite database that is not an
// absolute path, a PostgreSQL database without a DSN, and both a password file and a password
// credential are refused. A missing section is the default, the SQLite database of a single node.
func LoadDatabase(path string) (Database, error) {
	fh, err := os.Open(path) //nolint:gosec // G304: the path is the operator's --from or --to-file
	if err != nil {
		return Database{}, err
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, maxSize+1))
	if err != nil {
		return Database{}, err
	}
	if len(data) > maxSize {
		return Database{}, fmt.Errorf("config: %s is larger than %d bytes", path, maxSize)
	}
	var doc struct {
		Database yaml.Node `yaml:"database"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Database{}, fmt.Errorf("%s: config: %w", path, err)
	}
	var d Database
	if doc.Database.Kind != 0 {
		dec := yaml.NewDecoder(bytes.NewReader(mustMarshal(&doc.Database)))
		dec.KnownFields(true)
		if err := dec.Decode(&d); err != nil {
			return Database{}, fmt.Errorf("%s: database: %w", path, err)
		}
	}
	setDefault(&d.Driver, "sqlite")
	if d.Driver == "sqlite" {
		setDefault(&d.DSN, "/var/lib/rpmgr/controller.db")
	}
	if err := d.check(); err != nil {
		return Database{}, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

func mustMarshal(n *yaml.Node) []byte {
	b, err := yaml.Marshal(n)
	if err != nil { // a node that was just decoded
		panic(err)
	}
	return b
}

func (d Database) check() error {
	switch d.Driver {
	case "sqlite":
		if !filepath.IsAbs(d.DSN) || strings.ContainsAny(d.DSN, "?#%") {
			return fmt.Errorf("database.dsn %q: want an absolute path without '?', '#' or '%%'", d.DSN)
		}
		if d.PasswordFile != "" || d.PasswordCredential != "" {
			return errors.New("database: a SQLite database has no password")
		}
	case "postgres":
		if d.DSN == "" {
			return errors.New("database.dsn: a PostgreSQL database needs one")
		}
		if d.PasswordFile != "" && d.PasswordCredential != "" {
			return errors.New("database: password_file or password_credential, not both")
		}
	default:
		return fmt.Errorf("database.driver %q: want sqlite or postgres", d.Driver)
	}
	return nil
}
