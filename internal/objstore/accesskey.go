// SPDX-License-Identifier: Apache-2.0

package objstore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"go.yaml.in/yaml/v3"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

// maxKeyFile bounds how much of an access key file is read.
const maxKeyFile = 4096

// Credentials are an access key of the store. The secret key never appears in a log line, an
// error or a formatted value.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey secret.Value
}

// LogValue keeps the secret key out of logs.
func (c Credentials) LogValue() slog.Value {
	return slog.GroupValue(slog.String("access_key_id", c.AccessKeyID), slog.String("secret_access_key", secret.Redacted))
}

func (c Credentials) check() error {
	switch {
	case c.AccessKeyID == "" || c.SecretAccessKey.IsZero():
		return errors.New("objstore: the access key ID and the secret key are both needed")
	case !printable(c.AccessKeyID) || !printable(c.SecretAccessKey.Reveal()):
		return errors.New("objstore: the access key ID or the secret key holds a character that is not printable ASCII")
	}
	return nil
}

// LoadKeyFile reads an access key from a YAML file with the keys access_key_id and
// secret_access_key and nothing else. Symbolic links are followed, as container platforms mount
// secrets that way, but the file itself must be a regular file that neither its group nor other
// users can read or write.
func LoadKeyFile(path string) (Credentials, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is the operator's configuration
	if err != nil {
		return Credentials{}, fmt.Errorf("access key file: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only; a close error loses nothing
	fi, err := f.Stat()
	if err != nil {
		return Credentials{}, fmt.Errorf("access key file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return Credentials{}, fmt.Errorf("access key file %s: not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return Credentials{}, fmt.Errorf("access key file %s: mode %04o lets other users read it; use 0600 or 0400", path, perm)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return Credentials{}, fmt.Errorf("access key file: %w", err)
	}
	if len(data) > maxKeyFile {
		return Credentials{}, fmt.Errorf("access key file %s: larger than %d bytes", path, maxKeyFile)
	}
	var v struct {
		AccessKeyID     string `yaml:"access_key_id"`
		SecretAccessKey string `yaml:"secret_access_key"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&v); err != nil {
		// yaml's errors quote the offending text, which may be the secret: name the file only.
		return Credentials{}, fmt.Errorf("access key file %s: not YAML with access_key_id and secret_access_key only", path)
	}
	c := Credentials{AccessKeyID: v.AccessKeyID, SecretAccessKey: secret.New(v.SecretAccessKey)}
	if err := c.check(); err != nil {
		return Credentials{}, fmt.Errorf("access key file %s: %w", path, err)
	}
	return c, nil
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
