// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxKEKFile bounds how much of a KEK file is read; the file holds 44 base64 characters.
const maxKEKFile = 1024

// LoadKEKFile reads a KEK from a file (KEK source `file`, docs/04-security.md): the base64 encoding
// of 32 random bytes, optionally followed by a newline. Symbolic links are followed, because
// container platforms mount secrets that way, but the file itself must be a regular file that
// neither its group nor other users can read or write.
func LoadKEKFile(path string) (KEK, error) {
	return loadKEK(path, "KEK file", false)
}

// LoadSystemdCredential reads a KEK passed by systemd with LoadCredentialEncrypted= (KEK source
// `systemd-credential`): the file <name> in $CREDENTIALS_DIRECTORY, in the format of LoadKEKFile.
// Newer systemd versions give a service that runs as another user its credential with mode 0440,
// owned by root and the service's group, in a directory only the service and root can enter: a
// credential its own group may read is accepted, one other users may read is not.
func LoadSystemdCredential(name string, getenv func(string) string) (KEK, error) {
	dir := getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return KEK{}, errors.New("KEK credential: CREDENTIALS_DIRECTORY is not set; is the service started with LoadCredentialEncrypted=?")
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return KEK{}, fmt.Errorf("KEK credential: invalid name %q", name)
	}
	return loadKEK(filepath.Join(dir, name), "KEK credential", true)
}

// loadKEK reads and checks a KEK file; with groupRead, the group of the process (or root's) may
// read it too.
func loadKEK(path, what string, groupRead bool) (KEK, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is the operator's boot configuration
	if err != nil {
		return KEK{}, fmt.Errorf("%s: %w", what, err)
	}
	defer func() { _ = f.Close() }() // read-only; a close error loses nothing
	fi, err := f.Stat()
	if err != nil {
		return KEK{}, fmt.Errorf("%s: %w", what, err)
	}
	if !fi.Mode().IsRegular() {
		return KEK{}, fmt.Errorf("%s %s: not a regular file", what, path)
	}
	perm := fi.Mode().Perm()
	allowed := perm&0o077 == 0
	if groupRead && perm&0o037 == 0 && ownGroup(fi) {
		allowed = true
	}
	if !allowed {
		return KEK{}, fmt.Errorf("%s %s: mode %04o lets other users read it; use 0600 or 0400", what, path, perm)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKEKFile+1))
	if err != nil {
		return KEK{}, fmt.Errorf("%s: %w", what, err)
	}
	return parseKEK(data, what+" "+path)
}

func parseKEK(data []byte, what string) (KEK, error) {
	if len(data) > maxKEKFile {
		return KEK{}, fmt.Errorf("%s: larger than %d bytes", what, maxKEKFile)
	}
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return KEK{}, fmt.Errorf("%s: not base64", what)
	}
	if len(key) != keyLen {
		return KEK{}, fmt.Errorf("%s: %d bytes after decoding, want %d", what, len(key), keyLen)
	}
	return NewKEK(key)
}
