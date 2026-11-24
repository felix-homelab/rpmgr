// SPDX-License-Identifier: Apache-2.0

package revlog

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// DirBackend is the filesystem Backend, a directory usually on a share. An object is a file,
// published by a hard link, which fails when the name exists. Temporary files of writers, named
// with the prefix ".tmp-", are not listed. Releases before the padded keys named a file by its
// sequence number without leading zeros; those files are read, never renamed or rewritten, and
// new objects are always written padded.
type DirBackend struct {
	Dir string
}

const dirTmpPrefix = ".tmp-"

// legacyName is the unpadded name of a padded key.
func legacyName(key string) string {
	n, ok := parseKey(key)
	if !ok {
		return key
	}
	return strconv.FormatUint(n, 10)
}

// keyOf maps a file name to its key: a padded key is itself, a legacy name (digits only, no
// leading zero, a uint64) is padded; anything else is not a key.
func keyOf(name string) (string, bool) {
	if _, ok := parseKey(name); ok {
		return name, true
	}
	if name == "" || (name[0] == '0' && name != "0") {
		return "", false
	}
	n, err := strconv.ParseUint(name, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != name {
		return "", false
	}
	return Key(n), true
}

// List implements Backend. A legacy name is listed as its padded key.
func (d DirBackend) List(after string) ([]string, error) {
	des, err := os.ReadDir(d.Dir)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var keys []string
	for _, de := range des {
		if k, ok := keyOf(de.Name()); ok && k > after && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Get implements Backend. The padded file is read, else the legacy one. When both exist they must
// hold the same bytes, or the sink is broken.
func (d DirBackend) Get(key string) ([]byte, error) {
	padded, err := os.ReadFile(filepath.Join(d.Dir, filepath.Base(key)))              //nolint:gosec // G304: the configured sink
	legacy, lerr := os.ReadFile(filepath.Join(d.Dir, legacyName(filepath.Base(key)))) //nolint:gosec // G304: the configured sink
	switch {
	case err != nil && lerr == nil:
		return legacy, nil
	case err != nil:
		return nil, err
	case lerr == nil && !bytes.Equal(padded, legacy):
		return nil, fmt.Errorf("%w: sink entry %s exists as %s and as %s with different content", ErrBroken, key, key, legacyName(key))
	}
	return padded, nil
}

// CreateIfAbsent implements Backend: the data goes to a temporary file, is synced, and is linked
// to its key.
func (d DirBackend) CreateIfAbsent(key string, data []byte) error {
	if _, err := os.Lstat(filepath.Join(d.Dir, legacyName(filepath.Base(key)))); err == nil {
		return ErrExists
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(d.Dir, dirTmpPrefix+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640) //nolint:gosec // G304: the configured sink
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Link(tmp, filepath.Join(d.Dir, filepath.Base(key))); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return err
	}
	if dir, err := os.Open(d.Dir); err == nil { // the new name, durable
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
