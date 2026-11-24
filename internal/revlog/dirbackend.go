// SPDX-License-Identifier: Apache-2.0

package revlog

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DirBackend is the filesystem Backend, a directory usually on a share. An object is a file,
// published by a hard link, which fails when the name exists. Temporary files of writers, named
// with the prefix ".tmp-", are not listed.
type DirBackend struct {
	Dir string
}

const dirTmpPrefix = ".tmp-"

// List implements Backend.
func (d DirBackend) List(after string) ([]string, error) {
	des, err := os.ReadDir(d.Dir)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, de := range des {
		if n := de.Name(); !strings.HasPrefix(n, dirTmpPrefix) && n > after {
			keys = append(keys, n)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Get implements Backend.
func (d DirBackend) Get(key string) ([]byte, error) {
	return os.ReadFile(filepath.Join(d.Dir, filepath.Base(key))) //nolint:gosec // G304: the configured sink
}

// CreateIfAbsent implements Backend: the data goes to a temporary file, is synced, and is linked
// to its key.
func (d DirBackend) CreateIfAbsent(key string, data []byte) error {
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
