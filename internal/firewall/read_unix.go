// SPDX-License-Identifier: Apache-2.0

//go:build unix

package firewall

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// readChecked reads a regular file of at most limit bytes without following a symbolic link. With
// root set it also requires that the file and its directory, and every directory above it, are owned by uid and that neither
// group nor others may write them, as the updater requires of install.json.
func readChecked(path string, limit int64, root bool, uid uint32) ([]byte, error) {
	if root {
		if err := checkDir(filepath.Dir(path), uid); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0) //nolint:gosec // G304: a fixed path of the units
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err) // a link is ELOOP here
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	switch {
	case err != nil:
		return nil, err
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s is no regular file", path)
	case fi.Size() > limit:
		return nil, fmt.Errorf("%s has %d bytes, more than %d", path, fi.Size(), limit)
	}
	if root {
		if err := ownerOK(path, fi, uid); err != nil {
			return nil, err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("%s grew past %d bytes while it was read", path, limit)
	}
	return b, err
}

// lstat is os.Lstat; the tests replace it to stand in for a root-owned tree.
var lstat = os.Lstat

// checkDir applies the rule of ownerOK to dir and to every directory above it up to "/": a
// directory that another user owns, or that its group or others may write (a sticky bit does not
// excuse it), would let that user replace the directory below it and so the file.
func checkDir(dir string, uid uint32) error {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		fi, err := lstat(d)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is no plain directory", d)
		}
		if err := ownerOK(d, fi, uid); err != nil {
			return err
		}
		if d == filepath.Dir(d) {
			return nil
		}
	}
}

func ownerOK(path string, fi os.FileInfo, uid uint32) error {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok || sys.Uid != uid:
		return fmt.Errorf("%s is not owned by root", path)
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s may be written by its group or others", path)
	}
	return nil
}
