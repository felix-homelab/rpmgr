// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// check returns the path to start: bin, a regular file and not a link, in its directory with
// every symbolic link resolved. It checks the file and every directory above it, both along the
// path as given and along the resolved one, so that the service user can neither replace the
// binary nor redirect a directory to one of its own.
func (r binaryRule) check(bin string) (string, error) {
	if !filepath.IsAbs(bin) {
		return "", fmt.Errorf("%w: the binary %q is no absolute path", ErrRefused, bin)
	}
	bin = filepath.Clean(bin)
	fi, err := os.Lstat(bin)
	if err != nil {
		return "", fmt.Errorf("%w: the binary %s: %w", ErrRefused, bin, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%w: the binary %s is no regular file (a symbolic link is refused)", ErrRefused, bin)
	}
	if err := r.owned(bin, fi); err != nil {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(bin))
	if err != nil {
		return "", fmt.Errorf("%w: the binary's directory: %w", ErrRefused, err)
	}
	for _, d := range []string{filepath.Dir(bin), dir} {
		if err := r.dirs(d); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, filepath.Base(bin)), nil
}

// dirs checks dir and every directory above it, up to the rule's last one.
func (r binaryRule) dirs(dir string) error {
	for d := dir; ; d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil {
			return fmt.Errorf("%w: the binary's directory %s: %w", ErrRefused, d, err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%w: %s is no directory", ErrRefused, d)
		}
		if err := r.owned(d, fi); err != nil {
			return err
		}
		if d == r.stop || d == "/" {
			return nil
		}
	}
}

func (r binaryRule) owned(p string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: no owner of %s", ErrRefused, p)
	}
	if st.Uid != r.uid {
		return fmt.Errorf("%w: %s is owned by user %d, not root", ErrRefused, p, st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: its group or others may write %s (%v)", ErrRefused, p, fi.Mode().Perm())
	}
	return nil
}
