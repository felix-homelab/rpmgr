// SPDX-License-Identifier: Apache-2.0

package update

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// afterOpen, if set, runs after a staged file is opened and before it is read; tests use it to
// swap files under the updater.
var afterOpen func(name string)

// staged is the agent's staging directory, opened without following any symbolic link.
type staged struct{ fd int }

// openStaged opens the staging directory through a file descriptor: a symbolic link anywhere in
// the path, the directory itself included, is refused.
func openStaged(dir string) (*staged, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, dir, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("%w: the staging directory %s is no plain directory: %w", ErrHostile, dir, err)
		}
		return nil, fmt.Errorf("update: staging directory: %w", err)
	}
	return &staged{fd: fd}, nil
}

func (s *staged) Close() error { return unix.Close(s.fd) }

// open opens a file directly in the staging directory, which must be a regular file of at most
// limit bytes. It never follows a symbolic link and never blocks on a FIFO or a device.
func (s *staged) open(name string, limit int64) (*os.File, error) {
	fd, err := unix.Openat2(s.fd, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
			return nil, fmt.Errorf("%w: %s is a symbolic link: %w", ErrHostile, name, err)
		}
		return nil, fmt.Errorf("update: staged %s: %w", name, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("update: staged %s: %w", name, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: %s is no regular file", ErrHostile, name)
	case st.Size > limit:
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: %s has %d bytes, more than %d", ErrHostile, name, st.Size, limit)
	}
	f := os.NewFile(uintptr(fd), name)
	if afterOpen != nil {
		afterOpen(name)
	}
	return f, nil
}

// read reads a staged file of at most limit bytes into memory, where the agent cannot change it.
func (s *staged) read(name string, limit int64) ([]byte, error) {
	f, err := s.open(name, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("update: staged %s: %w", name, err)
	case int64(len(b)) > limit:
		return nil, fmt.Errorf("%w: %s grew past %d bytes while it was read", ErrHostile, name, limit)
	}
	return b, nil
}

// copy copies a staged file of at most limit bytes into out, a new file of the updater's root-only
// staging directory, and syncs it. A file that grows past the limit while it is copied is refused.
func (s *staged) copy(name string, out *os.File, limit int64) error {
	f, err := s.open(name, limit)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	n, err := io.Copy(out, io.LimitReader(f, limit+1))
	switch {
	case err != nil:
		return fmt.Errorf("update: copying %s: %w", name, err)
	case n > limit:
		return fmt.Errorf("%w: %s grew past %d bytes while it was copied", ErrHostile, name, limit)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("update: copying %s: %w", name, err)
	}
	return nil
}

// prepareStaging makes sure the root-only staging directory exists as a plain directory of mode
// 0700 owned by the updater's user, root, and removes the copies earlier runs left.
func prepareStaging(dir string) error {
	err := os.Mkdir(dir, 0o700)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("update: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o777 != 0o700 || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: %s must be a directory of mode 0700 that only the updater owns", ErrHostile, dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return fmt.Errorf("update: removing an earlier copy: %w", err)
		}
	}
	return nil
}

// readOwn reads one of the updater's own files, or the local policy: a regular file of at most
// maxMeta bytes, opened without following a symbolic link, owned by the updater's user, root, and
// writable by no one else. A missing file wraps fs.ErrNotExist.
func readOwn(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0) //nolint:gosec // G304: the updater's own files
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("update: %s is a symbolic link", path)
		}
		return nil, fmt.Errorf("update: %w", err)
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, fmt.Errorf("update: %w", err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > maxMeta:
		return nil, fmt.Errorf("update: %s is no regular file of at most %d bytes", path, maxMeta)
	case int(st.Uid) != os.Geteuid():
		return nil, fmt.Errorf("update: %s is owned by user %d, not by the updater's", path, st.Uid)
	case st.Mode&0o022 != 0:
		return nil, fmt.Errorf("update: %s has mode %04o; only its owner may write it", path, st.Mode&0o7777)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxMeta+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("update: %w", err)
	case len(b) > maxMeta:
		return nil, fmt.Errorf("update: %s grew past %d bytes", path, maxMeta)
	}
	return b, nil
}
