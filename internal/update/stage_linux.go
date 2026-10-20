// SPDX-License-Identifier: Apache-2.0

package update

import (
	"errors"
	"fmt"
	"io"
	"os"

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

// copy copies a staged file of at most limit bytes to dst, in the updater's root-only directory.
// A file that grows past the limit while it is copied is refused and the copy removed.
func (s *staged) copy(name, dst string, limit int64) error {
	f, err := s.open(name, limit)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G304: the updater's own staging directory
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	n, err := io.Copy(out, io.LimitReader(f, limit+1))
	if err == nil && n > limit {
		err = fmt.Errorf("%w: %s grew past %d bytes while it was copied", ErrHostile, name, limit)
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
		if errors.Is(err, ErrHostile) {
			return err
		}
		return fmt.Errorf("update: copying %s: %w", name, err)
	}
	return nil
}
