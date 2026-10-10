// SPDX-License-Identifier: Apache-2.0

//go:build unix

package controller

import (
	"io/fs"
	"os"
	"syscall"
)

// ownLike gives dir and everything in it to the owner of ref, when the process runs as root.
func ownLike(dir, ref string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	st, err := os.Stat(ref)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	// Walked within the root, so a symlink planted meanwhile cannot lead outside it.
	return fs.WalkDir(root.FS(), ".", func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return root.Lchown(p, int(sys.Uid), int(sys.Gid))
	})
}
