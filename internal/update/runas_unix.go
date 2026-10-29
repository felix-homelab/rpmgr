// SPDX-License-Identifier: Apache-2.0

//go:build unix

package update

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

// OwnerOf returns the owner of the directory dir, which must be a directory and no link. The
// updater takes the service user from the state directory's parent-protected entry, a path only
// root can change, and never from anything inside it.
func OwnerOf(dir string) (uid, gid uint32, err error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return 0, 0, err
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok {
		return 0, 0, fmt.Errorf("update: %s is no directory", dir)
	}
	return sys.Uid, sys.Gid, nil
}

// runAs runs bin as the user uid:gid with no supplementary groups, its standard output going to
// stdout, and returns what it wrote to standard error.
func runAs(ctx context.Context, uid, gid uint32, stdout io.Writer, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: the installed binary, fixed subcommands
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = stdout, &stderr
	err := cmd.Run()
	return stderr.Bytes(), err
}
