// SPDX-License-Identifier: Apache-2.0

// Command installscript writes the global install script (docs/10-operations.md, "Install paths")
// with the release root keys compiled into this build. It is a release tool and not part of the
// rpmgr binary:
//
//	installscript [-version <v>] [-o <file>]
//
// Without -version it writes the repository's copy, deploy/install.sh, which installs the latest
// release (go generate ./internal/installsh); with -version the copy the release workflow attaches
// to that release. A build with the rpmgrtest tag has test roots and is refused.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/felix-homelab/rpmgr/internal/installsh"
	"github.com/felix-homelab/rpmgr/internal/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "installscript:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("installscript", flag.ContinueOnError)
	version := fs.String("version", "", "the release the script is pinned to, without a leading v; empty for the latest")
	out := fs.String("o", "", "the file to write; standard output if empty")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if release.TestBuild {
		return errors.New("an rpmgrtest build has test root keys (D60)")
	}
	b, err := installsh.RenderGlobal(*version, release.Roots())
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(*out, b, 0o644) //nolint:gosec // G306: a script anyone may read
}
