// SPDX-License-Identifier: Apache-2.0

// Package version reports which build of rpmgr is running. Release builds set Version and
// Commit with -ldflags "-X github.com/felix-homelab/rpmgr/internal/version.Version=1.4.2 ...".
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Version is the release version without a leading "v"; "dev" for development builds.
var Version = "dev"

// Commit is the source revision; when it is not set, the VCS revision recorded by the Go
// toolchain is used, if any.
var Commit = ""

// Info describes the running binary.
type Info struct {
	Version   string
	Commit    string
	GoVersion string
	Platform  string
}

// Get returns the Info of the running binary.
func Get() Info {
	commit := Commit
	if commit == "" {
		commit = vcsRevision()
	}
	return Info{
		Version:   Version,
		Commit:    commit,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String formats the Info as one line, e.g. "rpmgr 1.4.2 (commit 3f2a…, go1.27.1, linux/amd64)".
func (i Info) String() string {
	commit := i.Commit
	if commit == "" {
		commit = "unknown"
	}
	return fmt.Sprintf("rpmgr %s (commit %s, %s, %s)", i.Version, commit, i.GoVersion, i.Platform)
}

func vcsRevision() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev, modified string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if rev != "" && modified == "true" {
		rev += "-dirty"
	}
	return rev
}
