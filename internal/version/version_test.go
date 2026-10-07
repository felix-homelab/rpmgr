// SPDX-License-Identifier: Apache-2.0

package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGetUsesLinkerValues(t *testing.T) {
	defer func(v, c string) { Version, Commit = v, c }(Version, Commit)
	Version, Commit = "1.4.2", "3f2a9c1"

	got := Get()
	if got.Version != "1.4.2" || got.Commit != "3f2a9c1" {
		t.Fatalf("Get() = %+v, want version 1.4.2 and commit 3f2a9c1", got)
	}
	if got.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q", got.GoVersion, runtime.Version())
	}
	if want := runtime.GOOS + "/" + runtime.GOARCH; got.Platform != want {
		t.Errorf("Platform = %q, want %q", got.Platform, want)
	}
	want := "rpmgr 1.4.2 (commit 3f2a9c1, " + runtime.Version() + ", " + got.Platform + ")"
	if s := got.String(); s != want {
		t.Errorf("String() = %q, want %q", s, want)
	}
}

func TestGetWithoutLinkerValues(t *testing.T) {
	defer func(v, c string) { Version, Commit = v, c }(Version, Commit)
	Version, Commit = "dev", ""

	got := Get()
	if got.Version != "dev" {
		t.Errorf("Version = %q, want dev", got.Version)
	}
	// Test binaries carry no VCS stamp, so the commit is unknown here.
	if s := got.String(); !strings.HasPrefix(s, "rpmgr dev (commit ") {
		t.Errorf("String() = %q, want prefix %q", s, "rpmgr dev (commit ")
	}
}

func TestStringWithoutCommit(t *testing.T) {
	i := Info{Version: "dev", GoVersion: "go1.27.1", Platform: "linux/arm64"}
	if s, want := i.String(), "rpmgr dev (commit unknown, go1.27.1, linux/arm64)"; s != want {
		t.Errorf("String() = %q, want %q", s, want)
	}
}
