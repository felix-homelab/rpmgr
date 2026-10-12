// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/installsh"
	"github.com/felix-homelab/rpmgr/internal/release"
)

// TestRun: the tool writes the global script of this build's root keys, pinned or not, and refuses
// a development version, an extra argument and an rpmgrtest build.
func TestRun(t *testing.T) {
	if release.TestBuild {
		if err := run(nil); err == nil {
			t.Fatal("an rpmgrtest build wrote a script")
		}
		return
	}
	for _, v := range []string{"", "0.1.0", "0.1.0-rc.2"} {
		out := filepath.Join(t.TempDir(), "install.sh")
		if err := run([]string{"-version", v, "-o", out}); err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		want, err := installsh.RenderGlobal(v, release.Roots())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%q: the written script differs from RenderGlobal's", v)
		}
	}
	for name, args := range map[string][]string{"a development version": {"-version", "dev"}, "an argument": {"extra"}} {
		if err := run(args); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
