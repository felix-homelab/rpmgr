// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package controller_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// TestOfflineRoot_Faults: the ceremony fails at each stage. Before the marker is logged the file is
// removed, the root stays online and nothing is recorded; from the append on, the file is kept
// (a restore would take the key out of the database), the generated passphrase comes back with the
// error, and `ca status` warns about the marker.
func TestOfflineRoot_Faults(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() { controller.CeremonyFault = nil })
	failAt := func(stage string, do func(path string)) {
		controller.CeremonyFault = func(s, path string) error {
			if s != stage {
				return nil
			}
			if do != nil { // a change to the medium, not a failure
				do(path)
				return nil
			}
			return errors.New("injected fault at " + stage)
		}
	}
	run := func(t *testing.T) (host, controller.OfflineRootResult, string, error) {
		h, _ := initHost(t)
		out := filepath.Join(t.TempDir(), "root.age")
		r, err := controller.OfflineRoot(ctx, controller.OfflineRootOptions{ConfigPath: h.cfg, Out: out, Getenv: noEnv})
		return h, r, out, err
	}
	markers := func(h host) []revlog.Entry {
		e, err := revlog.Read(filepath.Join(filepath.Dir(h.db), "revocations.log"))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}

	for _, tc := range []struct {
		name  string
		stage string
		do    func(path string)
		want  error
	}{
		// The read-back is of the medium: a file damaged after it was written must not pass.
		{"a file damaged on the medium", "written", func(p string) {
			b, _ := os.ReadFile(p)
			b[len(b)-3] ^= 1
			_ = os.WriteFile(p, b, 0o600) //nolint:gosec // G703: the ceremony's own output path in a test
		}, castore.ErrRootExport},
		{"a failure before the marker", "before-marker", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failAt(tc.stage, tc.do)
			h, r, out, err := run(t)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("err = %v", err)
			}
			if r.Passphrase != "" {
				t.Error("a passphrase came back for a file that was removed")
			}
			if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the file of a failed ceremony was left: %v", err)
			}
			if off, _, _ := rootRowOf(t, h); off || len(markers(h)) != 0 || len(auditOf(t, h, castore.RootActionOffline)) != 0 {
				t.Error("a failed ceremony changed the database or the log")
			}
		})
	}

	for _, stage := range []string{"appended", "commit"} {
		t.Run("a failure after the marker: "+stage, func(t *testing.T) {
			failAt(stage, nil)
			h, r, out, err := run(t)
			if err == nil || !strings.Contains(err.Error(), "is kept") {
				t.Fatalf("err = %v", err)
			}
			if r.Passphrase == "" {
				t.Fatal("the generated passphrase was thrown away with the file kept")
			}
			file, rerr := os.ReadFile(out)
			if rerr != nil {
				t.Fatalf("the file was removed: %v", rerr)
			}
			if _, err := pki.OpenRootFile(file, r.Passphrase); err != nil {
				t.Errorf("the kept file does not open with the passphrase returned: %v", err)
			}
			if off, _, _ := rootRowOf(t, h); off || len(auditOf(t, h, castore.RootActionOffline)) != 0 {
				t.Error("the failed transaction changed the database")
			}
			if m := markers(h); len(m) != 1 || m[0].Kind != revlog.RootOffline {
				t.Fatalf("log %+v", m)
			}
			w, err := controller.CAStatusWarnings(ctx, h.cfg)
			if err != nil || len(w) != 1 || !strings.Contains(w[0], "still in the database") {
				t.Errorf("warnings %q %v", w, err)
			}
		})
	}
}
