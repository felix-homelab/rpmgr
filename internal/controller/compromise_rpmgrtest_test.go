// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package controller_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
)

// TestReplaceCompromisedRoot_Faults: the replacement fails at each stage. Whatever the stage, nothing changes
// in the database and no tokens file is left, as the transaction rolls back and the file is removed; the
// markers are in the log only from the append on, where they make a restore of a current backup refuse
// until the command has run again, which then succeeds and leaves one consistent state.
func TestReplaceCompromisedRoot_Faults(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() { controller.CeremonyFault = nil })
	for _, stage := range []string{"planned", "written", "before-marker", "appended", "commit"} {
		t.Run(stage, func(t *testing.T) {
			h, _ := initHost(t)
			seedFleet(t, h)
			logPath := filepath.Join(filepath.Dir(h.db), "revocations.log")
			before := compromiseState(t, h)
			out := filepath.Join(t.TempDir(), "tokens")
			controller.CeremonyFault = func(s, _ string) error {
				if s == stage {
					return errors.New("injected fault at " + stage)
				}
				return nil
			}
			if _, err := controller.ReplaceCompromisedRoot(ctx, compromiseOpts(h, out)); err == nil {
				t.Fatal("the replacement succeeded despite the fault")
			}
			controller.CeremonyFault = nil
			if after := compromiseState(t, h); after != before {
				t.Fatalf("the failed run changed the database:\n%s\n%s", before, after)
			}
			if status, sealed := caRows(t, h); status[cakey.StatusActive] != 4 || sealed != 4 || len(status) != 1 {
				t.Fatalf("CA keys after the failure: %v, %d sealed", status, sealed)
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("a tokens file is left though no token is valid")
			}
			marks := rootMarkers(t, logPath)
			wantMarks := stage == "appended" || stage == "commit"
			if (len(marks) > 0) != wantMarks {
				t.Fatalf("markers %+v after a fault at %s", marks, stage)
			}
			if wantMarks {
				// A backup of the unchanged controller is older than its marker, so a restore refuses it.
				if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: backupOf(t, h)}); !errors.Is(err, controller.ErrOlderThanRootChange) {
					t.Fatalf("a restore after the failed run = %v, want the refusal that says to run the command again", err)
				}
			}
			// Run again: one consistent state.
			res, err := controller.ReplaceCompromisedRoot(ctx, compromiseOpts(h, out))
			if err != nil {
				t.Fatalf("the run after the failure: %v", err)
			}
			if status, sealed := caRows(t, h); status[cakey.StatusCompromised] != 4 || status[cakey.StatusActive] != 4 || sealed != 4 || res.Pin == "" {
				t.Fatalf("after the second run: %v, %d sealed", status, sealed)
			}
			if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o600 {
				t.Fatalf("tokens file after the second run: %v, %v", st, err)
			}
			if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: backupOf(t, h)}); err != nil {
				t.Fatalf("a restore of a backup taken after it: %v", err)
			}
		})
	}
}
