// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/policy"
)

// TestWatcher: a changed file, and SIGHUP, reload the policy, so readiness changes without a new
// revision; an invalid file denies everything.
func TestWatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	changes := make(chan *policy.Policy, 8)
	w := policy.NewWatcher(path, func(p *policy.Policy, _ error) { changes <- p })
	w.SetEvery(20 * time.Millisecond)
	if allows(w.Current(), "10.0.0.5:5432") {
		t.Fatal("allowed without a file")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	next := func(what string) *policy.Policy {
		t.Helper()
		select {
		case p := <-changes:
			return p
		case <-time.After(5 * time.Second):
			t.Fatalf("no reload after %s", what)
			return nil
		}
	}
	if _, err := policy.AllowTarget(path, "10.0.0.5:5432"); err != nil {
		t.Fatal(err)
	}
	if p := next("an edit"); !allows(p, "10.0.0.5:5432") || !allows(w.Current(), "10.0.0.5:5432") {
		t.Fatal("the edit is not in force")
	}
	if err := os.WriteFile(path, []byte("version: 1\nallow_targets: nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p := next("an invalid file"); p.Invalid == nil || allows(p, "10.0.0.5:5432") {
		t.Fatal("an invalid file did not deny everything")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	next("SIGHUP")
}
