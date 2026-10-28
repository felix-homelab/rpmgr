// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func waitOutcome(t *testing.T, dir string, cond func(Outcome) bool) Outcome {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		o, err := ReadOutcome(dir)
		if err == nil && cond(o) {
			return o
		}
		if time.Now().After(deadline) {
			t.Fatalf("no such outcome; last %+v, %v", o, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func signalSelf(t *testing.T) {
	t.Helper()
	if err := Signal(os.Getpid()); err != nil {
		t.Fatal(err)
	}
}

// TestTrigger_OneAtATime: SIGUSR2 starts a hand-off and records it; a signal during one is
// ignored; the next one after it is a new hand-off.
func TestTrigger_OneAtATime(t *testing.T) {
	dir := t.TempDir()
	release := make(chan struct{})
	var calls uint64
	tr := &Trigger{Dir: dir, Handoff: func(context.Context) (*Child, error) {
		calls++
		<-release
		return &Child{Pid: 4242, Generation: calls + 1}, nil
	}}
	stop := tr.Start(context.Background())
	defer stop()
	signalSelf(t)
	first := waitOutcome(t, dir, func(o Outcome) bool { return o.State == StateRunning })
	if first.OldPID != os.Getpid() {
		t.Errorf("old pid %d", first.OldPID)
	}
	signalSelf(t) // during the hand-off
	time.Sleep(100 * time.Millisecond)
	if o, _ := ReadOutcome(dir); o.ID != first.ID || o.State != StateRunning {
		t.Fatalf("a second signal changed the outcome: %+v", o)
	}
	release <- struct{}{}
	done := waitOutcome(t, dir, func(o Outcome) bool { return o.State == StateOK })
	if done.ID != first.ID || done.NewPID != 4242 || done.Generation != 2 {
		t.Errorf("outcome %+v", done)
	}
	signalSelf(t)
	close(release)
	second := waitOutcome(t, dir, func(o Outcome) bool { return o.State == StateOK && o.ID != first.ID })
	if calls != 2 || second.Generation != 3 {
		t.Errorf("calls %d, outcome %+v", calls, second)
	}
}

func TestTrigger_Outcomes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handoff func(context.Context) (*Child, error)
		state   string
		reason  string
	}{
		{"no hand-off yet", nil, StateRefused, "cannot hand off yet"},
		{"a refused binary", func(context.Context) (*Child, error) {
			return nil, fmt.Errorf("%w: the binary is writable", ErrRefused)
		}, StateRefused, "the binary is writable"},
		{"a new process not ready", func(context.Context) (*Child, error) {
			return nil, fmt.Errorf("%w: exited\nforged", ErrNotReady)
		}, StateFailed, "exited forged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stop := (&Trigger{Dir: dir, Handoff: tc.handoff}).Start(context.Background())
			defer stop()
			signalSelf(t)
			o := waitOutcome(t, dir, func(o Outcome) bool { return o.State != StateRunning })
			if o.State != tc.state || !strings.Contains(o.Reason, tc.reason) || o.NewPID != 0 {
				t.Errorf("outcome %+v, want %s with %q", o, tc.state, tc.reason)
			}
		})
	}
}

// TestReadOutcome_Hostile: the service user writes the runtime directory and root reads it; only
// a small regular file is read.
func TestReadOutcome_Hostile(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadOutcome(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no outcome: %v", err)
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte(`{"state":"ok","reason":"root's secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, OutcomeFile)
	for name, create := range map[string]func() error{
		"a link":   func() error { return os.Symlink(secret, file) },
		"a FIFO":   func() error { return syscall.Mkfifo(file, 0o600) },
		"too big":  func() error { return os.WriteFile(file, make([]byte, maxOutcome+1), 0o600) },
		"no JSON":  func() error { return os.WriteFile(file, []byte("state=ok"), 0o600) },
		"a folder": func() error { return os.Mkdir(file, 0o700) },
	} {
		t.Run(name, func(t *testing.T) {
			_ = os.Remove(file)
			if err := create(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := ReadOutcome(dir); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Error("read")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("hangs")
			}
		})
	}
	_ = os.Remove(file)
	want := Outcome{ID: 7, State: StateOK, OldPID: 1, NewPID: 2, Generation: 3}
	if err := WriteOutcome(dir, want); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadOutcome(dir); err != nil || got != want {
		t.Errorf("ReadOutcome = %+v, %v", got, err)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("outcome file mode: %v, %v", fi, err)
	}
}

// TestTrigger_CancelledMidHandoff: a context cancelled while a hand-off runs ends it, and the
// outcome says it failed, so that `rpmgr handoff` does not wait for the timeout.
func TestTrigger_CancelledMidHandoff(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	running := make(chan struct{})
	stop := (&Trigger{Dir: dir, Handoff: func(ctx context.Context) (*Child, error) {
		close(running)
		<-ctx.Done()
		return nil, fmt.Errorf("%w: %w", ErrNotReady, ctx.Err())
	}}).Start(ctx)
	defer stop()
	signalSelf(t)
	<-running
	waitOutcome(t, dir, func(o Outcome) bool { return o.State == StateRunning })
	cancel()
	o := waitOutcome(t, dir, func(o Outcome) bool { return o.State != StateRunning })
	if o.State != StateFailed || !strings.Contains(o.Reason, "canceled") || o.OldPID != os.Getpid() {
		t.Errorf("outcome %+v; want failed, canceled", o)
	}
}

// TestCapable: only the process that announced itself takes the hand-off signal.
func TestCapable(t *testing.T) {
	dir := t.TempDir()
	pid := os.Getpid()
	if Capable(dir, pid) {
		t.Error("a process that announced nothing is capable")
	}
	stop := (&Trigger{Dir: dir}).Start(context.Background())
	defer stop()
	if !Capable(dir, pid) {
		t.Error("the process that started its trigger is not capable")
	}
	for name, body := range map[string]string{
		"another process":  fmt.Sprint(pid + 1),
		"not a number":     "gateway",
		"empty":            "",
		"padded":           " " + fmt.Sprint(pid),
		"zero":             "0",
		"too long":         strings.Repeat("1", 100),
		"a negative value": "-1",
	} {
		if err := os.WriteFile(filepath.Join(dir, CapableFile), []byte(body), 0o644); err != nil { //nolint:gosec // G306: a test file
			t.Fatal(err)
		}
		if Capable(dir, pid) {
			t.Errorf("%s: %q is capable", name, body)
		}
	}
	if err := os.Remove(filepath.Join(dir, CapableFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.Args[0], filepath.Join(dir, CapableFile)); err != nil {
		t.Fatal(err)
	}
	if Capable(dir, pid) {
		t.Error("a link is capable")
	}
}
