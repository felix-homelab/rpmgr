// SPDX-License-Identifier: Apache-2.0

//go:build linux

package agentcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/handoff"
)

// TestHandoffCommand runs `rpmgr handoff` against this test process as the role's main process,
// which takes SIGUSR2 through a handoff.Trigger.
func TestHandoffCommand(t *testing.T) {
	run := RunDir
	t.Cleanup(func() { RunDir, mainPID, notifyType = run, nil, nil })
	notifyType = func(context.Context, string) (bool, error) { return true, nil }
	RunDir = t.TempDir()
	pid := os.Getpid()
	mainPID = func(context.Context, string) (int, error) { return pid, nil }
	dir := filepath.Join(RunDir, "gateway")
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // G301: as RuntimeDirectory= makes it
		t.Fatal(err)
	}
	var calls atomic.Int32
	start := func(t *testing.T, h func(context.Context) (*handoff.Child, error)) {
		t.Helper()
		stop := (&handoff.Trigger{Dir: dir, Handoff: func(ctx context.Context) (*handoff.Child, error) {
			calls.Add(1)
			if h == nil {
				return nil, fmt.Errorf("%w: no hand-off here", handoff.ErrRefused)
			}
			return h(ctx)
		}}).Start(context.Background())
		t.Cleanup(stop)
	}
	cmd := func(wait time.Duration) (string, error) {
		var out bytes.Buffer
		err := runHandoff(context.Background(), &cli.Env{Stdout: &out, Stderr: io.Discard, Getenv: os.Getenv}, "gateway", 10*time.Millisecond, wait)
		return out.String(), err
	}

	t.Run("ok", func(t *testing.T) {
		start(t, func(context.Context) (*handoff.Child, error) { return &handoff.Child{Pid: 77, Generation: 2}, nil })
		if out, err := cmd(10 * time.Second); err != nil || !strings.Contains(out, fmt.Sprintf("Process %d handed rpmgr-gateway over to process 77 (generation 2)", pid)) {
			t.Errorf("a hand-off: %q, %v", out, err)
		}
		// Two in a row: each waits for its own outcome, not the last one's.
		if out, err := cmd(10 * time.Second); err != nil || !strings.Contains(out, "process 77") || calls.Load() != 2 {
			t.Errorf("a second hand-off: %q, %v (%d hand-offs)", out, err, calls.Load())
		}
	})

	t.Run("failed", func(t *testing.T) {
		start(t, func(context.Context) (*handoff.Child, error) {
			return nil, fmt.Errorf("%w: not ready within the readiness window", handoff.ErrNotReady)
		})
		_, err := cmd(10 * time.Second)
		if err == nil || !strings.Contains(err.Error(), "hand-off failed") || !strings.Contains(err.Error(), "serves on") {
			t.Errorf("a failed hand-off: %v", err)
		}
	})
	t.Run("refused", func(t *testing.T) {
		start(t, nil)
		if _, err := cmd(10 * time.Second); err == nil || !strings.Contains(err.Error(), "hand-off refused") {
			t.Errorf("a refused hand-off: %v", err)
		}
	})
	t.Run("in progress", func(t *testing.T) {
		start(t, nil)
		n := calls.Load()
		if err := handoff.WriteOutcome(dir, handoff.Outcome{ID: 1, State: handoff.StateRunning, OldPID: pid}); err != nil {
			t.Fatal(err)
		}
		if _, err := cmd(10 * time.Second); err == nil || !strings.Contains(err.Error(), "in progress") {
			t.Errorf("during a hand-off: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
		if calls.Load() != n {
			t.Error("signalled the role during a hand-off")
		}
	})
	t.Run("no outcome", func(t *testing.T) {
		// A process that takes the signal but records nothing, such as one whose runtime
		// directory is gone.
		if err := os.Remove(filepath.Join(dir, handoff.OutcomeFile)); err != nil {
			t.Fatal(err)
		}
		stop := (&handoff.Trigger{Dir: filepath.Join(t.TempDir(), "gone")}).Start(context.Background())
		defer stop()
		if _, err := cmd(300 * time.Millisecond); err == nil || !strings.Contains(err.Error(), "no outcome") {
			t.Errorf("without an outcome: %v", err)
		}
	})
	t.Run("older process", func(t *testing.T) {
		// A process that never announced SIGUSR2 handling, as one of a release without the
		// hand-off, or a stale file of another process: refused, and no signal sent.
		for name, body := range map[string]*string{"no marker": nil, "another process": ptr(fmt.Sprint(pid + 1))} {
			_ = os.Remove(filepath.Join(dir, handoff.CapableFile))
			if body != nil {
				if err := os.WriteFile(filepath.Join(dir, handoff.CapableFile), []byte(*body), 0o644); err != nil { //nolint:gosec // G306: a test file
					t.Fatal(err)
				}
			}
			n := calls.Load()
			_, err := cmd(time.Second)
			if err == nil || !strings.Contains(err.Error(), "does not take hand-offs") {
				t.Errorf("%s: %v", name, err)
			}
			time.Sleep(50 * time.Millisecond)
			if calls.Load() != n {
				t.Errorf("%s: signalled the process", name)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, handoff.CapableFile), []byte(fmt.Sprint(pid)), 0o644); err != nil { //nolint:gosec // G306: a test file
			t.Fatal(err)
		}
	})
	t.Run("stale outcome of another process", func(t *testing.T) {
		// The last outcome is of a process that has been replaced since: neither "in progress"
		// nor the answer to this hand-off, which the command waits for.
		start(t, func(context.Context) (*handoff.Child, error) { return &handoff.Child{Pid: 78, Generation: 3}, nil })
		for _, o := range []handoff.Outcome{
			{ID: 1, State: handoff.StateRunning, OldPID: pid + 1},
			{ID: 2, State: handoff.StateFailed, Reason: "stale", OldPID: pid + 1},
		} {
			if err := handoff.WriteOutcome(dir, o); err != nil {
				t.Fatal(err)
			}
			out, err := cmd(10 * time.Second)
			if err != nil || !strings.Contains(out, "process 78 (generation 3)") {
				t.Errorf("after %+v: %q, %v", o, out, err)
			}
		}
	})
	t.Run("timeout", func(t *testing.T) {
		// The signal is taken but the hand-off never ends.
		hung := func(t *testing.T) {
			// Its own trigger, ended with the subtest: the hand-off hangs until then.
			ctx, cancel := context.WithCancel(context.Background())
			stop := (&handoff.Trigger{Dir: dir, Handoff: func(ctx context.Context) (*handoff.Child, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}}).Start(ctx)
			t.Cleanup(func() {
				cancel()
				stop()
				time.Sleep(100 * time.Millisecond) // the outcome of the ended hand-off
			})
		}
		hung(t)
		began := time.Now()
		_, err := cmd(200 * time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "no outcome") || time.Since(began) > 5*time.Second {
			t.Errorf("a hand-off that does not end: %v after %v", err, time.Since(began))
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		hung := func(t *testing.T) {
			// Its own trigger, ended with the subtest: the hand-off hangs until then.
			ctx, cancel := context.WithCancel(context.Background())
			stop := (&handoff.Trigger{Dir: dir, Handoff: func(ctx context.Context) (*handoff.Child, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}}).Start(ctx)
			t.Cleanup(func() {
				cancel()
				stop()
				time.Sleep(100 * time.Millisecond) // the outcome of the ended hand-off
			})
		}
		hung(t)
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		began := time.Now()
		err := runHandoff(ctx, &cli.Env{Stdout: io.Discard, Stderr: io.Discard, Getenv: os.Getenv}, "gateway", 10*time.Millisecond, time.Minute)
		if !errors.Is(err, context.Canceled) || time.Since(began) > 5*time.Second {
			t.Errorf("a cancelled command: %v after %v", err, time.Since(began))
		}
	})
	t.Run("not running", func(t *testing.T) {
		mainPID = func(context.Context, string) (int, error) { return 0, nil }
		if _, err := cmd(time.Second); err == nil || !strings.Contains(err.Error(), "does not run") {
			t.Errorf("a stopped unit: %v", err)
		}
		mainPID = func(context.Context, string) (int, error) { return 0, errors.New("systemctl: not found") }
		if _, err := cmd(time.Second); err == nil || !strings.Contains(err.Error(), "container") {
			t.Errorf("without systemd: %v", err)
		}
	})
	t.Run("a unit that is not Type=notify", func(t *testing.T) {
		defer func(f func(context.Context, string) (bool, error)) { notifyType = f }(notifyType)
		mainPID = func(context.Context, string) (int, error) { return pid, nil }
		start(t, func(context.Context) (*handoff.Child, error) { return nil, errors.New("must not be asked") })
		before := calls.Load()
		notifyType = func(context.Context, string) (bool, error) { return false, nil }
		if _, err := cmd(time.Second); err == nil || !strings.Contains(err.Error(), "not Type=notify") || !strings.Contains(err.Error(), "handoff.conf") {
			t.Errorf("a unit without the drop-in: %v", err)
		}
		notifyType = func(context.Context, string) (bool, error) { return false, errors.New("systemctl failed") }
		if _, err := cmd(time.Second); err == nil || !strings.Contains(err.Error(), "not Type=notify") {
			t.Errorf("a unit systemctl cannot show: %v", err)
		}
		if calls.Load() != before {
			t.Error("the process was signalled although the unit is not Type=notify")
		}
	})
	t.Run("usage", func(t *testing.T) {
		for _, args := range [][]string{nil, {"controller"}, {"gateway", "connector"}} {
			var u *cli.UsageError
			if err := Handoff().Run(context.Background(), &cli.Env{Stdout: io.Discard, Stderr: io.Discard, Getenv: os.Getenv}, args); !errors.As(err, &u) {
				t.Errorf("rpmgr handoff %v: %v", args, err)
			}
		}
	})
}

func ptr[T any](v T) *T { return &v }

// TestStartHandoffs: a role outside the hand-off roles gets no Link; a role that is not ready by
// itself is announced at once; the gateway and the connector report their own readiness through their Link, and the
// trigger of either announces the process only from then on.
func TestStartHandoffs(t *testing.T) {
	run := RunDir
	t.Cleanup(func() { RunDir = run })
	RunDir = t.TempDir()
	sock := filepath.Join(t.TempDir(), "notify")
	srv, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	env := &cli.Env{Stdout: io.Discard, Stderr: io.Discard, Getenv: func(k string) string {
		if k == "NOTIFY_SOCKET" {
			return sock
		}
		return ""
	}}
	capable := func(role string) bool {
		_, err := os.Stat(filepath.Join(RunDir, role, handoff.CapableFile))
		return err == nil
	}
	for _, role := range []string{"gateway", "connector", "all-in-one"} {
		if err := os.Mkdir(filepath.Join(RunDir, role), 0o755); err != nil { //nolint:gosec // G301: as RuntimeDirectory= makes it
			t.Fatal(err)
		}
	}

	ctx, finish, err := startHandoffs(context.Background(), env, "controller")
	if err != nil || handoff.LinkFrom(ctx) != nil {
		t.Fatalf("controller: %v, %v", handoff.LinkFrom(ctx), err)
	}
	finish(nil)

	// Every role with a hand-off reports its own readiness and takes SIGUSR2 only from then on.
	for _, role := range []string{"gateway", "connector", "all-in-one"} {
		ctx, finish, err = startHandoffs(context.Background(), env, role)
		if err != nil || handoff.LinkFrom(ctx) == nil {
			t.Fatalf("%s: %v", role, err)
		}
		if capable(role) {
			t.Fatalf("the %s takes SIGUSR2 before it is ready", role)
		}
		if err := handoff.LinkFrom(ctx).Ready(); err != nil || !capable(role) {
			t.Fatalf("%s ready: capable %v, %v", role, capable(role), err)
		}
		finish(nil)
	}
}
