// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Start turns SIGUSR2 into the role's hand-offs, one at a time, and records the outcome of each in
// the runtime directory. A signal while a hand-off runs is ignored: `rpmgr handoff` refuses to
// send one then. stop ends it; a hand-off in progress ends with ctx.
func (t *Trigger) Start(ctx context.Context) (stop func()) {
	log := t.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR2)
	if err := os.WriteFile(filepath.Join(t.Dir, CapableFile), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil { //nolint:gosec // G306: read by root's rpmgr handoff
		log.Warn("hand-off: announcing that this process takes SIGUSR2", "error", err)
	}
	done := make(chan struct{})
	var busy atomic.Bool
	go func() {
		for {
			select {
			case <-done:
				return
			case <-sig:
			}
			if !busy.CompareAndSwap(false, true) {
				log.Warn("hand-off refused: one is in progress")
				continue
			}
			o := Outcome{ID: time.Now().UnixNano(), State: StateRunning, OldPID: os.Getpid()}
			t.record(log, o)
			go func() {
				defer busy.Store(false)
				if t.Handoff == nil {
					o.State, o.Reason = StateRefused, "this role cannot hand off yet; restart it instead"
				} else if child, err := t.Handoff(ctx); err != nil {
					o.State, o.Reason = StateFailed, trim(err.Error())
					if errors.Is(err, ErrRefused) {
						o.State = StateRefused
					}
				} else {
					o.State, o.NewPID, o.Generation = StateOK, child.Pid, child.Generation
				}
				t.record(log, o)
			}()
		}
	}()
	return func() { signal.Stop(sig); close(done) }
}

func (t *Trigger) record(log *slog.Logger, o Outcome) {
	log.Info("hand-off", "state", o.State, "reason", o.Reason, "new_pid", o.NewPID, "generation", o.Generation)
	if err := WriteOutcome(t.Dir, o); err != nil {
		log.Warn("hand-off: recording the outcome", "error", err)
	}
}

// WriteOutcome replaces the outcome in dir.
func WriteOutcome(dir string, o Outcome) error {
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".handoff-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil { //nolint:gosec // G302: read by root's rpmgr handoff
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, OutcomeFile))
}

// ReadOutcome reads the outcome in dir. The service user writes the directory and root may read
// it: a link, a FIFO or anything but a small regular file is refused.
func ReadOutcome(dir string) (Outcome, error) {
	var o Outcome
	f, err := os.OpenFile(filepath.Join(dir, OutcomeFile), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0) //nolint:gosec // G304: the role's runtime directory
	if err != nil {
		return o, err
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return o, fmt.Errorf("handoff: %s is no regular file", OutcomeFile)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxOutcome+1))
	if err != nil {
		return o, err
	}
	if len(b) > maxOutcome {
		return o, fmt.Errorf("handoff: %s is over %d bytes", OutcomeFile, maxOutcome)
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return o, fmt.Errorf("handoff: %s: %w", OutcomeFile, err)
	}
	o.State, o.Reason = trim(o.State), trim(o.Reason)
	return o, nil
}

// Capable reports whether process pid announced in dir that it takes SIGUSR2 as a hand-off. A
// process of a release without the hand-off, one that has not started its trigger yet and one of
// another PID are not.
func Capable(dir string, pid int) bool {
	f, err := os.OpenFile(filepath.Join(dir, CapableFile), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0) //nolint:gosec // G304: the role's runtime directory
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(f, 32))
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(string(b))
	return err == nil && n == pid && pid > 0
}

// Signal asks the role's main process to hand off.
func Signal(pid int) error { return unix.Kill(pid, unix.SIGUSR2) }
