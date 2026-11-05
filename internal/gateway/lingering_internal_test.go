// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"syscall"
	"testing"
	"time"
)

type sent struct {
	mu   sync.Mutex
	sigs []syscall.Signal
	err  error
}

func (s *sent) kill(_ int, sig syscall.Signal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sigs = append(s.sigs, sig)
	return s.err
}

func (s *sent) got() []syscall.Signal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]syscall.Signal(nil), s.sigs...)
}

// TestEndLingering: an old process that still holds the pipe after the drain and a grace gets
// SIGTERM, and SIGKILL a grace later; one that ended, or a stopping new process, gets nothing
// (#1138).
func TestEndLingering(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	const d, g = 20 * time.Millisecond, 20 * time.Millisecond

	t.Run("lingers: SIGTERM then SIGKILL", func(t *testing.T) {
		var s sent
		endLingering(t.Context(), 4242, make(chan struct{}), d, g, s.kill, log)
		if got := s.got(); len(got) != 2 || got[0] != syscall.SIGTERM || got[1] != syscall.SIGKILL {
			t.Fatalf("signals %v, want SIGTERM then SIGKILL", got)
		}
	})
	t.Run("ends after the SIGTERM: no SIGKILL", func(t *testing.T) {
		var s sent
		gone := make(chan struct{})
		done := make(chan struct{})
		go func() { endLingering(t.Context(), 4242, gone, d, g, s.kill, log); close(done) }()
		for len(s.got()) == 0 {
			time.Sleep(time.Millisecond)
		}
		close(gone)
		<-done
		time.Sleep(3 * g)
		if got := s.got(); len(got) != 1 || got[0] != syscall.SIGTERM {
			t.Fatalf("signals %v, want only SIGTERM", got)
		}
	})
	t.Run("ended within the drain: nothing", func(t *testing.T) {
		var s sent
		gone := make(chan struct{})
		close(gone)
		endLingering(t.Context(), 4242, gone, d, g, s.kill, log)
		if got := s.got(); len(got) != 0 {
			t.Fatalf("signals %v for an old process that ended", got)
		}
	})
	t.Run("this process stops: nothing", func(t *testing.T) {
		var s sent
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		endLingering(ctx, 4242, make(chan struct{}), d, g, s.kill, log)
		if got := s.got(); len(got) != 0 {
			t.Fatalf("signals %v after the context ended", got)
		}
	})
	t.Run("no process to signal: nothing", func(t *testing.T) {
		for _, pid := range []int{0, 1, -1} {
			var s sent
			endLingering(t.Context(), pid, make(chan struct{}), d, g, s.kill, log)
			if got := s.got(); len(got) != 0 {
				t.Fatalf("pid %d: signals %v", pid, got)
			}
		}
	})
	t.Run("a failed signal ends the attempt", func(t *testing.T) {
		s := sent{err: errors.New("no such process")}
		endLingering(t.Context(), 4242, make(chan struct{}), d, g, s.kill, log)
		if got := s.got(); len(got) != 1 {
			t.Fatalf("signals %v, want one failed attempt", got)
		}
	})
}
