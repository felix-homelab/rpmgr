// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"context"
	"fmt"
	"sync"
)

// Link joins a role to its hand-offs. The command that starts the role creates it; the role finds
// it in its context (LinkFrom), takes its listeners from Inherited, tells Serve how to start its
// successor and calls Ready where it is ready to serve: a role that does not know the Link behaves
// as before.
type Link struct {
	// Inherited is the hand-off that started this process; nil after a plain start.
	Inherited *Handoff

	getenv func(string) string
	begin  func() // starts the trigger of a process a hand-off started, once it took over

	mu    sync.Mutex
	start func(ctx context.Context) (*Child, error)
	ready bool
}

// NewLink returns the Link of a process. begin starts the role's Trigger: at once after a plain
// start, but only once the process took over after a hand-off, so that its pid is not announced
// while the old process still serves and may be the one that keeps serving.
func NewLink(inherited *Handoff, getenv func(string) string, begin func()) *Link {
	return &Link{Inherited: inherited, getenv: getenv, begin: begin}
}

// Generation is this process's generation: 1 after a plain start.
func (l *Link) Generation() uint64 {
	if l.Inherited != nil {
		return l.Inherited.Manifest.Generation
	}
	return 1
}

// Serve sets how the role starts its successor; until then a hand-off is refused.
func (l *Link) Serve(start func(ctx context.Context) (*Child, error)) {
	l.mu.Lock()
	l.start = start
	l.mu.Unlock()
}

// Handoff is the Trigger's Handoff: the role's start function, else a refusal.
func (l *Link) Handoff(ctx context.Context) (*Child, error) {
	l.mu.Lock()
	start := l.start
	l.mu.Unlock()
	if start == nil {
		return nil, fmt.Errorf("%w: the role is not ready to hand off", ErrRefused)
	}
	return start(ctx)
}

// Ready is called once, where the role is ready to serve. After a plain start it tells systemd
// (Type=notify); after a hand-off it reports ready to the old process, waits for the switch and
// tells systemd the main process changed. An error means this process must not run on.
func (l *Link) Ready() error {
	l.mu.Lock()
	if l.ready {
		l.mu.Unlock()
		return nil
	}
	l.ready = true
	l.mu.Unlock()
	var err error
	if l.Inherited != nil {
		err = l.Inherited.Ready()
	} else {
		err = Notify(l.getenv)
	}
	if err == nil && l.begin != nil {
		l.begin()
	}
	return err
}

// Finish is called when the role ended with err. A process a hand-off started that never became
// ready tells the old process why, so that it serves on at once instead of waiting out the window.
func (l *Link) Finish(err error) {
	l.mu.Lock()
	ready := l.ready
	l.mu.Unlock()
	if l.Inherited == nil || ready {
		return
	}
	reason := "the role ended before it was ready"
	if err != nil {
		reason = err.Error()
	}
	l.Inherited.Fail(reason)
}

type linkKey struct{}

// WithLink returns a context that carries l.
func WithLink(ctx context.Context, l *Link) context.Context {
	return context.WithValue(ctx, linkKey{}, l)
}

// LinkFrom returns the Link in ctx, or nil.
func LinkFrom(ctx context.Context) *Link {
	l, _ := ctx.Value(linkKey{}).(*Link)
	return l
}
