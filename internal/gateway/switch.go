// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// The messages the new process of a hand-off sends the old one on the status pipe once it took
// over (docs/03-connections.md, "Restarts with socket hand-off", steps 4 and 5).
const (
	// msgSession: the new process has a data session of the connector in the reason.
	msgSession = "session"
	// msgRevoked: the new process's deny-list changed; the old one reads it again.
	msgRevoked = "revoked"
	// msgSuccessor: the new process hands off itself, which ends this drain early.
	msgSuccessor = "successor"
	// msgCut: the new process removed the route in the reason or changed its access rules; the old
	// one resets that route's connections.
	msgCut = "cut"
)

// movedEvery is how often the new process reports its sessions, and the old one checks them.
const movedEvery = 100 * time.Millisecond

// followNew runs in the old process once the new one took over. It drains the data sessions with
// reason handoff, so that connectors open new ones in the new process, and returns once every
// connector the old process had has a session there, the new process exited, the deadline passed
// or ctx ended: the old process then stops accepting. A revocation the new process reports closes
// the sessions of the revoked identity at once. The returned channel is closed when the new
// process hands off itself, which ends the drain early.
func followNew(ctx context.Context, recv func() (typ, reason string, err error), exited <-chan struct{}, sessions *Sessions, deadline time.Time, reload func(), cut func(routeID string), log *slog.Logger) (ended <-chan struct{}) {
	had := sessions.Connectors()
	every := denyPollEvery
	sessions.DrainHandoff(deadline)
	var mu sync.Mutex
	moved := map[string]bool{}
	end := make(chan struct{})
	go func() {
		for {
			typ, reason, err := recv()
			if err != nil {
				// The new process closed the pipe or exited; its exit does not end this drain, but no
				// revocation reaches this process any more: read the deny-list the new process
				// writes (docs/03, "Revision and deny-list check") until the drain ends.
				pollDenyList(ctx, every, deadline, reload)
				return
			}
			switch typ {
			case msgSession:
				mu.Lock()
				moved[reason] = true
				mu.Unlock()
			case msgRevoked:
				reload()
			case msgCut:
				cut(reason)
			case msgSuccessor:
				log.Info("the new process hands off itself; ending the drain")
				close(end)
				return
			default:
				log.Warn("unknown message from the new process", "type", typ)
			}
		}
	}()
	all := func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range had {
			if !moved[c] {
				return false
			}
		}
		return true
	}
	t := time.NewTicker(movedEvery)
	defer t.Stop()
	for !all() && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return end
		case <-exited:
			return end
		case <-end:
			return end
		case <-t.C:
		}
	}
	return end
}

// denyPollEvery is how often an old process without a pipe reads the deny-list again; a test
// shortens it.
var denyPollEvery = time.Second

// pollDenyList reads the deny-list again at once and then every given interval, until deadline or
// ctx.
func pollDenyList(ctx context.Context, every time.Duration, deadline time.Time, reload func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		reload()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !time.Now().Before(deadline) {
				return
			}
		}
	}
}

// reportSessions runs in the new process after it took over: it tells the old one which
// connectors have a data session here, until ctx ends.
func reportSessions(ctx context.Context, send func(typ, reason string) error, sessions *Sessions, log *slog.Logger) {
	sent := map[string]bool{}
	t := time.NewTicker(movedEvery)
	defer t.Stop()
	for {
		for _, c := range sessions.Connectors() {
			if sent[c] {
				continue
			}
			if err := send(msgSession, c); err != nil {
				log.Debug("telling the old process about a session", "error", err)
				return // the old process is gone
			}
			sent[c] = true
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// cuts carries the routes the new process removed or changed to the old one: those from before the
// pipe is ready wait for it.
type cuts struct {
	mu   sync.Mutex
	to   func(typ, reason string) error // the pipe to the old process, once set
	held []string
}

// send tells the old process to cut the route's connections, or keeps the route until attach.
func (c *cuts) send(routeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.to == nil {
		c.held = append(c.held, routeID)
		return
	}
	_ = c.to(msgCut, routeID)
}

// attach sets how to send to the old process and sends what was held.
func (c *cuts) attach(send func(typ, reason string) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.to = send
	for _, id := range c.held {
		_ = send(msgCut, id)
	}
	c.held = nil
}
