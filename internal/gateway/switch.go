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
)

// movedEvery is how often the new process reports its sessions, and the old one checks them.
const movedEvery = 100 * time.Millisecond

// followNew runs in the old process once the new one took over. It drains the data sessions with
// reason handoff, so that connectors open new ones in the new process, and returns once every
// connector the old process had has a session there, the new process exited, the deadline passed
// or ctx ended: the old process then stops accepting. A revocation the new process reports closes
// the sessions of the revoked identity at once. The returned channel is closed when the new
// process hands off itself, which ends the drain early.
func followNew(ctx context.Context, recv func() (typ, reason string, err error), exited <-chan struct{}, sessions *Sessions, deadline time.Time, reload func(), log *slog.Logger) (ended <-chan struct{}) {
	had := sessions.Connectors()
	sessions.DrainHandoff(deadline)
	var mu sync.Mutex
	moved := map[string]bool{}
	end := make(chan struct{})
	go func() {
		for {
			typ, reason, err := recv()
			if err != nil {
				return // the new process closed the pipe or exited; its own exit does not end this drain
			}
			switch typ {
			case msgSession:
				mu.Lock()
				moved[reason] = true
				mu.Unlock()
			case msgRevoked:
				reload()
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
