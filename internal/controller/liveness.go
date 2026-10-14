// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"time"

	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
)

// disconnected records that the agent's session with epoch ended, unless a newer one replaced it.
// The sessions of a stopping controller end while it drains, after the stop has cancelled s.sys
// and before the database closes, so the record does not depend on s.sys.
func (s *Sessions) disconnected(agentID string, epoch int64) {
	now := s.now().UTC()
	ctx := context.WithoutCancel(s.sys)
	err := store.WriteTx(ctx, s.db, func(tx *ent.Tx) error {
		return tx.AgentSession.Update().Where(agentsession.ID(agentID), agentsession.SessionEpoch(epoch)).
			SetDisconnectedAt(now).SetLastSeenAt(now).Exec(ctx)
	})
	switch {
	case err == nil:
	case s.sys.Err() != nil: // stopped beyond the drain: seenLoop ends the session at the next start
		s.log.Info("the agent's disconnect is recorded at the next start", "agent", agentID, "error", err)
	default:
		s.log.Error("cannot record that an agent disconnected", "agent", agentID, "error", err)
	}
}

// seenLoop keeps the sessions of this node current until ctx ends (docs/03-connections.md,
// "Timeouts, keepalive and backoff"): first it ends the sessions a stopped run of this node left
// open, then it marks its live sessions seen every s.seen.
func (s *Sessions) seenLoop(ctx context.Context) {
	s.endLeftOpen()
	t := time.NewTicker(s.seen)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.markSeen()
		}
	}
}

// endLeftOpen ends the sessions a stopped run of this node left open. A controller that stops
// before it could leaves them to its next start, which is no error.
func (s *Sessions) endLeftOpen() {
	err := store.WriteTx(s.sys, s.db, func(tx *ent.Tx) error {
		return tx.AgentSession.Update().Where(agentsession.ControllerNode(s.node), agentsession.DisconnectedAtIsNil(),
			agentsession.LastSeenAtLT(s.started)).SetDisconnectedAt(s.started).Exec(s.sys)
	})
	if err != nil && s.sys.Err() == nil {
		s.log.Error("cannot end the sessions a stopped controller left open", "error", err)
	}
}

// markSeen writes last_seen_at of every live session of this node.
func (s *Sessions) markSeen() {
	s.mu.Lock()
	live := make(map[string]int64, len(s.active))
	for id, sess := range s.active {
		live[id] = sess.epoch
	}
	s.mu.Unlock()
	if len(live) == 0 {
		return
	}
	now := s.now().UTC()
	err := store.WriteTx(s.sys, s.db, func(tx *ent.Tx) error {
		for id, epoch := range live {
			if err := tx.AgentSession.Update().Where(agentsession.ID(id), agentsession.SessionEpoch(epoch), agentsession.DisconnectedAtIsNil()).
				SetLastSeenAt(now).Exec(s.sys); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.Error("cannot mark the live sessions seen", "error", err)
	}
}
