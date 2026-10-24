// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
)

// RolloutBuckets is the number of buckets a rollout's percentages count in.
const RolloutBuckets = 100

// RolloutBucket places an agent in a rollout's percentages (docs/06-data-model.md, "Webhooks and
// releases (Phase 2)"; D121): the first two bytes of the SHA-256 of its ID, big-endian, modulo
// 100. A stage of p % takes every agent whose bucket is below p, so a later stage includes every
// agent of an earlier one, and an agent keeps its bucket in every rollout.
func RolloutBucket(agentID string) int {
	sum := sha256.Sum256([]byte(agentID))
	return int(binary.BigEndian.Uint16(sum[:2]) % RolloutBuckets)
}

// Errors of QueueRolloutTargets.
var (
	// ErrRolloutNotEasy: the rollout is a staged one, whose targets are fixed at its creation.
	ErrRolloutNotEasy = errors.New("store: the rollout is a staged rollout, which takes no further agents")
	// ErrRolloutEnded: the rollout is completed or cancelled.
	ErrRolloutEnded = errors.New("store: the rollout has ended")
)

// RolloutAgent is an agent an easy rollout queues: its ID, its kind and the version it last
// connected with.
type RolloutAgent struct {
	ID            string
	Kind          rollouttarget.AgentKind
	VersionBefore string
}

// QueueRolloutTargets adds agents to the end of the queue of an easy rollout that runs or is
// paused, in the order given (docs/04-security.md, "Easy rollouts"; D129), and returns each
// agent's target in that order. An agent the rollout already has keeps its place and its target,
// also when it is named twice. Call it in a configuration transaction: its lock orders the call
// with the rollout job, so that the job never completes a rollout while agents join it.
func QueueRolloutTargets(ctx context.Context, tx *ent.Tx, rolloutID string, agents []RolloutAgent) ([]*ent.RolloutTarget, error) {
	ro, err := tx.Rollout.Get(ctx, rolloutID)
	if err != nil {
		return nil, err
	}
	switch {
	case ro.Mode != rollout.ModeEasy:
		return nil, ErrRolloutNotEasy
	case ro.State != rollout.StateRunning && ro.State != rollout.StatePaused:
		return nil, ErrRolloutEnded
	}
	rows, err := tx.RolloutTarget.Query().Where(rollouttarget.RolloutID(ro.ID)).All(ctx)
	if err != nil {
		return nil, err
	}
	have := make(map[string]*ent.RolloutTarget, len(rows)+len(agents))
	last := 0
	for _, t := range rows {
		have[t.AgentID] = t
		if t.Position != nil {
			last = max(last, *t.Position)
		}
	}
	out := make([]*ent.RolloutTarget, 0, len(agents))
	for _, a := range agents {
		if t, ok := have[a.ID]; ok {
			out = append(out, t)
			continue
		}
		last++
		t, err := tx.RolloutTarget.Create().SetRolloutID(ro.ID).SetAgentID(a.ID).SetAgentKind(a.Kind).
			SetBucket(RolloutBucket(a.ID)).SetPosition(last).SetVersionBefore(a.VersionBefore).Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("store: queueing agent %s: %w", a.ID, err)
		}
		have[a.ID] = t
		out = append(out, t)
	}
	return out, nil
}
