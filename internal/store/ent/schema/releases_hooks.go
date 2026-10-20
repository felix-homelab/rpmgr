// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"

	"entgo.io/ent"

	gen "github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/hook"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
)

// Hooks keep a rollout's active flag in step with its state, so the partial unique index on it
// allows one rollout that is running or paused. The flag is never set by hand.
func (Rollout) Hooks() []ent.Hook {
	return []ent.Hook{hook.On(rolloutActive, ent.OpCreate|ent.OpUpdate|ent.OpUpdateOne)}
}

func rolloutActive(next ent.Mutator) ent.Mutator {
	return hook.RolloutFunc(func(ctx context.Context, m *gen.RolloutMutation) (ent.Value, error) {
		state, ok := m.State()
		if !ok {
			if m.Op().Is(ent.OpCreate) {
				state = rollout.DefaultState
			} else {
				m.ResetActive()
				return next.Mutate(ctx, m)
			}
		}
		m.SetActive(state == rollout.StateRunning || state == rollout.StatePaused)
		return next.Mutate(ctx, m)
	})
}
