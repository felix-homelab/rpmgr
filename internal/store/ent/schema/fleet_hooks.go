// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"
	"errors"

	"entgo.io/ent"

	gen "github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/hook"
)

// The fleet's hooks use generated types, so a checkout without generated code generates in two
// passes, as for scope.go.

// Hooks assign the slot of a new gateway.
func (Gateway) Hooks() []ent.Hook {
	return []ent.Hook{hook.On(assignSlot, ent.OpCreate)}
}

// assignSlot gives a new gateway the lowest slot that no active gateway of its group holds.
func assignSlot(next ent.Mutator) ent.Mutator {
	return hook.GatewayFunc(func(ctx context.Context, m *gen.GatewayMutation) (ent.Value, error) {
		group, ok := m.GatewayGroupID()
		if !ok {
			return next.Mutate(ctx, m)
		}
		taken, err := m.Client().Gateway.Query().
			Where(gateway.GatewayGroupID(group), gateway.DecommissionedAtIsNil()).
			Select(gateway.FieldSlot).Ints(ctx)
		if err != nil {
			return nil, err
		}
		used := map[int]bool{}
		for _, s := range taken {
			used[s] = true
		}
		for s := 1; s <= MaxGatewaysPerGroup; s++ {
			if !used[s] {
				m.SetSlot(s)
				return next.Mutate(ctx, m)
			}
		}
		return nil, ErrGroupFull
	})
}

// Hooks check that the token's role matches what it is bound to.
func (EnrollmentToken) Hooks() []ent.Hook {
	return []ent.Hook{hook.On(checkTokenBinding, ent.OpCreate)}
}

func checkTokenBinding(next ent.Mutator) ent.Mutator {
	return hook.EnrollmentTokenFunc(func(ctx context.Context, m *gen.EnrollmentTokenMutation) (ent.Value, error) {
		role, _ := m.Role()
		_, gw := m.GatewayID()
		_, con := m.ConnectorID()
		switch {
		case role == "gateway" && (!gw || con):
			return nil, errors.New("store: a gateway token is bound to one gateway and to no connector")
		case role == "connector" && gw:
			return nil, errors.New("store: a connector token is not bound to a gateway")
		}
		if exp, ok := m.ExpiresAt(); ok {
			// UTC, so that SQLite compares the stored text with the consumption's $now correctly.
			m.SetExpiresAt(exp.UTC())
		}
		uses, set := m.MaxUses()
		switch {
		case !set:
			m.SetMaxUses(1)
		case uses == 0:
			if ephemeral, _ := m.Ephemeral(); !ephemeral {
				return nil, errors.New("store: only an ephemeral token may have unlimited uses")
			}
			m.ClearMaxUses()
		}
		if uses, _ := m.MaxUses(); con && (uses != 1) {
			return nil, errors.New("store: a re-enrollment token is single-use")
		}
		return next.Mutate(ctx, m)
	})
}
