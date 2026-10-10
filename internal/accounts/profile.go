// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
)

// SetProfile changes a user's display name and, unless it is "", their web UI's theme: system,
// light or dark.
func (a *Accounts) SetProfile(ctx context.Context, userID, name, theme string) (*ent.User, error) {
	name, err := checkDisplayName(name)
	if err != nil {
		return nil, err
	}
	if theme != "" && user.ThemeValidator(user.Theme(theme)) != nil {
		return nil, ErrTheme
	}
	var u *ent.User
	err = store.WriteTx(store.CarryTxHook(a.sys, ctx), a.db, func(tx *ent.Tx) error {
		up, reason := tx.User.UpdateOneID(userID).SetDisplayName(name), "display name"
		if theme != "" {
			up, reason = up.SetTheme(user.Theme(theme)), "display name, theme"
		}
		if u, err = up.Save(a.sys); err != nil {
			return err
		}
		_, err = audit.Append(a.sys, tx, audit.Entry{ActorType: audit.ActorUser, ActorID: userID, Action: "user.update",
			TargetType: "user", TargetID: userID, Result: audit.Success, Reason: reason})
		return err
	})
	return u, err
}

// Users returns up to limit users with IDs after after, by ID.
func (a *Accounts) Users(after string, limit int) ([]*ent.User, error) {
	q := a.db.ReadClient().User.Query().Order(ent.Asc(user.FieldID)).Limit(limit)
	if after != "" {
		q.Where(user.IDGT(after))
	}
	return q.All(a.sys)
}

// ChangePassword sets a user's new password once the current one checks out; a wrong one is
// ErrCredentials. The change is a credential supersession in the revocation log.
func (m *MFA) ChangePassword(ctx context.Context, userID, current, next string) error {
	u, err := m.db.ReadClient().User.Get(m.sys, userID)
	if err != nil {
		return err
	}
	if _, err := m.Authenticate(ctx, u.Email, current); err != nil {
		return err
	}
	params, err := m.params()
	if err != nil {
		return err
	}
	hash, err := password.Hash(ctx, next, params)
	if err != nil {
		return err
	}
	return store.WriteTx(store.CarryTxHook(m.sys, ctx), m.db, func(tx *ent.Tx) error {
		if err := tx.User.UpdateOneID(userID).SetPasswordHash(hash).Exec(m.sys); err != nil {
			return err
		}
		return m.superseded(tx, userID, "user.password_change", "password changed")
	})
}
