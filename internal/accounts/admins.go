// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
)

// ErrLastInstanceAdmin refuses to revoke the role of the last active Instance Admin.
var ErrLastInstanceAdmin = errors.New("accounts: the instance keeps at least one active Instance Admin")

// SetInstanceAdmin grants or revokes a user's Instance Admin role, by actor (docs/04-security.md,
// "Roles"). The instance keeps at least one active Instance Admin. A revocation goes to the
// revocation log, so that a restore of an older backup cannot undo it.
func (m *MFA) SetInstanceAdmin(ctx context.Context, userID string, admin bool, actor string) (*ent.User, error) {
	var u *ent.User
	err := store.WriteTx(store.CarryTxHook(m.sys, ctx), m.db, func(tx *ent.Tx) error {
		cur, err := tx.User.Get(m.sys, userID)
		if ent.IsNotFound(err) {
			return ErrNoUser
		}
		if err != nil {
			return err
		}
		if cur.InstanceAdmin == admin {
			u = cur
			return nil
		}
		action, reason := "user.instance_admin_grant", "Instance Admin granted"
		if !admin {
			n, err := tx.User.Query().Where(user.InstanceAdmin(true), user.StatusEQ(user.StatusActive), user.IDNEQ(userID)).Count(m.sys)
			if err != nil || n == 0 {
				return errors.Join(err, errIf(n == 0, ErrLastInstanceAdmin))
			}
			action, reason = "user.instance_admin_revoke", "Instance Admin revoked"
		}
		if u, err = tx.User.UpdateOne(cur).SetInstanceAdmin(admin).Save(m.sys); err != nil {
			return err
		}
		if !admin && m.RevLog != nil {
			if _, err := m.RevLog.Append(revlog.Entry{Kind: revlog.InstanceAdminRevoked, Subject: userID, Actor: actor}); err != nil && m.Logger != nil {
				m.Logger.Error("cannot append an Instance Admin revocation to the revocation log; it applies anyway", "user", userID, "error", err)
			}
		}
		_, err = audit.Append(m.sys, tx, audit.Entry{ActorType: audit.ActorUser, ActorID: actor, Action: action,
			TargetType: "user", TargetID: userID, Result: audit.Success, Reason: reason})
		return err
	})
	return u, err
}
