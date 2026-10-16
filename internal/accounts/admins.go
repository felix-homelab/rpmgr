// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/authz"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
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
			if m.db.Dialect == store.Postgres {
				// Two revocations at once must not both count the other's role: the second waits
				// for the first's row locks, then counts what it committed.
				rows, err := tx.QueryContext(m.sys, "SELECT id FROM users WHERE instance_admin FOR UPDATE")
				if err != nil {
					return err
				}
				if err := rows.Close(); err != nil {
					return err
				}
			}
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

// Recoverable reports whether a user whose org roles are roles may recover the account of target,
// whose memberships are theirs (docs/04-security.md, "Account recovery"): only that of a user who
// is no Instance Admin and all of whose orgs they hold, as Owner, or, unless ownerOnly, as Admin
// where the user is no Owner. So an org's Owner or Admin never reaches another org, or the
// instance, through an account they share. The Instance Admin may recover anyone; the caller
// checks that first.
func Recoverable(roles map[string]string, target *ent.User, theirs []*ent.Membership, ownerOnly bool) bool {
	if target.InstanceAdmin || len(theirs) == 0 {
		return false
	}
	for _, m := range theirs {
		switch mine := roles[m.OrgID]; {
		case mine == authz.RoleOwner:
		case !ownerOnly && mine == authz.RoleAdmin && string(m.Role) != authz.RoleOwner:
		default:
			return false
		}
	}
	return true
}

// recoveryAudit adds to tx an entry in the audit log of each of orgs, the target's, so that their
// Owners and Admins see a recovery of their member's account, which the instance's log holds too.
func recoveryAudit(ctx context.Context, tx *ent.Tx, orgs []string, actor, action, target, reason string) error {
	for _, org := range orgs {
		if _, err := audit.Append(ctx, tx, audit.Entry{OrgID: org, ActorType: actorType(actor), ActorID: actor, Action: action,
			TargetType: "user", TargetID: target, Result: audit.Success, Reason: reason}); err != nil {
			return err
		}
	}
	return nil
}

// stillRecoverable reports whether the user who made a reset link for target may still recover
// their account: a link outlives changes of roles, and must not set the password of a user who has
// since become Instance Admin or joined another org, or after its maker lost the role. Links that
// no user made, from the e-mail request or the controller host, need no check.
func stillRecoverable(ctx context.Context, tx *ent.Tx, maker, target string) (bool, error) {
	if !strings.HasPrefix(maker, "usr_") || maker == target {
		return true, nil
	}
	by, err := tx.User.Get(ctx, maker)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil || by.Status != user.StatusActive {
		return false, err
	}
	if by.InstanceAdmin {
		return true, nil
	}
	mine, err := tx.Membership.Query().Where(membership.UserID(maker)).All(ctx)
	if err != nil {
		return false, err
	}
	roles := map[string]string{}
	for _, m := range mine {
		roles[m.OrgID] = string(m.Role)
	}
	u, err := tx.User.Get(ctx, target)
	if err != nil {
		return false, err
	}
	theirs, err := tx.Membership.Query().Where(membership.UserID(target)).All(ctx)
	if err != nil {
		return false, err
	}
	return Recoverable(roles, u, theirs, false), nil
}
