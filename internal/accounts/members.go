// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/invitation"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// InvitationTTL is how long an invitation works (docs/04-security.md, "Human authentication and
// sessions").
const InvitationTTL = 7 * 24 * time.Hour

// Errors of the member rules (docs/04-security.md, "Roles").
var (
	ErrRole         = errors.New("accounts: the role is owner, admin, operator or viewer")
	ErrOwnerOnly    = errors.New("accounts: only an Owner makes, changes or removes an Owner")
	ErrLastOwner    = errors.New("accounts: an org keeps at least one Owner")
	ErrNoMember     = errors.New("accounts: no such member")
	ErrMember       = errors.New("accounts: already a member of the org")
	ErrInvitation   = errors.New("accounts: the invitation is not valid, was used or has expired")
	ErrSignInFirst  = errors.New("accounts: an account with the invited address exists; sign in as it to accept")
	ErrOtherAddress = errors.New("accounts: the invitation is for another address")
)

// roles, from most to least powerful.
var roles = []string{authz.RoleOwner, authz.RoleAdmin, authz.RoleOperator, authz.RoleViewer}

// Member is a user's membership of an org.
type Member struct {
	UserID, Email, DisplayName, Role string
	Since                            time.Time
}

// Members applies the member rules of docs/04-security.md, "Roles": only an Owner makes, changes
// or removes an Owner, and an org keeps at least one. The caller's permission (members.write) is
// the API's to check; by and byRole are the acting member and their role. Removals and
// downgrades go to the revocation log.
type Members struct {
	*Accounts
	RevLog *revlog.Log
	Logger *slog.Logger
}

// List returns an org's members, Owners first.
func (m *Members) List(orgID string) ([]Member, error) {
	ms, err := m.db.ReadClient().Membership.Query().Where(membership.OrgID(orgID)).WithUser().
		Order(ent.Asc(membership.FieldCreatedAt), ent.Asc(membership.FieldID)).All(m.sys)
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(ms))
	for _, r := range ms {
		out = append(out, Member{UserID: r.UserID, Email: r.Edges.User.Email, DisplayName: r.Edges.User.DisplayName,
			Role: string(r.Role), Since: r.CreatedAt})
	}
	slices.SortStableFunc(out, func(a, b Member) int { return slices.Index(roles, a.Role) - slices.Index(roles, b.Role) })
	return out, nil
}

// Invite creates a one-time link that makes its holder a member of the org with role, and returns
// its token. Only an Owner invites an Owner.
func (m *Members) Invite(orgID, email, role, by, byRole string) (string, error) {
	if !slices.Contains(roles, role) {
		return "", ErrRole
	}
	if role == authz.RoleOwner && byRole != authz.RoleOwner {
		return "", ErrOwnerOnly
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return "", err
	}
	tok, err := token.New(token.Invitation)
	if err != nil {
		return "", err
	}
	err = store.WriteTx(m.sys, m.db, func(tx *ent.Tx) error {
		inv, err := tx.Invitation.Create().SetOrgID(orgID).SetEmail(email).SetRole(invitation.Role(role)).
			SetTokenHash(token.Hash(tok)).SetCreatedBy(by).SetCreatedAt(m.now()).SetExpiresAt(m.now().Add(InvitationTTL)).Save(m.sys)
		if err != nil {
			return err
		}
		return m.audit(tx, orgID, by, "member.invite", "invitation", inv.ID, email+" as "+role)
	})
	if err != nil {
		return "", err
	}
	return tok, nil
}

// AcceptInvitation uses an invitation. A signed-in user (signedIn, a user ID) joins the org if the
// invitation is for their address. Without one, an account is created for the invited address
// with displayName and password, unless one exists already, whose holder has to sign in first.
// It returns the member and the org.
func (m *Members) AcceptInvitation(ctx context.Context, tok, signedIn, displayName, pw string) (*ent.User, string, error) {
	if k, err := token.Parse(tok); err != nil || k != token.Invitation {
		return nil, "", ErrInvitation
	}
	inv, err := m.db.Client().Invitation.Query().Where(invitation.TokenHash(token.Hash(tok))).Only(m.sys)
	if ent.IsNotFound(err) || err == nil && (inv.AcceptedAt != nil || !inv.ExpiresAt.After(m.now())) {
		return nil, "", ErrInvitation
	}
	if err != nil {
		return nil, "", err
	}
	var hash string
	if signedIn == "" {
		if ok, err := m.db.Client().User.Query().Where(user.Email(inv.Email)).Exist(m.sys); err != nil || ok {
			return nil, "", errors.Join(err, errIf(ok, ErrSignInFirst))
		}
		if displayName, err = checkDisplayName(displayName); err != nil {
			return nil, "", err
		}
		params, err := m.params()
		if err != nil {
			return nil, "", err
		}
		if hash, err = password.Hash(ctx, pw, params); err != nil {
			return nil, "", err
		}
	}
	var u *ent.User
	err = store.WriteTx(m.sys, m.db, func(tx *ent.Tx) error {
		if signedIn != "" {
			if u, err = tx.User.Get(m.sys, signedIn); err != nil {
				return err
			}
			if u.Email != inv.Email {
				return ErrOtherAddress
			}
		} else {
			if u, err = tx.User.Create().SetEmail(inv.Email).SetDisplayName(displayName).SetPasswordHash(hash).
				SetCreatedAt(m.now()).Save(m.sys); err != nil {
				return err
			}
			if _, err := audit.Append(m.sys, tx, audit.Entry{ActorType: audit.ActorUser, ActorID: u.ID, AuthMethod: "invitation",
				Action: "user.create", TargetType: "user", TargetID: u.ID, Result: audit.Success, Reason: "invitation " + inv.ID}); err != nil {
				return err
			}
		}
		now := m.now()
		n, err := tx.Invitation.Update().Where(invitation.ID(inv.ID), invitation.AcceptedAtIsNil(), invitation.ExpiresAtGT(now)).
			SetAcceptedAt(now).SetAcceptedBy(u.ID).Save(m.sys)
		if err != nil || n != 1 {
			return errors.Join(err, errIf(n != 1, ErrInvitation))
		}
		if ok, err := tx.Membership.Query().Where(membership.OrgID(inv.OrgID), membership.UserID(u.ID)).Exist(m.sys); err != nil || ok {
			return errors.Join(err, errIf(ok, ErrMember))
		}
		if err := tx.Membership.Create().SetOrgID(inv.OrgID).SetUserID(u.ID).SetRole(membership.Role(inv.Role)).
			SetCreatedBy(inv.CreatedBy).SetCreatedAt(now).Exec(m.sys); err != nil {
			return err
		}
		return m.audit(tx, inv.OrgID, u.ID, "member.add", "user", u.ID, "invitation "+inv.ID+" as "+string(inv.Role))
	})
	if err != nil {
		return nil, "", err
	}
	return u, inv.OrgID, nil
}

// SetRole changes a member's role. Only an Owner makes or changes an Owner, and the last Owner
// stays one. A lower role is recorded as a downgrade in the revocation log.
func (m *Members) SetRole(orgID, userID, role, by, byRole string) error {
	if !slices.Contains(roles, role) {
		return ErrRole
	}
	return store.WriteTx(m.sys, m.db, func(tx *ent.Tx) error {
		cur, err := m.member(tx, orgID, userID)
		if err != nil {
			return err
		}
		old := string(cur.Role)
		if (old == authz.RoleOwner || role == authz.RoleOwner) && byRole != authz.RoleOwner {
			return ErrOwnerOnly
		}
		if old == role {
			return nil
		}
		if old == authz.RoleOwner {
			if err := m.keepOwner(tx, orgID); err != nil {
				return err
			}
		}
		if err := tx.Membership.UpdateOne(cur).SetRole(membership.Role(role)).Exec(m.sys); err != nil {
			return err
		}
		if slices.Index(roles, role) > slices.Index(roles, old) {
			m.revoked(revlog.RoleDowngraded, orgID, userID, role, by)
		}
		return m.audit(tx, orgID, by, "member.role", "user", userID, old+" to "+role)
	})
}

// Remove ends a membership. Only an Owner removes an Owner, and the last Owner stays.
func (m *Members) Remove(orgID, userID, by, byRole string) error {
	return store.WriteTx(m.sys, m.db, func(tx *ent.Tx) error {
		cur, err := m.member(tx, orgID, userID)
		if err != nil {
			return err
		}
		if cur.Role == membership.RoleOwner {
			if byRole != authz.RoleOwner {
				return ErrOwnerOnly
			}
			if err := m.keepOwner(tx, orgID); err != nil {
				return err
			}
		}
		if err := tx.Membership.DeleteOne(cur).Exec(m.sys); err != nil {
			return err
		}
		m.revoked(revlog.MemberRemoved, orgID, userID, "", by)
		return m.audit(tx, orgID, by, "member.remove", "user", userID, "was "+string(cur.Role))
	})
}

func (m *Members) member(tx *ent.Tx, orgID, userID string) (*ent.Membership, error) {
	cur, err := tx.Membership.Query().Where(membership.OrgID(orgID), membership.UserID(userID)).Only(m.sys)
	if ent.IsNotFound(err) {
		return nil, ErrNoMember
	}
	return cur, err
}

// keepOwner refuses a change that would leave the org without an Owner: it must have another.
func (m *Members) keepOwner(tx *ent.Tx, orgID string) error {
	n, err := tx.Membership.Query().Where(membership.OrgID(orgID), membership.RoleEQ(membership.RoleOwner)).Count(m.sys)
	if err != nil || n <= 1 {
		return errors.Join(err, errIf(n <= 1, ErrLastOwner))
	}
	return nil
}

// revoked appends a removal or downgrade to the revocation log inside the transaction that makes
// it; a failed append is reported and does not stop the change (docs/04-security.md, "Revocation
// log").
func (m *Members) revoked(kind revlog.Kind, orgID, userID, detail, by string) {
	if m.RevLog == nil {
		return
	}
	if _, err := m.RevLog.Append(revlog.Entry{Kind: kind, Org: orgID, Subject: userID, Detail: detail, Actor: by}); err != nil &&
		m.Logger != nil {
		m.Logger.Error("cannot append a membership change to the revocation log; it applies anyway", "org", orgID, "user", userID,
			"error", err)
	}
}

func (m *Members) audit(tx *ent.Tx, orgID, by, action, targetType, target, reason string) error {
	_, err := audit.Append(m.sys, tx, audit.Entry{OrgID: orgID, ActorType: actorType(by), ActorID: by, Action: action,
		TargetType: targetType, TargetID: target, Result: audit.Success, Reason: reason})
	return err
}
