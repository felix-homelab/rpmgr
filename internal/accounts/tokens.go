// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/apitoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// The lifetimes of an API token (docs/04-security.md, "Human authentication and sessions").
const (
	DefaultTokenTTL = 90 * 24 * time.Hour
	MaxTokenTTL     = 365 * 24 * time.Hour
)

// tokenTouchEvery is how often a token's last use is written at most.
const tokenTouchEvery = time.Minute

// Errors of API tokens.
var (
	ErrScope    = errors.New("accounts: a token's scopes are permissions its owner holds in the org")
	ErrTokenTTL = errors.New("accounts: a token expires within a year")
	ErrNoToken  = errors.New("accounts: no such token")
	ErrToken    = errors.New("accounts: the token is not valid, was revoked or has expired")
)

// Tokens are the personal API tokens of users, each bound to one org.
type Tokens struct {
	*Accounts
	RevLog *revlog.Log
	Logger *slog.Logger
}

// TokenOwner is what a token authenticates: its owner, the owner's current role in the token's
// org, and the token's scopes.
type TokenOwner struct {
	Token         *ent.APIToken
	User          *ent.User
	Role          string // the owner's current role in the token's org; empty if none
	InstanceAdmin bool
}

// Create makes a token for a user in an org and returns it with its row; the token is shown
// once. Its scopes must be permissions the user holds there now: those of their role, and
// instance.admin for an Instance Admin. ttl 0 is the default; mfa records a session with a second
// factor.
func (t *Tokens) Create(ctx context.Context, orgID, userID, name string, scopes []string, ttl time.Duration, mfa bool) (string, *ent.APIToken, error) {
	switch {
	case ttl == 0:
		ttl = DefaultTokenTTL
	case ttl < 0 || ttl > MaxTokenTTL:
		return "", nil, ErrTokenTTL
	}
	u, err := t.db.ReadClient().User.Get(t.sys, userID)
	if err != nil {
		return "", nil, err
	}
	m, err := t.db.ReadClient().Membership.Query().Where(membership.OrgID(orgID), membership.UserID(userID)).Only(t.sys)
	if err != nil {
		return "", nil, errors.Join(ErrScope, err)
	}
	if len(scopes) == 0 {
		return "", nil, ErrScope
	}
	orgSettings, _, err := settings.Org(t.sys, t.db.ReadClient(), orgID)
	if err != nil {
		return "", nil, err
	}
	for _, s := range scopes {
		ok := s == authz.PermInstanceAdmin && u.InstanceAdmin ||
			authz.OrgPermission(s) && authz.Grants(string(m.Role), s, orgSettings.GetOperatorsMayEnroll())
		if !ok {
			return "", nil, fmt.Errorf("%w: %s", ErrScope, s)
		}
	}
	slices.Sort(scopes)
	tok, err := token.New(token.PersonalAPI)
	if err != nil {
		return "", nil, err
	}
	var row *ent.APIToken
	err = store.WriteTx(store.CarryTxHook(t.sys, ctx), t.db, func(tx *ent.Tx) error {
		now := t.now()
		row, err = tx.APIToken.Create().SetOrgID(orgID).SetOwnerType(apitoken.OwnerTypeUser).SetOwnerID(userID).SetName(name).
			SetPrefix(tok[:len("rpmgr_pat_")+4]).SetTokenHash(token.Hash(tok)).SetScopes(slices.Compact(scopes)).SetMfa(mfa).
			SetCreatedAt(now).SetExpiresAt(now.Add(ttl)).Save(t.sys)
		if err != nil {
			return err
		}
		_, err = audit.Append(t.sys, tx, audit.Entry{OrgID: orgID, ActorType: audit.ActorUser, ActorID: userID,
			Action: "token.create", TargetType: "api_token", TargetID: row.ID, Result: audit.Success, Reason: fmt.Sprint(scopes)})
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return tok, row, nil
}

// List returns a user's tokens in an org that are neither revoked nor expired, newest first.
func (t *Tokens) List(orgID, userID string) ([]*ent.APIToken, error) {
	return t.db.ReadClient().APIToken.Query().Where(apitoken.OrgID(orgID), apitoken.OwnerID(userID), apitoken.RevokedAtIsNil(),
		apitoken.ExpiresAtGT(t.now())).Order(ent.Desc(apitoken.FieldCreatedAt), ent.Desc(apitoken.FieldID)).All(t.sys)
}

// Revoke ends a user's token in an org, recording it in the revocation log.
func (t *Tokens) Revoke(ctx context.Context, orgID, userID, tokenID string) error {
	return store.WriteTx(store.CarryTxHook(t.sys, ctx), t.db, func(tx *ent.Tx) error {
		n, err := tx.APIToken.Update().Where(apitoken.ID(tokenID), apitoken.OrgID(orgID), apitoken.OwnerID(userID),
			apitoken.RevokedAtIsNil()).SetRevokedAt(t.now()).Save(t.sys)
		if err != nil || n == 0 {
			return errors.Join(err, errIf(n == 0, ErrNoToken))
		}
		if t.RevLog != nil {
			if _, err := t.RevLog.Append(revlog.Entry{Kind: revlog.APITokenRevoked, Org: orgID, Subject: tokenID, Actor: userID}); err != nil &&
				t.Logger != nil {
				t.Logger.Error("cannot append a token revocation to the revocation log; it applies anyway", "token", tokenID, "error", err)
			}
		}
		_, err = audit.Append(t.sys, tx, audit.Entry{OrgID: orgID, ActorType: audit.ActorUser, ActorID: userID,
			Action: "token.revoke", TargetType: "api_token", TargetID: tokenID, Result: audit.Success})
		return err
	})
}

// Authenticate finds the live token of a bearer value, with its active owner and the owner's
// current role in the token's org, and records its use at most once a minute.
func (t *Tokens) Authenticate(tok, ip string) (*TokenOwner, error) {
	if k, err := token.Parse(tok); err != nil || k != token.PersonalAPI {
		return nil, ErrToken
	}
	row, err := t.db.ReadClient().APIToken.Query().Where(apitoken.TokenHash(token.Hash(tok))).Only(t.sys)
	if ent.IsNotFound(err) || err == nil && (row.RevokedAt != nil || !row.ExpiresAt.After(t.now())) {
		return nil, ErrToken
	}
	if err != nil {
		return nil, err
	}
	u, err := t.db.ReadClient().User.Query().Where(user.ID(row.OwnerID), user.StatusEQ(user.StatusActive)).Only(t.sys)
	if ent.IsNotFound(err) {
		return nil, ErrToken
	}
	if err != nil {
		return nil, err
	}
	role := ""
	if m, err := t.db.ReadClient().Membership.Query().Where(membership.OrgID(row.OrgID), membership.UserID(u.ID)).Only(t.sys); err == nil {
		role = string(m.Role)
	} else if !ent.IsNotFound(err) {
		return nil, err
	}
	if now := t.now(); row.LastUsedAt == nil || now.Sub(*row.LastUsedAt) >= tokenTouchEvery {
		if err := t.db.Client().APIToken.UpdateOneID(row.ID).SetLastUsedAt(now).SetLastUsedIP(truncateIP(ip)).Exec(t.sys); err != nil {
			return nil, err
		}
	}
	return &TokenOwner{Token: row, User: u, Role: role, InstanceAdmin: u.InstanceAdmin}, nil
}

func truncateIP(ip string) string {
	if len(ip) > 64 {
		return ip[:64]
	}
	return ip
}
