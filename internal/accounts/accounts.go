// SPDX-License-Identifier: Apache-2.0

// Package accounts manages local user accounts (docs/04-security.md, "Human authentication and
// sessions"): one-time links that set a user's password or create the first user, and the check
// of an e-mail address and password at sign-in.
package accounts

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/org"
	"github.com/felix-homelab/rpmgr/internal/store/ent/passwordreset"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// How long a link stays valid (docs/04-security.md, "Human authentication and sessions").
const (
	ResetLinkTTL     = 24 * time.Hour
	FirstUserLinkTTL = 7 * 24 * time.Hour
)

// Errors.
var (
	ErrHasUsers    = errors.New("accounts: the first user exists already")
	ErrNoUser      = errors.New("accounts: no such user")
	ErrLink        = errors.New("accounts: the link is not valid, was used or has expired")
	ErrCredentials = errors.New("accounts: wrong e-mail address or password")
	ErrEmail       = errors.New("accounts: not a valid e-mail address")
	ErrDisplayName = errors.New("accounts: a display name has 1 to 100 characters, none of them control characters")
)

// Accounts manages the users of one database.
type Accounts struct {
	db  *store.DB
	sys context.Context // the system scope: users belong to no org
	now func() time.Time
}

// New returns Accounts; sys carries the system scope, now is time.Now if nil.
func New(db *store.DB, sys context.Context, now func() time.Time) *Accounts {
	if now == nil {
		now = time.Now
	}
	return &Accounts{db: db, sys: sys, now: now}
}

// FirstUserLink creates the one-time link that creates the first user, Owner of the first org
// and Instance Admin, and returns its token; ErrHasUsers once any user exists. by is who asked:
// a user ID, or a local job such as "local-cli".
func (a *Accounts) FirstUserLink(by string) (string, error) {
	return a.link(by, "", FirstUserLinkTTL)
}

// ResetLink creates a one-time link that sets the password of a user and returns its token.
func (a *Accounts) ResetLink(userID, by string) (string, error) {
	return a.link(by, userID, ResetLinkTTL)
}

func (a *Accounts) link(by, userID string, ttl time.Duration) (string, error) {
	tok, err := token.New(token.PasswordReset)
	if err != nil {
		return "", err
	}
	err = store.WriteTx(a.sys, a.db, func(tx *ent.Tx) error {
		action := "user.reset_link"
		if userID == "" {
			action = "user.first_user_link"
			if n, err := tx.User.Query().Count(a.sys); err != nil || n > 0 {
				return errors.Join(err, errIf(n > 0, ErrHasUsers))
			}
		} else if ok, err := tx.User.Query().Where(user.ID(userID)).Exist(a.sys); err != nil || !ok {
			return errors.Join(err, errIf(!ok, ErrNoUser))
		}
		c := tx.PasswordReset.Create().SetTokenHash(token.Hash(tok)).SetCreatedBy(by).SetCreatedAt(a.now()).
			SetExpiresAt(a.now().Add(ttl))
		if userID != "" {
			c.SetUserID(userID)
		}
		r, err := c.Save(a.sys)
		if err != nil {
			return err
		}
		_, err = audit.Append(a.sys, tx, audit.Entry{ActorType: actorType(by), ActorID: by, Action: action,
			TargetType: "user", TargetID: userID, Result: audit.Success, Reason: "link " + r.ID})
		return err
	})
	if err != nil {
		return "", err
	}
	return tok, nil
}

// CompleteReset uses a link: it sets the password of the link's user or, for a first-user link,
// creates the first user with email and displayName, who becomes Owner of the first org (created
// if there is none) and Instance Admin. A link works once, until it expires.
func (a *Accounts) CompleteReset(ctx context.Context, tok, newPassword, email, displayName string) (*ent.User, error) {
	if k, err := token.Parse(tok); err != nil || k != token.PasswordReset {
		return nil, ErrLink
	}
	link, err := a.db.Client().PasswordReset.Query().Where(passwordreset.TokenHash(token.Hash(tok))).Only(a.sys)
	if ent.IsNotFound(err) || err == nil && (link.UsedAt != nil || !link.ExpiresAt.After(a.now())) {
		return nil, ErrLink
	}
	if err != nil {
		return nil, err
	}
	first := link.UserID == nil
	if first {
		if email, err = NormalizeEmail(email); err != nil {
			return nil, err
		}
		if displayName, err = checkDisplayName(displayName); err != nil {
			return nil, err
		}
	}
	params, err := a.params()
	if err != nil {
		return nil, err
	}
	hash, err := password.Hash(ctx, newPassword, params)
	if err != nil {
		return nil, err
	}
	var u *ent.User
	err = store.WriteTx(a.sys, a.db, func(tx *ent.Tx) error {
		now := a.now()
		n, err := tx.PasswordReset.Update().Where(passwordreset.ID(link.ID), passwordreset.UsedAtIsNil(),
			passwordreset.ExpiresAtGT(now)).SetUsedAt(now).Save(a.sys)
		if err != nil || n != 1 {
			return errors.Join(err, errIf(n != 1, ErrLink))
		}
		if !first {
			if u, err = tx.User.UpdateOneID(*link.UserID).SetPasswordHash(hash).Save(a.sys); err != nil {
				return err
			}
			_, err = audit.Append(a.sys, tx, audit.Entry{ActorType: audit.ActorUser, ActorID: u.ID, AuthMethod: "reset-link",
				Action: "user.password_reset", TargetType: "user", TargetID: u.ID, Result: audit.Success, Reason: "link " + link.ID})
			return err
		}
		u, err = a.createFirst(tx, email, displayName, hash, link.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// createFirst creates the first user in tx, with the Owner role of the first org.
func (a *Accounts) createFirst(tx *ent.Tx, email, displayName, hash, linkID string) (*ent.User, error) {
	if n, err := tx.User.Query().Count(a.sys); err != nil || n > 0 {
		return nil, errors.Join(err, errIf(n > 0, ErrHasUsers))
	}
	o, err := tx.Org.Query().Order(ent.Asc(org.FieldID)).First(a.sys)
	if ent.IsNotFound(err) {
		o, err = tx.Org.Create().SetName("Default").SetSlug("default").Save(a.sys)
	}
	if err != nil {
		return nil, err
	}
	u, err := tx.User.Create().SetEmail(email).SetDisplayName(displayName).SetPasswordHash(hash).SetInstanceAdmin(true).
		SetCreatedAt(a.now()).Save(a.sys)
	if err != nil {
		return nil, err
	}
	if err := tx.Membership.Create().SetOrgID(o.ID).SetUserID(u.ID).SetRole(authz.RoleOwner).SetCreatedBy(u.ID).
		SetCreatedAt(a.now()).Exec(a.sys); err != nil {
		return nil, err
	}
	for _, e := range []audit.Entry{
		{Action: "user.create", TargetType: "user", TargetID: u.ID, Reason: "first user, Instance Admin, link " + linkID},
		{OrgID: o.ID, Action: "member.add", TargetType: "user", TargetID: u.ID, Reason: "first user, role owner"},
	} {
		e.ActorType, e.ActorID, e.AuthMethod, e.Result = audit.ActorUser, u.ID, "reset-link", audit.Success
		if _, err := audit.Append(a.sys, tx, e); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// Authenticate checks an e-mail address and password and returns the active user they belong to;
// any mismatch is ErrCredentials. An unknown address costs one hash like a known one. A hash made
// with other parameters than the instance's profile is replaced, and the sign-in recorded.
func (a *Accounts) Authenticate(ctx context.Context, email, pw string) (*ent.User, error) {
	params, err := a.params()
	if err != nil {
		return nil, err
	}
	var u *ent.User
	stored := ""
	if norm, err := NormalizeEmail(email); err == nil {
		u, err = a.db.Client().User.Query().Where(user.Email(norm)).Only(a.sys)
		switch {
		case ent.IsNotFound(err):
			u = nil
		case err != nil:
			return nil, err
		case u.PasswordHash != nil:
			stored = *u.PasswordHash
		}
	}
	ok, rehash, err := password.Verify(ctx, pw, stored, params)
	if err != nil && stored != "" {
		return nil, err
	}
	if !ok || u == nil || u.Status != user.StatusActive {
		return nil, ErrCredentials
	}
	upd := u.Update().SetLastLoginAt(a.now())
	if rehash {
		if h, err := password.Hash(ctx, pw, params); err == nil {
			upd.SetPasswordHash(h)
		}
	}
	return upd.Save(a.sys)
}

// params are the hash parameters of the instance's profile.
func (a *Accounts) params() (password.Params, error) {
	inst, _, err := settings.Instance(a.sys, a.db.Client())
	if err != nil {
		return password.Params{}, err
	}
	return password.ParamsOf(inst.GetPasswordHashProfile()), nil
}

// NormalizeEmail returns an e-mail address in the form it is stored and compared in: trimmed and
// lower-case, with one @ between a local part and a domain, at most 254 bytes, without spaces or
// control characters.
func NormalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") || len(s) > 254 || !utf8.ValidString(s) ||
		strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", ErrEmail
	}
	return s, nil
}

func checkDisplayName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if n := utf8.RuneCountInString(s); n < 1 || n > 100 || !utf8.ValidString(s) || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", ErrDisplayName
	}
	return s, nil
}

func actorType(by string) audit.ActorType {
	if strings.HasPrefix(by, "usr_") {
		return audit.ActorUser
	}
	return audit.ActorSystem
}

func errIf(cond bool, err error) error {
	if cond {
		return err
	}
	return nil
}

// LinkURL is the address of a link's page in the web UI: the token goes in the fragment, which
// browsers never send to a server, so it stays out of access logs and Referer headers.
func LinkURL(publicURL, tok string) string {
	return strings.TrimSuffix(publicURL, "/") + "/reset#" + tok
}
