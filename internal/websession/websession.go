// SPDX-License-Identifier: Apache-2.0

// Package websession keeps the server-side sessions of signed-in browsers (docs/04-security.md,
// "Human authentication and sessions"): an opaque rpmgr_ses_ token in a __Host- cookie, stored
// only as its hash, with an idle and an absolute timeout. Revoking a session records it in the
// revocation log.
package websession

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/predicate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/session"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// The cookie and the timeouts (docs/04-security.md, "Human authentication and sessions").
const (
	CookieName      = "__Host-rpmgr_session"
	IdleTimeout     = 8 * time.Hour
	AbsoluteTimeout = 7 * 24 * time.Hour
)

// touchEvery is how often a session's last use is written at most, so that busy sessions do not
// write on every request.
const touchEvery = time.Minute

// ErrNoSession is returned for a token that names no live session: unknown, expired or revoked.
var ErrNoSession = errors.New("websession: no such session")

// Options configure Sessions.
type Options struct {
	DB     *store.DB
	Sys    context.Context // the system scope: sessions belong to no org
	RevLog *revlog.Log     // required
	Now    func() time.Time
	Logger *slog.Logger
}

// Sessions are the web sessions of one controller.
type Sessions struct{ o Options }

// New returns Sessions.
func New(o Options) *Sessions {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Sessions{o: o}
}

// Create starts a session for a user who just signed in with the methods in amr, and returns
// its token.
func (s *Sessions) Create(userID string, amr []string, ip, userAgent string) (string, *ent.Session, error) {
	tok, err := token.New(token.Session)
	if err != nil {
		return "", nil, err
	}
	now := s.o.Now()
	sess, err := s.o.DB.Client().Session.Create().SetUserID(userID).SetTokenHash(token.Hash(tok)).SetCreatedAt(now).
		SetLastSeenAt(now).SetIdleExpiresAt(now.Add(IdleTimeout)).SetAbsoluteExpiresAt(now.Add(AbsoluteTimeout)).
		SetAmr(amr).SetIP(truncate(ip, 64)).SetUserAgent(truncate(userAgent, 512)).Save(s.o.Sys)
	if err != nil {
		return "", nil, err
	}
	return tok, sess, nil
}

// Lookup returns the live session of a token and moves its idle expiry on, never past the
// absolute one.
func (s *Sessions) Lookup(tok string) (*ent.Session, error) {
	if k, err := token.Parse(tok); err != nil || k != token.Session {
		return nil, ErrNoSession
	}
	sess, err := s.o.DB.ReadClient().Session.Query().Where(session.TokenHash(token.Hash(tok))).Only(s.o.Sys)
	if ent.IsNotFound(err) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	now := s.o.Now()
	if !live(sess, now) {
		return nil, ErrNoSession
	}
	if now.Sub(sess.LastSeenAt) >= touchEvery {
		idle := now.Add(IdleTimeout)
		if idle.After(sess.AbsoluteExpiresAt) {
			idle = sess.AbsoluteExpiresAt
		}
		if sess, err = s.o.DB.Client().Session.UpdateOneID(sess.ID).SetLastSeenAt(now).SetIdleExpiresAt(idle).Save(s.o.Sys); err != nil {
			return nil, err
		}
	}
	return sess, nil
}

// Elevate records a step-up of a live session, which counts until window from now, adds how the
// user authenticated to the session's methods, and gives the session a new token, which it
// returns (docs/04-security.md: sessions rotate at step-up).
func (s *Sessions) Elevate(id, method string, window time.Duration) (string, *ent.Session, error) {
	tok, err := token.New(token.Session)
	if err != nil {
		return "", nil, err
	}
	now := s.o.Now()
	sess, err := s.o.DB.Client().Session.Get(s.o.Sys, id)
	if err != nil {
		return "", nil, err
	}
	if !live(sess, now) {
		return "", nil, ErrNoSession
	}
	amr := sess.Amr
	if !slices.Contains(amr, method) {
		amr = append(amr, method)
	}
	sess, err = s.o.DB.Client().Session.UpdateOneID(id).SetTokenHash(token.Hash(tok)).SetElevatedUntil(now.Add(window)).
		SetAmr(amr).Save(s.o.Sys)
	if err != nil {
		return "", nil, err
	}
	return tok, sess, nil
}

// List returns a user's live sessions, newest first.
func (s *Sessions) List(userID string) ([]*ent.Session, error) {
	now := s.o.Now()
	return s.o.DB.ReadClient().Session.Query().Where(session.UserID(userID), session.RevokedAtIsNil(),
		session.IdleExpiresAtGT(now), session.AbsoluteExpiresAtGT(now)).Order(ent.Desc(session.FieldCreatedAt), ent.Desc(session.FieldID)).
		All(s.o.Sys)
}

// Revoke ends one session of a user; ErrNoSession if the user has no such live session. actor is
// who revoked it, for the revocation log.
func (s *Sessions) Revoke(userID, id, actor string) error {
	n, err := s.revoke(actor, "revoked", session.UserID(userID), session.ID(id))
	if err == nil && n == 0 {
		return ErrNoSession
	}
	return err
}

// RevokeAll ends every live session of a user except keep, as a password or MFA change does, and
// returns how many it ended.
func (s *Sessions) RevokeAll(userID, keep, actor, reason string) (int, error) {
	return s.revoke(actor, reason, session.UserID(userID), session.IDNEQ(keep))
}

// revoke ends the live sessions that match, appending each to the revocation log in the revoking
// transaction; an append that fails is reported and does not stop the revocation
// (docs/04-security.md, "Revocation log").
func (s *Sessions) revoke(actor, reason string, where ...predicate.Session) (int, error) {
	now := s.o.Now()
	n := 0
	err := store.WriteTx(s.o.Sys, s.o.DB, func(tx *ent.Tx) error {
		ids, err := tx.Session.Query().Where(append(where, session.RevokedAtIsNil(), session.IdleExpiresAtGT(now),
			session.AbsoluteExpiresAtGT(now))...).IDs(s.o.Sys)
		if err != nil || len(ids) == 0 {
			return err
		}
		for _, id := range ids {
			if _, err := s.o.RevLog.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: id, Detail: reason, Actor: actor}); err != nil {
				s.o.Logger.Error("cannot append a session revocation to the revocation log; the session is revoked anyway",
					"session", id, "error", err)
			}
		}
		n, err = tx.Session.Update().Where(session.IDIn(ids...)).SetRevokedAt(now).Save(s.o.Sys)
		return err
	})
	return n, err
}

// live reports whether a session can still be used at now.
func live(sess *ent.Session, now time.Time) bool {
	return sess.RevokedAt == nil && now.Before(sess.IdleExpiresAt) && now.Before(sess.AbsoluteExpiresAt)
}

// Cookie returns the session cookie for a token (docs/04-security.md: Secure, HttpOnly, Path=/,
// no Domain, SameSite=Lax), expiring with the session's absolute timeout.
func Cookie(tok string, sess *ent.Session) *http.Cookie {
	return &http.Cookie{Name: CookieName, Value: tok, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Expires: sess.AbsoluteExpiresAt.UTC()}
}

// ClearCookie returns a cookie that removes the session cookie.
func ClearCookie() *http.Cookie {
	return &http.Cookie{Name: CookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: -1}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
