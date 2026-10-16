// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/recoverycode"
	"github.com/felix-homelab/rpmgr/internal/store/ent/totpcredential"
	"github.com/felix-homelab/rpmgr/internal/totp"
)

// RecoveryCodes is how many recovery codes a user gets.
const RecoveryCodes = 10

// Errors of the second factor.
var (
	ErrMFAEnrolled  = errors.New("accounts: an authenticator is set up already; remove it first")
	ErrNoMFA        = errors.New("accounts: no authenticator is set up")
	ErrSecondFactor = errors.New("accounts: the code is not valid or was used")
)

// MFA manages the credentials of users beyond their first password: an authenticator app (TOTP),
// recovery codes and password changes (docs/04-security.md, "Human authentication and sessions").
// Every change is a credential supersession in the revocation log.
type MFA struct {
	*Accounts
	Sealer *secret.Sealer
	RevLog *revlog.Log
	Logger *slog.Logger
}

// For returns a copy of m whose writes carry the API request ctx, as Accounts.For.
func (m *MFA) For(ctx context.Context) *MFA {
	c := *m
	c.Accounts = m.Accounts.For(ctx)
	return &c
}

// HasMFA reports whether a user has a confirmed authenticator.
func (m *MFA) HasMFA(userID string) (bool, error) {
	return m.db.ReadClient().TOTPCredential.Query().Where(totpcredential.UserID(userID), totpcredential.ConfirmedAtNotNil()).
		Exist(m.sys)
}

// EnrollTOTP creates an authenticator secret for a user, replacing one not confirmed yet, and
// returns it with its otpauth URI; the secret counts once ConfirmTOTP accepted a code of it.
func (m *MFA) EnrollTOTP(userID, issuer string) ([]byte, string, error) {
	u, _, err := m.User(userID)
	if err != nil {
		return nil, "", err
	}
	seed, err := totp.NewSecret()
	if err != nil {
		return nil, "", err
	}
	err = store.WriteTx(m.sys, m.db, func(tx *ent.Tx) error {
		old, err := tx.TOTPCredential.Query().Where(totpcredential.UserID(userID)).Only(m.sys)
		switch {
		case ent.IsNotFound(err):
		case err != nil:
			return err
		case old.ConfirmedAt != nil:
			return ErrMFAEnrolled
		default:
			if err := tx.TOTPCredential.DeleteOne(old).Exec(m.sys); err != nil {
				return err
			}
		}
		id := ids.New("tot") // the seed is sealed for its row, recorded for `rpmgr kek status`
		sealed, err := store.Seal(m.sys, tx, m.Sealer, seedContext(id), secret.FromBytes(seed))
		if err != nil {
			return err
		}
		return tx.TOTPCredential.Create().SetID(id).SetUserID(userID).SetSeedEnc(sealed).SetCreatedAt(m.now()).Exec(m.sys)
	})
	if err != nil {
		return nil, "", err
	}
	return seed, totp.URI(seed, issuer, u.Email), nil
}

// ConfirmTOTP accepts the first code of a new authenticator, which then counts, and returns the
// user's new recovery codes, shown once.
func (m *MFA) ConfirmTOTP(userID, code string) ([]string, error) {
	cred, err := m.db.Client().TOTPCredential.Query().Where(totpcredential.UserID(userID)).Only(m.sys)
	if ent.IsNotFound(err) {
		return nil, ErrNoMFA
	}
	if err != nil {
		return nil, err
	}
	if cred.ConfirmedAt != nil {
		return nil, ErrMFAEnrolled
	}
	seed, err := m.seed(cred)
	if err != nil {
		return nil, err
	}
	step, ok := totp.Verify(seed, code, m.now(), cred.LastStep)
	if !ok {
		return nil, ErrSecondFactor
	}
	var codes []string
	err = store.WriteTx(m.sys, m.db, func(tx *ent.Tx) error {
		if err := tx.TOTPCredential.UpdateOne(cred).SetConfirmedAt(m.now()).SetLastStep(step).Exec(m.sys); err != nil {
			return err
		}
		if codes, err = m.newRecoveryCodes(tx, userID); err != nil {
			return err
		}
		return m.superseded(tx, userID, userID, "user.mfa_enroll", revlog.MFA, "authenticator set up")
	})
	return codes, err
}

// RemoveTOTP removes a user's authenticator and recovery codes and, in the same transaction, ends
// the sessions endSessions ends; actor is the user, or the admin who recovers their account, for
// whom orgs, the user's, get an entry in their audit logs too.
func (m *MFA) RemoveTOTP(userID, actor string, endSessions func(tx *ent.Tx) (int, error), orgs ...string) error {
	return store.WriteTx(m.sys, m.db, func(tx *ent.Tx) error {
		n, err := tx.TOTPCredential.Delete().Where(totpcredential.UserID(userID)).Exec(m.sys)
		if err != nil || n == 0 {
			return errors.Join(err, errIf(n == 0, ErrNoMFA))
		}
		if _, err := tx.RecoveryCode.Delete().Where(recoverycode.UserID(userID)).Exec(m.sys); err != nil {
			return err
		}
		ended := 0
		if endSessions != nil {
			if ended, err = endSessions(tx); err != nil {
				return err
			}
		}
		reason := fmt.Sprintf("authenticator removed; %d sessions ended", ended)
		if actor != userID {
			reason = fmt.Sprintf("authenticator removed by an admin; %d sessions ended", ended)
			if err := recoveryAudit(m.sys, tx, orgs, actor, "member.mfa_remove", userID, reason); err != nil {
				return err
			}
		}
		return m.superseded(tx, userID, actor, "user.mfa_remove", revlog.MFA, reason)
	})
}

// RegenerateRecoveryCodes replaces a user's recovery codes and returns the new ones, shown once.
// endSessions ends the user's other sessions in the same transaction (docs/04-security.md:
// replacing the codes ends them) and returns how many it ended, which the audit entry names; an
// error rolls the change back. nil ends none.
func (m *MFA) RegenerateRecoveryCodes(userID string, endSessions func(tx *ent.Tx) (int, error)) ([]string, error) {
	if ok, err := m.HasMFA(userID); err != nil || !ok {
		return nil, errors.Join(err, errIf(!ok, ErrNoMFA))
	}
	var codes []string
	err := store.WriteTx(m.sys, m.db, func(tx *ent.Tx) error {
		var err error
		if codes, err = m.newRecoveryCodes(tx, userID); err != nil {
			return err
		}
		ended := 0
		if endSessions != nil {
			if ended, err = endSessions(tx); err != nil {
				return err
			}
		}
		return m.superseded(tx, userID, userID, "user.recovery_codes", revlog.RecoveryCodes,
			fmt.Sprintf("recovery codes replaced; %d other sessions ended", ended))
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// VerifySecondFactor checks a code of the user's authenticator, or one of their recovery codes,
// and uses it up: an authenticator code works once, and no older one works after it; a recovery
// code works once. It returns "otp" or "recovery".
func (m *MFA) VerifySecondFactor(userID, code string) (string, error) {
	code = strings.TrimSpace(code)
	if len(code) == totp.Digits {
		cred, err := m.db.Client().TOTPCredential.Query().Where(totpcredential.UserID(userID),
			totpcredential.ConfirmedAtNotNil()).Only(m.sys)
		if ent.IsNotFound(err) {
			return "", ErrSecondFactor
		}
		if err != nil {
			return "", err
		}
		seed, err := m.seed(cred)
		if err != nil {
			return "", err
		}
		step, ok := totp.Verify(seed, code, m.now(), cred.LastStep)
		if !ok {
			return "", ErrSecondFactor
		}
		// Only one request can move last_step past a step, so a code raced twice works once.
		n, err := m.db.Client().TOTPCredential.Update().Where(totpcredential.ID(cred.ID), totpcredential.LastStepLT(step)).
			SetLastStep(step).Save(m.sys)
		if err != nil || n != 1 {
			return "", errors.Join(err, errIf(n != 1, ErrSecondFactor))
		}
		return "otp", nil
	}
	n, err := m.db.Client().RecoveryCode.Update().Where(recoverycode.UserID(userID), recoverycode.CodeHash(recoveryHash(code)),
		recoverycode.UsedAtIsNil()).SetUsedAt(m.now()).Save(m.sys)
	if err != nil || n != 1 {
		return "", errors.Join(err, errIf(n != 1, ErrSecondFactor))
	}
	return "recovery", nil
}

func (m *MFA) seed(cred *ent.TOTPCredential) ([]byte, error) {
	v, err := m.Sealer.Open(seedContext(cred.ID), cred.SeedEnc)
	if err != nil {
		return nil, err
	}
	return []byte(v.Reveal()), nil
}

// newRecoveryCodes replaces a user's recovery codes in tx: 10 codes of 80 random bits each, in
// base32 groups of four, stored as SHA-256 hashes.
func (m *MFA) newRecoveryCodes(tx *ent.Tx, userID string) ([]string, error) {
	if _, err := tx.RecoveryCode.Delete().Where(recoverycode.UserID(userID)).Exec(m.sys); err != nil {
		return nil, err
	}
	codes := make([]string, RecoveryCodes)
	for i := range codes {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		s := strings.ToLower(base32.StdEncoding.EncodeToString(b))
		codes[i] = s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
		if err := tx.RecoveryCode.Create().SetUserID(userID).SetCodeHash(recoveryHash(codes[i])).SetCreatedAt(m.now()).
			Exec(m.sys); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// superseded records a change of a user's credentials by actor in the audit log and, as what, in
// the revocation log.
func (m *MFA) superseded(tx *ent.Tx, userID, actor, action, what, reason string) error {
	logSuperseded(m.RevLog, m.Logger, userID, what, actor)
	_, err := audit.Append(m.sys, tx, audit.Entry{ActorType: audit.ActorUser, ActorID: actor, Action: action,
		TargetType: "user", TargetID: userID, Result: audit.Success, Reason: reason})
	return err
}

// recoveryHash is how a recovery code is stored and looked up: case and dashes do not matter.
func recoveryHash(code string) []byte {
	h := sha256.Sum256([]byte(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(code)), "-", "")))
	return h[:]
}

func seedContext(id string) secret.Context {
	return secret.Context{Table: "totp_credentials", Column: "seed_enc", RowID: id}
}
