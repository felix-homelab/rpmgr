// SPDX-License-Identifier: Apache-2.0

// Package enroll enrolls agents (docs/03-connections.md, "Enrollment"; docs/04-security.md,
// "Tokens" and "Flow").
package enroll

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// RetryWindow is how long a retry with the same token and key gets the certificate issued the
// first time, so a lost response does not burn a single-use token (docs/04-security.md, "Tokens").
const RetryWindow = 10 * time.Minute

// ErrInvalidToken is returned for every token that cannot be redeemed: malformed, unknown,
// expired, revoked or used up. The cases are deliberately not told apart.
var ErrInvalidToken = errors.New("enroll: the token is invalid, expired, revoked or used up")

// Grant is what a consumed token allows.
type Grant struct {
	TokenID        string
	OrgID          string
	Role           string // connector or gateway
	GatewayGroupID string
	GatewayID      string // gateway tokens: the gateway the Admin created
	ConnectorID    string // re-enrollment tokens: the connector being replaced
	Ephemeral      bool
}

// Issue assigns the identity of a grant and issues and records its certificate with
// pki.CA.IssueEnrolled, in tx, the transaction that consumed the token.
type Issue func(ctx context.Context, tx *ent.Tx, g Grant) (*x509.Certificate, error)

// Redeem redeems an enrollment token for csr in one transaction that needs the system scope:
//  1. a certificate the token already issued for the same key within RetryWindow is returned as it
//     is, and nothing is consumed (retry is true);
//  2. otherwise the token is consumed with one atomic statement, so concurrent uses have one
//     winner;
//  3. then issue runs; if it fails, the consumption is rolled back, so a malformed CSR does not
//     burn the token.
func Redeem(ctx context.Context, db *store.DB, tok string, csr *x509.CertificateRequest, ip string,
	now time.Time, issue Issue) (cert *x509.Certificate, g Grant, retry bool, err error) {
	if k, err := token.Parse(tok); err != nil || k != token.Enrollment {
		return nil, Grant{}, false, ErrInvalidToken
	}
	if csr == nil || csr.CheckSignature() != nil {
		return nil, Grant{}, false, pki.ErrBadCSR
	}
	hash, key := token.Hash(tok), pki.PublicKeyHash(csr.RawSubjectPublicKeyInfo)
	now = now.UTC()
	err = store.WriteTx(ctx, db, func(tx *ent.Tx) error {
		if cert, g, err = earlier(ctx, tx, hash, key, now); err != nil || cert != nil {
			retry = cert != nil
			return err
		}
		if g, err = consume(ctx, tx, hash, ip, now); err != nil {
			return err
		}
		cert, err = issue(ctx, tx, g)
		return err
	})
	if err != nil {
		return nil, Grant{}, false, err
	}
	return cert, g, retry, nil
}

// earlier returns the certificate the token issued for key within RetryWindow, if any.
func earlier(ctx context.Context, tx *ent.Tx, hash []byte, key string, now time.Time) (*x509.Certificate, Grant, error) {
	t, err := tx.EnrollmentToken.Query().Where(enrollmenttoken.TokenHash(hash), enrollmenttoken.RevokedAtIsNil()).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, Grant{}, nil
	}
	if err != nil {
		return nil, Grant{}, err
	}
	issued, err := tx.IssuedCertificate.Query().
		Where(issuedcertificate.EnrollmentTokenID(t.ID), issuedcertificate.PubkeySha256(key)).All(ctx)
	if err != nil {
		return nil, Grant{}, err
	}
	for _, ic := range issued {
		if now.Sub(ic.NotBefore.Add(pki.Backdate)) > RetryWindow || len(ic.Certificate) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(ic.Certificate)
		if err != nil {
			return nil, Grant{}, fmt.Errorf("enroll: stored certificate %s: %w", ic.ID, err)
		}
		return cert, grantOf(t.ID, t.OrgID, string(t.Role), t.GatewayGroupID, t.GatewayID, t.ConnectorID, t.Ephemeral), nil
	}
	return nil, Grant{}, nil
}

// consume is the statement of docs/04-security.md, "Tokens".
func consume(ctx context.Context, tx *ent.Tx, hash []byte, ip string, now time.Time) (Grant, error) {
	rows, err := tx.QueryContext(ctx, `UPDATE enrollment_tokens
		SET use_count = use_count + 1, last_used_at = $1, last_used_ip = $2
		WHERE token_hash = $3 AND revoked_at IS NULL AND expires_at > $1
		  AND (max_uses IS NULL OR use_count < max_uses)
		RETURNING id, org_id, role, gateway_group_id, gateway_id, connector_id, ephemeral`, now, ip, hash)
	if err != nil {
		return Grant{}, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Grant{}, err
		}
		return Grant{}, ErrInvalidToken
	}
	var id, org, role string
	var group, gw, con *string
	var eph bool
	if err := rows.Scan(&id, &org, &role, &group, &gw, &con, &eph); err != nil {
		return Grant{}, err
	}
	return grantOf(id, org, role, group, gw, con, eph), rows.Close()
}

func grantOf(id, org, role string, group, gw, con *string, eph bool) Grant {
	deref := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	return Grant{TokenID: id, OrgID: org, Role: role, GatewayGroupID: deref(group), GatewayID: deref(gw),
		ConnectorID: deref(con), Ephemeral: eph}
}
