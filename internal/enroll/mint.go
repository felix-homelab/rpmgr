// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"context"
	"errors"
	"time"

	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// The lifetimes of an enrollment token (docs/04-security.md, "Tokens").
const (
	DefaultTokenTTL = time.Hour
	MaxTokenTTL     = 30 * 24 * time.Hour
)

// Why a token cannot be minted.
var (
	ErrTokenTTL   = errors.New("enroll: a token lasts at most 30 days")
	ErrMultiUse   = errors.New("enroll: only an ephemeral connector token with a set lifetime may enroll more than one connector")
	ErrBound      = errors.New("enroll: a token bound to a gateway or a connector is single-use, not ephemeral and has no labels")
	ErrRetired    = errors.New("enroll: the gateway or connector is decommissioned")
	ErrDisposable = errors.New("enroll: an ephemeral connector is not re-enrolled; enroll a new one")
)

// Mint is the scope of a new token. The store's tenancy rules check that the org's gateway
// group, gateway or connector it names exists.
type Mint struct {
	Org       string
	CreatedBy string // the user's ID
	// GatewayID makes a gateway token for that gateway (R15); ConnectorID a re-enrollment token
	// for that connector. Neither is a connector token.
	GatewayID, ConnectorID string
	GatewayGroupID         string // a connector token's scope, if any
	Labels                 map[string]string
	Ephemeral              bool
	// MaxUses nil is one use; 0 is unlimited.
	MaxUses *int
	// TTL 0 is DefaultTokenTTL.
	TTL time.Duration
}

// MintToken creates a token in tx and returns it, shown once, with its row.
func MintToken(ctx context.Context, tx *ent.Tx, m Mint, now time.Time) (string, *ent.EnrollmentToken, error) {
	ttl := m.TTL
	switch {
	case ttl == 0:
		ttl = DefaultTokenTTL
	case ttl < 0 || ttl > MaxTokenTTL:
		return "", nil, ErrTokenTTL
	}
	bound := m.GatewayID != "" || m.ConnectorID != ""
	switch {
	case bound && (m.Ephemeral || len(m.Labels) > 0 || m.MaxUses != nil && *m.MaxUses != 1 || m.GatewayGroupID != ""):
		return "", nil, ErrBound
	case m.MaxUses != nil && *m.MaxUses != 1 && (!m.Ephemeral || m.TTL == 0):
		return "", nil, ErrMultiUse
	}
	c := tx.EnrollmentToken.Create().SetOrgID(m.Org).SetRole(enrollmenttoken.RoleConnector).SetEphemeral(m.Ephemeral).
		SetExpiresAt(now.Add(ttl)).SetCreatedBy(m.CreatedBy).SetCreatedAt(now)
	switch {
	case m.GatewayID != "":
		gw, err := tx.Gateway.Get(ctx, m.GatewayID)
		if err != nil {
			return "", nil, err
		}
		if gw.DecommissionedAt != nil {
			return "", nil, ErrRetired
		}
		c.SetRole(enrollmenttoken.RoleGateway).SetGatewayID(gw.ID).SetGatewayGroupID(gw.GatewayGroupID)
	case m.ConnectorID != "":
		con, err := tx.Connector.Get(ctx, m.ConnectorID)
		if err != nil {
			return "", nil, err
		}
		if con.DecommissionedAt != nil {
			return "", nil, ErrRetired
		}
		// It is purged soon after its last disconnect, which a token bound to it would block.
		if con.Ephemeral {
			return "", nil, ErrDisposable
		}
		c.SetConnectorID(con.ID)
	default:
		if m.GatewayGroupID != "" {
			if _, err := tx.GatewayGroup.Get(ctx, m.GatewayGroupID); err != nil {
				return "", nil, err
			}
			c.SetGatewayGroupID(m.GatewayGroupID)
		}
		if len(m.Labels) > 0 {
			c.SetLabels(m.Labels)
		}
	}
	if m.MaxUses != nil {
		c.SetMaxUses(*m.MaxUses) // 0 is unlimited, which the store keeps as null; unset is 1
	}
	tok, err := token.New(token.Enrollment)
	if err != nil {
		return "", nil, err
	}
	row, err := c.SetTokenHash(token.Hash(tok)).Save(ctx)
	if err != nil {
		return "", nil, err
	}
	return tok, row, nil
}
