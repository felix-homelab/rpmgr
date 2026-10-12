// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/websession"
)

// Credentials authenticate API callers (api.Authenticator): an API token as
// "Authorization: Bearer", never anywhere else, or else the session cookie.
type Credentials struct {
	Sessions *websession.Sessions
	Tokens   *accounts.Tokens
}

// Authenticate implements api.Authenticator. A token's caller holds only the owner's current role
// in the token's org, and only the token's scopes of it.
func (c Credentials) Authenticate(ctx context.Context, h http.Header) (*api.Caller, error) {
	v := h.Get("Authorization")
	if v == "" {
		return c.Sessions.Authenticate(ctx, h)
	}
	tok, ok := strings.CutPrefix(v, "Bearer ")
	if !ok {
		return nil, errors.New("apisvc: the Authorization header takes a Bearer token only")
	}
	o, err := c.Tokens.Authenticate(strings.TrimSpace(tok), hostOf(api.PeerAddr(ctx)))
	if err != nil {
		return nil, err
	}
	roles := map[string]string{}
	if o.Role != "" {
		roles[o.Token.OrgID] = o.Role
	}
	return &api.Caller{Principal: authz.Principal{UserID: o.User.ID, Memberships: roles}, CredentialID: o.Token.ID,
		AuthMethod: "token", InstanceAdmin: o.InstanceAdmin, Scopes: o.Token.Scopes, MFA: o.Token.Mfa}, nil
}
