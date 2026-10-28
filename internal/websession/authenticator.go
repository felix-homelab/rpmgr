// SPDX-License-Identifier: Apache-2.0

package websession

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
)

// ErrDisabled is returned for the session of a disabled user.
var ErrDisabled = errors.New("websession: the user is disabled")

// Authenticate finds the caller of an API request from its session cookie: nil without one, the
// user with the roles of their memberships for a live session, and an error for any other cookie
// (api.Authenticator). A recheck (api.Rechecking) leaves the session's idle expiry alone.
func (s *Sessions) Authenticate(ctx context.Context, h http.Header) (*api.Caller, error) {
	c, err := (&http.Request{Header: h}).Cookie(CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	lookup := s.Lookup
	if api.Rechecking(ctx) {
		lookup = s.Check
	}
	sess, err := lookup(c.Value)
	if err != nil {
		return nil, err
	}
	u, err := s.o.DB.ReadClient().User.Query().Where(user.ID(sess.UserID)).Only(s.o.Sys)
	if err != nil {
		return nil, err
	}
	if u.Status != user.StatusActive {
		return nil, ErrDisabled
	}
	ms, err := s.o.DB.ReadClient().Membership.Query().Where(membership.UserID(u.ID)).All(s.o.Sys)
	if err != nil {
		return nil, err
	}
	roles := make(map[string]string, len(ms))
	for _, m := range ms {
		roles[m.OrgID] = string(m.Role)
	}
	caller := &api.Caller{Principal: authz.Principal{UserID: u.ID, Memberships: roles}, CredentialID: sess.ID,
		AuthMethod: "session", InstanceAdmin: u.InstanceAdmin,
		MFA: slices.Contains(sess.Amr, "otp") || slices.Contains(sess.Amr, "recovery")}
	if sess.ElevatedUntil != nil {
		caller.StepUpAt = sess.ElevatedUntil.Add(-api.StepUpWindow)
	}
	return caller, nil
}
