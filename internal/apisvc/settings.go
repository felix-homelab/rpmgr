// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"slices"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// Settings is SettingsService. The instance settings are instance rows, which its methods read and
// write in the controller's system scope; the org settings in the org scope the interceptor gives.
type Settings struct {
	rpmgrv1connect.UnimplementedSettingsServiceHandler
	DB     *store.DB
	Sys    context.Context
	Sealer *secret.Sealer
	Now    func() time.Time
}

// GetInstanceSettings implements SettingsService.
func (s *Settings) GetInstanceSettings(ctx context.Context, _ *connect.Request[rpmgrv1.GetInstanceSettingsRequest]) (
	*connect.Response[rpmgrv1.GetInstanceSettingsResponse], error) {
	sys := store.CarryTxHook(s.Sys, ctx)
	inst, version, err := settings.Instance(sys, s.DB.ReadClient())
	if err != nil {
		return nil, storeError(err)
	}
	pw, err := settings.InstanceSecret(sys, s.DB.ReadClient(), s.Sealer, settings.SMTPPassword)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.GetInstanceSettingsResponse{Settings: inst, Etag: etagOf(version), SmtpPasswordSet: !pw.IsZero()}), nil
}

// UpdateInstanceSettings implements SettingsService. The revision belongs to no org: the settings
// are the instance's.
func (s *Settings) UpdateInstanceSettings(ctx context.Context, req *connect.Request[rpmgrv1.UpdateInstanceSettingsRequest]) (
	*connect.Response[rpmgrv1.UpdateInstanceSettingsResponse], error) {
	m := req.Msg
	sys := store.CarryTxHook(s.Sys, ctx)
	cur, version, err := settings.Instance(sys, s.DB.ReadClient())
	if err != nil {
		return nil, storeError(err)
	}
	if err := api.CheckEtag(m.GetEtag(), version, cur); err != nil {
		return nil, err
	}
	rev, err := settings.UpdateInstance(sys, s.DB, m.GetSettings(), m.GetUpdateMask(), checked(m.GetEtag(), version))
	if err != nil {
		return nil, settingsError(err)
	}
	inst, version, err := settings.Instance(sys, s.DB.ReadClient())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateInstanceSettingsResponse{Settings: inst, Etag: etagOf(version), Revision: revisionOf(rev)}), nil
}

// SetSmtpPassword implements SettingsService.
func (s *Settings) SetSmtpPassword(ctx context.Context, req *connect.Request[rpmgrv1.SetSmtpPasswordRequest]) (
	*connect.Response[rpmgrv1.SetSmtpPasswordResponse], error) {
	pw := secret.FromBytes([]byte(req.Msg.GetPassword()))
	if req.Msg.GetPassword() == "" {
		pw = secret.Value{}
	}
	if err := settings.SetInstanceSecret(store.CarryTxHook(s.Sys, ctx), s.DB, s.Sealer, settings.SMTPPassword, pw); err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.SetSmtpPasswordResponse{}), nil
}

// GetOrgSettings implements SettingsService.
func (s *Settings) GetOrgSettings(ctx context.Context, req *connect.Request[rpmgrv1.GetOrgSettingsRequest]) (
	*connect.Response[rpmgrv1.GetOrgSettingsResponse], error) {
	org, version, err := settings.Org(ctx, s.DB.ReadClient(), req.Msg.GetOrgId())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetOrgSettingsResponse{Settings: org, Etag: etagOf(version)}), nil
}

// UpdateOrgSettings implements SettingsService. Turning the MFA requirement on or off is an MFA
// change, which needs a step-up (docs/04-security.md, "Human authentication and sessions"); a
// default gateway group must be one of the org's.
func (s *Settings) UpdateOrgSettings(ctx context.Context, req *connect.Request[rpmgrv1.UpdateOrgSettingsRequest]) (
	*connect.Response[rpmgrv1.UpdateOrgSettingsResponse], error) {
	m := req.Msg
	c := s.DB.ReadClient()
	cur, version, err := settings.Org(ctx, c, m.GetOrgId())
	if err != nil {
		return nil, storeError(err)
	}
	if err := api.CheckEtag(m.GetEtag(), version, cur); err != nil {
		return nil, err
	}
	paths := m.GetUpdateMask().GetPaths()
	if slices.Contains(paths, "require_mfa") && m.GetSettings().GetRequireMfa() != cur.GetRequireMfa() {
		if err := api.RequireStepUp(ctx, s.now()); err != nil {
			return nil, err
		}
	}
	if id := m.GetSettings().GetDefaultGatewayGroupId(); id != "" && slices.Contains(paths, "default_gateway_group_id") {
		if _, err := c.GatewayGroup.Get(ctx, id); err != nil {
			return nil, storeError(err)
		}
	}
	rev, err := settings.UpdateOrg(ctx, s.DB, m.GetOrgId(), m.GetSettings(), m.GetUpdateMask(), checked(m.GetEtag(), version))
	if err != nil {
		return nil, settingsError(err)
	}
	org, version, err := settings.Org(ctx, s.DB.ReadClient(), m.GetOrgId())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateOrgSettingsResponse{Settings: org, Etag: etagOf(version), Revision: revisionOf(rev)}), nil
}

func (s *Settings) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// checked is the version an update checks the stored settings against: the one read, if the
// caller sent an etag, so a change since the read is refused; 0 skips the check.
func checked(etag string, version int64) int64 {
	if etag == "" {
		return 0
	}
	return version
}

// settingsError gives the settings package's errors their API codes.
func settingsError(err error) error {
	switch {
	case errors.Is(err, settings.ErrEtagMismatch):
		return withReason(connect.NewError(connect.CodeFailedPrecondition, err), api.ReasonEtagMismatch)
	case errors.Is(err, settings.ErrInvalid):
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return storeError(err)
}
