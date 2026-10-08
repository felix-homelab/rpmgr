// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"connectrpc.com/connect"
	"entgo.io/ent/dialect/sql"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/enroll"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/predicate"
)

// Enrollment is EnrollmentService. Its methods run in the org scope the interceptor gives them.
type Enrollment struct {
	rpmgrv1connect.UnimplementedEnrollmentServiceHandler
	DB  *store.DB
	API *api.Server
	Now func() time.Time
	// PublicURL and RootPin go into install commands.
	PublicURL, RootPin string
}

// CreateEnrollmentToken implements EnrollmentService.
func (e *Enrollment) CreateEnrollmentToken(ctx context.Context, req *connect.Request[rpmgrv1.CreateEnrollmentTokenRequest]) (
	*connect.Response[rpmgrv1.CreateEnrollmentTokenResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, e.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateEnrollmentTokenResponse, error) {
		mint := enroll.Mint{Org: m.GetOrgId(), ConnectorID: m.GetConnectorId(), GatewayGroupID: m.GetGatewayGroupId(),
			Labels: m.GetLabels(), Ephemeral: m.GetEphemeral(), TTL: m.GetTtl().AsDuration()}
		if m.MaxUses != nil {
			n := int(m.GetMaxUses())
			mint.MaxUses = &n
		}
		tok, row, err := e.mint(ctx, mint)
		if err != nil {
			return nil, err
		}
		return &rpmgrv1.CreateEnrollmentTokenResponse{Token: tok, EnrollmentToken: enrollmentTokenOf(row)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// CreateGatewayEnrollmentToken implements EnrollmentService.
func (e *Enrollment) CreateGatewayEnrollmentToken(ctx context.Context, req *connect.Request[rpmgrv1.CreateGatewayEnrollmentTokenRequest]) (
	*connect.Response[rpmgrv1.CreateGatewayEnrollmentTokenResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, e.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateGatewayEnrollmentTokenResponse, error) {
		gw, err := e.DB.ReadClient().Gateway.Get(ctx, m.GetGatewayId())
		if err != nil {
			return nil, storeError(err)
		}
		tok, row, err := e.mint(ctx, enroll.Mint{Org: gw.OrgID, GatewayID: gw.ID, TTL: m.GetTtl().AsDuration()})
		if err != nil {
			return nil, err
		}
		return &rpmgrv1.CreateGatewayEnrollmentTokenResponse{Token: tok, EnrollmentToken: enrollmentTokenOf(row)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// mint mints a token for the caller in one write transaction, with the request's audit entry.
func (e *Enrollment) mint(ctx context.Context, m enroll.Mint) (string, *ent.EnrollmentToken, error) {
	m.CreatedBy = api.CallerFrom(ctx).UserID
	var (
		tok string
		row *ent.EnrollmentToken
	)
	err := store.WriteTx(ctx, e.DB, func(tx *ent.Tx) error {
		var err error
		tok, row, err = enroll.MintToken(ctx, tx, m, e.now())
		return err
	})
	switch {
	case errors.Is(err, enroll.ErrTokenTTL), errors.Is(err, enroll.ErrMultiUse), errors.Is(err, enroll.ErrBound),
		errors.Is(err, enroll.ErrDisposable):
		return "", nil, connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, enroll.ErrRetired):
		return "", nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return "", nil, storeError(err)
	}
	return tok, row, nil
}

// ListEnrollmentTokens implements EnrollmentService.
func (e *Enrollment) ListEnrollmentTokens(ctx context.Context, req *connect.Request[rpmgrv1.ListEnrollmentTokensRequest]) (
	*connect.Response[rpmgrv1.ListEnrollmentTokensResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := e.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	q := e.DB.ReadClient().EnrollmentToken.Query().Where(enrollmenttoken.OrgID(m.GetOrgId())).
		Order(ent.Asc(enrollmenttoken.FieldID)).Limit(size + 1)
	if !m.GetShowInactive() {
		// UTC, as the store keeps expires_at: SQLite compares the text.
		q.Where(enrollmenttoken.RevokedAtIsNil(), enrollmenttoken.ExpiresAtGT(e.now().UTC()), usesLeft)
	}
	if after != "" {
		q.Where(enrollmenttoken.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListEnrollmentTokensResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = e.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		out.EnrollmentTokens = append(out.EnrollmentTokens, enrollmentTokenOf(r))
	}
	return connect.NewResponse(out), nil
}

// RevokeEnrollmentToken implements EnrollmentService. A second revocation keeps the first's time.
func (e *Enrollment) RevokeEnrollmentToken(ctx context.Context, req *connect.Request[rpmgrv1.RevokeEnrollmentTokenRequest]) (
	*connect.Response[rpmgrv1.RevokeEnrollmentTokenResponse], error) {
	var row *ent.EnrollmentToken
	err := store.WriteTx(ctx, e.DB, func(tx *ent.Tx) error {
		cur, err := tx.EnrollmentToken.Get(ctx, req.Msg.GetEnrollmentTokenId())
		if err != nil {
			return err
		}
		if cur.Role == enrollmenttoken.RoleGateway && !api.Permits(ctx, cur.OrgID, authz.PermInfrastructureWrite) {
			return connect.NewError(connect.CodePermissionDenied, errors.New("apisvc: a gateway's token needs infrastructure.write"))
		}
		if row = cur; cur.RevokedAt != nil {
			return nil
		}
		row, err = tx.EnrollmentToken.UpdateOne(cur).SetRevokedAt(e.now()).Save(ctx)
		return err
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.RevokeEnrollmentTokenResponse{EnrollmentToken: enrollmentTokenOf(row)}), nil
}

// usesLeft holds a token that may still enroll: unlimited, or used fewer times than allowed.
var usesLeft = predicate.EnrollmentToken(func(s *sql.Selector) {
	s.Where(sql.Or(sql.IsNull(s.C(enrollmenttoken.FieldMaxUses)),
		sql.ColumnsLT(s.C(enrollmenttoken.FieldUseCount), s.C(enrollmenttoken.FieldMaxUses))))
})

// GetInstallCommand implements EnrollmentService. Every value is quoted for the shell, and a
// target that could break out of its quotes is refused.
func (e *Enrollment) GetInstallCommand(_ context.Context, req *connect.Request[rpmgrv1.GetInstallCommandRequest]) (
	*connect.Response[rpmgrv1.GetInstallCommandResponse], error) {
	m := req.Msg
	base := strings.TrimSuffix(e.PublicURL, "/")
	lines := []string{"curl -fsSL " + shellQuote(base+"/install.sh") + " | sudo sh -s --",
		"  --controller " + shellQuote(base) + " --ca-pin " + shellQuote(e.RootPin)}
	if m.GetRole() == rpmgrv1.AgentRole_AGENT_ROLE_GATEWAY {
		if len(m.GetAllowTargets()) > 0 {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: a gateway has no local policy to allow targets in"))
		}
		lines = append(lines, "  --role gateway")
	}
	for _, t := range m.GetAllowTargets() {
		if err := policy.CheckTarget(t); err != nil || strings.ContainsFunc(t, func(r rune) bool { return r == '\'' || unicode.IsControl(r) }) {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: allow target %q: want ip:port, [ipv6]:port or a socket path", t))
		}
		lines = append(lines, "  --allow-target "+shellQuote(t))
	}
	return connect.NewResponse(&rpmgrv1.GetInstallCommandResponse{Command: strings.Join(lines, " \\\n"), ControllerUrl: base,
		CaPin: e.RootPin}), nil
}

// shellQuote quotes s for a POSIX shell: in single quotes, each single quote closed, escaped and
// reopened.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (e *Enrollment) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func enrollmentTokenOf(r *ent.EnrollmentToken) *rpmgrv1.EnrollmentToken {
	out := &rpmgrv1.EnrollmentToken{Id: r.ID, Role: rpmgrv1.AgentRole_AGENT_ROLE_CONNECTOR, Labels: r.Labels, Ephemeral: r.Ephemeral,
		UseCount: int32(r.UseCount), ExpireTime: timestamppb.New(r.ExpiresAt), //nolint:gosec // G115: bounded by max_uses
		CreateTime: timestamppb.New(r.CreatedAt), CreatedBy: r.CreatedBy, LastUseIp: r.LastUsedIP}
	if r.Role == enrollmenttoken.RoleGateway {
		out.Role = rpmgrv1.AgentRole_AGENT_ROLE_GATEWAY
	}
	for dst, src := range map[*string]*string{&out.GatewayGroupId: r.GatewayGroupID, &out.GatewayId: r.GatewayID, &out.ConnectorId: r.ConnectorID} {
		if src != nil {
			*dst = *src
		}
	}
	if r.MaxUses != nil {
		out.MaxUses = int32(*r.MaxUses) //nolint:gosec // G115: at most 100 000
	}
	for dst, src := range map[**timestamppb.Timestamp]*time.Time{&out.LastUseTime: r.LastUsedAt, &out.RevokeTime: r.RevokedAt} {
		if src != nil {
			*dst = timestamppb.New(*src)
		}
	}
	return out
}
