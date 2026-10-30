// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	ealert "github.com/felix-homelab/rpmgr/internal/store/ent/alert"
)

// ListAlerts implements StatusService: an org's alerts by ID, the ones that fire unless the
// request names a state. The org scope shows only the org's own rows.
func (s *Status) ListAlerts(ctx context.Context, req *connect.Request[rpmgrv1.ListAlertsRequest]) (
	*connect.Response[rpmgrv1.ListAlertsResponse], error) {
	m := req.Msg
	alerts, next, err := s.listAlerts(ctx, m, m.GetOrgId(), m.GetState(), m.GetPageSize(), m.GetPageToken())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.ListAlertsResponse{Alerts: alerts, NextPageToken: next}), nil
}

// ListInstanceAlerts implements StatusService: the alerts of no org, for the Instance Admin the
// interceptor admits.
func (s *Status) ListInstanceAlerts(_ context.Context, req *connect.Request[rpmgrv1.ListInstanceAlertsRequest]) (
	*connect.Response[rpmgrv1.ListInstanceAlertsResponse], error) {
	m := req.Msg
	alerts, next, err := s.listAlerts(s.Sys, m, "", m.GetState(), m.GetPageSize(), m.GetPageToken())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.ListInstanceAlertsResponse{Alerts: alerts, NextPageToken: next}), nil
}

// listAlerts returns a page of the alerts of org, or of the instance for "", in state.
func (s *Status) listAlerts(ctx context.Context, req proto.Message, org string, state rpmgrv1.AlertState, pageSize int32, token string) (
	[]*rpmgrv1.Alert, string, error) {
	size, err := api.PageSize(pageSize)
	if err != nil {
		return nil, "", err
	}
	after, err := s.API.AfterPage(token, req)
	if err != nil {
		return nil, "", err
	}
	want := ealert.StateFiring
	switch state {
	case rpmgrv1.AlertState_ALERT_STATE_PENDING:
		want = ealert.StatePending
	case rpmgrv1.AlertState_ALERT_STATE_RESOLVED:
		want = ealert.StateResolved
	}
	q := s.DB.ReadClient().Alert.Query().Where(ealert.StateEQ(want)).Order(ent.Asc(ealert.FieldID)).Limit(size + 1)
	if org == "" {
		q.Where(ealert.OrgIDIsNil())
	} else {
		q.Where(ealert.OrgID(org))
	}
	if after != "" {
		q.Where(ealert.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, "", storeError(err)
	}
	next := ""
	if len(rows) > size {
		rows = rows[:size]
		next = s.API.PageToken(rows[size-1].ID, req)
	}
	out := make([]*rpmgrv1.Alert, 0, len(rows))
	for _, r := range rows {
		a := &rpmgrv1.Alert{Id: r.ID, Kind: r.Kind, SubjectType: r.SubjectType, SubjectId: r.SubjectID,
			SubjectName: r.SubjectName, Since: timestamppb.New(r.Since)}
		switch r.State {
		case ealert.StatePending:
			a.State = rpmgrv1.AlertState_ALERT_STATE_PENDING
		case ealert.StateFiring:
			a.State = rpmgrv1.AlertState_ALERT_STATE_FIRING
		case ealert.StateResolved:
			a.State = rpmgrv1.AlertState_ALERT_STATE_RESOLVED
		}
		if r.FiredAt != nil {
			a.FiredAt = timestamppb.New(*r.FiredAt)
		}
		if r.ResolvedAt != nil {
			a.ResolvedAt = timestamppb.New(*r.ResolvedAt)
		}
		out = append(out, a)
	}
	return out, next, nil
}
