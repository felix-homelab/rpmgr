// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"slices"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentstate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/schema"
)

// How long WatchApplyStatus streams, and how often it looks again.
const (
	WatchApplyFor   = 60 * time.Second
	watchApplyEvery = 500 * time.Millisecond
)

// Status is StatusService. Its methods run in the org scope the interceptor gives them.
type Status struct {
	rpmgrv1connect.UnimplementedStatusServiceHandler
	DB *store.DB
	// Sys is the controller's system scope: the revisions WatchEvents reads are instance rows.
	Sys context.Context
	Now func() time.Time
	// Every is how often the streams look again; 0 is 500 ms for WatchApplyStatus and 1 s for
	// WatchEvents.
	Every time.Duration
}

// GetApplyStatus implements StatusService.
func (s *Status) GetApplyStatus(ctx context.Context, req *connect.Request[rpmgrv1.GetApplyStatusRequest]) (
	*connect.Response[rpmgrv1.GetApplyStatusResponse], error) {
	st, err := ApplyStatusOf(ctx, s.DB.ReadClient(), req.Msg.GetOrgId(), revisionFrom(req.Msg.GetRevision()), s.now())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetApplyStatusResponse{ApplyStatus: st}), nil
}

// WatchApplyStatus implements StatusService: it sends the status at once and after every change,
// and ends once the state is final or WatchApplyFor has passed.
func (s *Status) WatchApplyStatus(ctx context.Context, req *connect.Request[rpmgrv1.WatchApplyStatusRequest],
	stream *connect.ServerStream[rpmgrv1.WatchApplyStatusResponse]) error {
	every := s.Every
	if every == 0 {
		every = watchApplyEvery
	}
	ctx, cancel := context.WithTimeout(ctx, WatchApplyFor)
	defer cancel()
	rev := revisionFrom(req.Msg.GetRevision())
	var last *rpmgrv1.ApplyStatus
	for {
		st, err := ApplyStatusOf(ctx, s.DB.ReadClient(), req.Msg.GetOrgId(), rev, s.now())
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return storeError(err)
		}
		if !proto.Equal(st, last) {
			if err := stream.Send(&rpmgrv1.WatchApplyStatusResponse{ApplyStatus: st}); err != nil {
				return err
			}
			last = st
		}
		if st.GetState() != rpmgrv1.ApplyState_APPLY_STATE_PENDING {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(every):
		}
	}
}

func (s *Status) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// revisionFrom is a revision of the API in the store's terms.
func revisionFrom(r *rpmgrv1.Revision) store.Revision {
	return store.Revision{DBEpoch: r.GetDbEpoch(), Seq: r.GetSeq()}
}

// ApplyStatusOf derives how far the agents of org are with rev at now (docs/07-api.md, "Writes and
// apply status"): over the agents with a live control session, as an offline agent gets the
// revision when it connects.
func ApplyStatusOf(ctx context.Context, c *ent.Client, org string, rev store.Revision, now time.Time) (*rpmgrv1.ApplyStatus, error) {
	gws, err := c.Gateway.Query().Where(gateway.OrgID(org), gateway.DecommissionedAtIsNil()).IDs(ctx)
	if err != nil {
		return nil, err
	}
	cons, err := c.Connector.Query().Where(connector.OrgID(org), connector.DecommissionedAtIsNil()).IDs(ctx)
	if err != nil {
		return nil, err
	}
	ids := append(gws, cons...)
	slices.Sort(ids)
	sessions, err := c.AgentSession.Query().Where(agentsession.IDIn(ids...)).All(ctx)
	if err != nil {
		return nil, err
	}
	states, err := c.AgentState.Query().Where(agentstate.IDIn(ids...)).All(ctx)
	if err != nil {
		return nil, err
	}
	bySession, byState := map[string]*ent.AgentSession{}, map[string]*ent.AgentState{}
	for _, x := range sessions {
		bySession[x.ID] = x
	}
	for _, x := range states {
		byState[x.ID] = x
	}
	out := &rpmgrv1.ApplyStatus{}
	var rejected, timedOut bool
	for _, id := range ids {
		sess := bySession[id]
		if sess == nil || !schema.AgentSessionLive(sess.DisconnectedAt, sess.LastSeenAt, now) {
			off := &rpmgrv1.OfflineAgent{AgentId: id}
			if sess != nil {
				off.LastSeenTime = timestamppb.New(sess.LastSeenAt)
			}
			out.Offline = append(out.Offline, off)
			continue
		}
		out.AgentsTotal++
		st := byState[id]
		a := &rpmgrv1.AgentApplyStatus{AgentId: id}
		switch snapshot.RevisionStatus(st, rev, now) {
		case snapshot.ApplyApplied:
			out.AgentsApplied++
			continue
		case snapshot.ApplyRejected:
			rejected, a.State = true, rpmgrv1.ApplyState_APPLY_STATE_REJECTED
			for _, r := range st.LastRejection {
				a.Errors = append(a.Errors, &rpmgrv1.ApplyError{ResourceId: r["resource_id"], Message: r["message"]})
			}
		case snapshot.ApplyTimedOut:
			timedOut, a.State = true, rpmgrv1.ApplyState_APPLY_STATE_APPLY_TIMEOUT
		default:
			a.State = rpmgrv1.ApplyState_APPLY_STATE_PENDING
		}
		out.Agents = append(out.Agents, a)
	}
	switch {
	case rejected:
		out.State = rpmgrv1.ApplyState_APPLY_STATE_REJECTED
	case timedOut:
		out.State = rpmgrv1.ApplyState_APPLY_STATE_APPLY_TIMEOUT
	case out.AgentsApplied == out.AgentsTotal:
		out.State = rpmgrv1.ApplyState_APPLY_STATE_APPLIED
	default:
		out.State = rpmgrv1.ApplyState_APPLY_STATE_PENDING
	}
	return out, nil
}
