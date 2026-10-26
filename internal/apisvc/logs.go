// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The limits of live logs (docs/03-connections.md, "Timeouts, keepalive and backoff"): streams
// open at once per user and per agent, on this controller replica.
const (
	maxLogsPerUser  = 2
	maxLogsPerAgent = 4
)

// logHeartbeat is how often a stream without lines sends an empty message, so that no proxy on the
// way takes it for idle and closes it.
var logHeartbeat = 15 * time.Second

// logRecheck is how often a stream admits its caller again, so that a member who lost the role,
// or a session or token that was revoked, stops receiving lines (docs/03-connections.md,
// "Timeouts, keepalive and backoff").
var logRecheck = 15 * time.Second

// LogOpener opens live-log operations on agents, normally the controller's Sessions.
type LogOpener interface {
	OpenLogs(ctx context.Context, agentID string, p *agentv1.LogParams) (LogStream, error)
}

// LogStream is an open live-log operation: Recv returns the agent's frames, io.EOF when the agent
// ended it and ErrLogsDeadline when its deadline did; Close ends it.
type LogStream interface {
	Recv() (*agentv1.AttachFrame, error)
	Close(reason string)
}

// ErrLogsUnavailable is an agent that has no control session here, or whose release runs no live
// logs, or that refused the operation.
var ErrLogsUnavailable = errors.New("apisvc: the agent is offline or runs no live logs")

// ErrLogsDeadline is a live log that reached its deadline: the stream ends without an error, and
// the viewer may open a new one.
var ErrLogsDeadline = errors.New("apisvc: the live log reached its deadline")

// Logs implements rpmgrv1connect.LogServiceHandler (docs/07-api.md, "Services").
type Logs struct {
	DB     *store.DB
	Opener LogOpener // nil makes every agent unavailable

	mu      sync.Mutex
	byUser  map[string]int
	byAgent map[string]int
}

// StreamLogs implements LogService: the interceptor admitted the caller with agents.logs in the
// agent's org, so another org's agent was NOT_FOUND already. Each stream counts against the
// caller's and the agent's limits; its opening is audited as agent.logs_open with its level,
// filter and raise; the client's cancel ends the operation on the agent.
func (l *Logs) StreamLogs(ctx context.Context, req *connect.Request[rpmgrv1.StreamLogsRequest],
	st *connect.ServerStream[rpmgrv1.StreamLogsResponse]) error {
	in := req.Msg
	kind := ""
	switch {
	case ids.Valid("con", in.GetAgentId()):
		kind = "connector"
	case ids.Valid("gw", in.GetAgentId()):
		kind = "gateway"
	default:
		return connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: agent_id names a connector or a gateway"))
	}
	org, err := l.orgOf(ctx, kind, in.GetAgentId())
	if err != nil {
		return err
	}
	caller := api.CallerFrom(ctx)
	if !l.reserve(caller.UserID, in.GetAgentId()) {
		return connect.NewError(connect.CodeResourceExhausted, fmt.Errorf(
			"apisvc: at most %d live logs per user and %d per agent are open at once", maxLogsPerUser, maxLogsPerAgent))
	}
	defer l.release(caller.UserID, in.GetAgentId())
	if l.Opener == nil {
		return connect.NewError(connect.CodeUnavailable, ErrLogsUnavailable)
	}
	op, err := l.Opener.OpenLogs(ctx, in.GetAgentId(), &agentv1.LogParams{Level: in.GetLevel(), Filter: in.GetFilter(),
		RaiseToDebug: in.GetRaiseToDebug()})
	switch {
	case errors.Is(err, ErrLogsUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	case err != nil:
		return err
	}
	// Every return ends the operation on the agent, which learns when the viewer left.
	defer func() {
		reason := ""
		if ctx.Err() != nil {
			reason = "the viewer left"
		}
		op.Close(reason)
	}()
	if err := store.WriteTx(ctx, l.DB, func(tx *ent.Tx) error {
		_, err := audit.Append(ctx, tx, audit.Entry{OrgID: org, ActorType: audit.ActorUser, ActorID: caller.UserID, Action: "agent.logs_open",
			TargetType: kind, TargetID: in.GetAgentId(), Result: audit.Success,
			Reason: "level " + strconv.Quote(in.GetLevel()) + ", filter " + strconv.Quote(in.GetFilter()) +
				", raise to debug " + strconv.FormatBool(in.GetRaiseToDebug())})
		return err
	}); err != nil {
		return err
	}
	// The headers go out at once, and an empty message while no line comes.
	if err := st.Send(nil); err != nil {
		return nil // the client went away
	}
	type frame struct {
		f   *agentv1.AttachFrame
		err error
	}
	frames := make(chan frame)
	go func() {
		for {
			f, err := op.Recv()
			select {
			case frames <- frame{f, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	beat := time.NewTicker(logHeartbeat)
	defer beat.Stop()
	check := time.NewTicker(logRecheck)
	defer check.Stop()
	for {
		var fr frame
		select {
		case <-ctx.Done():
			return nil
		case <-check.C:
			if err := api.Recheck(ctx); err != nil {
				return lostAccess(err)
			}
			continue
		case <-beat.C:
			if err := st.Send(&rpmgrv1.StreamLogsResponse{}); err != nil {
				return nil
			}
			continue
		case fr = <-frames:
		}
		switch {
		case errors.Is(fr.err, io.EOF), errors.Is(fr.err, ErrLogsDeadline), ctx.Err() != nil:
			return nil
		case fr.err != nil:
			return connect.NewError(connect.CodeUnavailable, fmt.Errorf("apisvc: the live log ended: %w", fr.err))
		}
		line := fr.f.GetLog()
		if line == nil {
			continue
		}
		if err := st.Send(&rpmgrv1.StreamLogsResponse{Line: &rpmgrv1.LogLine{Time: line.GetTime(), Level: line.GetLevel(),
			Text: line.GetText(), DroppedBefore: line.GetDroppedBefore(), Truncated: line.GetTruncated()}}); err != nil {
			return nil // the client went away
		}
		beat.Reset(logHeartbeat)
	}
}

// lostAccess is the error that ends a stream whose caller no longer passes the check of a new
// request: PERMISSION_DENIED for a caller without the permission, also for a member who left the
// org, whom a new request would tell NOT_FOUND; otherwise the check's own error, such as
// UNAUTHENTICATED for credentials that are no longer valid.
func lostAccess(err error) error {
	switch connect.CodeOf(err) {
	case connect.CodePermissionDenied, connect.CodeNotFound:
		return connect.NewError(connect.CodePermissionDenied, errors.New("apisvc: the caller may no longer read this agent's log"))
	}
	return err
}

// orgOf is the org of the connector or gateway, read in the caller's scope.
func (l *Logs) orgOf(ctx context.Context, kind, id string) (string, error) {
	var org string
	err := store.ReadTx(ctx, l.DB, func(tx *ent.Tx, _ store.Revision) error {
		if kind == "connector" {
			c, err := tx.Connector.Get(ctx, id)
			if err == nil {
				org = c.OrgID
			}
			return err
		}
		g, err := tx.Gateway.Get(ctx, id)
		if err == nil {
			org = g.OrgID
		}
		return err
	})
	if ent.IsNotFound(err) {
		return "", connect.NewError(connect.CodeNotFound, errors.New("apisvc: not found"))
	}
	return org, err
}

// reserve counts a stream against the user's and the agent's limits, if both have room.
func (l *Logs) reserve(user, agent string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byUser == nil {
		l.byUser, l.byAgent = map[string]int{}, map[string]int{}
	}
	if l.byUser[user] >= maxLogsPerUser || l.byAgent[agent] >= maxLogsPerAgent {
		return false
	}
	l.byUser[user]++
	l.byAgent[agent]++
	return true
}

func (l *Logs) release(user, agent string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byUser[user]--; l.byUser[user] <= 0 {
		delete(l.byUser, user)
	}
	if l.byAgent[agent]--; l.byAgent[agent] <= 0 {
		delete(l.byAgent, agent)
	}
}
