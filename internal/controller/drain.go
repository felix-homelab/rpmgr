// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
)

// recordDraining keeps the old process an agent reports, or forgets it when the agent says it is
// gone. The state lives in this replica's memory with the agent's session, like an operation's
// (docs/03-connections.md, "Showing and ending the drain").
func (s *Sessions) recordDraining(agentID string, d *agentv1.DrainingProcess) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[agentID] == nil {
		return
	}
	if !d.GetActive() {
		delete(s.drains, agentID)
		return
	}
	if s.drains == nil {
		s.drains = map[string]*agentv1.DrainingProcess{}
	}
	s.drains[agentID] = d
}

// Draining implements apisvc.Drains: the old process the agent's new process reported, nil for
// none, or for an agent without a control session with this replica.
func (s *Sessions) Draining(agentID string) *rpmgrv1.DrainingProcess {
	s.mu.Lock()
	d := s.drains[agentID]
	s.mu.Unlock()
	if d == nil {
		return nil
	}
	return &rpmgrv1.DrainingProcess{Connections: d.GetConnections(), Flows: d.GetFlows(), Sessions: d.GetSessions(),
		Since: timestamppb.New(d.GetSince().AsTime()), Ends: timestamppb.New(d.GetEnds().AsTime())}
}

// EndDrain implements apisvc.Drains: it asks the agent to end the drain of its old process and
// returns the old process as it last reported it.
func (s *Sessions) EndDrain(ctx context.Context, agentID string) (*rpmgrv1.DrainingProcess, error) {
	d := s.Draining(agentID)
	if d == nil {
		if s.isConnected(agentID) {
			return nil, apisvc.ErrNoDrain
		}
		return nil, apisvc.ErrDrainNotConnected
	}
	r, err := s.ask(ctx, agentID, agentproto.CapDrainEnd, func(opID string) *agentv1.ControllerMessage {
		return &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_EndDrain{EndDrain: &agentv1.EndDrain{OpId: opID}}}
	})
	switch {
	case errors.Is(err, ErrNotConnected):
		return nil, apisvc.ErrDrainNotConnected
	case errors.Is(err, errNoCapability):
		return nil, apisvc.ErrDrainUnsupported
	case err != nil:
		return nil, err
	case r.GetError() != "":
		return nil, fmt.Errorf("%w: %s", apisvc.ErrNoDrain, r.GetError())
	}
	return d, nil
}

// isConnected reports whether the agent has a control session with this replica.
func (s *Sessions) isConnected(agentID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[agentID] != nil
}
