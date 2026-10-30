// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// recordFirewall keeps the state of its host's firewall management that a gateway reports. Like a
// drain it lives in this replica's memory with the agent's session, and the gateway reports it again
// in the first Status of every session (docs/04-security.md, "Host firewall for port pools").
func (s *Sessions) recordFirewall(agentID string, f *agentv1.FirewallState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[agentID] == nil {
		return
	}
	if s.firewall == nil {
		s.firewall = map[string]*agentv1.FirewallState{}
	}
	s.firewall[agentID] = f
}

// Firewall implements apisvc.Firewalls: the state the gateway reported, nil for none, or for a
// gateway without a control session with this replica.
func (s *Sessions) Firewall(agentID string) *rpmgrv1.FirewallStatus {
	s.mu.Lock()
	f := s.firewall[agentID]
	s.mu.Unlock()
	if f == nil {
		return nil
	}
	out := &rpmgrv1.FirewallStatus{State: rpmgrv1.FirewallState_FIREWALL_STATE_UNSPECIFIED, Reason: f.GetReason(),
		Rules: f.GetRules(), Refused: f.GetRefused()}
	switch f.GetPhase() {
	case agentv1.FirewallPhase_FIREWALL_PHASE_OFF:
		out.State = rpmgrv1.FirewallState_FIREWALL_STATE_OFF
	case agentv1.FirewallPhase_FIREWALL_PHASE_APPLIED:
		out.State = rpmgrv1.FirewallState_FIREWALL_STATE_APPLIED
	case agentv1.FirewallPhase_FIREWALL_PHASE_FAILED:
		out.State = rpmgrv1.FirewallState_FIREWALL_STATE_FAILED
	}
	if f.GetReported() != nil {
		out.ReportTime = timestamppb.New(f.GetReported().AsTime())
	}
	return out
}
