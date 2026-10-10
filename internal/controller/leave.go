// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
)

// Leave lets an agent revoke its own identity, for `rpmgr leave` (docs/03-connections.md,
// "Leaving"): its connector or gateway is decommissioned as an admin's decommission does, with the
// agent as the actor, and the deny-list applies at once, which ends its sessions. Only a valid
// certificate reaches it, so a revoked agent cannot call it; an agent whose row is decommissioned
// already changes nothing.
func (s *Sessions) Leave(ctx context.Context, _ *agentv1.LeaveRequest) (*agentv1.LeaveResponse, error) {
	agent, ok := AgentFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	id := agent.Identity
	if id.Kind != pki.KindConnector && id.Kind != pki.KindGateway {
		return nil, status.Error(codes.PermissionDenied, "only a connector or a gateway leaves")
	}
	now := s.now()
	revoked := false
	_, err := store.ConfigTx(store.RevisionOrg(s.sys, id.Org), s.db, func(tx *ent.Tx) ([]string, error) {
		var err error
		if id.Kind == pki.KindConnector {
			_, err = tx.Connector.Update().Where(connector.ID(id.ID), connector.DecommissionedAtIsNil()).
				SetDecommissionedAt(now).SetEnabled(false).Save(s.sys)
		} else {
			_, err = tx.Gateway.Update().Where(gateway.ID(id.ID), gateway.DecommissionedAtIsNil()).
				SetDecommissionedAt(now).SetEnabled(false).Save(s.sys)
		}
		if err != nil {
			return nil, err
		}
		row, changed, err := pki.RevokeIdentity(s.sys, tx, id, "left", now)
		if err != nil || !changed {
			return []string{id.ID}, err
		}
		revoked = true
		appendLog(s.revlog, s.log, revlog.Entry{Kind: revlog.IdentityRevoked, Org: id.Org, Subject: id.String(), Detail: "left",
			NotAfter: &row.NotAfter, Actor: id.ID})
		_, err = audit.Append(s.sys, tx, audit.Entry{OrgID: id.Org, ActorType: audit.ActorAgent, ActorID: id.ID, Action: "identity.revoke",
			TargetType: string(id.Kind), TargetID: id.ID, Result: audit.Success, Reason: "left with rpmgr leave"})
		return []string{id.ID}, err
	})
	if err != nil {
		s.log.Error("an agent could not leave", "agent", id.String(), "error", err)
		return nil, status.Error(codes.Unavailable, "the controller cannot revoke the identity now")
	}
	if revoked {
		s.applyDeny()
	}
	return &agentv1.LeaveResponse{}, nil
}
