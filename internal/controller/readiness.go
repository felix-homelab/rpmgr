// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"cmp"
	"maps"
	"slices"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/datasession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/resourcestatus"
)

// maxNotReady is how many not-ready resources of one agent the controller keeps
// (docs/03-connections.md, "Configuration reconciliation"); an agent cannot make it keep more.
const maxNotReady = 1024

// readiness records the resources an agent reports not ready. With all set, list is the whole set
// of an Applied and replaces what was recorded; otherwise it holds the changes of a Status, where a
// resource without a reason is ready again or gone. A resource whose reason and detail did not
// change keeps its since.
func (s *Sessions) readiness(id pki.Identity, list []*agentv1.ResourceStatus, all bool) {
	next := map[string]*agentv1.ResourceStatus{}
	for _, r := range list {
		if r.GetResourceId() != "" {
			next[clip(r.GetResourceId())] = r
		}
	}
	now := s.now()
	err := store.WriteTx(s.sys, s.db, func(tx *ent.Tx) error {
		cur, err := tx.ResourceStatus.Query().Where(resourcestatus.AgentID(id.ID)).All(s.sys)
		if err != nil {
			return err
		}
		held := map[string]*ent.ResourceStatus{}
		for _, row := range cur {
			r, reported := next[row.ResourceID]
			switch {
			case all && !reported, reported && r.GetReason() == agentv1.NotReadyReason_NOT_READY_REASON_UNSPECIFIED:
				if err := tx.ResourceStatus.DeleteOne(row).Exec(s.sys); err != nil {
					return err
				}
			default:
				held[row.ResourceID] = row
			}
		}
		for _, rid := range slices.Sorted(maps.Keys(next)) {
			r := next[rid]
			if r.GetReason() == agentv1.NotReadyReason_NOT_READY_REASON_UNSPECIFIED {
				continue
			}
			reason, detail := r.GetReason().String(), clip(r.GetDetail())
			switch row, ok := held[rid]; {
			case ok && row.Reason == reason && row.Detail == detail:
			case ok:
				if err := tx.ResourceStatus.UpdateOne(row).SetReason(reason).SetDetail(detail).SetSince(now).Exec(s.sys); err != nil {
					return err
				}
			case len(held) < maxNotReady:
				row, err := tx.ResourceStatus.Create().SetOrgID(id.Org).SetAgentID(id.ID).SetResourceID(rid).SetReason(reason).
					SetDetail(detail).SetSince(now).Save(s.sys)
				if err != nil {
					return err
				}
				held[rid] = row
			}
		}
		return nil
	})
	if err != nil {
		s.log.Error("cannot record an agent's readiness", "agent", id.ID, "error", err)
	}
}

// maxDataSessions is how many data sessions of one gateway the controller keeps
// (docs/03-connections.md, "Configuration reconciliation").
const maxDataSessions = 4096

// dataSessions replaces what a gateway reported of its connectors' data sessions; a session it
// still reports keeps when it was first heard of.
func (s *Sessions) dataSessions(id pki.Identity, list []*agentv1.DataSession) {
	type key struct{ connector, transport string }
	next := map[key]*agentv1.DataSession{}
	for _, d := range list {
		tr := ""
		switch d.GetTransport() {
		case agentv1.Transport_TRANSPORT_QUIC:
			tr = "quic"
		case agentv1.Transport_TRANSPORT_H2:
			tr = "h2"
		}
		if d.GetConnectorId() != "" && tr != "" && len(next) < maxDataSessions {
			next[key{clip(d.GetConnectorId()), tr}] = d
		}
	}
	now := s.now()
	err := store.WriteTx(s.sys, s.db, func(tx *ent.Tx) error {
		cur, err := tx.DataSession.Query().Where(datasession.GatewayID(id.ID)).All(s.sys)
		if err != nil {
			return err
		}
		held := map[key]*ent.DataSession{}
		for _, row := range cur {
			k := key{row.ConnectorID, string(row.Transport)}
			if _, ok := next[k]; !ok {
				if err := tx.DataSession.DeleteOne(row).Exec(s.sys); err != nil {
					return err
				}
				continue
			}
			held[k] = row
		}
		for _, k := range slices.SortedFunc(maps.Keys(next), func(a, b key) int {
			return cmp.Or(cmp.Compare(a.connector, b.connector), cmp.Compare(a.transport, b.transport))
		}) {
			rtt := next[k].GetRtt().AsDuration().Milliseconds()
			if row, ok := held[k]; ok {
				if err := tx.DataSession.UpdateOne(row).SetRttMs(max(rtt, 0)).SetReportedAt(now).Exec(s.sys); err != nil {
					return err
				}
				continue
			}
			if err := tx.DataSession.Create().SetOrgID(id.Org).SetGatewayID(id.ID).SetConnectorID(k.connector).
				SetTransport(datasession.Transport(k.transport)).SetRttMs(max(rtt, 0)).SetEstablishedAt(now).SetReportedAt(now).
				Exec(s.sys); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.Error("cannot record a gateway's data sessions", "gateway", id.ID, "error", err)
	}
}
