// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
)

// fakeDrains is the old processes the controller holds, by agent ID, and the drains ended.
type fakeDrains struct {
	mu    sync.Mutex
	held  map[string]*rpmgrv1.DrainingProcess
	err   error
	ended []string
}

func (f *fakeDrains) Draining(id string) *rpmgrv1.DrainingProcess {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held[id]
}

func (f *fakeDrains) EndDrain(_ context.Context, id string) (*rpmgrv1.DrainingProcess, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	d := f.held[id]
	if d == nil {
		return nil, apisvc.ErrNoDrain
	}
	f.ended = append(f.ended, id)
	delete(f.held, id)
	return d, nil
}

func (f *fakeDrains) set(id string, d *rpmgrv1.DrainingProcess) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.held == nil {
		f.held = map[string]*rpmgrv1.DrainingProcess{}
	}
	f.held[id] = d
}

func oldProcess() *rpmgrv1.DrainingProcess {
	return &rpmgrv1.DrainingProcess{Connections: 12, Flows: 3, Sessions: 2,
		Since: timestamppb.New(time.Unix(1000, 0)), Ends: timestamppb.New(time.Unix(1300, 0))}
}

// TestEndGatewayDrain (D160): a gateway's status shows its old process; an Admin ends the drain
// after a step-up and the call is audited; a Viewer, a call without a step-up and another org's
// caller are refused; no old process, a gateway that is gone from the controller and an agent of an
// earlier release are FAILED_PRECONDITION; the all-in-one's own gateway needs the Instance Admin.
func TestEndGatewayDrain(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	built, err := createGateway(ada, org, group, "local", "local.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	e.db.Client().Gateway.UpdateOneID(built.GetId()).SetBuiltIn(true).ExecX(e.sys)
	end := func(b *browser, id string) (*rpmgrv1.DrainingProcess, error) {
		r, err := b.gw.EndGatewayDrain(ctx, connect.NewRequest(&rpmgrv1.EndGatewayDrainRequest{GatewayId: id}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetEnded(), nil
	}
	status := func() *rpmgrv1.DrainingProcess {
		r, err := ada.gw.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: gw.GetId()}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetGateway().GetStatus().GetDraining()
	}

	if status() != nil {
		t.Fatal("a gateway with no old process shows one")
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := end(ada, gw.GetId()); code(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), apisvc.ErrNoDrain.Error()) {
		t.Fatalf("ending a drain that is not there: %v", err)
	}
	e.drains.set(gw.GetId(), oldProcess())
	if d := status(); d.GetConnections() != 12 || d.GetFlows() != 3 || d.GetSessions() != 2 || d.GetEnds().AsTime().Unix() != 1300 {
		t.Fatalf("the status shows %v", d)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := end(vwr, gw.GetId()); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer ends a drain: %v", err)
	}
	adm, _ := e.join(t, ada, org, "adm@example.com", "admin")
	if _, err := end(adm, gw.GetId()); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("an Admin without a step-up: %v", err)
	}
	if len(e.drains.ended) != 0 {
		t.Fatal("a refused call ended a drain")
	}
	if err := adm.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	ended, err := end(adm, gw.GetId())
	if err != nil || ended.GetConnections() != 12 || len(e.drains.ended) != 1 || e.drains.ended[0] != gw.GetId() {
		t.Fatalf("an Admin ends the drain: %v %v %v", ended, err, e.drains.ended)
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.GatewayService.EndGatewayDrain"), auditentry.TargetID(gw.GetId())).
		CountX(e.sys); n == 0 {
		t.Fatal("the call is not audited")
	}
	if status() != nil {
		t.Fatal("the status shows the old process after the drain ended")
	}

	// The agent says why it cannot.
	for _, c := range []error{apisvc.ErrDrainNotConnected, apisvc.ErrDrainUnsupported} {
		e.drains.mu.Lock()
		e.drains.err = c
		e.drains.mu.Unlock()
		if _, err := end(ada, gw.GetId()); code(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), c.Error()) {
			t.Fatalf("%v: %v", c, err)
		}
	}
	e.drains.mu.Lock()
	e.drains.err = nil
	e.drains.mu.Unlock()

	// The all-in-one's own gateway: the Instance Admin only, not an Admin of the org.
	e.drains.set(built.GetId(), oldProcess())
	if _, err := end(adm, built.GetId()); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Admin ends the built-in gateway's drain: %v", err)
	}
	if _, err := end(ada, built.GetId()); err != nil {
		t.Fatalf("the Instance Admin ends it: %v", err)
	}
	if _, err := end(ada, "gw_nobody"); code(err) != connect.CodeNotFound {
		t.Fatalf("an unknown gateway: %v", err)
	}
}

// TestEndConnectorDrain (D160): the same for a connector, with connectors.write.
func TestEndConnectorDrain(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	nas := e.addConnector(t, org, "nas", nil)
	e.drains.set(nas.ID, oldProcess())
	end := func(b *browser) error {
		_, err := b.con.EndConnectorDrain(ctx, connect.NewRequest(&rpmgrv1.EndConnectorDrainRequest{ConnectorId: nas.ID}))
		return err
	}
	r, err := ada.con.GetConnector(ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: nas.ID}))
	if err != nil || r.Msg.GetConnector().GetSession().GetDraining().GetConnections() != 12 {
		t.Fatalf("the connector shows %v %v", r, err)
	}
	st, err := ada.con.GetConnectorStatus(ctx, connect.NewRequest(&rpmgrv1.GetConnectorStatusRequest{ConnectorId: nas.ID}))
	if err != nil || st.Msg.GetStatus().GetSession().GetDraining().GetSessions() != 2 {
		t.Fatalf("the connector's status shows %v %v", st, err)
	}
	l, err := ada.con.ListConnectors(ctx, connect.NewRequest(&rpmgrv1.ListConnectorsRequest{OrgId: org}))
	if err != nil || l.Msg.GetConnectors()[0].GetSession().GetDraining() == nil {
		t.Fatalf("the list shows %v %v", l, err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if err := end(vwr); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer: %v", err)
	}
	if err := end(ada); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("without a step-up: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if err := end(ada); err != nil || len(e.drains.ended) != 1 {
		t.Fatalf("ending the drain: %v %v", err, e.drains.ended)
	}
	if err := end(ada); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a second call: %v", err)
	}
}
