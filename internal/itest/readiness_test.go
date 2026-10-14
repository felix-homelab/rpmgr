// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/datasession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/resourcestatus"
)

// TestReadiness_ReportedToController: a route whose target the connector's local policy stops
// allowing is recorded as not ready, with the reason and the blocked target, without a new
// revision; and a change made while the connector has no control session reaches the controller
// with the session's first Status, as an unchanged snapshot brings no new Applied.
func TestReadiness_ReportedToController(t *testing.T) {
	p := newDataPlane(t)
	c := p.dial(t)
	_ = c.Close()
	status := func() *ent.ResourceStatus { return p.status(t, p.connector) }
	waitFor := func(what string, ok func(*ent.ResourceStatus) bool) *ent.ResourceStatus {
		t.Helper()
		return p.waitForStatus(t, p.connector, what, ok)
	}
	if r := status(); r != nil {
		t.Fatalf("a ready route has a status row: %+v", r)
	}
	allowed, err := os.ReadFile(p.conCfg.PolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.conCfg.PolicyFile, []byte("version: 1\nallow_targets: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := waitFor("after the policy blocked the target", func(r *ent.ResourceStatus) bool { return r != nil })
	if r.Reason != "NOT_READY_REASON_BLOCKED_BY_LOCAL_POLICY" || r.Detail == "" || r.OrgID != p.c.Org {
		t.Fatalf("the blocked route: %+v", r)
	}
	t.Logf("blocked: %s", fmt.Sprint(r.Detail))

	p.stopConnector()
	if err := os.WriteFile(p.conCfg.PolicyFile, allowed, 0o600); err != nil { //nolint:gosec // G703: the test's own policy file
		t.Fatal(err)
	}
	p.startConnector(t, nil)
	waitFor("after a restart with the target allowed again", func(r *ent.ResourceStatus) bool { return r == nil })
}

// TestReadiness_GatewayPortBoundLater: a gateway that starts while its tcp route's port is taken
// reports the route not ready with the first Status of its control session, as its unchanged
// snapshot brings no new Applied; once the port is free and the gateway binds it, it reports the
// route ready again, without a new revision.
func TestReadiness_GatewayPortBoundLater(t *testing.T) {
	p := newDataPlane(t)
	c := p.dial(t)
	_ = c.Close()
	p.stopGateway()
	taken, err := net.Listen("tcp", addr(p.publicPort))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = taken.Close() }()
	p.startGateway(t)
	r := p.waitForStatus(t, p.gatewayID, "while the port is taken", func(r *ent.ResourceStatus) bool { return r != nil })
	if r.Reason != "NOT_READY_REASON_PORT_IN_USE" || r.OrgID != p.c.Org {
		t.Fatalf("the route on a taken port: %+v", r)
	}
	_ = taken.Close()
	p.waitForStatus(t, p.gatewayID, "once the port is free", func(r *ent.ResourceStatus) bool { return r == nil })
	c = p.dial(t)
	_ = c.Close()
}

// status returns what the controller records about the readiness of the route on agent, nil if it
// is ready.
func (p *dataPlane) status(t *testing.T, agent string) *ent.ResourceStatus {
	t.Helper()
	r, err := p.c.DB.Client().ResourceStatus.Query().Where(resourcestatus.AgentID(agent), resourcestatus.ResourceID(p.routeID)).
		Only(p.c.Sys)
	if ent.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// waitForStatus waits up to 15 s until ok accepts the route's status on agent.
func (p *dataPlane) waitForStatus(t *testing.T, agent, what string, ok func(*ent.ResourceStatus) bool) *ent.ResourceStatus {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if r := p.status(t, agent); ok(r) {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the route's status is %+v", what, p.status(t, agent))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestDataSessions_ReportedToController: a gateway reports its connectors' data sessions to the
// controller a moment after they change: the connector's sessions appear once it connects, and go
// once it stops.
func TestDataSessions_ReportedToController(t *testing.T) {
	p := newDataPlane(t)
	c := p.dial(t)
	_ = c.Close()
	sessions := func() []*ent.DataSession {
		return p.c.DB.Client().DataSession.Query().Where(datasession.GatewayID(p.gatewayID), datasession.ConnectorID(p.connector)).
			AllX(p.c.Sys)
	}
	wait := func(what string, ok func([]*ent.DataSession) bool) []*ent.DataSession {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			if got := sessions(); ok(got) {
				return got
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %v", what, sessions())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	got := wait("a connected connector", func(s []*ent.DataSession) bool { return len(s) > 0 })
	for _, s := range got {
		if s.OrgID != p.c.Org || s.EstablishedAt.IsZero() {
			t.Fatalf("a data session row: %+v", s)
		}
	}
	p.stopConnector()
	wait("a stopped connector", func(s []*ent.DataSession) bool { return len(s) == 0 })
}
