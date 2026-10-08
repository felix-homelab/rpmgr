// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"fmt"
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
	status := func() *ent.ResourceStatus {
		r, err := p.c.DB.Client().ResourceStatus.Query().Where(resourcestatus.AgentID(p.connector), resourcestatus.ResourceID(p.routeID)).
			Only(p.c.Sys)
		if ent.IsNotFound(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	waitFor := func(what string, ok func(*ent.ResourceStatus) bool) *ent.ResourceStatus {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			if r := status(); ok(r) {
				return r
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: the route's status is %+v", what, status())
			}
			time.Sleep(50 * time.Millisecond)
		}
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
