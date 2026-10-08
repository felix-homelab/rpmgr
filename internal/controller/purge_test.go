// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/predicate"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestPurge (docs/04-security.md, "Lifecycle"): an ephemeral connector is purged 30 minutes after
// its last disconnect, by its recorded end, by a session no controller has seen since, or by its
// enrollment if it never connected, with its identity revoked and its route targets, observed
// rows and tokens gone; a tombstone goes after 90 days with its expired certificate records,
// unless a route target still names it or a certificate has not expired; a second run changes
// nothing.
func TestPurge(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "org-a")
		c := db.Client()
		now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
		group := c.GatewayGroup.Create().SetOrgID(org).SetName("eu").SaveX(sys)
		route := c.Route.Create().SetOrgID(org).SetName("web").SetType("tcp").SetGatewayGroupID(group.ID).SaveX(sys)
		n := 0
		addConnector := func(ephemeral bool, created time.Time, edit func(*ent.ConnectorCreate)) string {
			n++
			name := fmt.Sprintf("c%d", n)
			cc := c.Connector.Create().SetOrgID(org).SetName(name).SetSpiffeID("spiffe://rpmgr-teststor/org/" + org + "/connector/" + name).
				SetPubkeySha256("k").SetEphemeral(ephemeral).SetCreatedAt(created)
			if edit != nil {
				edit(cc)
			}
			return cc.SaveX(sys).ID
		}
		session := func(id string, lastSeen time.Time, disconnected *time.Time) {
			cs := c.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").
				SetConnectedAt(lastSeen).SetLastSeenAt(lastSeen)
			if disconnected != nil {
				cs.SetDisconnectedAt(*disconnected)
			}
			cs.ExecX(sys)
		}
		serial := 0
		certificate := func(kind, id string, notAfter time.Time, token *string) {
			serial++
			c.IssuedCertificate.Create().SetID(fmt.Sprintf("%04x", serial)).SetOrgID(org).SetSubjectID(id).
				SetSubjectType(issuedSubject(kind)).SetSpiffeID("spiffe://rpmgr-teststor/org/" + org + "/" + kind + "/" + id).SetPubkeySha256("k").
				SetNotBefore(notAfter.Add(-30 * 24 * time.Hour)).SetNotAfter(notAfter).SetNillableEnrollmentTokenID(token).ExecX(sys)
		}
		at := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
		long := now.Add(-time.Hour)

		// Ephemeral connectors.
		goneByEnd := addConnector(true, long, nil)
		session(goneByEnd, *at(31 * time.Minute), at(31*time.Minute))
		c.RouteTarget.Create().SetOrgID(org).SetRouteID(route.ID).SetConnectorID(goneByEnd).SetKind("address").SetHost("127.0.0.1").SetPort(80).ExecX(sys)
		c.ResourceStatus.Create().SetOrgID(org).SetAgentID(goneByEnd).SetResourceID(route.ID).SetReason("NOT_READY_REASON_ENVIRONMENT").SetSince(long).ExecX(sys)
		c.DataSession.Create().SetOrgID(org).SetGatewayID("gw_x").SetConnectorID(goneByEnd).SetTransport("quic").SetEstablishedAt(long).SetReportedAt(long).ExecX(sys)
		certificate("connector", goneByEnd, now.Add(24*time.Hour), nil)
		recentEnd := addConnector(true, long, nil)
		session(recentEnd, *at(29 * time.Minute), at(29*time.Minute))
		live := addConnector(true, long, nil)
		session(live, *at(10 * time.Second), nil)
		unseen := addConnector(true, long, nil)
		session(unseen, *at(40 * time.Minute), nil)
		neverOld := addConnector(true, now.Add(-31*time.Minute), nil)
		neverNew := addConnector(true, now.Add(-5*time.Minute), nil)

		// Tombstones.
		decommissioned := func(d time.Duration) func(*ent.ConnectorCreate) {
			return func(cc *ent.ConnectorCreate) { cc.SetDecommissionedAt(now.Add(-d)).SetEnabled(false) }
		}
		old := addConnector(false, long.Add(-200*24*time.Hour), decommissioned(91*24*time.Hour))
		tok := c.EnrollmentToken.Create().SetOrgID(org).SetTokenHash([]byte("t1")).SetRole("connector").SetConnectorID(old).
			SetExpiresAt(now.Add(-100 * 24 * time.Hour)).SetCreatedBy("usr_x").SaveX(sys)
		certificate("connector", old, now.Add(-95*24*time.Hour), &tok.ID)
		withTarget := addConnector(false, long, decommissioned(91*24*time.Hour))
		c.RouteTarget.Create().SetOrgID(org).SetRouteID(route.ID).SetConnectorID(withTarget).SetKind("address").SetHost("127.0.0.1").SetPort(81).ExecX(sys)
		young := addConnector(false, long, decommissioned(89*24*time.Hour))
		unexpired := addConnector(false, long, decommissioned(91*24*time.Hour))
		certificate("connector", unexpired, now.Add(time.Hour), nil)
		gw := c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group.ID).SetName("gw1").SetTunnelEndpoints([]string{"gw1.example.com:443"}).
			SetDecommissionedAt(now.Add(-91 * 24 * time.Hour)).SetEnabled(false).SaveX(sys)
		c.EnrollmentToken.Create().SetOrgID(org).SetTokenHash([]byte("t2")).SetRole("gateway").SetGatewayID(gw.ID).SetGatewayGroupID(group.ID).
			SetExpiresAt(long).SetCreatedBy("usr_x").ExecX(sys)
		certificate("gateway", gw.ID, now.Add(-95*24*time.Hour), nil)

		logPath := filepath.Join(t.TempDir(), "revocations.log")
		rl, err := revlog.Open(logPath, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		var denied atomic.Int32
		job := controller.PurgeJob(controller.PurgeOptions{DB: db, RevLog: rl, Denied: func() { denied.Add(1) }, Now: func() time.Time { return now }})
		run := func() {
			t.Helper()
			if err := job.Run(context.WithoutCancel(sys), lease.Lease{}); err != nil {
				t.Fatal(err)
			}
		}
		run()
		exists := func(id string) bool { return c.Connector.Query().Where(connectorID(id)).ExistX(sys) }
		for name, id := range map[string]string{"ended 31 min ago": goneByEnd, "unseen for 40 min": unseen, "never connected, 31 min": neverOld,
			"a 91-day tombstone": old} {
			if exists(id) {
				t.Errorf("%s: kept", name)
			}
		}
		for name, id := range map[string]string{"ended 29 min ago": recentEnd, "live": live, "never connected, 5 min": neverNew,
			"a tombstone with a target": withTarget, "an 89-day tombstone": young, "a tombstone with a live certificate": unexpired} {
			if !exists(id) {
				t.Errorf("%s: purged", name)
			}
		}
		if c.Gateway.Query().CountX(sys) != 0 || c.EnrollmentToken.Query().CountX(sys) != 0 {
			t.Fatalf("the gateway tombstone or the bound tokens are left: %d gateways, %d tokens",
				c.Gateway.Query().CountX(sys), c.EnrollmentToken.Query().CountX(sys))
		}
		if c.RouteTarget.Query().CountX(sys) != 1 || c.ResourceStatus.Query().CountX(sys) != 0 || c.DataSession.Query().CountX(sys) != 0 ||
			c.AgentSession.Query().CountX(sys) != 2 {
			t.Fatalf("left behind: %d targets, %d statuses, %d data sessions, %d sessions", c.RouteTarget.Query().CountX(sys),
				c.ResourceStatus.Query().CountX(sys), c.DataSession.Query().CountX(sys), c.AgentSession.Query().CountX(sys))
		}
		// The ephemeral connector's certificate stays, for the revocation; the tombstones' expired ones go.
		if certs := c.IssuedCertificate.Query().CountX(sys); certs != 2 {
			t.Fatalf("%d certificate records left, want the ephemeral one's and the unexpired one", certs)
		}
		revokedIDs := c.RevokedIdentity.Query().CountX(sys)
		entries, err := revlog.Read(logPath)
		if err != nil || revokedIDs != 5 || len(entries) != 5 || denied.Load() != 1 {
			t.Fatalf("%d identities revoked, %d log entries (%v), deny-list applied %d times", revokedIDs, len(entries), err, denied.Load())
		}
		if n := c.AuditEntry.Query().Where(auditentry.Action("connector.purge")).CountX(sys); n != 4 {
			t.Fatalf("%d connector purges audited", n)
		}

		run()
		if c.Connector.Query().CountX(sys) != 6 || denied.Load() != 1 {
			t.Fatalf("a second run: %d connectors, deny-list applied %d times", c.Connector.Query().CountX(sys), denied.Load())
		}
	})
}

func connectorID(id string) predicate.Connector { return connector.ID(id) }

func issuedSubject(kind string) issuedcertificate.SubjectType {
	return issuedcertificate.SubjectType(kind)
}
