// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/configrevision"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/hook"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portpool"
	"github.com/felix-homelab/rpmgr/internal/store/ent/predicate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestPurge (docs/04-security.md, "Lifecycle"): an ephemeral connector is purged 30 minutes after
// its last disconnect, by its recorded end, by a session no controller has seen since, or by its
// enrollment if it never connected, with its identity revoked and its route targets, observed
// rows and tokens gone; a decommissioned connector's targets go at once, and a route left with no
// target goes with them (D78); a tombstone goes after 90 days with its expired certificate
// records, unless a certificate has not expired; a second run changes nothing.
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

		// A rollout names the purged ephemeral connector, the purged gateway and a live connector.
		rel := c.Release.Create().SetVersion("0.2.0").SetChannel("stable").SetManifestSeq(2).SetManifest([]byte("{}")).
			SetSignature([]byte("s")).SetSigningKeyStatement([]byte("{}")).SetStatementSignature([]byte("s")).SetSource("check").SaveX(sys)
		ro := c.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_x").SaveX(sys)
		for id, kind := range map[string]string{goneByEnd: "connector", gw.ID: "gateway", live: "connector"} {
			c.RolloutTarget.Create().SetRolloutID(ro.ID).SetAgentID(id).SetAgentKind(rollouttarget.AgentKind(kind)).
				SetBucket(store.RolloutBucket(id)).ExecX(sys)
		}

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
		// The purge's revisions belong to the org, so its event stream sees them.
		if all, mine := c.ConfigRevision.Query().CountX(sys), c.ConfigRevision.Query().Where(configrevision.OrgID(org)).CountX(sys); all == 0 || mine != all {
			t.Errorf("%d of the purge's %d revisions belong to the org", mine, all)
		}
		exists := func(id string) bool { return c.Connector.Query().Where(connectorID(id)).ExistX(sys) }
		for name, id := range map[string]string{"ended 31 min ago": goneByEnd, "unseen for 40 min": unseen, "never connected, 31 min": neverOld,
			"a 91-day tombstone": old, "a tombstone that had a target": withTarget} {
			if exists(id) {
				t.Errorf("%s: kept", name)
			}
		}
		for name, id := range map[string]string{"ended 29 min ago": recentEnd, "live": live, "never connected, 5 min": neverNew,
			"an 89-day tombstone": young, "a tombstone with a live certificate": unexpired} {
			if !exists(id) {
				t.Errorf("%s: purged", name)
			}
		}
		if c.Gateway.Query().CountX(sys) != 0 || c.EnrollmentToken.Query().CountX(sys) != 0 {
			t.Fatalf("the gateway tombstone or the bound tokens are left: %d gateways, %d tokens",
				c.Gateway.Query().CountX(sys), c.EnrollmentToken.Query().CountX(sys))
		}
		// The route lost its last target, so it went too.
		if c.Route.Query().CountX(sys) != 0 || c.AuditEntry.Query().Where(auditentry.Action("route.delete"), auditentry.TargetID(route.ID)).CountX(sys) != 1 {
			t.Fatalf("the route without targets: %d routes left", c.Route.Query().CountX(sys))
		}
		if c.RouteTarget.Query().CountX(sys) != 0 || c.ResourceStatus.Query().CountX(sys) != 0 || c.DataSession.Query().CountX(sys) != 0 ||
			c.AgentSession.Query().CountX(sys) != 2 {
			t.Fatalf("left behind: %d targets, %d statuses, %d data sessions, %d sessions", c.RouteTarget.Query().CountX(sys),
				c.ResourceStatus.Query().CountX(sys), c.DataSession.Query().CountX(sys), c.AgentSession.Query().CountX(sys))
		}
		if left := c.RolloutTarget.Query().Select(rollouttarget.FieldAgentID).StringsX(sys); len(left) != 1 || left[0] != live {
			t.Fatalf("rollout targets left: %v, want only the live connector's", left)
		}
		// The ephemeral connector's certificate stays, for the revocation; the tombstones' expired ones go.
		if certs := c.IssuedCertificate.Query().CountX(sys); certs != 2 {
			t.Fatalf("%d certificate records left, want the ephemeral one's and the unexpired one", certs)
		}
		revokedIDs := c.RevokedIdentity.Query().CountX(sys)
		entries, err := revlog.Read(logPath)
		if err != nil || revokedIDs != 6 || len(entries) != 6 || denied.Load() != 1 {
			t.Fatalf("%d identities revoked, %d log entries (%v), deny-list applied %d times", revokedIDs, len(entries), err, denied.Load())
		}
		if n := c.AuditEntry.Query().Where(auditentry.Action("connector.purge")).CountX(sys); n != 5 {
			t.Fatalf("%d connector purges audited", n)
		}

		run()
		if c.Connector.Query().CountX(sys) != 5 || denied.Load() != 1 {
			t.Fatalf("a second run: %d connectors, deny-list applied %d times", c.Connector.Query().CountX(sys), denied.Load())
		}
	})
}

func connectorID(id string) predicate.Connector { return connector.ID(id) }

func issuedSubject(kind string) issuedcertificate.SubjectType {
	return issuedcertificate.SubjectType(kind)
}

// TestPurge_RetiresRoutes (D78): a connector decommissioned before D78 keeps route targets that
// hold their routes' ports; the purge deletes them at once, and each route left with no target,
// freeing its port, while the tombstone stays for its 90 days; a route with a target on another
// connector keeps that one; a purged ephemeral connector's routes go the same way.
func TestPurge_RetiresRoutes(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "org-a")
		c := db.Client()
		now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
		group := c.GatewayGroup.Create().SetOrgID(org).SetName("eu").SaveX(sys).ID
		for _, p := range []routes.Protocol{routes.TCP, routes.UDP} {
			c.PortPool.Create().SetOrgID(org).SetGatewayGroupID(group).SetProtocol(portpool.Protocol(p)).SetPortFrom(20000).SetPortTo(20009).ExecX(sys)
		}
		addConnector := func(name string, edit func(*ent.ConnectorCreate)) string {
			cc := c.Connector.Create().SetOrgID(org).SetName(name).SetSpiffeID("spiffe://rpmgr-teststor/org/" + org + "/connector/" + name).
				SetPubkeySha256("k").SetCreatedAt(now.Add(-time.Hour))
			if edit != nil {
				edit(cc)
			}
			return cc.SaveX(sys).ID
		}
		legacy := addConnector("legacy", func(cc *ent.ConnectorCreate) { cc.SetDecommissionedAt(now.Add(-24 * time.Hour)).SetEnabled(false) })
		pi := addConnector("pi", nil)
		runner := addConnector("runner", func(cc *ent.ConnectorCreate) { cc.SetEphemeral(true) })
		c.AgentSession.Create().SetID(runner).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetConnectedAt(now.Add(-time.Hour)).
			SetLastSeenAt(now.Add(-31 * time.Minute)).SetDisconnectedAt(now.Add(-31 * time.Minute)).ExecX(sys)
		portRoute := func(name string, p routes.Protocol, port int, connectors ...string) string {
			r := c.Route.Create().SetOrgID(org).SetName(name).SetType(route.Type(p)).SetGatewayGroupID(group).SaveX(sys)
			tx, err := c.Tx(sys)
			if err != nil {
				t.Fatal(err)
			}
			a, err := routes.Allocate(sys, tx, org, group, p, port)
			if err == nil {
				if _, err = tx.PortAllocation.UpdateOne(a).SetRouteID(r.ID).Save(sys); err == nil {
					if p == routes.TCP {
						err = tx.RouteTCP.Create().SetOrgID(org).SetRouteID(r.ID).SetPortAllocationID(a.ID).Exec(sys)
					} else {
						err = tx.RouteUDP.Create().SetOrgID(org).SetRouteID(r.ID).SetPortAllocationID(a.ID).Exec(sys)
					}
				}
			}
			if err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			for _, con := range connectors {
				c.RouteTarget.Create().SetOrgID(org).SetRouteID(r.ID).SetConnectorID(con).SetKind("address").SetHost("10.0.0.5").SetPort(5432).ExecX(sys)
			}
			return r.ID
		}
		pg := portRoute("pg", routes.TCP, 20005, legacy)
		shared := portRoute("shared", routes.TCP, 20006, legacy, pi)
		ci := portRoute("ci", routes.UDP, 20005, runner)

		job := controller.PurgeJob(controller.PurgeOptions{DB: db, Now: func() time.Time { return now }})
		// A connector whose route cannot go fails alone: its targets stay, rolled back, for the next
		// run, and the ephemeral connector is purged all the same, its identity revoked.
		var fail atomic.Bool
		fail.Store(true)
		c.Route.Use(func(next ent.Mutator) ent.Mutator {
			return hook.RouteFunc(func(ctx context.Context, m *ent.RouteMutation) (ent.Value, error) {
				if id, ok := m.ID(); ok && id == pg && fail.Load() && m.Op().Is(ent.OpDeleteOne) {
					return nil, errors.New("the store failed")
				}
				return next.Mutate(ctx, m)
			})
		})
		if err := job.Run(context.WithoutCancel(sys), lease.Lease{}); err == nil {
			t.Fatal("a failed retirement went unreported")
		}
		if !c.Route.Query().Where(routeID(pg)).ExistX(sys) || c.RouteTarget.Query().Where(routetarget.ConnectorID(legacy)).CountX(sys) != 2 {
			t.Fatal("a failed retirement was not rolled back")
		}
		if c.Connector.Query().Where(connectorID(runner)).ExistX(sys) || c.RevokedIdentity.Query().CountX(sys) != 1 {
			t.Fatal("the ephemeral connector was not purged and revoked after another connector failed")
		}
		fail.Store(false)
		if err := job.Run(context.WithoutCancel(sys), lease.Lease{}); err != nil {
			t.Fatal(err)
		}
		for name, id := range map[string]string{"pg": pg, "ci": ci} {
			if c.Route.Query().Where(routeID(id)).ExistX(sys) {
				t.Errorf("route %s with no target left: kept", name)
			}
		}
		if got := c.RouteTarget.Query().Where(routetarget.RouteID(shared)).AllX(sys); len(got) != 1 || got[0].ConnectorID != pi {
			t.Fatalf("the shared route's targets: %v", got)
		}
		if ports := c.PortAllocation.Query().AllX(sys); len(ports) != 1 || ports[0].Port != 20006 {
			t.Fatalf("port allocations left: %v, want only the shared route's", ports)
		}
		if !c.Connector.Query().Where(connectorID(legacy)).ExistX(sys) || c.Connector.Query().Where(connectorID(runner)).ExistX(sys) {
			t.Fatal("the legacy tombstone went, or the ephemeral connector stayed")
		}
		if n := c.AuditEntry.Query().Where(auditentry.Action("route.delete"), auditentry.ActorID("purge-agents")).CountX(sys); n != 2 {
			t.Fatalf("%d route deletions audited", n)
		}
	})
}

func routeID(id string) predicate.Route { return route.ID(id) }
