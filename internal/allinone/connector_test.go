// SPDX-License-Identifier: Apache-2.0

package allinone_test

import (
	"context"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/ent/resourcestatus"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// db opens the host's database next to its Run.
func (h *host) db(t *testing.T) (*store.DB, context.Context, *ent.GatewayGroup) {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sys := storetest.SystemCtx(t)
	return db, sys, db.Client().GatewayGroup.Query().Where(gatewaygroup.Name(allinone.GroupName)).OnlyX(sys)
}

// tcpRoute adds a tcp route on the default group from port to target through the connector.
func tcpRoute(t *testing.T, db *store.DB, sys context.Context, group *ent.GatewayGroup, name string, port int, connectorID, target string) string {
	t.Helper()
	host, p, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	targetPort, _ := strconv.Atoi(p)
	var id string
	if _, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
		if _, err := routes.AddPool(sys, tx, group.OrgID, group.ID, routes.TCP, port, port); err != nil {
			return nil, err
		}
		alloc, err := routes.Allocate(sys, tx, group.OrgID, group.ID, routes.TCP, port)
		if err != nil {
			return nil, err
		}
		rt, err := tx.Route.Create().SetOrgID(group.OrgID).SetName(name).SetType("tcp").SetGatewayGroupID(group.ID).Save(sys)
		if err != nil {
			return nil, err
		}
		id = rt.ID
		if err := tx.RouteTCP.Create().SetOrgID(group.OrgID).SetRouteID(rt.ID).SetPortAllocationID(alloc.ID).Exec(sys); err != nil {
			return nil, err
		}
		return []string{rt.ID}, tx.RouteTarget.Create().SetOrgID(group.OrgID).SetRouteID(rt.ID).SetConnectorID(connectorID).
			SetKind("address").SetHost(host).SetPort(targetPort).Exec(sys)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// echoes reports whether the public port answers through the data plane.
func echoes(port int) bool {
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	return ping(c, "through the built-in connector") == nil
}

// blocked returns the readiness detail with which the connector reports the route blocked by its
// local policy, or "".
func blocked(db *store.DB, sys context.Context, connectorID, routeID string) string {
	st, err := db.Client().ResourceStatus.Query().Where(resourcestatus.AgentID(connectorID), resourcestatus.ResourceID(routeID)).Only(sys)
	if err != nil || !strings.Contains(strings.ToLower(st.Reason), "blocked") {
		return ""
	}
	return st.Detail
}

// TestAllInOne_OwnConnector (ADR-0019): init enrolls the built-in connector "local" next to the
// built-in gateway; Run serves a tcp route to a service on the host through it, in memory. Its
// local policy decides: without a file nothing is allowed, and with everything allowed rpmgr's own
// ports, which are the admin listener, port 443, port 80 and a route's port, stay refused.
func TestAllInOne_OwnConnector(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	db, sys, group := h.db(t)
	con, gw := db.Client().Connector.GetX(sys, r.ConnectorID), db.Client().Gateway.GetX(sys, r.GatewayID)
	if con.Name != allinone.ConnectorName || !con.BuiltIn || con.OrgID != group.OrgID || !gw.BuiltIn {
		t.Fatalf("the built-in agents: %+v %+v", con, gw)
	}
	if id, err := agent.ReadIdentity(h.cfg.Connector().IdentityDir); err != nil || id.AgentID != r.ConnectorID {
		t.Fatalf("the connector's identity: %+v %v", id, err)
	}
	svc, public := echoService(t), freePort(t)
	route := tcpRoute(t, db, sys, group, "echo", public, r.ConnectorID, "127.0.0.1:"+strconv.Itoa(svc))
	reg := telemetry.NewRegistry()
	h.registry = reg
	h.run(t)
	waitFor(t, "not ready", h.ready)
	checkRoles(t, reg)
	waitFor(t, "the route is not blocked without a policy file", func() bool {
		return blocked(db, sys, r.ConnectorID, route) == "127.0.0.1:"+strconv.Itoa(svc)
	})
	if echoes(public) {
		t.Fatal("served without a policy file")
	}
	if err := os.WriteFile(h.cfg.PolicyFile, []byte("version: 1\nallow_targets: [0.0.0.0/0, \"[::/0]\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the route is not served through the built-in connector", func() bool { return echoes(public) })

	_, adminPort, _ := net.SplitHostPort(h.cfg.Listen.Admin)
	for i, port := range []string{adminPort, strconv.Itoa(h.port), strconv.Itoa(h.port80), strconv.Itoa(public)} {
		loop := tcpRoute(t, db, sys, group, fmt.Sprintf("own-%d", i), freePort(t), r.ConnectorID, "127.0.0.1:"+port)
		waitFor(t, "port "+port+" is not refused as rpmgr's own", func() bool {
			return blocked(db, sys, r.ConnectorID, loop) == "127.0.0.1:"+port+policy.OwnPort
		})
	}
	if !echoes(public) {
		t.Fatal("the allowed route stopped")
	}
}

// TestAllInOne_EnrollsItsConnector (ADR-0019): Run enrolls the built-in connector when its
// identity is missing, as on an installation initialised before it: again as the same connector
// while that is in service, as a new one once it was decommissioned, and only once. It also marks
// an older installation's gateway built in.
func TestAllInOne_EnrollsItsConnector(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	db, sys, _ := h.db(t)
	db.Client().Gateway.UpdateOneID(r.GatewayID).SetBuiltIn(false).ExecX(sys)
	identity := h.cfg.Connector().IdentityDir
	tokens := func() int {
		return db.Client().EnrollmentToken.Query().Where(enrollmenttoken.RoleEQ(enrollmenttoken.RoleConnector)).CountX(sys)
	}
	if err := os.RemoveAll(identity); err != nil {
		t.Fatal(err)
	}
	stop := h.run(t)
	waitFor(t, "not ready", h.ready)
	id, err := agent.ReadIdentity(identity)
	if err != nil || id.AgentID != r.ConnectorID {
		t.Fatalf("the connector enrolled again as %+v, %v; want %s", id, err, r.ConnectorID)
	}
	if !db.Client().Gateway.GetX(sys, r.GatewayID).BuiltIn || tokens() != 2 {
		t.Fatalf("gateway built in: %v, %d connector tokens", db.Client().Gateway.GetX(sys, r.GatewayID).BuiltIn, tokens())
	}
	stop()

	h.run(t)() // a start with an identity enrolls nothing
	if tokens() != 2 {
		t.Fatalf("%d connector tokens after a plain restart", tokens())
	}

	db.Client().Connector.UpdateOneID(r.ConnectorID).SetDecommissionedAt(time.Now()).SetEnabled(false).ExecX(sys)
	if err := os.RemoveAll(identity); err != nil {
		t.Fatal(err)
	}
	h.run(t)
	waitFor(t, "not ready", h.ready)
	id, err = agent.ReadIdentity(identity)
	if err != nil || id.AgentID == r.ConnectorID {
		t.Fatalf("a new connector: %+v, %v", id, err)
	}
	if c := db.Client().Connector.GetX(sys, id.AgentID); c.Name != allinone.ConnectorName || !c.BuiltIn {
		t.Fatalf("the new connector: %+v", c)
	}
}

// TestAllInOne_StartsFromAnOlderSchema: an all-in-one whose database lacks the built-in columns,
// as one initialised before ADR-0019, starts: the controller migrates first, then Run marks the
// gateway built in and enrolls the missing connector, once.
func TestAllInOne_StartsFromAnOlderSchema(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	db, _, _ := h.db(t)
	ctx := context.Background()
	// The migration that added built_in, and every later one, are not applied yet; the later ones
	// apply again over what they made, as SQLite migrations rebuild their tables, except the
	// tables a later migration creates, which go first.
	var builtIn string
	if err := db.Writer.QueryRowContext(ctx, "SELECT version FROM "+store.RevisionTable+" WHERE description = 'agents_built_in'").Scan(&builtIn); err != nil {
		t.Fatal(err)
	}
	// The connector, its token and certificate go too: an all-in-one from before had none.
	conn, err := db.Writer.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"PRAGMA foreign_keys = OFF",
		"DELETE FROM issued_certificates WHERE enrollment_token_id IN (SELECT id FROM enrollment_tokens WHERE built_in)",
		"DELETE FROM enrollment_tokens WHERE built_in", "DELETE FROM connectors",
		"ALTER TABLE gateways DROP COLUMN built_in", "ALTER TABLE connectors DROP COLUMN built_in",
		"ALTER TABLE enrollment_tokens DROP COLUMN built_in",
		"DROP TABLE health_checks", "DROP TABLE gateway_pages", "DROP TABLE connect_authorities", "DROP TABLE connect_listeners", "DROP TABLE rollout_targets", "DROP TABLE rollouts", "DROP TABLE releases",
		"DELETE FROM " + store.RevisionTable + " WHERE version >= '" + builtIn + "'",
		"PRAGMA foreign_keys = ON",
	} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = conn.Close()
	if err := os.RemoveAll(filepath.Join(h.cfg.StateDir, "connector")); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	stop := h.run(t)
	waitFor(t, "not ready", h.ready)
	stop()
	db, sys, _ := h.db(t)
	id, err := agent.ReadIdentity(h.cfg.Connector().IdentityDir)
	if err != nil || id.AgentID == r.ConnectorID {
		t.Fatalf("the connector: %+v, %v", id, err)
	}
	if c := db.Client().Connector.GetX(sys, id.AgentID); !c.BuiltIn || !db.Client().Gateway.GetX(sys, r.GatewayID).BuiltIn {
		t.Fatal("not built in")
	}
	if n := db.Client().Connector.Query().CountX(sys); n != 1 {
		t.Fatalf("%d connectors, want the one enrolled", n)
	}
	h.run(t)() // and a second start enrolls nothing
	if n := db.Client().Connector.Query().CountX(sys); n != 1 {
		t.Fatalf("%d connectors after a restart", n)
	}
}

// checkRoles: on the all-in-one's registry, the series its gateway and its connector register
// carry their role, the controller's carry none, and the connector has no QUIC socket whose
// metrics it would report (docs/10-operations.md, "Metrics").
func checkRoles(t *testing.T, reg prometheus.Gatherer) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]map[string]bool{}
	for _, mf := range mfs {
		roles[mf.GetName()] = map[string]bool{}
		for _, m := range mf.GetMetric() {
			role := ""
			for _, l := range m.GetLabel() {
				if l.GetName() == "role" {
					role = l.GetValue()
				}
			}
			roles[mf.GetName()][role] = true
		}
	}
	for name, want := range map[string][]string{
		"rpmgr_agent_applied_revision":      {"connector", "gateway"},
		"rpmgr_gateway_sessions":            {"gateway"},
		"rpmgr_quic_gso_enabled":            {"gateway"},
		"rpmgr_controller_control_sessions": {""},
		"go_goroutines":                     {""},
	} {
		got := slices.Sorted(maps.Keys(roles[name]))
		if !slices.Equal(got, want) {
			t.Errorf("%s: role labels %q, want %q", name, got, want)
		}
	}
}
