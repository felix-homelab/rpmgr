// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestMigrations_ConnectListenersKeepPlainRoutes: the migration that adds CONNECT listeners
// rebuilds route_tcp on SQLite, which cannot drop a column's NOT NULL in place; a tcp route stored
// before it keeps its row, its port and its idle timeout, in plain mode and on no listener.
func TestMigrations_ConnectListenersKeepPlainRoutes(t *testing.T) {
	ctx := context.Background()
	all, err := migrations.Dir(store.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	files, err := all.Files()
	if err != nil {
		t.Fatal(err)
	}
	var before []string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), "_connect_listeners.sql") {
			break
		}
		before = append(before, f.Name(), string(f.Bytes()))
	}
	if len(before) == 2*len(files) {
		t.Fatal("no connect_listeners migration")
	}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), store.SQLiteOptions{})
	if _, err := store.Migrate(ctx, db, testDir(t, before...)); err != nil {
		t.Fatal(err)
	}
	sys := storetest.SystemCtx(t)
	org := storetest.Org(t, db, "org-a")
	group := db.Client().GatewayGroup.Create().SetOrgID(org).SetName("eu").SaveX(sys)
	route := db.Client().Route.Create().SetOrgID(org).SetName("ssh").SetType("tcp").SetGatewayGroupID(group.ID).SaveX(sys)
	port := db.Client().PortAllocation.Create().SetOrgID(org).SetGatewayGroupID(group.ID).SetProtocol("tcp").SetPort(20001).
		SetRouteID(route.ID).SaveX(sys)
	if _, err := db.Writer.ExecContext(ctx, "INSERT INTO route_tcp (org_id, route_id, port_allocation_id, idle_timeout_seconds) VALUES ($1, $2, $3, 60)",
		org, route.ID, port.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := store.Migrate(ctx, db, all); err != nil || n == 0 {
		t.Fatalf("the later migrations: %d applied, %v", n, err)
	}
	if err := store.Check(ctx, db); err != nil {
		t.Fatal(err)
	}
	got, err := db.Client().RouteTCP.Query().Where(routetcp.RouteID(route.ID)).Only(sys)
	if err != nil {
		t.Fatal(err)
	}
	if got.PortAllocationID == nil || *got.PortAllocationID != port.ID || got.ConnectListenerID != nil ||
		got.ListenerMode != routetcp.ListenerModePlain || got.IdleTimeoutSeconds != 60 {
		t.Fatalf("the route's row after the migration: %+v", got)
	}
}
