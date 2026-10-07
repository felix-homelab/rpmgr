// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// TestReadiness: ready with a reachable, migrated database; not ready without the migrations or
// with the database closed.
func TestReadiness(t *testing.T) {
	ctx := context.Background()
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	dir, err := migrations.Dir(db.Dialect)
	if err != nil {
		t.Fatal(err)
	}
	r := controller.NewReadiness(db, dir, storetest.SystemCtx(t))
	if err := r.Ready(ctx); err != nil {
		t.Fatalf("a migrated database: %v", err)
	}

	empty, err := store.OpenSQLite(ctx, filepath.Join(t.TempDir(), "empty.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = empty.Close() }()
	if err := controller.NewReadiness(empty, dir, storetest.SystemCtx(t)).Ready(ctx); err == nil {
		t.Fatal("ready without migrations")
	}

	_ = db.Close()
	if err := r.Ready(ctx); err == nil {
		t.Fatal("ready with the database closed")
	}
}

// TestControllerMetrics: the controller reports its control sessions and each agent's apply status,
// labelled by stable IDs only, never by addresses.
func TestControllerMetrics(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := pushEnv(t, db)
	reg := telemetry.NewRegistry()
	if err := e.sessions.Register(reg); err != nil {
		t.Fatal(err)
	}
	cert, id := e.agentCert(t)
	st := e.open(t, testCtx(t), cert, hello("0.1.0"))
	recv(t, st)
	e.recvSnapshot(t, st, id)
	e.waitState(t, id.ID, func(s *ent.AgentState) bool { return s.PushedAt != nil })

	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, f := range families {
		if !strings.HasPrefix(f.GetName(), "rpmgr_") {
			continue
		}
		found[f.GetName()] = true
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() != "agent" && l.GetName() != "status" {
					t.Errorf("%s has the label %s", f.GetName(), l.GetName())
				}
				if net.ParseIP(l.GetValue()) != nil || strings.Contains(l.GetValue(), "127.0.0.1") {
					t.Errorf("%s has an address as a label value: %s", f.GetName(), l.GetValue())
				}
			}
		}
		switch f.GetName() {
		case "rpmgr_controller_control_sessions":
			if v := f.GetMetric()[0].GetGauge().GetValue(); v != 1 {
				t.Errorf("control sessions %v", v)
			}
		case "rpmgr_agent_apply_status":
			m := f.GetMetric()
			if len(m) != 1 || m[0].GetLabel()[0].GetValue() != id.ID || m[0].GetLabel()[1].GetValue() != "pending" {
				t.Errorf("apply status %v", m)
			}
		}
	}
	if !found["rpmgr_controller_control_sessions"] || !found["rpmgr_agent_apply_status"] {
		t.Fatalf("metrics found: %v", found)
	}
}
