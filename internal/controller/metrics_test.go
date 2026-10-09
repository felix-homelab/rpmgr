// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// families gathers reg's metrics by name.
func families(t *testing.T, reg *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*dto.MetricFamily{}
	for _, f := range mfs {
		out[f.GetName()] = f
	}
	return out
}

// TestMetrics (docs/10-operations.md, "Metrics"): the controller reports each hostname's latest
// ACME certificate expiry, how long audit entries have waited for a checkpoint, and every rate
// limit's refusals, at 0 from the start.
func TestMetrics(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	org := storetest.Org(t, db, "org-a")
	now := time.Now()
	reg := prometheus.NewRegistry()
	m, err := controller.NewMetrics(reg, db, sys, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	f := families(t, reg)
	if len(f["rpmgr_ratelimit_refused_total"].GetMetric()) != 4 || f["rpmgr_audit_checkpoint_age_seconds"].GetMetric()[0].GetGauge().GetValue() != 0 {
		t.Fatalf("at start: %v %v", f["rpmgr_ratelimit_refused_total"], f["rpmgr_audit_checkpoint_age_seconds"])
	}
	if _, ok := f["rpmgr_acme_cert_expiry_timestamp_seconds"]; ok {
		t.Fatal("an expiry without a certificate")
	}

	soon, later := now.Add(10*24*time.Hour).Truncate(time.Second), now.Add(80*24*time.Hour).Truncate(time.Second)
	c := db.Client()
	c.Certificate.Create().SetOrgID(org).SetSource("acme").SetSans([]string{"app.example.com", "www.example.com"}).SetNotAfter(soon).ExecX(sys)
	c.Certificate.Create().SetOrgID(org).SetSource("acme").SetSans([]string{"app.example.com"}).SetNotAfter(later).ExecX(sys)
	c.Certificate.Create().SetOrgID(org).SetSource("uploaded").SetSans([]string{"up.example.com"}).SetNotAfter(soon).ExecX(sys)
	c.Certificate.Create().SetOrgID(org).SetSource("acme").SetSans([]string{"pending.example.com"}).SetStatus("pending").ExecX(sys)
	entry, err := audit.Record(context.Background(), db, audit.Entry{OrgID: org, ActorType: audit.ActorSystem, ActorID: "test",
		Action: "test.run", Result: audit.Success})
	if err != nil {
		t.Fatal(err)
	}
	now = entry.Time.Add(90 * time.Minute)
	m.Refused(controller.LimitLogin)()
	m.Refused(controller.LimitLogin)()

	f = families(t, reg)
	expiry := map[string]float64{}
	for _, s := range f["rpmgr_acme_cert_expiry_timestamp_seconds"].GetMetric() {
		expiry[s.GetLabel()[0].GetValue()] = s.GetGauge().GetValue()
	}
	if len(expiry) != 2 || expiry["app.example.com"] != float64(later.Unix()) || expiry["www.example.com"] != float64(soon.Unix()) {
		t.Fatalf("ACME expiry: %v", expiry)
	}
	if age := f["rpmgr_audit_checkpoint_age_seconds"].GetMetric()[0].GetGauge().GetValue(); age != (90 * time.Minute).Seconds() {
		t.Fatalf("checkpoint age: %v", age)
	}
	for _, s := range f["rpmgr_ratelimit_refused_total"].GetMetric() {
		want := 0.0
		if s.GetLabel()[0].GetValue() == controller.LimitLogin {
			want = 2
		}
		if s.GetCounter().GetValue() != want {
			t.Fatalf("refusals of %s: %v", s.GetLabel()[0].GetValue(), s.GetCounter().GetValue())
		}
	}
}
