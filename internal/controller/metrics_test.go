// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/cfranges"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/dns/budget"
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
	// The Cloudflare IP ranges' age starts at the built-in list's, and each refresh result at 0.
	if age := f["rpmgr_dns_cloudflare_ranges_age_seconds"].GetMetric()[0].GetGauge().GetValue(); age != now.Sub(cfranges.Fallback().At).Seconds() {
		t.Fatalf("ranges age %v at start", age)
	}
	if len(f["rpmgr_dns_cloudflare_ranges_refresh_total"].GetMetric()) != 3 {
		t.Fatalf("refresh results at start: %v", f["rpmgr_dns_cloudflare_ranges_refresh_total"])
	}
	m.RangesResult()(controller.RangesRejected)
	rejected := 0.0
	for _, mt := range families(t, reg)["rpmgr_dns_cloudflare_ranges_refresh_total"].GetMetric() {
		if mt.GetLabel()[0].GetValue() == controller.RangesRejected {
			rejected = mt.GetCounter().GetValue()
		}
	}
	if rejected != 1 {
		t.Fatalf("rejected count %v, want 1", rejected)
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

// TestMetrics_DNS (docs/10-operations.md, "Metrics"): the names by status, the records by state, a
// token's expiry, the shared budget's use and block of each provider are read at each scrape; the
// passes and the requests are counted as they happen. An instance without a provider reports none
// of the gauges.
func TestMetrics_DNS(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	org := storetest.Org(t, db, "org-a")
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	reg := prometheus.NewRegistry()
	m, err := controller.NewMetrics(reg, db, sys, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"rpmgr_dns_names", "rpmgr_dns_records", "rpmgr_dns_provider_token_expiry_timestamp_seconds", "rpmgr_dns_rate_budget_used", "rpmgr_dns_rate_blocked_seconds"} {
		if _, ok := families(t, reg)[n]; ok {
			t.Fatalf("%s without a provider", n)
		}
	}

	c := db.Client()
	expiry := now.Add(72 * time.Hour)
	p := c.DNSProvider.Create().SetOrgID(org).SetKind("cloudflare").SetName("cf").SetCredentialEnc([]byte("x")).SetTokenExpiresAt(expiry).SaveX(sys)
	c.DNSProvider.Create().SetOrgID(org).SetKind("cloudflare").SetName("cf-no-expiry").SetCredentialEnc([]byte("x")).ExecX(sys)
	z := c.DNSZone.Create().SetOrgID(org).SetDNSProviderID(p.ID).SetProviderZoneID("pz").SetName("example.com").SaveX(sys)
	c.DNSNameStatus.Create().SetOrgID(org).SetDNSZoneID(z.ID).SetName("a.example.com").SetStatus("published").ExecX(sys)
	c.DNSNameStatus.Create().SetOrgID(org).SetDNSZoneID(z.ID).SetName("b.example.com").SetStatus("published").ExecX(sys)
	c.DNSNameStatus.Create().SetOrgID(org).SetDNSZoneID(z.ID).SetName("c.example.com").SetStatus("conflict").ExecX(sys)
	c.DNSRecord.Create().SetOrgID(org).SetDNSZoneID(z.ID).SetName("a.example.com").SetType("A").SetContent("192.0.2.1").SetTTL(60).SetState("synced").ExecX(sys)
	b := &budget.Budget{DB: db, Now: func() time.Time { return now }}
	for range 3 {
		if err := b.Take(sys, p.ID, budget.Job); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Block(sys, p.ID, now.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}
	m.SyncResult()("example.com", "ok")
	m.SyncResult()("example.com", "ok")
	m.SyncResult()("example.com", "rate_limited")
	m.ProviderRequest()(p.ID, "200")
	m.ProviderRequest()(p.ID, "429")

	value := func(name string, labels ...string) float64 {
		t.Helper()
	next:
		for _, mt := range families(t, reg)[name].GetMetric() {
			values := []string{}
			for _, l := range mt.GetLabel() { // sorted by label name, not in the order declared
				values = append(values, l.GetValue())
			}
			for _, want := range labels {
				if !slices.Contains(values, want) {
					continue next
				}
			}
			if mt.GetCounter() != nil {
				return mt.GetCounter().GetValue()
			}
			return mt.GetGauge().GetValue()
		}
		t.Fatalf("%s%v is absent", name, labels)
		return 0
	}
	for _, c := range []struct {
		name   string
		labels []string
		want   float64
	}{
		{"rpmgr_dns_names", []string{"example.com", "published"}, 2},
		{"rpmgr_dns_names", []string{"example.com", "conflict"}, 1},
		{"rpmgr_dns_records", []string{"example.com", "synced"}, 1},
		{"rpmgr_dns_provider_token_expiry_timestamp_seconds", []string{p.ID}, float64(expiry.Unix())},
		{"rpmgr_dns_rate_budget_used", []string{p.ID}, 3},
		{"rpmgr_dns_rate_blocked_seconds", []string{p.ID}, 90},
		{"rpmgr_dns_sync_runs_total", []string{"example.com", "ok"}, 2},
		{"rpmgr_dns_sync_runs_total", []string{"example.com", "rate_limited"}, 1},
		{"rpmgr_dns_provider_requests_total", []string{p.ID, "429"}, 1},
	} {
		if got := value(c.name, c.labels...); got != c.want {
			t.Errorf("%s%v = %v, want %v", c.name, c.labels, got, c.want)
		}
	}
	// The provider without an expiry has none: one series only.
	if n := len(families(t, reg)["rpmgr_dns_provider_token_expiry_timestamp_seconds"].GetMetric()); n != 1 {
		t.Errorf("%d expiry series, want 1", n)
	}
}
