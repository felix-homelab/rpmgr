// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/alerts"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/alert"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestDNSAlerts (docs/10-operations.md, "Suggested alerts"): a held zone, a zone whose provider
// fails, a drifted record, a name in conflict and a provider whose token is refused or about to
// expire each raise their alert for the org that owns them, the ones with a duration only after it;
// a disabled zone raises none; and each resolves when its condition ends.
func TestDNSAlerts(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	org := storetest.Org(t, db, "org-a")
	c := db.Client()
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	clock := now
	leases := lease.New(db, "ctn_test", nil)
	job := controller.AlertJob(controller.AlertOptions{DB: db, Leases: leases, Now: func() time.Time { return clock }, Logger: slog.New(slog.DiscardHandler)})
	held, _, err := leases.TryAcquire(sys, "alerts")
	if err != nil {
		t.Fatal(err)
	}
	run := func() {
		t.Helper()
		if err := job.Run(context.WithoutCancel(sys), held); err != nil {
			t.Fatal(err)
		}
	}
	state := func(kind string) string {
		a := c.Alert.Query().Where(alert.Kind(kind)).AllX(sys)
		if len(a) == 0 {
			return "none"
		}
		return string(a[len(a)-1].State)
	}
	want := func(kind, st string) {
		t.Helper()
		if got := state(kind); got != st {
			t.Fatalf("%s: alert %s, want %s", kind, got, st)
		}
	}

	p := c.DNSProvider.Create().SetOrgID(org).SetKind("cloudflare").SetName("cf").SetCredentialEnc([]byte("x")).SaveX(sys)
	zone := c.DNSZone.Create().SetOrgID(org).SetDNSProviderID(p.ID).SetProviderZoneID("pz1").SetName("example.com").SaveX(sys) // held by default
	off := c.DNSZone.Create().SetOrgID(org).SetDNSProviderID(p.ID).SetProviderZoneID("pz2").SetName("off.example").
		SetSyncState("disabled").SetProviderStatus("unreachable").SaveX(sys)
	c.DNSRecord.Create().SetOrgID(org).SetDNSZoneID(off.ID).SetName("a.off.example").SetType("A").SetContent("192.0.2.1").SetTTL(300).SetState("drifted").ExecX(sys)
	run()
	want(alerts.DNSZoneHeld, "firing")
	for _, k := range []string{alerts.DNSSyncFailing, alerts.DNSRecordDrifted, alerts.DNSConflict, alerts.DNSTokenProblem} {
		want(k, "none") // the disabled zone's problems are nobody's
	}
	if a := c.Alert.Query().Where(alert.Kind(alerts.DNSZoneHeld)).OnlyX(sys); a.SubjectID != zone.ID || a.OrgID == nil || *a.OrgID != org {
		t.Fatalf("the alert is about %s of %v", a.SubjectID, a.OrgID)
	}

	// The zone is approved; its provider fails, a record drifted, a name is in conflict, and the
	// token expires in two days.
	zone.Update().SetSyncState("active").SetProviderStatus("rate_limited").ExecX(sys)
	c.DNSRecord.Create().SetOrgID(org).SetDNSZoneID(zone.ID).SetName("www.example.com").SetType("A").SetContent("192.0.2.2").SetTTL(300).SetState("drifted").ExecX(sys)
	c.DNSNameStatus.Create().SetOrgID(org).SetDNSZoneID(zone.ID).SetName("app.example.com").SetStatus("conflict").SetSince(now).ExecX(sys)
	exp := now.Add(48 * time.Hour)
	p.Update().SetTokenExpiresAt(exp).ExecX(sys)
	run()
	want(alerts.DNSZoneHeld, "resolved")
	want(alerts.DNSRecordDrifted, "firing")
	want(alerts.DNSTokenProblem, "firing")
	want(alerts.DNSSyncFailing, "pending")
	want(alerts.DNSConflict, "pending")
	clock = now.Add(alerts.DNSSyncFailingFor)
	run()
	want(alerts.DNSSyncFailing, "firing")
	want(alerts.DNSConflict, "firing")

	// All is well again, and a refused token is its own cause.
	zone.Update().SetProviderStatus("ok").ExecX(sys)
	c.DNSRecord.Delete().ExecX(sys)
	c.DNSNameStatus.Delete().ExecX(sys)
	p.Update().ClearTokenExpiresAt().SetStatus("invalid").ExecX(sys)
	run()
	want(alerts.DNSSyncFailing, "resolved")
	want(alerts.DNSRecordDrifted, "resolved")
	want(alerts.DNSConflict, "resolved")
	want(alerts.DNSTokenProblem, "firing")
	p.Update().SetStatus("ok").ExecX(sys)
	run()
	want(alerts.DNSTokenProblem, "resolved")
}
