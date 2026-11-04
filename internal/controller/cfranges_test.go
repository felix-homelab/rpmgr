// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/alerts"
	"github.com/felix-homelab/rpmgr/internal/cfranges"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/alert"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// lists are the built-in list's ranges as strings, from which the tests make the lists Cloudflare
// might answer with.
func lists() (v4, v6 []string) {
	f := cfranges.Fallback()
	for _, p := range f.IPv4 {
		v4 = append(v4, p.String())
	}
	for _, p := range f.IPv6 {
		v6 = append(v6, p.String())
	}
	return v4, v6
}

func answer(v4, v6 []string) string {
	q := func(l []string) string {
		out := []string{}
		for _, s := range l {
			out = append(out, `"`+s+`"`)
		}
		return "[" + strings.Join(out, ",") + "]"
	}
	return fmt.Sprintf(`{"result":{"ipv4_cidrs":%s,"ipv6_cidrs":%s},"success":true}`, q(v4), q(v6))
}

// TestCloudflareRangesJob (docs/15-dns.md, "Proxied HTTP routes"): the job fetches the list when
// the stored one is a day old, stores an accepted one, keeps the list in use for an empty or a
// largely different one and when Cloudflare cannot be reached, counts each result, does nothing
// while the setting is off, and with a lost lease stores nothing.
func TestCloudflareRangesJob(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	v4, v6 := lists()
	var body atomic.Value
	var status atomic.Int32
	var hits atomic.Int32
	body.Store(answer(v4[2:], v6)) // two IPv4 ranges fewer than the built-in list
	status.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()

	clock := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	results := map[string]int{}
	leases := lease.New(db, "ctn_test", nil)
	job := controller.CloudflareRangesJob(controller.CloudflareRangesOptions{DB: db, Leases: leases, Now: func() time.Time { return clock },
		Logger: slog.New(slog.DiscardHandler), URL: srv.URL, Result: func(r string) { results[r]++ }})
	held, ok, err := leases.TryAcquire(sys, "cloudflare-ranges")
	if err != nil || !ok {
		t.Fatal("no lease", err)
	}
	run := func() error { return job.Run(context.WithoutCancel(sys), held) }
	stored := func() *rpmgrv1.CloudflareIpRanges {
		t.Helper()
		s, _, err := settings.Instance(sys, db.Client())
		if err != nil {
			t.Fatal(err)
		}
		return s.GetCloudflareIpRanges()
	}

	// Offline from the start: the built-in list stays in use, nothing is stored.
	status.Store(503)
	if err := run(); !errors.Is(err, cfranges.ErrFetch) || stored() != nil || results[controller.RangesFailed] != 1 {
		t.Fatalf("offline: err %v, stored %v, results %v", err, stored(), results)
	}
	s, _, _ := settings.Instance(sys, db.Client())
	if got := cfranges.FromSettings(s); !got.At.Equal(cfranges.Fallback().At) {
		t.Fatalf("offline: the list in use is from %s, want the fallback", got.At)
	}

	// A refresh within the sanity bounds is stored with its time.
	status.Store(200)
	if err := run(); err != nil || results[controller.RangesOK] != 1 {
		t.Fatalf("first refresh: %v, results %v", err, results)
	}
	first := stored()
	if !first.GetRefreshedAt().AsTime().Equal(clock) || len(first.GetIpv4Cidrs()) != len(v4)-2 || len(first.GetIpv6Cidrs()) != len(v6) {
		t.Fatalf("stored %v", first)
	}
	if n := db.Client().ConfigRevision.Query().CountX(sys); n != 1 {
		t.Fatalf("%d revisions, want the one of the refresh", n)
	}

	// Within a day nothing is fetched; a day on, it is.
	before := hits.Load()
	clock = clock.Add(23 * time.Hour)
	if err := run(); err != nil || hits.Load() != before {
		t.Fatalf("23 h later: err %v, %d requests, want none", err, hits.Load()-before)
	}
	clock = clock.Add(2 * time.Hour)
	body.Store(answer(append(v4[2:], "192.0.2.0/24"), v6))
	if err := run(); err != nil || hits.Load() != before+1 || len(stored().GetIpv4Cidrs()) != len(v4)-1 {
		t.Fatalf("25 h later: err %v, stored %v", err, stored())
	}
	good := stored()

	// An empty list, a list that has lost or gained most entries, and a body that is no list are
	// rejected: the stored list stays, the job reports it, and it is tried again at the next run.
	clock = clock.Add(25 * time.Hour)
	for name, b := range map[string]string{
		"empty":        `{"result":{"ipv4_cidrs":[],"ipv6_cidrs":[]},"success":true}`,
		"no IPv4":      answer(nil, v6),
		"most changed": answer([]string{"1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24"}, []string{"2001:db8::/32"}),
		"everything":   answer([]string{"0.0.0.0/0"}, v6),
		"not a list":   `<html>`,
	} {
		body.Store(b)
		if err := run(); !errors.Is(err, cfranges.ErrRejected) || !proto.Equal(stored(), good) {
			t.Errorf("%s: err %v, stored %v; want a rejection and the old list", name, err, stored())
		}
	}
	if results[controller.RangesRejected] != 5 {
		t.Errorf("results %v, want 5 rejected", results)
	}

	// Cloudflare unreachable: the stored list stays.
	status.Store(500)
	if err := run(); !errors.Is(err, cfranges.ErrFetch) || !proto.Equal(stored(), good) {
		t.Errorf("failing source: err %v, stored %v", err, stored())
	}

	// With the setting off nothing is fetched, however old the list.
	status.Store(200)
	body.Store(answer(v4, v6))
	if _, err := settings.UpdateInstance(sys, db, &rpmgrv1.InstanceSettings{CloudflareIpRefresh: proto.Bool(false)},
		&fieldmaskpb.FieldMask{Paths: []string{"cloudflare_ip_refresh"}}, 0); err != nil {
		t.Fatal(err)
	}
	before = hits.Load()
	if err := run(); err != nil || hits.Load() != before || !proto.Equal(stored(), good) {
		t.Errorf("refresh off: err %v, %d requests", err, hits.Load()-before)
	}
	if _, err := settings.UpdateInstance(sys, db, &rpmgrv1.InstanceSettings{}, &fieldmaskpb.FieldMask{Paths: []string{"cloudflare_ip_refresh"}}, 0); err != nil {
		t.Fatal(err)
	}

	// A replica that lost the lease stores nothing.
	if err := leases.Release(sys, held); err != nil {
		t.Fatal(err)
	}
	if err := run(); !errors.Is(err, lease.ErrLost) || !proto.Equal(stored(), good) {
		t.Errorf("lost lease: err %v, want ErrLost and the old list", err)
	}
}

// TestCloudflareRangesStaleAlert (docs/10-operations.md, "Suggested alerts"): the alert fires 15
// minutes after the list in use is older than 3 days while a route is proxied and the refresh is
// on; it does not fire with no proxied route, with the refresh off or with a fresh list, and it
// resolves when a refresh succeeds.
func TestCloudflareRangesStaleAlert(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	clock := now
	proxied := true
	leases := lease.New(db, "ctn_test", nil)
	job := controller.AlertJob(controller.AlertOptions{DB: db, Leases: leases, Now: func() time.Time { return clock }, Logger: slog.New(slog.DiscardHandler),
		ProxiedRoutes: func(context.Context, *ent.Client) (bool, error) { return proxied, nil }})
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
	state := func() string {
		a := db.Client().Alert.Query().Where(alert.Kind(alerts.CloudflareRangesStale)).AllX(sys)
		if len(a) == 0 {
			return "none"
		}
		return string(a[len(a)-1].State)
	}
	record := func(at time.Time) {
		t.Helper()
		r := cfranges.Fallback()
		r.At = at
		if _, err := settings.RecordCloudflareRanges(sys, db, r.Proto(), nil); err != nil {
			t.Fatal(err)
		}
	}
	record(now.Add(-4 * 24 * time.Hour))

	proxied = false
	run()
	if got := state(); got != "none" {
		t.Fatalf("no proxied route: alert %s, want none", got)
	}
	proxied = true
	run()
	if got := state(); got != "pending" {
		t.Fatalf("stale with a proxied route: alert %s, want pending", got)
	}
	clock = now.Add(alerts.CloudflareRangesStaleFor)
	run()
	if got := state(); got != "firing" {
		t.Fatalf("15 min on: alert %s, want firing", got)
	}
	record(clock) // a refresh succeeded
	run()
	if got := state(); got != "resolved" {
		t.Fatalf("after a refresh: alert %s, want resolved", got)
	}

	// With the refresh off the operator chose the list: no alert however old it is.
	clock = clock.Add(10 * 24 * time.Hour)
	if _, err := settings.UpdateInstance(sys, db, &rpmgrv1.InstanceSettings{CloudflareIpRefresh: proto.Bool(false)},
		&fieldmaskpb.FieldMask{Paths: []string{"cloudflare_ip_refresh"}}, 0); err != nil {
		t.Fatal(err)
	}
	run()
	run()
	if n := db.Client().Alert.Query().Where(alert.Kind(alerts.CloudflareRangesStale), alert.StateIn(alert.StatePending, alert.StateFiring)).CountX(sys); n != 0 {
		t.Fatalf("%d open alerts with the refresh off, want none", n)
	}
}

// TestProxiedRoutes: only an enabled http route with dns_proxied makes the Cloudflare ranges matter.
func TestProxiedRoutes(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	org := storetest.Org(t, db, "org-a")
	c := db.Client()
	group := c.GatewayGroup.Create().SetOrgID(org).SetName("eu").SaveX(sys)
	add := func(name string, enabled, proxied bool) {
		r := c.Route.Create().SetOrgID(org).SetName(name).SetType("http").SetGatewayGroupID(group.ID).SetEnabled(enabled).SaveX(sys)
		c.RouteHTTP.Create().SetOrgID(org).SetRouteID(r.ID).SetDNSProxied(proxied).ExecX(sys)
	}
	got := func() bool {
		t.Helper()
		ok, err := controller.ProxiedRoutes(sys, c)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if got() {
		t.Fatal("proxied routes without any route")
	}
	add("plain", true, false)
	add("off", false, true)
	if got() {
		t.Fatal("a route that is not proxied, or not enabled, counted")
	}
	add("cf", true, true)
	if !got() {
		t.Fatal("an enabled proxied route did not count")
	}
}
