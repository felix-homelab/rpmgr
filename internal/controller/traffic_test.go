// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestTrafficRollups (docs/06-data-model.md, "Desired vs observed state"): a gateway's cumulative
// route counters go into the hourly and daily buckets of their report by their increase; the hour
// and the day change at their boundaries in UTC; a lower counter, or a new process of the gateway,
// counts the whole report; an unknown route is skipped.
func TestTrafficRollups(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		var clock atomic.Pointer[time.Time]
		set := func(at time.Time) { clock.Store(&at) }
		// The last second of the current hour, so that certificates stay valid.
		end := time.Now().UTC().Truncate(time.Hour).Add(time.Hour - time.Second)
		set(end)
		e := startSessionsWith(t, db, func(o *controller.SessionsOptions) { o.Now = func() time.Time { return *clock.Load() } })
		sys := storetest.SystemCtx(t)
		group := db.Client().GatewayGroup.Create().SetOrgID(e.org).SetName("eu").SaveX(sys)
		web := db.Client().Route.Create().SetOrgID(e.org).SetName("web").SetType("tcp").SetGatewayGroupID(group.ID).SaveX(sys)
		gwCert, _ := e.certOf(t, pki.KindGateway)
		st := e.open(t, testCtx(t), gwCert, hello("0.1.0"))
		if recv(t, st).GetWelcome() == nil {
			t.Fatal("no Welcome")
		}
		report := func(st controlStream, in, out, conns, errs uint64) {
			t.Helper()
			send(t, st, &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{Counters: []*agentv1.RouteCounters{
				{RouteId: web.ID, BytesIn: in, BytesOut: out, ConnectionsTotal: conns, ErrorsTotal: errs},
				{RouteId: "rt_gone", BytesIn: 999}}}}})
		}
		type row struct{ in, out, conns, errs int64 }
		hourly := func(bucket time.Time) row {
			r, err := db.Client().RouteTrafficHourly.Query().All(sys)
			if err != nil {
				t.Fatal(err)
			}
			for _, h := range r {
				if h.Bucket.Equal(bucket) && h.RouteID == web.ID {
					return row{h.BytesIn, h.BytesOut, h.Connections, h.Errors}
				}
			}
			return row{}
		}
		daily := func(bucket time.Time) row {
			for _, d := range db.Client().RouteTrafficDaily.Query().AllX(sys) {
				if d.Bucket.Equal(bucket) {
					return row{d.BytesIn, d.BytesOut, d.Connections, d.Errors}
				}
			}
			return row{}
		}
		wait := func(what string, f func() row, want row) {
			t.Helper()
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				got := f()
				if got == want {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s: %+v, want %+v", what, got, want)
				}
			}
		}
		hour := end.Truncate(time.Hour)
		day := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, time.UTC)

		report(st, 100, 50, 2, 1)
		wait("the first report", func() row { return hourly(hour) }, row{100, 50, 2, 1})
		set(end.Add(31 * time.Second)) // the next hour
		report(st, 160, 70, 3, 1)
		wait("the increase in the next hour", func() row { return hourly(hour.Add(time.Hour)) }, row{60, 20, 1, 0})
		if got := hourly(hour); got != (row{100, 50, 2, 1}) {
			t.Fatalf("the first hour changed: %+v", got)
		}
		if end.Add(31*time.Second).Day() == end.Day() {
			wait("the day", func() row { return daily(day) }, row{160, 70, 3, 1})
		}
		report(st, 10, 5, 1, 0) // the gateway forgot the route: counted anew
		wait("a lower counter", func() row { return hourly(hour.Add(time.Hour)) }, row{70, 25, 2, 0})

		// A new process of the gateway: everything it reports counts.
		h := hello("0.1.0")
		h.BootId = "boot-2"
		st2 := e.open(t, testCtx(t), gwCert, h)
		if recv(t, st2).GetWelcome() == nil {
			t.Fatal("no Welcome after the restart")
		}
		report(st2, 30, 6, 1, 0)
		wait("after a restart", func() row { return hourly(hour.Add(time.Hour)) }, row{100, 31, 3, 0})

		// The next day starts a new daily bucket: the day after the second hour's, which is already
		// the next one when the test starts in the last hour of a day in UTC.
		second := end.Add(31 * time.Second)
		nextDay := time.Date(second.Year(), second.Month(), second.Day(), 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)
		set(nextDay.Add(time.Second))
		report(st2, 40, 6, 1, 0)
		wait("the next day", func() row { return daily(nextDay) }, row{10, 0, 0, 0})
		if n := db.Client().RouteTrafficHourly.Query().CountX(sys); n != 3 {
			t.Fatalf("%d hourly rows, want 3, none for the unknown route", n)
		}
	})
}

// TestRollupJob: the singleton job removes hourly and daily buckets past their retention, 30 and
// 400 days by default, and the baselines of routes not reported within the hourly retention.
func TestRollupJob(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	sys := storetest.SystemCtx(t)
	now := time.Now().UTC().Truncate(time.Hour)
	c := db.Client()
	for i, age := range []time.Duration{0, 29 * 24 * time.Hour, 31 * 24 * time.Hour, 399 * 24 * time.Hour, 401 * 24 * time.Hour} {
		b := now.Add(-age)
		c.RouteTrafficHourly.Create().SetOrgID(e.org).SetRouteID(fmt.Sprint("rt_", i)).SetBucket(b).SetBytesIn(1).SetBytesOut(1).
			SetConnections(1).SetErrors(0).ExecX(sys)
		c.RouteTrafficDaily.Create().SetOrgID(e.org).SetRouteID(fmt.Sprint("rt_", i)).SetBucket(b).SetBytesIn(1).SetBytesOut(1).
			SetConnections(1).SetErrors(0).ExecX(sys)
		c.TrafficBaseline.Create().SetOrgID(e.org).SetGatewayID("gw_1").SetRouteID(fmt.Sprint("rt_", i)).SetBytesIn(1).SetBytesOut(1).
			SetConnections(1).SetErrors(0).SetReportedAt(b).ExecX(sys)
	}
	leases := lease.New(db, "ctn_test", nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		leases.Run(ctx, controller.RollupJob(controller.RollupOptions{DB: db, Leases: leases, Now: func() time.Time { return now }}),
			func(err error) { t.Errorf("job: %v", err) })
		close(done)
	}()
	waitUntil(t, func() bool { return c.RouteTrafficDaily.Query().CountX(sys) == 4 })
	cancel()
	<-done
	if n := c.RouteTrafficHourly.Query().CountX(sys); n != 2 {
		t.Fatalf("%d hourly buckets left, want the 2 within 30 days", n)
	}
	if n := c.TrafficBaseline.Query().CountX(sys); n != 2 {
		t.Fatalf("%d baselines left, want the 2 reported within 30 days", n)
	}
}
