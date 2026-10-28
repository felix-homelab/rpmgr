// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/alerts"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/alert"
	"github.com/felix-homelab/rpmgr/internal/store/ent/event"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestAlertJob (#647): the job observes each condition of the alerts the controller evaluates
// from its own state, fires each alert once its duration passed, leaves out what is not set up,
// disabled or ephemeral, resolves what ended, and with a lost lease changes nothing.
func TestAlertJob(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	org := storetest.Org(t, db, "org-a")
	sys := storetest.SystemCtx(t)
	c := db.Client()
	now := time.Now().UTC().Truncate(time.Second)

	group := c.GatewayGroup.Create().SetOrgID(org).SetName("eu").SaveX(sys)
	gw := c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group.ID).SetName("gw1").SetTunnelEndpoints([]string{"gw1.example:443"}).SaveX(sys)
	unset := c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group.ID).SetName("gw2").SetTunnelEndpoints([]string{"gw2.example:443"}).SaveX(sys)
	connector := func(name string, ephemeral, enabled bool) *ent.Connector {
		return c.Connector.Create().SetOrgID(org).SetName(name).SetSpiffeID("spiffe://t/org/" + org + "/connector/" + name).
			SetPubkeySha256(name).SetEphemeral(ephemeral).SetEnabled(enabled).SaveX(sys)
	}
	nas, ci, off := connector("nas", false, true), connector("ci", true, true), connector("off", false, false)
	session := func(id string, disconnected *time.Time) {
		c.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_test").SetConnectedAt(now.Add(-time.Hour)).
			SetLastSeenAt(now).SetNillableDisconnectedAt(disconnected).ExecX(sys)
	}
	gone := now.Add(-10 * time.Minute)
	session(gw.ID, &gone)
	session(ci.ID, &gone)
	session(off.ID, &gone)
	session(nas.ID, nil)
	// nas runs 40 s off and rejected the snapshot it was sent last.
	c.AgentState.Create().SetID(nas.ID).SetOrgID(org).SetClockOffsetMs(40_000).SetPushedHash([]byte("h2")).SetPushedAt(now).
		SetRejectedHash([]byte("h2")).SetAppliedHash([]byte("h1")).ExecX(sys)
	serial := 0
	issued := func(subject, kind string, notAfter time.Time, revoked bool) {
		serial++
		cr := c.IssuedCertificate.Create().SetID(fmt.Sprintf("%04x", serial)).SetOrgID(org).SetSubjectID(subject).SetSubjectType(issuedcertificate.SubjectType(kind)).
			SetSpiffeID("spiffe://t/" + subject).SetPubkeySha256("k").SetNotBefore(notAfter.Add(-7 * 24 * time.Hour)).SetNotAfter(notAfter)
		if revoked {
			cr.SetRevokedAt(now)
		}
		cr.ExecX(sys)
	}
	issued(nas.ID, "connector", now.Add(47*time.Hour), false) // renewal failing
	issued(gw.ID, "gateway", now.Add(time.Hour), false)       // an older one, superseded by
	issued(gw.ID, "gateway", now.Add(6*24*time.Hour), false)  // the newest
	issued(gw.ID, "gateway", now.Add(9*24*time.Hour), true)   // revoked: does not count
	soon := c.Certificate.Create().SetOrgID(org).SetSource("acme").SetSans([]string{"shop.example.com"}).SetNotBefore(now).
		SetNotAfter(now.Add(3 * 24 * time.Hour)).SaveX(sys)
	c.Certificate.Create().SetOrgID(org).SetSource("acme").SetSans([]string{"blog.example.com"}).SetNotBefore(now).
		SetNotAfter(now.Add(30 * 24 * time.Hour)).ExecX(sys)
	c.Certificate.Create().SetOrgID(org).SetSource("uploaded").SetSans([]string{"old.example.com"}).SetNotBefore(now).
		SetNotAfter(now.Add(24 * time.Hour)).ExecX(sys)
	web := c.Route.Create().SetOrgID(org).SetName("web").SetType("tls_passthrough").SetGatewayGroupID(group.ID).SaveX(sys)
	c.Route.Create().SetOrgID(org).SetName("idle").SetType("tls_passthrough").SetGatewayGroupID(group.ID).SetEnabled(false).ExecX(sys)

	clock := now
	shipping := revlog.Status{Sink: true, Unshipped: 1, Oldest: now.Add(-6 * time.Minute)}
	leases := lease.New(db, "ctn_test", nil)
	job := controller.AlertJob(controller.AlertOptions{DB: db, Leases: leases, Now: func() time.Time { return clock }, Logger: slog.New(slog.DiscardHandler),
		RevocationLog: func() revlog.Status { return shipping }})
	held, ok, err := leases.TryAcquire(sys, "alerts")
	if err != nil || !ok {
		t.Fatal("no lease", err)
	}
	run := func() {
		t.Helper()
		if err := job.Run(context.WithoutCancel(sys), held); err != nil {
			t.Fatal(err)
		}
	}
	firing := func() map[string]string {
		out := map[string]string{}
		for _, a := range c.Alert.Query().Where(alert.StateEQ(alert.StateFiring)).AllX(sys) {
			out[a.Kind] += a.SubjectID + " "
		}
		return out
	}

	run()
	want := map[string]string{
		alerts.AgentOffline:        gw.ID + " ",
		alerts.ConfigNotApplied:    nas.ID + " ",
		alerts.ClockSkew:           nas.ID + " ",
		alerts.AgentCertExpiring:   nas.ID + " ",
		alerts.PublicCertExpiring:  soon.ID + " ",
		alerts.RevocationLogOnHost: "revocation_log ",
	}
	got := firing()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s fires for %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("firing %v, want %v", got, want)
	}
	if n := c.Alert.Query().Where(alert.StateEQ(alert.StatePending)).CountX(sys); n != 1 {
		t.Errorf("%d pending, want the route alert waiting its 2 min", n)
	}
	_ = unset

	// Two minutes on, the route alert fires; once the gateway is back and the log shipped, theirs
	// resolve.
	clock = now.Add(2 * time.Minute)
	c.AgentSession.UpdateOneID(gw.ID).ClearDisconnectedAt().SetLastSeenAt(clock).ExecX(sys)
	shipping = revlog.Status{Sink: true}
	run()
	if got := firing()[alerts.RouteNoReadyTarget]; got != web.ID+" " {
		t.Fatalf("route alert fires for %q, want %s", got, web.ID)
	}
	var resolved []string
	for _, e := range c.Event.Query().Where(event.Type("alert.resolve")).AllX(sys) {
		resolved = append(resolved, e.SubjectID)
	}
	slices.Sort(resolved)
	if want := []string{gw.ID, "revocation_log"}; !slices.Equal(resolved, want) {
		t.Fatalf("resolved %v, want %v", resolved, want)
	}
	fires := c.Event.Query().Where(event.Type("alert.fire")).CountX(sys)
	run()
	if n := c.Event.Query().Where(event.Type("alert.fire")).CountX(sys); n != fires {
		t.Fatalf("%d alert.fire events after another pass, want still %d", n, fires)
	}

	// nas drops for a pass and comes back, its snapshot still rejected and its clock still off:
	// while it is away nothing is known of either, so neither alert resolves or fires again; its
	// offline alert waits its 5 min and goes without an event.
	all := c.Event.Query().CountX(sys)
	clock = now.Add(3 * time.Minute)
	c.AgentSession.UpdateOneID(nas.ID).SetDisconnectedAt(clock).ExecX(sys)
	run()
	if got := firing(); got[alerts.ConfigNotApplied] != nas.ID+" " || got[alerts.ClockSkew] != nas.ID+" " {
		t.Fatalf("firing %v while nas is offline, want its configuration and clock alerts kept", got)
	}
	clock = now.Add(4 * time.Minute)
	c.AgentSession.UpdateOneID(nas.ID).ClearDisconnectedAt().SetLastSeenAt(clock).ExecX(sys)
	run()
	if n := c.Event.Query().CountX(sys); n != all {
		t.Fatalf("%d events after nas was offline for a pass, want none", n-all)
	}
	// A replica that lost the lease writes nothing.
	clock = now.Add(time.Hour)
	before := c.Event.Query().CountX(sys)
	c.Route.UpdateOne(web).SetEnabled(false).ExecX(sys)
	if err := job.Run(context.WithoutCancel(sys), lease.Lease{Name: "alerts", Token: held.Token + 1}); !errors.Is(err, lease.ErrLost) {
		t.Fatalf("lost lease: %v", err)
	}
	if c.Event.Query().CountX(sys) != before || firing()[alerts.RouteNoReadyTarget] == "" {
		t.Fatal("a pass without the lease changed the alerts")
	}
}
