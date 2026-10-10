// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetrafficdaily"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetraffichourly"
	"github.com/felix-homelab/rpmgr/internal/store/ent/trafficbaseline"
)

// maxCounters bounds the routes of one gateway report that are rolled up.
const maxCounters = 4096

// traffic is the increase of a route's counters over a report.
type traffic struct{ bytesIn, bytesOut, conns, errors int64 }

func (t traffic) zero() bool { return t == traffic{} }

// counters rolls a gateway's route counters up into the hourly and daily traffic of the routes
// (docs/06-data-model.md, "Desired vs observed state"): each counter's increase over the last
// report goes into the bucket of now. Counters start anew with the gateway's process, which a new
// boot ID shows, and with a route the gateway forgot, which a lower counter shows: then all of
// them count. A route that is gone is skipped.
func (s *Sessions) counters(id pki.Identity, list []*agentv1.RouteCounters) {
	if len(list) == 0 {
		return
	}
	if len(list) > maxCounters {
		list = list[:maxCounters]
	}
	err := store.WriteTx(s.sys, s.db, func(tx *ent.Tx) error {
		boot := ""
		if st, err := tx.AgentState.Get(s.sys, id.ID); err == nil {
			boot = st.BootID
		} else if !ent.IsNotFound(err) {
			return err
		}
		ids := make([]string, 0, len(list))
		for _, c := range list {
			ids = append(ids, c.GetRouteId())
		}
		routes, err := tx.Route.Query().Where(route.IDIn(ids...)).All(s.sys)
		if err != nil {
			return err
		}
		orgOf := map[string]string{}
		for _, r := range routes {
			orgOf[r.ID] = r.OrgID
		}
		bases, err := tx.TrafficBaseline.Query().Where(trafficbaseline.GatewayID(id.ID)).All(s.sys)
		if err != nil {
			return err
		}
		baseOf := map[string]*ent.TrafficBaseline{}
		for _, b := range bases {
			baseOf[b.RouteID] = b
		}
		slices.SortFunc(list, func(a, b *agentv1.RouteCounters) int { return strings.Compare(a.GetRouteId(), b.GetRouteId()) })
		for _, c := range list {
			org, ok := orgOf[c.GetRouteId()]
			if !ok {
				continue
			}
			cur := traffic{counter(c.GetBytesIn()), counter(c.GetBytesOut()), counter(c.GetConnectionsTotal()), counter(c.GetErrorsTotal())}
			base := baseOf[c.GetRouteId()]
			delta := cur
			if base != nil && base.BootID == boot && cur.bytesIn >= base.BytesIn && cur.bytesOut >= base.BytesOut &&
				cur.conns >= base.Connections && cur.errors >= base.Errors {
				delta = traffic{cur.bytesIn - base.BytesIn, cur.bytesOut - base.BytesOut, cur.conns - base.Connections, cur.errors - base.Errors}
			}
			if err := s.rollUp(tx, org, c.GetRouteId(), delta); err != nil {
				return err
			}
			if err := s.rebase(tx, base, id, org, c.GetRouteId(), boot, cur); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.Error("cannot roll up a gateway's route counters", "gateway", id.ID, "error", err)
	}
}

// counter is a reported counter as the store keeps it.
func counter(v uint64) int64 { return int64(min(v, 1<<63-1)) } //nolint:gosec // G115: bounded above

// rollUp adds a route's traffic to its hourly and daily buckets of now.
func (s *Sessions) rollUp(tx *ent.Tx, org, routeID string, d traffic) error {
	if d.zero() {
		return nil
	}
	now := s.now().UTC()
	hour, day := now.Truncate(time.Hour), time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	h, err := tx.RouteTrafficHourly.Query().Where(routetraffichourly.RouteID(routeID), routetraffichourly.Bucket(hour)).Only(s.sys)
	switch {
	case ent.IsNotFound(err):
		err = tx.RouteTrafficHourly.Create().SetOrgID(org).SetRouteID(routeID).SetBucket(hour).SetBytesIn(d.bytesIn).
			SetBytesOut(d.bytesOut).SetConnections(d.conns).SetErrors(d.errors).Exec(s.sys)
	case err == nil:
		err = h.Update().AddBytesIn(d.bytesIn).AddBytesOut(d.bytesOut).AddConnections(d.conns).AddErrors(d.errors).Exec(s.sys)
	}
	if err != nil {
		return err
	}
	dd, err := tx.RouteTrafficDaily.Query().Where(routetrafficdaily.RouteID(routeID), routetrafficdaily.Bucket(day)).Only(s.sys)
	switch {
	case ent.IsNotFound(err):
		return tx.RouteTrafficDaily.Create().SetOrgID(org).SetRouteID(routeID).SetBucket(day).SetBytesIn(d.bytesIn).
			SetBytesOut(d.bytesOut).SetConnections(d.conns).SetErrors(d.errors).Exec(s.sys)
	case err == nil:
		return dd.Update().AddBytesIn(d.bytesIn).AddBytesOut(d.bytesOut).AddConnections(d.conns).AddErrors(d.errors).Exec(s.sys)
	}
	return err
}

// rebase records a gateway's latest counters of a route as the baseline of its next report.
func (s *Sessions) rebase(tx *ent.Tx, base *ent.TrafficBaseline, id pki.Identity, org, routeID, boot string, t traffic) error {
	now := s.now()
	if base == nil {
		return tx.TrafficBaseline.Create().SetOrgID(org).SetGatewayID(id.ID).SetRouteID(routeID).SetBootID(boot).
			SetBytesIn(t.bytesIn).SetBytesOut(t.bytesOut).SetConnections(t.conns).SetErrors(t.errors).SetReportedAt(now).Exec(s.sys)
	}
	return base.Update().SetBootID(boot).SetBytesIn(t.bytesIn).SetBytesOut(t.bytesOut).SetConnections(t.conns).SetErrors(t.errors).
		SetReportedAt(now).Exec(s.sys)
}

// RollupEvery is how often the rollup job removes traffic past its retention.
const RollupEvery = time.Hour

// RollupOptions are the inputs of RollupJob.
type RollupOptions struct {
	DB     *store.DB
	Leases *lease.Leases
	Now    func() time.Time
	Logger *slog.Logger
}

// RollupJob is the singleton job that keeps the traffic rollups for the instance's retention
// (docs/06-data-model.md, "Desired vs observed state"): hourly and daily buckets past their
// retention go, and so do the baselines of routes no gateway reported for the hourly retention.
func RollupJob(o RollupOptions) lease.Job {
	return lease.Job{Name: "rollups", Reason: "keep the route traffic rollups", Every: RollupEvery,
		Run: func(ctx context.Context, l lease.Lease) error {
			set, _, err := settings.Instance(ctx, o.DB.ReadClient())
			if err != nil {
				return err
			}
			now := o.Now().UTC()
			hourly, daily := now.Add(-set.GetHourlyRollupRetention().AsDuration()), now.Add(-set.GetDailyRollupRetention().AsDuration())
			return store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
				if err := o.Leases.Fence(ctx, tx, l); err != nil {
					return err
				}
				if _, err := tx.RouteTrafficHourly.Delete().Where(routetraffichourly.BucketLT(hourly)).Exec(ctx); err != nil {
					return err
				}
				if _, err := tx.RouteTrafficDaily.Delete().Where(routetrafficdaily.BucketLT(daily)).Exec(ctx); err != nil {
					return err
				}
				_, err := tx.TrafficBaseline.Delete().Where(trafficbaseline.ReportedAtLT(hourly)).Exec(ctx)
				return err
			})
		}}
}
