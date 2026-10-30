// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"log/slog"
	"net/url"
	"time"

	"github.com/felix-homelab/rpmgr/internal/alerts"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/auditsink"
	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/schema"
	ewebhook "github.com/felix-homelab/rpmgr/internal/store/ent/webhook"
)

// AlertOptions configure the alert job.
type AlertOptions struct {
	DB     *store.DB
	Leases *lease.Leases
	Now    func() time.Time
	Logger *slog.Logger
	// RevocationLog is this replica's revocation-log status; nil without one.
	RevocationLog func() revlog.Status
}

// AlertJob is the singleton job that evaluates the alerts of docs/10-operations.md ("Suggested
// alerts", D142) every alerts.Every: it observes which conditions hold, then moves the alerts in
// one fenced transaction, so a replica that lost the lease changes nothing.
func AlertJob(o AlertOptions) lease.Job {
	return lease.Job{Name: "alerts", Reason: "evaluate the alerts", Every: alerts.Every,
		Run: func(ctx context.Context, l lease.Lease) error {
			now := o.Now().UTC()
			obs, err := observe(ctx, o, now)
			if err != nil {
				return err
			}
			var changed []events.Event
			err = store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
				if err := o.Leases.Fence(ctx, tx, l); err != nil {
					return err
				}
				if changed, err = alerts.Apply(ctx, tx, now, obs); err != nil {
					return err
				}
				_, err = alerts.Purge(ctx, tx, now.Add(-events.Keep))
				return err
			})
			if err != nil {
				return err
			}
			for _, e := range changed {
				o.Logger.Info("alert", "event", e.Type, "org", e.OrgID, "summary", e.Summary)
			}
			return nil
		}}
}

// agentRef is an agent the alerts look at.
type agentRef struct{ org, typ, name string }

// observe returns every condition that holds at now. Any failed read fails the pass, so a
// condition is never taken to have ended because it could not be read.
func observe(ctx context.Context, o AlertOptions, now time.Time) ([]alerts.Observation, error) {
	c := o.DB.ReadClient()
	var obs []alerts.Observation
	add := func(org, kind, typ, id, name string, since time.Time) {
		obs = append(obs, alerts.Observation{OrgID: org, Kind: kind, SubjectType: typ, SubjectID: id, SubjectName: name, Since: since})
	}

	// The agents: enabled, not decommissioned, and not ephemeral, which come and go by design.
	agents := map[string]agentRef{}
	gws, err := c.Gateway.Query().Where(gateway.DecommissionedAtIsNil(), gateway.Enabled(true)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range gws {
		agents[g.ID] = agentRef{g.OrgID, "gateway", g.Name}
	}
	cons, err := c.Connector.Query().Where(connector.DecommissionedAtIsNil(), connector.Enabled(true), connector.Ephemeral(false)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, x := range cons {
		agents[x.ID] = agentRef{x.OrgID, "connector", x.Name}
	}
	sessions, err := c.AgentSession.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	online := map[string]bool{}
	for _, s := range sessions {
		a, ok := agents[s.ID]
		if !ok {
			continue
		}
		// An agent that never connected has no session and is no alert: it is not set up yet.
		if online[s.ID] = schema.AgentSessionLive(s.DisconnectedAt, s.LastSeenAt, now); !online[s.ID] {
			since := s.LastSeenAt
			if s.DisconnectedAt != nil {
				since = *s.DisconnectedAt
			}
			add(a.org, alerts.AgentOffline, a.typ, s.ID, a.name, since)
		}
	}
	states, err := c.AgentState.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	for _, st := range states {
		a, ok := agents[st.ID]
		if !ok {
			continue
		}
		// An offline agent's configuration and clock are not known now: its alerts of them neither
		// resolve nor fire again when it is back, and none opens while it is away.
		if !online[st.ID] {
			for _, kind := range []string{alerts.ConfigNotApplied, alerts.ClockSkew} {
				obs = append(obs, alerts.Observation{OrgID: a.org, Kind: kind, SubjectType: a.typ, SubjectID: st.ID, SubjectName: a.name, Unknown: true})
			}
			continue
		}
		if s := snapshot.ApplyStatus(st, now); s == snapshot.ApplyRejected || s == snapshot.ApplyTimedOut {
			add(a.org, alerts.ConfigNotApplied, a.typ, st.ID, a.name, time.Time{})
		}
		if off := time.Duration(st.ClockOffsetMs) * time.Millisecond; off > alerts.ClockSkewOver || off < -alerts.ClockSkewOver {
			add(a.org, alerts.ClockSkew, a.typ, st.ID, a.name, time.Time{})
		}
	}

	// Agent certificates: the newest unrevoked one of each agent expires within the window.
	certs, err := c.IssuedCertificate.Query().Where(issuedcertificate.RevokedAtIsNil(),
		issuedcertificate.SubjectTypeIn(issuedcertificate.SubjectTypeConnector, issuedcertificate.SubjectTypeGateway)).All(ctx)
	if err != nil {
		return nil, err
	}
	newest := map[string]time.Time{}
	for _, x := range certs {
		if x.NotAfter.After(newest[x.SubjectID]) {
			newest[x.SubjectID] = x.NotAfter
		}
	}
	for id, at := range newest {
		if a, ok := agents[id]; ok && at.Sub(now) < alerts.AgentCertWithin {
			add(a.org, alerts.AgentCertExpiring, a.typ, id, a.name, time.Time{})
		}
	}

	// Public certificates from ACME that expire within the window.
	pub, err := c.Certificate.Query().Where(certificate.SourceEQ(certificate.SourceAcme), certificate.NotAfterNotNil(),
		certificate.NotAfterLT(now.Add(alerts.PublicCertWithin))).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, x := range pub {
		name := ""
		if len(x.Sans) > 0 {
			name = x.Sans[0]
		}
		add(x.OrgID, alerts.PublicCertExpiring, "certificate", x.ID, name, time.Time{})
	}

	// Routes without a ready target, per org.
	orgs, err := c.Org.Query().IDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, org := range orgs {
		rs, err := apisvc.RoutesWithoutReadyTarget(ctx, c, org, now)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			add(org, alerts.RouteNoReadyTarget, "route", r.ID, r.Name, time.Time{})
		}
	}

	// Webhook endpoints without a success for an hour while deliveries failed; an instance
	// endpoint's is an instance alert.
	hooks, err := c.Webhook.Query().Where(ewebhook.Enabled(true), ewebhook.FailingSinceLTE(now.Add(-alerts.WebhookFailingFor))).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range hooks {
		name := h.URL
		if u, err := url.Parse(h.URL); err == nil {
			name = u.Hostname() // the URL's path may hold the receiver's token
		}
		add(deref(h.OrgID), alerts.WebhookFailing, "webhook", h.ID, name, *h.FailingSince)
	}

	// The instance's alerts.
	oldest, pending, err := audit.Uncovered(ctx, o.DB)
	if err != nil {
		return nil, err
	}
	if pending && now.Sub(oldest) > alerts.CheckpointsBehindFor {
		add("", alerts.CheckpointsBehind, "instance", "audit", "audit checkpoints", time.Time{})
	}
	if o.RevocationLog != nil && o.RevocationLog().Alerting(now) {
		add("", alerts.RevocationLogOnHost, "instance", "revocation_log", "revocation log", time.Time{})
	}
	backlogs, err := auditsink.Backlogs(ctx, o.DB)
	if err != nil {
		return nil, err
	}
	for _, b := range backlogs {
		if b.Enabled && !b.Oldest.IsZero() && now.Sub(b.Oldest) > alerts.AuditSinkBacklogFor {
			add("", alerts.AuditSinkBacklog, "audit_sink", b.SinkID, b.Sink, time.Time{})
		}
	}
	return obs, nil
}
