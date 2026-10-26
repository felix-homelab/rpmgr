// SPDX-License-Identifier: Apache-2.0

// Package alerts moves the alerts the controller evaluates through their states
// (docs/10-operations.md, "Suggested alerts"; docs/06-data-model.md, "Observability (Phase 2)").
// The alert job observes which conditions hold now; Apply turns those observations into alert rows
// and writes the events alert.fire and alert.resolve once each, in the job's transaction, so a
// restart or a lease takeover never fires an alert twice.
package alerts

import (
	"context"
	"fmt"
	"time"

	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/alert"
)

// Every is how often the alert job evaluates the conditions (docs/03-connections.md, "Timeouts,
// keepalive and backoff").
const Every = 30 * time.Second

// The kinds of alert the controller evaluates (D142), the names alert_types will choose from.
const (
	AgentOffline         = "agent_offline"
	ConfigNotApplied     = "config_not_applied"
	AgentCertExpiring    = "agent_certificate_expiring"
	PublicCertExpiring   = "public_certificate_expiring"
	RouteNoReadyTarget   = "route_no_ready_connector"
	ClockSkew            = "clock_skew"
	CheckpointsBehind    = "audit_checkpoints_behind"
	RevocationLogOnHost  = "revocation_log_on_host"
	WebhookFailing       = "webhook_failing"
	offlineFor           = 5 * time.Minute
	routeNoReadyFor      = 2 * time.Minute
	AgentCertWithin      = 48 * time.Hour
	PublicCertWithin     = 14 * 24 * time.Hour
	ClockSkewOver        = 30 * time.Second
	CheckpointsBehindFor = time.Hour
	WebhookFailingFor    = time.Hour
)

// For is how long a kind's condition must hold before its alert fires; the conditions with a
// threshold of their own fire as soon as they are seen.
var For = map[string]time.Duration{AgentOffline: offlineFor, RouteNoReadyTarget: routeNoReadyFor}

// titles name each kind for people, in summaries and e-mails.
var titles = map[string]string{
	AgentOffline:        "Agent offline",
	ConfigNotApplied:    "Configuration not applied",
	AgentCertExpiring:   "Certificate renewal failing",
	PublicCertExpiring:  "Public certificate expiring",
	RouteNoReadyTarget:  "Route has no ready connector",
	ClockSkew:           "Clock skew",
	CheckpointsBehind:   "Audit checkpoints behind",
	RevocationLogOnHost: "Revocation log not yet off-host",
	WebhookFailing:      "Webhook endpoint failing",
}

// Observation is a condition that holds now for one subject. Since is when it began, where the
// state tells (an agent's disconnection); zero means when the job first saw it.
type Observation struct {
	OrgID       string // empty: an instance alert
	Kind        string
	SubjectType string
	SubjectID   string
	SubjectName string
	Since       time.Time
}

func (o Observation) key() string {
	return o.OrgID + "\x00" + o.Kind + "\x00" + o.SubjectType + "\x00" + o.SubjectID
}

func keyOf(a *ent.Alert) string {
	org := ""
	if a.OrgID != nil {
		org = *a.OrgID
	}
	return org + "\x00" + a.Kind + "\x00" + a.SubjectType + "\x00" + a.SubjectID
}

// Apply moves the open alerts to what obs says at now, in tx, the job's fenced transaction. obs
// must hold every condition of every kind that holds now: an open alert without an observation
// resolves (a pending one never fired, so it goes without an event). It returns the
// events of the alerts that fired and resolved.
func Apply(ctx context.Context, tx *ent.Tx, now time.Time, obs []Observation) ([]events.Event, error) {
	open, err := tx.Alert.Query().Where(alert.StateIn(alert.StatePending, alert.StateFiring)).All(ctx)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]*ent.Alert, len(open))
	for _, a := range open {
		byKey[keyOf(a)] = a
	}
	var out []events.Event
	seen := map[string]bool{}
	for _, o := range obs {
		k := o.key()
		if seen[k] {
			continue
		}
		seen[k] = true
		a := byKey[k]
		if a == nil {
			since := o.Since
			if since.IsZero() || since.After(now) {
				since = now
			}
			c := tx.Alert.Create().SetKind(o.Kind).SetSubjectType(o.SubjectType).SetSubjectID(o.SubjectID).
				SetSubjectName(o.SubjectName).SetSince(since).SetState(alert.StatePending)
			if o.OrgID != "" {
				c.SetOrgID(o.OrgID)
			}
			if a, err = c.Save(ctx); err != nil {
				return nil, fmt.Errorf("alerts: add %s: %w", o.Kind, err)
			}
		}
		if a.State == alert.StatePending && now.Sub(a.Since) >= For[o.Kind] {
			if err := tx.Alert.UpdateOne(a).SetState(alert.StateFiring).SetFiredAt(now).Exec(ctx); err != nil {
				return nil, err
			}
			ch, err := event(ctx, tx, a, "alert.fire")
			if err != nil {
				return nil, err
			}
			out = append(out, ch)
		}
	}
	for k, a := range byKey {
		if seen[k] {
			continue
		}
		if a.State == alert.StatePending {
			if err := tx.Alert.DeleteOne(a).Exec(ctx); err != nil {
				return nil, err
			}
			continue
		}
		if err := tx.Alert.UpdateOne(a).SetState(alert.StateResolved).SetResolvedAt(now).Exec(ctx); err != nil {
			return nil, err
		}
		ch, err := event(ctx, tx, a, "alert.resolve")
		if err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, nil
}

// event writes the event of a's firing or resolving: its subject is what the alert is about, and
// its summary begins with the alert's kind (docs/07-api.md, "Webhooks (Phase 2)").
func event(ctx context.Context, tx *ent.Tx, a *ent.Alert, typ string) (events.Event, error) {
	e := events.Event{Type: typ, SubjectType: a.SubjectType, SubjectID: a.SubjectID, SubjectName: a.SubjectName}
	if a.OrgID != nil {
		e.OrgID = *a.OrgID
	}
	name := a.SubjectName
	if name == "" {
		name = a.SubjectID
	}
	verb := "fires"
	if typ == "alert.resolve" {
		verb = "resolved"
	}
	e.Summary = fmt.Sprintf("%s: %s %s, %s", a.Kind, Title(a.Kind), verb, name)
	return events.Add(ctx, tx, e)
}

// Title is a kind's name for people.
func Title(kind string) string {
	if t, ok := titles[kind]; ok {
		return t
	}
	return kind
}

// Purge deletes the alerts that resolved before before, in tx.
func Purge(ctx context.Context, tx *ent.Tx, before time.Time) (int, error) {
	return tx.Alert.Delete().Where(alert.StateEQ(alert.StateResolved), alert.ResolvedAtLT(before)).Exec(ctx)
}
