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
// state tells (an agent's disconnection); zero means when the job first saw it. Unknown says that
// the job cannot tell now whether the condition holds, as for an offline agent's configuration: an
// open alert of it keeps its state, neither firing nor resolving, and none is opened.
type Observation struct {
	OrgID       string // empty: an instance alert
	Kind        string
	SubjectType string
	SubjectID   string
	SubjectName string
	Since       time.Time
	Unknown     bool
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
// resolves (a pending one never fired, so it goes without an event), and one whose observation is
// Unknown stays as it is. It returns the
// events of the alerts that fired and resolved.
func Apply(ctx context.Context, tx *ent.Tx, now time.Time, obs []Observation) ([]events.Event, error) {
	return ApplyChosen(ctx, tx, now, obs, nil)
}

// Chosen reports whether org gets alerts of kind, as the org setting alert_types chooses; an
// instance alert (empty org) is always chosen.
type Chosen func(ctx context.Context, org, kind string) (bool, error)

// ApplyChosen is Apply for an instance where orgs choose their alert types: the alerts of a kind
// the org did not choose move through their states as before, but write no event, so no webhook
// and no e-mail hears of them. A nil chosen chooses everything.
func ApplyChosen(ctx context.Context, tx *ent.Tx, now time.Time, obs []Observation, chosen Chosen) ([]events.Event, error) {
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
		if o.Unknown {
			continue
		}
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
			if err := emit(ctx, tx, a, "alert.fire", chosen, &out); err != nil {
				return nil, err
			}
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
		if err := emit(ctx, tx, a, "alert.resolve", chosen, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// emit writes the event of a's change and adds it to out, unless the alert's org did not choose its
// kind.
func emit(ctx context.Context, tx *ent.Tx, a *ent.Alert, typ string, chosen Chosen, out *[]events.Event) error {
	if chosen != nil && a.OrgID != nil {
		ok, err := chosen(ctx, *a.OrgID, a.Kind)
		if err != nil || !ok {
			return err
		}
	}
	ch, err := event(ctx, tx, a, typ)
	if err != nil {
		return err
	}
	*out = append(*out, ch)
	return nil
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
