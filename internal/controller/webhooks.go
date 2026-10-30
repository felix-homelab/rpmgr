// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"entgo.io/ent/dialect/sql"

	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/event"
	"github.com/felix-homelab/rpmgr/internal/store/ent/predicate"
	ewebhook "github.com/felix-homelab/rpmgr/internal/store/ent/webhook"
	"github.com/felix-homelab/rpmgr/internal/store/ent/webhookdelivery"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// WebhookEvery is how often the delivery job looks for events to deliver and retries that are due.
const WebhookEvery = 2 * time.Second

// WebhookOptions configure the delivery job.
type WebhookOptions struct {
	DB     *store.DB
	Leases *lease.Leases
	Sealer *secret.Sealer
	Sender *webhook.Sender
	Now    func() time.Time
	Logger *slog.Logger
	// Own returns the controller's own addresses, which org endpoints never reach; it is called
	// once per pass, so an interface that appears later (a VPN, a Docker bridge) is excluded too.
	Own func() []netip.Addr
	// Private returns the ranges org endpoints may reach (webhook_private_ranges); nil is none.
	Private func(ctx context.Context) ([]netip.Prefix, error)
	// policy replaces the endpoints' egress policies; only tests set it.
	policy func(*ent.Webhook) egress.Policy
}

// WebhookJob is the singleton job that delivers events to the enabled endpoints
// (docs/07-api.md, "Webhooks (Phase 2)"): at least once, each attempt recorded after it was sent
// in a fenced transaction, so a replica that lost the lease records nothing and the new holder
// sends again, with the same Rpmgr-Event-Id.
func WebhookJob(o WebhookOptions) lease.Job {
	return lease.Job{Name: "webhooks", Reason: "deliver the webhooks", Every: WebhookEvery,
		Run: func(ctx context.Context, l lease.Lease) error { return deliverWebhooks(ctx, o, l) }}
}

// attempt is one delivery of a pass.
type attempt struct {
	hook  *ent.Webhook
	event *ent.Event
	n     int
	prev  *ent.WebhookDelivery // the failed attempt this one retries
	code  int
	err   error
	sent  time.Time
}

func deliverWebhooks(ctx context.Context, o WebhookOptions, l lease.Lease) error {
	now := o.Now().UTC()
	c := o.DB.ReadClient()
	hooks, err := c.Webhook.Query().Where(ewebhook.Enabled(true)).All(ctx)
	if err != nil || len(hooks) == 0 {
		return err
	}
	var private []netip.Prefix
	if o.Private != nil {
		if private, err = o.Private(ctx); err != nil {
			return err
		}
	}
	var own []netip.Addr
	if o.Own != nil {
		own = o.Own()
	}
	var work []*attempt
	for _, h := range hooks {
		due, err := dueFor(ctx, c, h, now)
		if err != nil {
			return err
		}
		work = append(work, due...)
	}
	if len(work) == 0 {
		return nil
	}
	var wg sync.WaitGroup
	for _, a := range work {
		d, err := delivery(o, a, now, private, own)
		if err != nil {
			a.err, a.sent = err, now
			if o.Logger != nil && !errors.Is(err, errDropped) {
				// The error names no secret: it comes from the KEK's unsealing or the envelope.
				o.Logger.ErrorContext(ctx, "a webhook delivery cannot be prepared", "webhook", a.hook.ID, "event", a.event.ID, "err", err)
			}
			continue
		}
		wg.Go(func() {
			a.code, a.err = o.Sender.Send(ctx, d)
			a.sent = o.Now().UTC()
		})
	}
	wg.Wait()
	return store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
		if err := o.Leases.Fence(ctx, tx, l); err != nil {
			return err
		}
		return record(ctx, tx, work, o.Now().UTC())
	})
}

// dueFor returns at most webhook.PerEndpoint deliveries of h: the retries that are due first, then
// the events from h's enabled_at on, within the give-up window, that h wants and has no attempt of.
func dueFor(ctx context.Context, c *ent.Client, h *ent.Webhook, now time.Time) ([]*attempt, error) {
	from := h.EnabledAt
	if w := now.Add(-webhook.GiveUp); w.After(from) {
		from = w
	}
	retries, err := c.WebhookDelivery.Query().Where(webhookdelivery.WebhookID(h.ID), webhookdelivery.NextAttemptAtLTE(now)).
		Order(ent.Asc(webhookdelivery.FieldNextAttemptAt)).Limit(webhook.PerEndpoint).All(ctx)
	if err != nil {
		return nil, err
	}
	var out []*attempt
	for _, r := range retries {
		e, err := c.Event.Get(ctx, r.EventID)
		switch {
		case ent.IsNotFound(err):
			e = nil
		case err != nil:
			return nil, err
		}
		// A retry of an event that is gone, or older than the endpoint's enabling, is dropped.
		out = append(out, &attempt{hook: h, event: e, n: r.Attempt + 1, prev: r})
	}
	if len(out) == webhook.PerEndpoint {
		return out, nil
	}
	q := c.Event.Query().Where(event.TsGTE(from), sameOrg(h), notDelivered(h.ID))
	if len(h.EventTypes) > 0 {
		var any []predicate.Event
		for _, t := range h.EventTypes {
			if p, ok := strings.CutSuffix(t, "*"); ok {
				any = append(any, event.TypeHasPrefix(p))
			} else {
				any = append(any, event.Type(t))
			}
		}
		q.Where(event.Or(any...))
	}
	evs, err := q.Order(ent.Asc(event.FieldTs), ent.Asc(event.FieldID)).Limit(webhook.PerEndpoint - len(out)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		out = append(out, &attempt{hook: h, event: e, n: 1})
	}
	return out, nil
}

// sameOrg selects the events of h's org, or the instance events for an instance endpoint.
func sameOrg(h *ent.Webhook) predicate.Event {
	if h.OrgID == nil {
		return event.OrgIDIsNil()
	}
	return event.OrgID(*h.OrgID)
}

// notDelivered selects the events without an attempt to the endpoint id.
func notDelivered(id string) predicate.Event {
	return func(s *sql.Selector) {
		d := sql.Table(webhookdelivery.Table)
		s.Where(sql.NotExists(sql.Select(d.C(webhookdelivery.FieldID)).From(d).
			Where(sql.And(sql.EQ(d.C(webhookdelivery.FieldWebhookID), id), sql.ColumnsEQ(d.C(webhookdelivery.FieldEventID), s.C(event.FieldID))))))
	}
}

// delivery is the request of a: the envelope, signed with the endpoint's secret and, during a
// rotation, its previous one, under the endpoint's egress policy.
func delivery(o WebhookOptions, a *attempt, now time.Time, private []netip.Prefix, own []netip.Addr) (webhook.Delivery, error) {
	h := a.hook
	if a.event == nil || a.event.Ts.Before(h.EnabledAt) {
		return webhook.Delivery{}, errDropped
	}
	cur, err := o.Sealer.Open(secret.Context{Table: "webhooks", Column: "secret_enc", RowID: h.ID}, h.SecretEnc)
	if err != nil {
		return webhook.Delivery{}, err
	}
	secrets := []secret.Value{cur}
	if h.PreviousSecretEnc != nil && h.PreviousUntil != nil && now.Before(*h.PreviousUntil) {
		prev, err := o.Sealer.Open(secret.Context{Table: "webhooks", Column: "previous_secret_enc", RowID: h.ID}, *h.PreviousSecretEnc)
		if err != nil {
			return webhook.Delivery{}, err
		}
		secrets = append(secrets, prev)
	}
	e := a.event
	body, err := webhook.Body(events.Event{ID: e.ID, OrgID: deref(e.OrgID), Type: e.Type, Time: e.Ts, ActorType: string(e.ActorType),
		ActorID: e.ActorID, SubjectType: e.SubjectType, SubjectID: e.SubjectID, SubjectName: e.SubjectName, Summary: e.Summary, Changed: e.Changed})
	if err != nil {
		return webhook.Delivery{}, err
	}
	p := egress.Policy{Internal: h.OrgID == nil}
	if h.OrgID != nil {
		p.Private, p.Own = private, own
	}
	if o.policy != nil {
		p = o.policy(h)
	}
	return webhook.Delivery{URL: h.URL, EventID: e.ID, EventType: e.Type, Body: body, Secrets: secrets, Policy: p}, nil
}

// errDropped marks a retry whose event is gone or predates the endpoint's enabling.
var errDropped = errors.New("the event is no longer delivered")

// record writes the attempts of a pass and what they mean for their endpoints: the next retry or
// none, the endpoint's last success or the start of its failing, and its disabling after
// webhook.DisableAfter of failing, with the event webhook.disable.
func record(ctx context.Context, tx *ent.Tx, work []*attempt, now time.Time) error {
	byHook := map[string][]*attempt{}
	for _, a := range work {
		if a.prev != nil {
			// The new attempt carries the schedule from here on.
			if err := tx.WebhookDelivery.UpdateOne(a.prev).ClearNextAttemptAt().Exec(ctx); err != nil {
				return err
			}
		}
		if errors.Is(a.err, errDropped) {
			continue
		}
		byHook[a.hook.ID] = append(byHook[a.hook.ID], a)
		e := a.event

		cr := tx.WebhookDelivery.Create().SetWebhookID(a.hook.ID).SetNillableOrgID(a.hook.OrgID).SetEventID(e.ID).SetEventType(e.Type).
			SetAttempt(a.n).SetStatusCode(a.code).SetSentAt(a.sent)
		if a.err != nil {
			cr.SetError(webhook.Describe(a.err))
			if next, ok := webhook.Next(a.n, a.sent, e.Ts); ok {
				cr.SetNextAttemptAt(next)
			}
		}
		if err := cr.Exec(ctx); err != nil {
			return err
		}
	}
	for _, as := range byHook {
		h := as[0].hook
		ok := false
		for _, a := range as {
			ok = ok || a.err == nil
		}
		u := tx.Webhook.UpdateOneID(h.ID)
		switch {
		case ok:
			u.SetLastSuccessAt(now).ClearFailingSince()
		case h.FailingSince == nil:
			u.SetFailingSince(now)
		case now.Sub(*h.FailingSince) >= webhook.DisableAfter:
			u.SetEnabled(false).SetDisabledReason(ewebhook.DisabledReasonFailing).AddVersion(1)
			if _, err := events.Add(ctx, tx, events.Event{OrgID: deref(h.OrgID), Type: "webhook.disable", SubjectType: "webhook",
				SubjectID: h.ID, Summary: "webhook.disable: no successful delivery for 3 days"}); err != nil {
				return err
			}
		}
		if err := u.Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// PurgeDeliveries deletes the deliveries older than webhook.KeepFor and, of an endpoint with more
// than webhook.KeepAtMost, the oldest ones past the give-up window that no retry waits on.
func PurgeDeliveries(ctx context.Context, tx *ent.Tx, now time.Time) error {
	if _, err := tx.WebhookDelivery.Delete().Where(webhookdelivery.SentAtLT(now.Add(-webhook.KeepFor))).Exec(ctx); err != nil {
		return err
	}
	var over []struct {
		WebhookID string `json:"webhook_id"`
		Count     int    `json:"count"`
	}
	if err := tx.WebhookDelivery.Query().GroupBy(webhookdelivery.FieldWebhookID).Aggregate(ent.Count()).Scan(ctx, &over); err != nil {
		return err
	}
	for _, w := range over {
		if w.Count <= webhook.KeepAtMost {
			continue
		}
		cut, err := tx.WebhookDelivery.Query().Where(webhookdelivery.WebhookID(w.WebhookID)).
			Order(ent.Desc(webhookdelivery.FieldSentAt), ent.Desc(webhookdelivery.FieldID)).Offset(webhook.KeepAtMost - 1).First(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.WebhookDelivery.Delete().Where(webhookdelivery.WebhookID(w.WebhookID), webhookdelivery.SentAtLT(cut.SentAt),
			webhookdelivery.SentAtLT(now.Add(-webhook.GiveUp)), webhookdelivery.NextAttemptAtIsNil()).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ownAddresses are the addresses of this host's interfaces, which org endpoints never reach: a
// controller listening on every address listens on each of them.
func ownAddresses() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}
