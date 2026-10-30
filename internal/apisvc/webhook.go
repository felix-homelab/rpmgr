// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	ewebhook "github.com/felix-homelab/rpmgr/internal/store/ent/webhook"
	"github.com/felix-homelab/rpmgr/internal/store/ent/webhookdelivery"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// Webhooks is WebhookService: an org's endpoints (docs/07-api.md, "Webhooks (Phase 2)"). Its
// methods run in the org scope the interceptor gives them. An endpoint's secret is sealed under
// the KEK, returned once by CreateWebhook and RotateWebhookSecret, and read by nothing else but
// the delivery job and TestWebhook, which sign with it.
type Webhooks struct {
	rpmgrv1connect.UnimplementedWebhookServiceHandler
	DB     *store.DB
	API    *api.Server
	Sealer *secret.Sealer
	// Sender sends the test event; nil refuses TestWebhook.
	Sender *webhook.Sender
	// Own are the controller's own addresses, which org endpoints never reach.
	Own []netip.Addr
	// Private returns the ranges org endpoints may reach (webhook_private_ranges); nil is none.
	Private func(ctx context.Context) ([]netip.Prefix, error)
	Logger  *slog.Logger
	Now     func() time.Time
	// Policy replaces the endpoints' egress policy; only tests set it.
	Policy func(*ent.Webhook) egress.Policy
}

// webhookFields are the fields UpdateWebhook may change.
var webhookFields = []string{"url", "event_types", "enabled"}

func (w *Webhooks) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Webhooks) secretContext(id, column string) secret.Context {
	return secret.Context{Table: "webhooks", Column: column, RowID: id}
}

func invalid(err error) error { return connect.NewError(connect.CodeInvalidArgument, err) }

// checkWebhook validates what a caller sets.
func checkWebhook(url string, types []string) error {
	if err := webhook.ValidateURL(url); err != nil {
		return invalid(err)
	}
	if err := webhook.ValidateEventTypes(types); err != nil {
		return invalid(err)
	}
	return nil
}

// CreateWebhook implements WebhookService.
func (w *Webhooks) CreateWebhook(ctx context.Context, req *connect.Request[rpmgrv1.CreateWebhookRequest]) (
	*connect.Response[rpmgrv1.CreateWebhookResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, w.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateWebhookResponse, error) {
		in := m.GetWebhook()
		if err := checkWebhook(in.GetUrl(), in.GetEventTypes()); err != nil {
			return nil, err
		}
		sec, err := webhook.NewSecret()
		if err != nil {
			return nil, err
		}
		id := ids.New("whk")
		sealed, err := w.Sealer.Seal(w.secretContext(id, "secret_enc"), sec)
		if err != nil {
			return nil, err
		}
		var row *ent.Webhook
		err = store.WriteTx(ctx, w.DB, func(tx *ent.Tx) error {
			row, err = tx.Webhook.Create().SetID(id).SetOrgID(m.GetOrgId()).SetURL(in.GetUrl()).SetEventTypes(in.GetEventTypes()).
				SetSecretEnc(sealed).Save(ctx)
			return err
		})
		if err != nil {
			return nil, storeError(err)
		}
		return &rpmgrv1.CreateWebhookResponse{Webhook: w.webhookOf(row), Secret: sec.Reveal()}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// GetWebhook implements WebhookService.
func (w *Webhooks) GetWebhook(ctx context.Context, req *connect.Request[rpmgrv1.GetWebhookRequest]) (
	*connect.Response[rpmgrv1.GetWebhookResponse], error) {
	row, err := w.DB.ReadClient().Webhook.Get(ctx, req.Msg.GetWebhookId())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetWebhookResponse{Webhook: w.webhookOf(row)}), nil
}

// ListWebhooks implements WebhookService.
func (w *Webhooks) ListWebhooks(ctx context.Context, req *connect.Request[rpmgrv1.ListWebhooksRequest]) (
	*connect.Response[rpmgrv1.ListWebhooksResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := w.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	q := w.DB.ReadClient().Webhook.Query().Where(ewebhook.OrgID(m.GetOrgId())).Order(ent.Asc(ewebhook.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(ewebhook.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListWebhooksResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = w.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		out.Webhooks = append(out.Webhooks, w.webhookOf(r))
	}
	return connect.NewResponse(out), nil
}

// UpdateWebhook implements WebhookService. Enabling an endpoint that was disabled, for whatever
// reason, clears the disable and its failing period, and events count from now on (D143).
func (w *Webhooks) UpdateWebhook(ctx context.Context, req *connect.Request[rpmgrv1.UpdateWebhookRequest]) (
	*connect.Response[rpmgrv1.UpdateWebhookResponse], error) {
	m := req.Msg
	var row *ent.Webhook
	err := store.WriteTx(ctx, w.DB, func(tx *ent.Tx) error {
		cur, err := tx.Webhook.Get(ctx, m.GetWebhook().GetId())
		if err != nil {
			return err
		}
		if err := api.CheckEtag(m.GetEtag(), cur.Version, w.webhookOf(cur)); err != nil {
			return err
		}
		next := proto.Clone(w.webhookOf(cur)).(*rpmgrv1.Webhook)
		if err := api.ApplyMask(next, m.GetWebhook(), m.GetUpdateMask(), webhookFields...); err != nil {
			return err
		}
		if err := checkWebhook(next.GetUrl(), next.GetEventTypes()); err != nil {
			return err
		}
		u := tx.Webhook.UpdateOneID(cur.ID).Where(ewebhook.Version(cur.Version)).SetURL(next.GetUrl()).
			SetEventTypes(next.GetEventTypes()).AddVersion(1)
		switch {
		case cur.Enabled && !next.GetEnabled():
			u.SetEnabled(false).SetDisabledReason(ewebhook.DisabledReasonPerson)
		case !cur.Enabled && next.GetEnabled():
			u.SetEnabled(true).ClearDisabledReason().ClearFailingSince().SetEnabledAt(w.now().UTC())
		}
		row, err = u.Save(ctx)
		return err
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateWebhookResponse{Webhook: w.webhookOf(row)}), nil
}

// DeleteWebhook implements WebhookService: the endpoint and its deliveries go together.
func (w *Webhooks) DeleteWebhook(ctx context.Context, req *connect.Request[rpmgrv1.DeleteWebhookRequest]) (
	*connect.Response[rpmgrv1.DeleteWebhookResponse], error) {
	id := req.Msg.GetWebhookId()
	err := store.WriteTx(ctx, w.DB, func(tx *ent.Tx) error {
		cur, err := tx.Webhook.Get(ctx, id)
		if err != nil {
			return err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, w.webhookOf(cur)); err != nil {
			return err
		}
		if _, err := tx.WebhookDelivery.Delete().Where(webhookdelivery.WebhookID(id)).Exec(ctx); err != nil {
			return err
		}
		return tx.Webhook.DeleteOneID(id).Where(ewebhook.Version(cur.Version)).Exec(ctx)
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeleteWebhookResponse{}), nil
}

// RotateWebhookSecret implements WebhookService: the old secret moves to previous_secret_enc and
// signs for webhook.PreviousSigns more, next to the new one. A second rotation within that period
// drops the oldest secret at once, which was due to stop anyway.
func (w *Webhooks) RotateWebhookSecret(ctx context.Context, req *connect.Request[rpmgrv1.RotateWebhookSecretRequest]) (
	*connect.Response[rpmgrv1.RotateWebhookSecretResponse], error) {
	id := req.Msg.GetWebhookId()
	sec, err := webhook.NewSecret()
	if err != nil {
		return nil, err
	}
	sealed, err := w.Sealer.Seal(w.secretContext(id, "secret_enc"), sec)
	if err != nil {
		return nil, err
	}
	var row *ent.Webhook
	err = store.WriteTx(ctx, w.DB, func(tx *ent.Tx) error {
		cur, err := tx.Webhook.Get(ctx, id)
		if err != nil {
			return err
		}
		old, err := w.Sealer.Open(w.secretContext(id, "secret_enc"), cur.SecretEnc)
		if err != nil {
			return w.unsealFailed(ctx, id, err)
		}
		prev, err := w.Sealer.Seal(w.secretContext(id, "previous_secret_enc"), old)
		if err != nil {
			return err
		}
		row, err = tx.Webhook.UpdateOneID(id).Where(ewebhook.Version(cur.Version)).SetSecretEnc(sealed).SetPreviousSecretEnc(prev).
			SetPreviousUntil(w.now().UTC().Add(webhook.PreviousSigns)).AddVersion(1).Save(ctx)
		return err
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.RotateWebhookSecretResponse{Webhook: w.webhookOf(row), Secret: sec.Reveal()}), nil
}

// ListWebhookDeliveries implements WebhookService, the newest first: delivery IDs sort by time.
func (w *Webhooks) ListWebhookDeliveries(ctx context.Context, req *connect.Request[rpmgrv1.ListWebhookDeliveriesRequest]) (
	*connect.Response[rpmgrv1.ListWebhookDeliveriesResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := w.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	q := w.DB.ReadClient().WebhookDelivery.Query().Where(webhookdelivery.WebhookID(m.GetWebhookId())).
		Order(ent.Desc(webhookdelivery.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(webhookdelivery.IDLT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListWebhookDeliveriesResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = w.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		d := &rpmgrv1.WebhookDelivery{Id: r.ID, WebhookId: r.WebhookID, EventId: r.EventID, EventType: r.EventType,
			Attempt: int32(r.Attempt), StatusCode: int32(r.StatusCode), Error: r.Error, SendTime: timestamppb.New(r.SentAt)} //nolint:gosec // G115: bounded
		if r.NextAttemptAt != nil {
			d.NextAttemptTime = timestamppb.New(*r.NextAttemptAt)
		}
		out.Deliveries = append(out.Deliveries, d)
	}
	return connect.NewResponse(out), nil
}

// TestWebhook implements WebhookService: it signs a webhook.test event with the endpoint's
// secrets and sends it through the egress guard at once, outside any transaction. The test is
// recorded in the deliveries' place by the audit entry of the request, not as a delivery.
func (w *Webhooks) TestWebhook(ctx context.Context, req *connect.Request[rpmgrv1.TestWebhookRequest]) (
	*connect.Response[rpmgrv1.TestWebhookResponse], error) {
	if w.Sender == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: this controller sends no webhooks"))
	}
	id := req.Msg.GetWebhookId()
	h, err := w.DB.ReadClient().Webhook.Get(ctx, id)
	if err != nil {
		return nil, storeError(err)
	}
	cur, err := w.Sealer.Open(w.secretContext(id, "secret_enc"), h.SecretEnc)
	if err != nil {
		return nil, w.unsealFailed(ctx, id, err)
	}
	secrets := []secret.Value{cur}
	now := w.now().UTC()
	if h.PreviousSecretEnc != nil && h.PreviousUntil != nil && now.Before(*h.PreviousUntil) {
		prev, err := w.Sealer.Open(w.secretContext(id, "previous_secret_enc"), *h.PreviousSecretEnc)
		if err != nil {
			return nil, w.unsealFailed(ctx, id, err)
		}
		secrets = append(secrets, prev)
	}
	e := events.Event{ID: ids.New("evt"), OrgID: deref(h.OrgID), Type: "webhook.test", Time: now, ActorType: "user",
		SubjectType: "webhook", SubjectID: id, Summary: "webhook.test: a test event"}
	if c := api.CallerFrom(ctx); c != nil {
		e.ActorID = c.UserID
	}
	body, err := webhook.Body(e)
	if err != nil {
		return nil, err
	}
	p := egress.Policy{Own: w.Own}
	if w.Private != nil {
		if p.Private, err = w.Private(ctx); err != nil {
			return nil, err
		}
	}
	if w.Policy != nil {
		p = w.Policy(h)
	}
	code, err := w.Sender.Send(ctx, webhook.Delivery{URL: h.URL, EventID: e.ID, EventType: e.Type, Body: body, Secrets: secrets, Policy: p})
	out := &rpmgrv1.TestWebhookResponse{Delivered: err == nil, StatusCode: int32(code)} //nolint:gosec // G115: an HTTP status
	if err != nil {
		out.Error = webhook.Describe(err)
	}
	return connect.NewResponse(out), nil
}

// unsealFailed logs that a secret could not be opened, naming the endpoint but never the secret,
// and returns the error a caller sees.
func (w *Webhooks) unsealFailed(ctx context.Context, id string, err error) error {
	if w.Logger != nil {
		w.Logger.ErrorContext(ctx, "a webhook secret cannot be unsealed", "webhook", id, "err", err)
	}
	return connect.NewError(connect.CodeInternal, errors.New("apisvc: the endpoint's secret cannot be read"))
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// webhookOf is the API's view of an endpoint: it has no secret, only whether one is set.
func (w *Webhooks) webhookOf(r *ent.Webhook) *rpmgrv1.Webhook {
	out := &rpmgrv1.Webhook{Id: r.ID, OrgId: deref(r.OrgID), Url: r.URL, EventTypes: r.EventTypes, Enabled: r.Enabled, SecretSet: true,
		CreateTime: timestamppb.New(r.CreatedAt), Etag: etagOf(r.Version)}
	if r.DisabledReason != nil {
		out.DisabledReason = map[ewebhook.DisabledReason]rpmgrv1.WebhookDisabledReason{
			ewebhook.DisabledReasonFailing: rpmgrv1.WebhookDisabledReason_WEBHOOK_DISABLED_REASON_FAILING,
			ewebhook.DisabledReasonPerson:  rpmgrv1.WebhookDisabledReason_WEBHOOK_DISABLED_REASON_PERSON}[*r.DisabledReason]
	}
	if r.PreviousUntil != nil && r.PreviousSecretEnc != nil && w.now().Before(*r.PreviousUntil) {
		out.PreviousSecretSigns, out.PreviousSecretUntil = true, timestamppb.New(*r.PreviousUntil)
	}
	if r.LastSuccessAt != nil {
		out.LastSuccessTime = timestamppb.New(*r.LastSuccessAt)
	}
	if r.FailingSince != nil {
		out.FailingSinceTime = timestamppb.New(*r.FailingSince)
	}
	return out
}
