// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
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
	"github.com/felix-homelab/rpmgr/internal/ratelimit"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	ewebhook "github.com/felix-homelab/rpmgr/internal/store/ent/webhook"
	"github.com/felix-homelab/rpmgr/internal/store/ent/webhookdelivery"
	"github.com/felix-homelab/rpmgr/internal/store/ent/webhookmessage"
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
	// Instance is what a chat message shows of the instance (webhook.Context): the public URL,
	// the trust domain and the version.
	Instance webhook.Context
	// Sender sends the test event; nil refuses TestWebhook.
	Sender *webhook.Sender
	// Sys is the controller's system scope, under which InstanceWebhooks reads and writes: an
	// endpoint of no org belongs to no org's scope.
	Sys context.Context
	// Own returns the controller's own addresses, which org endpoints never reach; it is asked at
	// every test, so an interface added since the start is excluded too.
	Own func() []netip.Addr
	// Private returns the ranges org endpoints may reach (webhook_private_ranges); nil is none.
	Private func(ctx context.Context) ([]netip.Prefix, error)
	Logger  *slog.Logger
	Now     func() time.Time
	// Tests limits TestWebhook per caller; nil makes the limiter of docs/03-connections.md.
	Tests *ratelimit.Limiter
	// Policy replaces the endpoints' egress policy; only tests set it.
	Policy func(*ent.Webhook) egress.Policy

	limiter sync.Once
}

// webhookFields are the fields UpdateWebhook may change.
var webhookFields = []string{"url", "event_types", "enabled", "format", "secret_url", "mention", "mention_when", "discord_username",
	"discord_avatar_url", "thread_name"}

// optionsOfProto are the options a request sets (D170).
func optionsOfProto(in *rpmgrv1.Webhook) webhook.Options {
	return webhook.Options{Mention: in.GetMention(), MentionWhen: mentionWhen[in.GetMentionWhen()], Username: in.GetDiscordUsername(),
		AvatarURL: in.GetDiscordAvatarUrl(), ThreadName: in.GetThreadName()}
}

var mentionWhen = map[rpmgrv1.WebhookMentionWhen]string{
	rpmgrv1.WebhookMentionWhen_WEBHOOK_MENTION_WHEN_UNSPECIFIED: webhook.MentionNever,
	rpmgrv1.WebhookMentionWhen_WEBHOOK_MENTION_WHEN_NEVER:       webhook.MentionNever,
	rpmgrv1.WebhookMentionWhen_WEBHOOK_MENTION_WHEN_CRITICAL:    webhook.MentionCritical,
	rpmgrv1.WebhookMentionWhen_WEBHOOK_MENTION_WHEN_ALL:         webhook.MentionAll,
}

func mentionWhenProto(w ewebhook.MentionWhen) rpmgrv1.WebhookMentionWhen {
	for k, v := range mentionWhen {
		if v == string(w) && k != rpmgrv1.WebhookMentionWhen_WEBHOOK_MENTION_WHEN_UNSPECIFIED {
			return k
		}
	}
	return rpmgrv1.WebhookMentionWhen_WEBHOOK_MENTION_WHEN_NEVER
}

type instanceKey struct{}

// instanceCtx marks ctx as the request of an instance endpoint.
func instanceCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, instanceKey{}, true)
}

// scope returns the context a method reads and writes under: the request's own, which has the
// caller's org scope, or for an instance endpoint the system scope, with the request's audit hook.
func (w *Webhooks) scope(ctx context.Context) context.Context {
	if ctx.Value(instanceKey{}) != nil && w.Sys != nil {
		return store.CarryTxHook(w.Sys, ctx)
	}
	return ctx
}

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

// checkWebhook validates what a caller sets. An org's endpoint also names no host that only the
// controller's own side can be (webhook.ValidateOrgURL); an instance endpoint may. A chat format
// has its URL in secret_url and none in url, an rpmgr endpoint the other way round.
func checkWebhook(f webhook.Format, url, secretURL string, types []string, instance bool) error {
	if err := checkEndpointURL(f, url, secretURL, instance); err != nil {
		return err
	}
	if err := webhook.ValidateEventTypes(types); err != nil {
		return invalid(err)
	}
	return nil
}

// checkEndpointURL validates the URL of an endpoint of format f, naming neither URL in its error.
func checkEndpointURL(f webhook.Format, url, secretURL string, instance bool) error {
	if f.Chat() {
		if url != "" {
			return invalid(errors.New("apisvc: the URL of a chat endpoint is secret_url; url is output only"))
		}
		if err := webhook.ValidateChatURL(secretURL, instance); err != nil {
			return invalid(err)
		}
		return nil
	}
	if secretURL != "" {
		return invalid(errors.New("apisvc: secret_url is for a chat format; an rpmgr endpoint has a url"))
	}
	check := webhook.ValidateOrgURL
	if instance {
		check = webhook.ValidateURL
	}
	if err := check(url); err != nil {
		return invalid(err)
	}
	return nil
}

// formatOf is the format a request names; none is rpmgr.
func formatOf(f rpmgrv1.WebhookFormat) (webhook.Format, error) {
	switch f {
	case rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_UNSPECIFIED, rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_RPMGR:
		return webhook.FormatRPMgr, nil
	case rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_DISCORD:
		return webhook.FormatDiscord, nil
	case rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_SLACK:
		return webhook.FormatSlack, nil
	case rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_TEAMS:
		return webhook.FormatTeams, nil
	}
	return "", invalid(errors.New("apisvc: format is not rpmgr, discord, slack or teams"))
}

// formatProto is the API's name of a stored format.
func formatProto(f ewebhook.Format) rpmgrv1.WebhookFormat {
	return map[ewebhook.Format]rpmgrv1.WebhookFormat{
		ewebhook.FormatRpmgr:   rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_RPMGR,
		ewebhook.FormatDiscord: rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_DISCORD,
		ewebhook.FormatSlack:   rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_SLACK,
		ewebhook.FormatTeams:   rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_TEAMS}[f]
}

// openURL opens the sealed URL of a chat endpoint, for the delivery job and the test only.
func (w *Webhooks) openURL(h *ent.Webhook) (secret.Value, error) {
	if h.URLEnc == nil || len(*h.URLEnc) == 0 { // NULL reads as an empty value
		return secret.Value{}, errors.New("apisvc: a chat endpoint without its URL")
	}
	return w.Sealer.Open(w.secretContext(h.ID, "url_enc"), *h.URLEnc)
}

// CreateWebhook implements WebhookService.
func (w *Webhooks) CreateWebhook(ctx context.Context, req *connect.Request[rpmgrv1.CreateWebhookRequest]) (
	*connect.Response[rpmgrv1.CreateWebhookResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, w.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateWebhookResponse, error) {
		row, sec, err := w.create(ctx, m.GetOrgId(), m.GetWebhook())
		if err != nil {
			return nil, err
		}
		return &rpmgrv1.CreateWebhookResponse{Webhook: w.webhookOf(row), Secret: sec}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// create makes an endpoint of org, or of the instance for "", and returns it with its secret, or
// none for a chat format. An org, or the instance, has at most webhook.MaxPerOrg endpoints.
func (w *Webhooks) create(ctx context.Context, org string, in *rpmgrv1.Webhook) (*ent.Webhook, string, error) {
	ctx = w.scope(ctx)
	f, err := formatOf(in.GetFormat())
	if err != nil {
		return nil, "", err
	}
	if err := checkWebhook(f, in.GetUrl(), in.GetSecretUrl(), in.GetEventTypes(), org == ""); err != nil {
		return nil, "", err
	}
	opts := optionsOfProto(in)
	if err := webhook.ValidateOptions(f, opts); err != nil {
		return nil, "", invalid(err)
	}
	id := ids.New("whk")
	var sec secret.Value
	var sealed []byte
	shown, urlEnc := in.GetUrl(), []byte(nil)
	if f.Chat() {
		if urlEnc, err = w.Sealer.Seal(w.secretContext(id, "url_enc"), secret.New(in.GetSecretUrl())); err != nil {
			return nil, "", err
		}
		shown, sealed = webhook.RedactURL(in.GetSecretUrl()), []byte{}
	} else {
		if sec, err = webhook.NewSecret(); err != nil {
			return nil, "", err
		}
		if sealed, err = w.Sealer.Seal(w.secretContext(id, "secret_enc"), sec); err != nil {
			return nil, "", err
		}
	}
	owner, scope := &org, ewebhook.OrgID(org)
	if org == "" {
		owner, scope = nil, ewebhook.OrgIDIsNil()
	}
	var row *ent.Webhook
	err = store.WriteTx(ctx, w.DB, func(tx *ent.Tx) error {
		n, err := tx.Webhook.Query().Where(scope).Count(ctx)
		if err != nil {
			return err
		}
		if n >= webhook.MaxPerOrg {
			return connect.NewError(connect.CodeResourceExhausted,
				fmt.Errorf("apisvc: at most %d webhook endpoints; delete one first", webhook.MaxPerOrg))
		}
		c := tx.Webhook.Create().SetID(id).SetNillableOrgID(owner).SetURL(shown).SetEventTypes(in.GetEventTypes()).
			SetFormat(ewebhook.Format(f)).SetSecretEnc(sealed).SetMention(opts.Mention).SetMentionWhen(ewebhook.MentionWhen(opts.MentionWhen)).
			SetDiscordUsername(opts.Username).SetDiscordAvatarURL(opts.AvatarURL).SetThreadName(opts.ThreadName)
		if urlEnc != nil {
			c.SetURLEnc(urlEnc)
		}
		row, err = c.Save(ctx)
		return err
	})
	if err != nil {
		return nil, "", storeError(err)
	}
	if f.Chat() {
		return row, "", nil
	}
	return row, sec.Reveal(), nil
}

// GetWebhook implements WebhookService.
func (w *Webhooks) GetWebhook(ctx context.Context, req *connect.Request[rpmgrv1.GetWebhookRequest]) (
	*connect.Response[rpmgrv1.GetWebhookResponse], error) {
	ctx = w.scope(ctx)
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
	rows, err := w.listHooks(ctx, m.GetOrgId(), after, size)
	if err != nil {
		return nil, err
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

// listHooks returns size+1 endpoints of org, or of the instance for "", after the ID after.
func (w *Webhooks) listHooks(ctx context.Context, org, after string, size int) ([]*ent.Webhook, error) {
	ctx = w.scope(ctx)
	scope := ewebhook.OrgID(org)
	if org == "" {
		scope = ewebhook.OrgIDIsNil()
	}
	q := w.DB.ReadClient().Webhook.Query().Where(scope).Order(ent.Asc(ewebhook.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(ewebhook.IDGT(after))
	}
	rows, err := q.All(ctx)
	return rows, storeError(err)
}

// UpdateWebhook implements WebhookService. Enabling an endpoint that was disabled, for whatever
// reason, clears the disable and its failing period, and events count from now on (D143).
func (w *Webhooks) UpdateWebhook(ctx context.Context, req *connect.Request[rpmgrv1.UpdateWebhookRequest]) (
	*connect.Response[rpmgrv1.UpdateWebhookResponse], error) {
	ctx = w.scope(ctx)
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
		f, err := formatOf(next.GetFormat())
		if err != nil {
			return err
		}
		u := tx.Webhook.UpdateOneID(cur.ID).Where(ewebhook.Version(cur.Version)).SetEventTypes(next.GetEventTypes()).AddVersion(1)
		if err := w.updateTarget(u, cur, next, f, slices.Contains(m.GetUpdateMask().GetPaths(), "url")); err != nil {
			return err
		}
		// The options are checked against the format the endpoint will have, so that a change of
		// format that leaves an option the new one has no use for is refused, not ignored.
		opts := optionsOfProto(next)
		if err := webhook.ValidateOptions(f, opts); err != nil {
			return invalid(err)
		}
		u.SetMention(opts.Mention).SetMentionWhen(ewebhook.MentionWhen(opts.MentionWhen)).SetDiscordUsername(opts.Username).
			SetDiscordAvatarURL(opts.AvatarURL).SetThreadName(opts.ThreadName)
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

// updateTarget checks the format and URL of an update and sets them on u. A chat endpoint's URL,
// which holds the service's token, changes only by a new secret_url, and a new format needs one: a
// URL belongs to its service. An rpmgr endpoint does not become a chat one without its signing
// secret going, and a chat one does not become rpmgr, which would need a secret to show once.
func (w *Webhooks) updateTarget(u *ent.WebhookUpdateOne, cur *ent.Webhook, next *rpmgrv1.Webhook, f webhook.Format, urlInMask bool) error {
	curFormat := webhook.Format(cur.Format)
	secretURL := next.GetSecretUrl()
	switch {
	case !f.Chat():
		if curFormat.Chat() {
			return connect.NewError(connect.CodeFailedPrecondition,
				errors.New("apisvc: a chat endpoint does not become an rpmgr one, which has a signing secret; make a new endpoint"))
		}
		// A URL that is not changed is not checked again: endpoints from before a rule stay editable.
		if next.GetUrl() == cur.URL && secretURL == "" {
			if err := webhook.ValidateEventTypes(next.GetEventTypes()); err != nil {
				return invalid(err)
			}
		} else if err := checkWebhook(f, next.GetUrl(), secretURL, next.GetEventTypes(), cur.OrgID == nil); err != nil {
			return err
		}
		u.SetURL(next.GetUrl())
		return nil
	case urlInMask:
		return invalid(errors.New("apisvc: the URL of a chat endpoint is secret_url; url is output only"))
	case f != curFormat && secretURL == "":
		return invalid(errors.New("apisvc: a new format needs a new secret_url: a URL belongs to its service"))
	}
	if err := webhook.ValidateEventTypes(next.GetEventTypes()); err != nil {
		return invalid(err)
	}
	u.SetFormat(ewebhook.Format(f))
	if secretURL == "" {
		return nil
	}
	if err := webhook.ValidateChatURL(secretURL, cur.OrgID == nil); err != nil {
		return invalid(err)
	}
	sealed, err := w.Sealer.Seal(w.secretContext(cur.ID, "url_enc"), secret.New(secretURL))
	if err != nil {
		return err
	}
	u.SetURL(webhook.RedactURL(secretURL)).SetURLEnc(sealed)
	if !curFormat.Chat() {
		u.SetSecretEnc([]byte{}).ClearPreviousSecretEnc().ClearPreviousUntil()
	}
	return nil
}

// DeleteWebhook implements WebhookService: the endpoint and its deliveries go together.
func (w *Webhooks) DeleteWebhook(ctx context.Context, req *connect.Request[rpmgrv1.DeleteWebhookRequest]) (
	*connect.Response[rpmgrv1.DeleteWebhookResponse], error) {
	ctx = w.scope(ctx)
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
		if _, err := tx.WebhookMessage.Delete().Where(webhookmessage.WebhookID(id)).Exec(ctx); err != nil {
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
	ctx = w.scope(ctx)
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
		if webhook.Format(cur.Format).Chat() {
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: a chat endpoint has no signing secret to rotate"))
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
	ctx = w.scope(ctx)
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
	out, err := w.test(ctx, req.Msg.GetWebhookId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(out), nil
}

// allowTest takes one of the caller's tests (docs/03-connections.md, "Timeouts, keepalive and
// backoff"): a test sends a request to a receiver from the controller, so it is limited.
func (w *Webhooks) allowTest(c *api.Caller) error {
	w.limiter.Do(func() {
		if w.Tests == nil {
			w.Tests = ratelimit.New(webhook.TestEvery, webhook.TestBurst, w.now)
		}
	})
	key := ""
	if c != nil {
		key = cmp.Or(c.UserID, c.CredentialID)
	}
	if !w.Tests.Allow(key) {
		return connect.NewError(connect.CodeResourceExhausted, fmt.Errorf(
			"apisvc: at most %d test sends in a burst, then one every %s", webhook.TestBurst, webhook.TestEvery))
	}
	return nil
}

// test sends the test event of endpoint id.
func (w *Webhooks) test(ctx context.Context, id string) (*rpmgrv1.TestWebhookResponse, error) {
	if w.Sender == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: this controller sends no webhooks"))
	}
	caller := api.CallerFrom(ctx)
	ctx = w.scope(ctx)
	h, err := w.DB.ReadClient().Webhook.Get(ctx, id)
	if err != nil {
		return nil, storeError(err)
	}
	if err := w.allowTest(caller); err != nil {
		return nil, err
	}
	f := webhook.Format(h.Format)
	var secrets []secret.Value
	var target secret.Value
	now := w.now().UTC()
	if f.Chat() {
		if target, err = w.openURL(h); err != nil {
			return nil, w.unsealFailed(ctx, id, err)
		}
	} else {
		cur, err := w.Sealer.Open(w.secretContext(id, "secret_enc"), h.SecretEnc)
		if err != nil {
			return nil, w.unsealFailed(ctx, id, err)
		}
		secrets = []secret.Value{cur}
	}
	if !f.Chat() && h.PreviousSecretEnc != nil && h.PreviousUntil != nil && now.Before(*h.PreviousUntil) {
		prev, err := w.Sealer.Open(w.secretContext(id, "previous_secret_enc"), *h.PreviousSecretEnc)
		if err != nil {
			return nil, w.unsealFailed(ctx, id, err)
		}
		secrets = append(secrets, prev)
	}
	e := events.Event{ID: ids.New("evt"), OrgID: deref(h.OrgID), Type: "webhook.test", Time: now, ActorType: "user",
		SubjectType: "webhook", SubjectID: id, Summary: "webhook.test: a test event"}
	if caller != nil {
		e.ActorID = caller.UserID
	}
	body, err := webhook.Body(e)
	if f.Chat() {
		mc := w.Instance
		mc.Resolve(ctx, w.DB.ReadClient(), e)
		mc.Options = webhook.OptionsOf(h)
		body, err = webhook.ChatBody(f, e, mc)
	}
	if err != nil {
		return nil, err
	}
	p := egress.Policy{Internal: h.OrgID == nil}
	if h.OrgID != nil {
		if w.Own != nil {
			p.Own = w.Own()
		}
		if w.Private != nil {
			if p.Private, err = w.Private(ctx); err != nil {
				return nil, err
			}
		}
	}
	if w.Policy != nil {
		p = w.Policy(h)
	}
	code, err := w.Sender.Send(ctx, webhook.Delivery{URL: h.URL, Target: target, EventID: e.ID, EventType: e.Type, Body: body, Secrets: secrets, Policy: p})
	out := &rpmgrv1.TestWebhookResponse{Delivered: err == nil, StatusCode: int32(code)} //nolint:gosec // G115: an HTTP status
	if err != nil {
		out.Error = webhook.Describe(err)
	}
	return out, nil
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

// webhookOf is the API's view of an endpoint: it has no secret, only whether one is set, and of a
// chat format only the scheme and host of its URL.
func (w *Webhooks) webhookOf(r *ent.Webhook) *rpmgrv1.Webhook {
	out := &rpmgrv1.Webhook{Id: r.ID, OrgId: deref(r.OrgID), Url: r.URL, EventTypes: r.EventTypes, Enabled: r.Enabled, SecretSet: len(r.SecretEnc) > 0, Format: formatProto(r.Format),
		CreateTime: timestamppb.New(r.CreatedAt), Etag: etagOf(r.Version), Mention: r.Mention, MentionWhen: mentionWhenProto(r.MentionWhen),
		DiscordUsername: r.DiscordUsername, DiscordAvatarUrl: r.DiscordAvatarURL, ThreadName: r.ThreadName}
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

// PreviewWebhookMessage implements WebhookService: the messages a chat endpoint of the given
// format and options would post. It reads the org's name only and sends nothing.
func (w *Webhooks) PreviewWebhookMessage(ctx context.Context, req *connect.Request[rpmgrv1.PreviewWebhookMessageRequest]) (
	*connect.Response[rpmgrv1.PreviewWebhookMessageResponse], error) {
	mc := w.Instance
	if o, err := w.DB.ReadClient().Org.Get(ctx, req.Msg.GetOrgId()); err == nil {
		mc.OrgName = o.Name
	}
	return w.preview(req.Msg.GetWebhook(), mc)
}

// preview makes the sample messages of in, with the instance's footer and link.
func (w *Webhooks) preview(in *rpmgrv1.Webhook, mc webhook.Context) (*connect.Response[rpmgrv1.PreviewWebhookMessageResponse], error) {
	f, err := formatOf(in.GetFormat())
	if err != nil {
		return nil, err
	}
	mc.Options = optionsOfProto(in)
	samples, err := webhook.Preview(f, mc, w.now())
	if err != nil {
		return nil, invalid(err)
	}
	out := &rpmgrv1.PreviewWebhookMessageResponse{}
	for _, s := range samples {
		out.Previews = append(out.Previews, &rpmgrv1.WebhookPreview{EventType: s.EventType, Body: s.Body})
	}
	return connect.NewResponse(out), nil
}
