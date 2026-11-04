// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// The tokens of the chat services' URLs, which must appear nowhere but in the sealed column.
const (
	discordURL = "https://discord.com/api/webhooks/123456789012345678/DISCORDTOKEN-abcdefghijklmnop"
	slackURL   = "https://hooks.slack.com/services/T0000/B0000/SLACKTOKENabcdefghijklmnop"
	teamsURL   = "https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=TEAMSTOKEN-abcdefghijklmnop"
)

var chatTokens = []string{"DISCORDTOKEN-abcdefghijklmnop", "SLACKTOKENabcdefghijklmnop", "TEAMSTOKEN-abcdefghijklmnop"}

func newChat(t *testing.T, e *env, b *browser, org string, f rpmgrv1.WebhookFormat, secretURL string, types ...string) (*rpmgrv1.CreateWebhookResponse, error) {
	t.Helper()
	e.logs.Secret(secretURL)
	for _, tok := range chatTokens {
		e.logs.Secret(tok)
	}
	r, err := b.wh.CreateWebhook(context.Background(), connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org,
		Webhook: &rpmgrv1.Webhook{Format: f, SecretUrl: secretURL, EventTypes: types}}))
	if err != nil {
		return nil, err
	}
	return r.Msg, nil
}

// TestWebhook_ChatURLSealedAndRedacted (#1060, D162): the URL of a Discord, Slack or Teams
// endpoint holds the service's token, so it is stored sealed, answered as its scheme and host, and
// appears in no read, list, audit entry, event or log line; the endpoint has no signing secret.
func TestWebhook_ChatURLSealedAndRedacted(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	for _, c := range []struct {
		f      rpmgrv1.WebhookFormat
		url    string
		shown  string
		column string
	}{
		{rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_DISCORD, discordURL, "https://discord.com", "discord"},
		{rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_SLACK, slackURL, "https://hooks.slack.com", "slack"},
		{rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_TEAMS, teamsURL, "https://prod-12.westus.logic.azure.com:443", "teams"},
	} {
		r, err := newChat(t, e, ada, org, c.f, c.url, "route.*")
		if err != nil {
			t.Fatalf("%s: %v", c.column, err)
		}
		w := r.GetWebhook()
		if r.GetSecret() != "" || w.GetSecretSet() || w.GetUrl() != c.shown || w.GetSecretUrl() != "" || w.GetFormat() != c.f || !w.GetEnabled() {
			t.Fatalf("%s: created %v with secret %q", c.column, w, r.GetSecret())
		}
		row := e.db.Client().Webhook.GetX(e.sys, w.GetId())
		if string(row.Format) != c.column || row.URL != c.shown || len(row.SecretEnc) != 0 || row.URLEnc == nil || len(*row.URLEnc) == 0 {
			t.Fatalf("%s: stored %+v", c.column, row)
		}
		// Sealed: not the URL, not its token, and it opens under its own context only.
		for _, plain := range []string{c.url, strings.TrimPrefix(c.url, c.shown)} {
			if bytes.Contains(*row.URLEnc, []byte(plain)) {
				t.Fatalf("%s: the URL is stored in the clear", c.column)
			}
		}
		v, err := e.sealer.Open(secret.Context{Table: "webhooks", Column: "url_enc", RowID: w.GetId()}, *row.URLEnc)
		if err != nil || v.Reveal() != c.url { //nolint:forbidigo // the test reads back the URL it stored
			t.Fatalf("%s: the stored URL does not open to the one set: %v", c.column, err)
		}
		if _, err := e.sealer.Open(secret.Context{Table: "webhooks", Column: "secret_enc", RowID: w.GetId()}, *row.URLEnc); err == nil {
			t.Fatalf("%s: the URL opens under another column's context", c.column)
		}
	}

	// A change of the URL, a read, a list and a test send show none of it either.
	list, err := ada.wh.ListWebhooks(ctx, connect.NewRequest(&rpmgrv1.ListWebhooksRequest{OrgId: org}))
	if err != nil || len(list.Msg.GetWebhooks()) != 3 {
		t.Fatalf("list: %v %v", list, err)
	}
	first := list.Msg.GetWebhooks()[0]
	get, err := ada.wh.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: first.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	up, err := updateHook(ada, &rpmgrv1.Webhook{Id: first.GetId(), SecretUrl: discordURL + "2"}, first.GetEtag(), "secret_url")
	if err != nil {
		t.Fatal(err)
	}
	reads := fmt.Sprint(list.Msg, get.Msg, up)
	for _, s := range []string{reads, everythingStored(t, e)} {
		for _, tok := range chatTokens {
			if strings.Contains(s, tok) {
				t.Errorf("a read, an audit entry or an event holds the token %s", tok)
			}
		}
	}
	// The audit diff of the request records that a URL was given, not what.
	if !strings.Contains(everythingStored(t, e), api.Redacted) {
		t.Error("the audit entries do not show the URL as redacted")
	}
	if e.db.Client().Webhook.GetX(e.sys, first.GetId()).Version != 2 {
		t.Error("a new URL did not bump the version")
	}
}

// TestWebhooks_ChatInvalid: a chat endpoint takes its URL in secret_url only, an rpmgr endpoint in
// url only; a URL without a path, with http, credentials, a fragment or a loopback host, or a
// format that does not exist, is refused, and no refusal names the URL.
//
//nolint:gosec // G101: test URLs
func TestWebhooks_ChatInvalid(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	d, s := rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_DISCORD, rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_SLACK
	for name, c := range map[string]*rpmgrv1.Webhook{
		"the URL in url":           {Format: d, Url: discordURL},
		"both URLs":                {Format: d, Url: discordURL, SecretUrl: discordURL},
		"no URL":                   {Format: d},
		"no path":                  {Format: d, SecretUrl: "https://discord.com"},
		"a slash only":             {Format: s, SecretUrl: "https://hooks.slack.com/"},
		"http":                     {Format: s, SecretUrl: "http://hooks.slack.com/services/T/B/SLACKTOKENabcdefghijklmnop"},
		"credentials":              {Format: s, SecretUrl: "https://u:p@hooks.slack.com/services/T/B/SLACKTOKENabcdefghijklmnop"},
		"a fragment":               {Format: s, SecretUrl: slackURL + "#x"},
		"loopback":                 {Format: s, SecretUrl: "https://127.0.0.1/services/T/B/SLACKTOKENabcdefghijklmnop"},
		"localhost":                {Format: s, SecretUrl: "https://localhost/services/T/B/SLACKTOKENabcdefghijklmnop"},
		"too long":                 {Format: s, SecretUrl: slackURL + strings.Repeat("a", webhook.MaxURL)},
		"secret_url with rpmgr":    {SecretUrl: slackURL},
		"secret_url, explicit":     {Format: rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_RPMGR, Url: hookURL, SecretUrl: slackURL},
		"an unknown format":        {Format: rpmgrv1.WebhookFormat(99), SecretUrl: slackURL},
		"a bad type with a format": {Format: s, SecretUrl: slackURL, EventTypes: []string{"Route Update"}},
	} {
		_, err := ada.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org, Webhook: c}))
		if code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && (strings.Contains(err.Error(), "SLACKTOKEN") || strings.Contains(err.Error(), "DISCORDTOKEN")) {
			t.Errorf("%s: the error names the URL: %v", name, err)
		}
	}
	if n := e.db.Client().Webhook.Query().CountX(e.sys); n != 0 {
		t.Fatalf("%d endpoints after the refusals", n)
	}
	// An unspecified format is rpmgr: today's request is unchanged.
	if w, sec := newHook(t, e, ada, org, hookURL); w.GetFormat() != rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_RPMGR || sec == "" || !w.GetSecretSet() || w.GetUrl() != hookURL {
		t.Fatalf("the default format: %v %q", w, sec)
	}
}

// TestWebhooks_ChatUpdate: a chat endpoint's URL changes by a new secret_url only; a new format
// needs one; an rpmgr endpoint becomes a chat one and loses its secrets; a chat endpoint does not
// become rpmgr and cannot be rotated; the event filter and enabling work as for any endpoint.
//
//nolint:gosec // G101: test URLs
func TestWebhooks_ChatUpdate(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	sealedOf := func(id string) []byte { return *e.db.Client().Webhook.GetX(e.sys, id).URLEnc }
	r, err := newChat(t, e, ada, org, rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_DISCORD, discordURL)
	if err != nil {
		t.Fatal(err)
	}
	w, id := r.GetWebhook(), r.GetWebhook().GetId()
	etag, before := w.GetEtag(), sealedOf(id)

	// The event filter and enabling leave the URL as it is.
	up, err := updateHook(ada, &rpmgrv1.Webhook{Id: id, EventTypes: []string{"alert.*"}}, etag, "event_types")
	if err != nil || up.GetUrl() != "https://discord.com" || !bytes.Equal(sealedOf(id), before) {
		t.Fatalf("event types: %v %v", up, err)
	}
	if up, err = updateHook(ada, &rpmgrv1.Webhook{Id: id, Enabled: false}, up.GetEtag(), "enabled"); err != nil || up.GetEnabled() {
		t.Fatalf("disable: %v %v", up, err)
	}
	if up, err = updateHook(ada, &rpmgrv1.Webhook{Id: id, Enabled: true}, up.GetEtag(), "enabled"); err != nil || !up.GetEnabled() || !bytes.Equal(sealedOf(id), before) {
		t.Fatalf("enable: %v %v", up, err)
	}

	slack, teams := rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_SLACK, rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_TEAMS
	for name, c := range map[string]struct {
		w     *rpmgrv1.Webhook
		paths []string
		want  connect.Code
	}{
		"url in the mask":           {&rpmgrv1.Webhook{Id: id, Url: "https://discord.com"}, []string{"url"}, connect.CodeInvalidArgument},
		"a format without its URL":  {&rpmgrv1.Webhook{Id: id, Format: slack}, []string{"format"}, connect.CodeInvalidArgument},
		"a bad URL":                 {&rpmgrv1.Webhook{Id: id, SecretUrl: "http://discord.com/x/y"}, []string{"secret_url"}, connect.CodeInvalidArgument},
		"a URL without a path":      {&rpmgrv1.Webhook{Id: id, SecretUrl: "https://discord.com"}, []string{"secret_url"}, connect.CodeInvalidArgument},
		"an empty URL":              {&rpmgrv1.Webhook{Id: id}, []string{"secret_url"}, 0},
		"becoming rpmgr":            {&rpmgrv1.Webhook{Id: id, Format: rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_RPMGR, Url: hookURL}, []string{"format", "url"}, connect.CodeFailedPrecondition},
		"format cleared to default": {&rpmgrv1.Webhook{Id: id, Url: hookURL}, []string{"format", "url"}, connect.CodeFailedPrecondition},
		"an unknown format":         {&rpmgrv1.Webhook{Id: id, Format: rpmgrv1.WebhookFormat(99), SecretUrl: slackURL}, []string{"format", "secret_url"}, connect.CodeInvalidArgument},
	} {
		cur := e.db.Client().Webhook.GetX(e.sys, id)
		_, err := updateHook(ada, c.w, fmt.Sprint(cur.Version), c.paths...)
		if code(err) != c.want {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if after := e.db.Client().Webhook.GetX(e.sys, id); after.Version != cur.Version && c.want != 0 {
			t.Errorf("%s: a refused update changed the endpoint", name)
		}
	}

	// A new URL of the same format, and a new format with its URL.
	cur := e.db.Client().Webhook.GetX(e.sys, id)
	up, err = updateHook(ada, &rpmgrv1.Webhook{Id: id, SecretUrl: discordURL + "x"}, fmt.Sprint(cur.Version), "secret_url")
	if err != nil || bytes.Equal(sealedOf(id), before) || up.GetFormat() != rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_DISCORD {
		t.Fatalf("a new URL: %v %v", up, err)
	}
	if up, err = updateHook(ada, &rpmgrv1.Webhook{Id: id, Format: slack, SecretUrl: slackURL}, up.GetEtag(), "format", "secret_url"); err != nil ||
		up.GetFormat() != slack || up.GetUrl() != "https://hooks.slack.com" || up.GetSecretSet() {
		t.Fatalf("discord to slack: %v %v", up, err)
	}
	v, _ := e.sealer.Open(secret.Context{Table: "webhooks", Column: "url_enc", RowID: id}, sealedOf(id))
	if v.Reveal() != slackURL { //nolint:forbidigo // the test reads back the URL it stored
		t.Fatal("the slack URL is not the stored one")
	}

	// A chat endpoint has no secret to rotate.
	if _, err := ada.wh.RotateWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateWebhookSecretRequest{WebhookId: id})); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("rotating a chat endpoint: %v", err)
	}

	// An rpmgr endpoint, rotated once, becomes a chat one: its secrets go.
	rw, _ := newHook(t, e, ada, org, hookURL)
	if _, err := ada.wh.RotateWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateWebhookSecretRequest{WebhookId: rw.GetId()})); err != nil {
		t.Fatal(err)
	}
	before2 := e.db.Client().Webhook.GetX(e.sys, rw.GetId())
	if before2.PreviousSecretEnc == nil || len(*before2.PreviousSecretEnc) == 0 || len(before2.SecretEnc) == 0 {
		t.Fatal("the rpmgr endpoint has no secrets to lose")
	}
	for name, c := range map[string]*rpmgrv1.Webhook{
		"no URL":                {Id: rw.GetId(), Format: teams},
		"the old URL as secret": {Id: rw.GetId(), Format: teams, SecretUrl: "https://example.com"},
	} {
		if _, err := updateHook(ada, c, fmt.Sprint(before2.Version), "format", "secret_url"); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	up, err = updateHook(ada, &rpmgrv1.Webhook{Id: rw.GetId(), Format: teams, SecretUrl: teamsURL}, fmt.Sprint(before2.Version), "format", "secret_url")
	if err != nil || up.GetFormat() != teams || up.GetSecretSet() || up.GetPreviousSecretSigns() || up.GetUrl() != "https://prod-12.westus.logic.azure.com:443" {
		t.Fatalf("rpmgr to teams: %v %v", up, err)
	}
	after2 := e.db.Client().Webhook.GetX(e.sys, rw.GetId())
	if len(after2.SecretEnc) != 0 || (after2.PreviousSecretEnc != nil && len(*after2.PreviousSecretEnc) != 0) || after2.PreviousUntil != nil || after2.URLEnc == nil {
		t.Fatalf("stored %+v", after2)
	}
	// An rpmgr endpoint cannot be given a secret_url without a chat format.
	rw2, _ := newHook(t, e, ada, org, hookURL)
	if _, err := updateHook(ada, &rpmgrv1.Webhook{Id: rw2.GetId(), SecretUrl: slackURL}, "", "secret_url"); code(err) != connect.CodeInvalidArgument {
		t.Errorf("secret_url on an rpmgr endpoint: %v", err)
	}
	// An rpmgr endpoint's URL still changes as before, and an unchanged one is not checked again.
	if up, err = updateHook(ada, &rpmgrv1.Webhook{Id: rw2.GetId(), Url: hookURL + "/v2"}, "", "url"); err != nil || up.GetUrl() != hookURL+"/v2" {
		t.Fatalf("an rpmgr URL: %v %v", up, err)
	}
}

// TestWebhooks_ChatTest: a test send to a chat endpoint posts the service's message to the stored
// URL without a signature, and neither the answer nor the error of a failing send nor a transport
// error that embeds the URL shows any of it.
func TestWebhooks_ChatTest(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	var status atomic.Int32
	status.Store(204)
	var got atomic.Pointer[http.Request]
	var body atomic.Pointer[[]byte]
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store(r)
		body.Store(&b)
		rw.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	sender := &webhook.Sender{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}}
	e.webhooks.Sender = sender
	e.webhooks.Policy = func(*ent.Webhook) egress.Policy { return egress.Policy{Internal: true} }
	u := "https://example.com:" + port + "/api/webhooks/1/DISCORDTOKEN-abcdefghijklmnop?wait=true"
	r, err := newChat(t, e, ada, org, rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_DISCORD, u)
	if err != nil {
		t.Fatal(err)
	}
	id := r.GetWebhook().GetId()
	test := func() *rpmgrv1.TestWebhookResponse {
		t.Helper()
		resp, err := ada.wh.TestWebhook(ctx, connect.NewRequest(&rpmgrv1.TestWebhookRequest{WebhookId: id}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg
	}
	if resp := test(); !resp.GetDelivered() || resp.GetStatusCode() != 204 {
		t.Fatalf("a test send: %v", resp)
	}
	req := got.Load()
	if req.URL.Path != "/api/webhooks/1/DISCORDTOKEN-abcdefghijklmnop" || req.URL.RawQuery != "wait=true" || req.Header.Get(webhook.HeaderSignature) != "" ||
		!strings.Contains(string(*body.Load()), `"embeds"`) || !strings.Contains(string(*body.Load()), "webhook.test") {
		t.Fatalf("the request %s %v: %s", req.URL, req.Header, *body.Load())
	}
	status.Store(500)
	if resp := test(); resp.GetDelivered() || resp.GetStatusCode() != 500 || strings.Contains(resp.GetError(), "DISCORDTOKEN") {
		t.Fatalf("a failing receiver: %v", resp)
	}
	status.Store(429)
	if resp := test(); resp.GetDelivered() || resp.GetStatusCode() != 429 || !strings.Contains(resp.GetError(), "rate limiting") {
		t.Fatalf("a rate limit: %v", resp)
	}
	// A transport error that embeds the whole URL.
	sender.Proxy = func(r *http.Request) (*url.URL, error) { return nil, fmt.Errorf("the proxy for %s is down", r.URL) }
	if resp := test(); resp.GetDelivered() || strings.Contains(resp.GetError(), "DISCORDTOKEN") || !strings.Contains(resp.GetError(), "redacted") {
		t.Fatalf("a transport error: %v", resp)
	}
	// A URL that cannot be opened: an error that tells nothing.
	e.db.Client().Webhook.UpdateOneID(id).SetURLEnc([]byte("not sealed at all")).ExecX(e.sys)
	if _, err := ada.wh.TestWebhook(ctx, connect.NewRequest(&rpmgrv1.TestWebhookRequest{WebhookId: id})); code(err) != connect.CodeInternal ||
		strings.Contains(err.Error(), "DISCORDTOKEN") {
		t.Fatalf("an unsealable URL: %v", err)
	}
}

// TestInstanceWebhooks_Chat: the instance's endpoint may be a chat one, with the same sealing, and
// a chat endpoint of an instance is no org's.
func TestInstanceWebhooks_Chat(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	e.logs.Secret(slackURL)
	r, err := ada.iwh.CreateInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateInstanceWebhookRequest{
		Webhook: &rpmgrv1.Webhook{Format: rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_SLACK, SecretUrl: slackURL}}))
	if err != nil {
		t.Fatal(err)
	}
	w := r.Msg.GetWebhook()
	if r.Msg.GetSecret() != "" || w.GetSecretSet() || w.GetUrl() != "https://hooks.slack.com" || w.GetOrgId() != "" {
		t.Fatalf("created %v", w)
	}
	row := e.db.Client().Webhook.GetX(e.sys, w.GetId())
	if row.OrgID != nil || row.URLEnc == nil || bytes.Contains(*row.URLEnc, []byte("SLACKTOKEN")) {
		t.Fatalf("stored %+v", row)
	}
	if strings.Contains(everythingStored(t, e), "SLACKTOKEN") {
		t.Error("an audit entry or event holds the token")
	}
	if _, err := ada.iwh.RotateInstanceWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateInstanceWebhookSecretRequest{WebhookId: w.GetId()})); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("rotate: %v", err)
	}
	if _, err := ada.wh.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: w.GetId()})); code(err) != connect.CodeNotFound {
		t.Errorf("the org's service reads the instance's endpoint: %v (org %s)", err, org)
	}
}

// TestWebhooks_ChatURLBoundToItsRow: a sealed URL copied to another endpoint's row does not open
// there, so a webhooks.write holder with database access cannot redirect one endpoint's token to
// another; the test send fails without naming either URL.
func TestWebhooks_ChatURLBoundToItsRow(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	e.webhooks.Sender = &webhook.Sender{}
	a, err := newChat(t, e, ada, org, rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_DISCORD, discordURL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newChat(t, e, ada, org, rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_SLACK, slackURL)
	if err != nil {
		t.Fatal(err)
	}
	from := e.db.Client().Webhook.GetX(e.sys, a.GetWebhook().GetId())
	e.db.Client().Webhook.UpdateOneID(b.GetWebhook().GetId()).SetURLEnc(*from.URLEnc).ExecX(e.sys)
	_, err = ada.wh.TestWebhook(ctx, connect.NewRequest(&rpmgrv1.TestWebhookRequest{WebhookId: b.GetWebhook().GetId()}))
	if code(err) != connect.CodeInternal || strings.Contains(err.Error(), "TOKEN") {
		t.Fatalf("a URL sealed for another row: %v", err)
	}
}
