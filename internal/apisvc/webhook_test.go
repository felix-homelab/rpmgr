// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"encoding/base32"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/event"
	"github.com/felix-homelab/rpmgr/internal/store/ent/webhookdelivery"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

const hookURL = "https://hooks.example.com/rpmgr"

func newHook(t *testing.T, e *env, b *browser, org, url string, types ...string) (*rpmgrv1.Webhook, string) {
	t.Helper()
	r, err := b.wh.CreateWebhook(context.Background(), connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org,
		Webhook: &rpmgrv1.Webhook{Url: url, EventTypes: types}}))
	if err != nil {
		t.Fatal(err)
	}
	e.logs.Secret(r.Msg.GetSecret())
	return r.Msg.GetWebhook(), r.Msg.GetSecret()
}

func updateHook(b *browser, w *rpmgrv1.Webhook, etag string, paths ...string) (*rpmgrv1.Webhook, error) {
	r, err := b.wh.UpdateWebhook(context.Background(), connect.NewRequest(&rpmgrv1.UpdateWebhookRequest{Webhook: w, Etag: etag,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}))
	if err != nil {
		return nil, err
	}
	return r.Msg.GetWebhook(), nil
}

// everythingStored is every audit entry and event of the instance as text, to search for a secret.
func everythingStored(t *testing.T, e *env) string {
	t.Helper()
	var sb strings.Builder
	for _, a := range e.db.Client().AuditEntry.Query().AllX(e.sys) {
		fmt.Fprintf(&sb, "%+v\n", a)
	}
	for _, ev := range e.db.Client().Event.Query().AllX(e.sys) {
		fmt.Fprintf(&sb, "%+v\n", ev)
	}
	return sb.String()
}

// TestWebhook_SecretWriteOnly (#650): the secret is returned once, by CreateWebhook and
// RotateWebhookSecret, with the documented prefix and 256 random bits; no later response, audit
// entry, event or log line carries it; the stored value is sealed.
func TestWebhook_SecretWriteOnly(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	w, first := newHook(t, e, ada, org, hookURL)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimPrefix(first, webhook.SecretPrefix))
	if !strings.HasPrefix(first, "rpmgr_whs_") || err != nil || len(raw) != 32 || !w.GetSecretSet() || !w.GetEnabled() {
		t.Fatalf("created %v with secret %d bytes: %v", w, len(raw), err)
	}
	row := e.db.Client().Webhook.GetX(e.sys, w.GetId())
	if strings.Contains(string(row.SecretEnc), first) {
		t.Fatal("the secret is stored in the clear")
	}
	if v, err := e.sealer.Open(secret.Context{Table: "webhooks", Column: "secret_enc", RowID: w.GetId()}, row.SecretEnc); err != nil || v.Reveal() != first { //nolint:forbidigo // the test reads back the secret it stored
		t.Fatalf("the stored secret does not open to the shown one: %v", err)
	}

	rot, err := ada.wh.RotateWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateWebhookSecretRequest{WebhookId: w.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	second := rot.Msg.GetSecret()
	e.logs.Secret(second)
	if second == first || !strings.HasPrefix(second, "rpmgr_whs_") {
		t.Fatalf("rotated to %q", second)
	}
	_, _ = ada.wh.UpdateWebhook(ctx, connect.NewRequest(&rpmgrv1.UpdateWebhookRequest{Webhook: &rpmgrv1.Webhook{Id: w.GetId(), Url: hookURL + "/2"},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"url"}}}))
	_, _ = ada.wh.TestWebhook(ctx, connect.NewRequest(&rpmgrv1.TestWebhookRequest{WebhookId: w.GetId()}))

	get, err := ada.wh.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: w.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	list, err := ada.wh.ListWebhooks(ctx, connect.NewRequest(&rpmgrv1.ListWebhooksRequest{OrgId: org}))
	if err != nil || len(list.Msg.GetWebhooks()) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	reads := fmt.Sprint(get.Msg, list.Msg, rot.Msg.GetWebhook())
	stored := everythingStored(t, e)
	for name, s := range map[string]string{"get, list and the rotated endpoint": reads, "audit entries and events": stored} {
		for _, k := range []string{first, second, strings.TrimPrefix(first, webhook.SecretPrefix), strings.TrimPrefix(second, webhook.SecretPrefix)} {
			if strings.Contains(s, k) {
				t.Errorf("%s carry a secret", name)
			}
		}
	}
	// The audit entry of the rotation exists and the events are typed by the method's name.
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.WebhookService.RotateWebhookSecret"), auditentry.ResultEQ("success")).CountX(e.sys); n != 1 {
		t.Errorf("%d audit entries of the rotation", n)
	}
	for _, typ := range []string{"webhook.create", "webhook_secret.rotate", "webhook.update"} {
		if e.db.Client().Event.Query().Where(event.Type(typ)).CountX(e.sys) != 1 {
			t.Errorf("no event %s", typ)
		}
	}
}

// TestWebhooks: an endpoint is made, read, listed in pages, changed by its mask, and deleted with
// its deliveries; bad URLs, event types and masks are refused; Owners and Admins manage, an
// Operator and a Viewer do not.
func TestWebhooks(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	w, _ := newHook(t, e, ada, org, hookURL, "route.*", "token.revoke")
	if w.GetOrgId() != org || w.GetEtag() != "1" || !w.GetEnabled() || w.GetDisabledReason() != 0 || len(w.GetEventTypes()) != 2 {
		t.Fatalf("created %v", w)
	}

	for name, c := range map[string]struct {
		url   string
		types []string
	}{
		"http":           {"http://hooks.example.com/x", nil},
		"credentials":    {"https://user:pw@hooks.example.com/x", nil},
		"empty":          {"", nil},
		"no host":        {"https:///x", nil},
		"fragment":       {"https://hooks.example.com/x#f", nil},
		"too long":       {"https://hooks.example.com/" + strings.Repeat("a", webhook.MaxURL), nil},
		"ftp":            {"ftp://hooks.example.com/x", nil},
		"a bad type":     {hookURL, []string{"Route Update"}},
		"a star inside":  {hookURL, []string{"ro*ute.update"}},
		"a double":       {hookURL, []string{"route.*", "route.*"}},
		"too many types": {hookURL, strings.Split(strings.Repeat("a.b,", webhook.MaxEventTypes+1), ",")[:webhook.MaxEventTypes+1]},
	} {
		_, err := ada.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org,
			Webhook: &rpmgrv1.Webhook{Url: c.url, EventTypes: c.types}}))
		if code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if code(func() error {
		_, err := ada.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org}))
		return err
	}()) != connect.CodeInvalidArgument {
		t.Error("a request without an endpoint")
	}
	if n := e.db.Client().Webhook.Query().CountX(e.sys); n != 1 {
		t.Fatalf("%d endpoints after the refusals", n)
	}

	// The update mask decides what changes; a bad value or field is refused and changes nothing.
	up, err := updateHook(ada, &rpmgrv1.Webhook{Id: w.GetId(), Url: hookURL + "/v2", EventTypes: []string{"gateway.*"}, Enabled: false}, "1", "url")
	if err != nil || up.GetUrl() != hookURL+"/v2" || len(up.GetEventTypes()) != 2 || !up.GetEnabled() || up.GetEtag() != "2" {
		t.Fatalf("a masked update: %v %v", up, err)
	}
	for name, c := range map[string]struct {
		w     *rpmgrv1.Webhook
		etag  string
		paths []string
		want  connect.Code
	}{
		"no mask":        {&rpmgrv1.Webhook{Id: w.GetId()}, "", nil, connect.CodeInvalidArgument},
		"the ID":         {&rpmgrv1.Webhook{Id: w.GetId()}, "", []string{"id"}, connect.CodeInvalidArgument},
		"the org":        {&rpmgrv1.Webhook{Id: w.GetId()}, "", []string{"org_id"}, connect.CodeInvalidArgument},
		"a bad URL":      {&rpmgrv1.Webhook{Id: w.GetId(), Url: "http://x.example"}, "", []string{"url"}, connect.CodeInvalidArgument},
		"an empty URL":   {&rpmgrv1.Webhook{Id: w.GetId()}, "", []string{"url"}, connect.CodeInvalidArgument},
		"a bad type":     {&rpmgrv1.Webhook{Id: w.GetId(), EventTypes: []string{"x y"}}, "", []string{"event_types"}, connect.CodeInvalidArgument},
		"a stale etag":   {&rpmgrv1.Webhook{Id: w.GetId(), Enabled: true}, "1", []string{"enabled"}, connect.CodeFailedPrecondition},
		"another ID":     {&rpmgrv1.Webhook{Id: "whk_00000000000000000000000000"}, "", []string{"url"}, connect.CodeNotFound},
		"a malformed ID": {&rpmgrv1.Webhook{Id: "nope"}, "", []string{"url"}, connect.CodeNotFound},
	} {
		if _, err := updateHook(ada, c.w, c.etag, c.paths...); code(err) != c.want {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if up, err = updateHook(ada, &rpmgrv1.Webhook{Id: w.GetId(), EventTypes: nil}, "", "event_types"); err != nil || len(up.GetEventTypes()) != 0 {
		t.Fatalf("clearing the types (all events): %v %v", up, err)
	}

	// Pages, by ID.
	second, _ := newHook(t, e, ada, org, hookURL+"/b")
	third, _ := newHook(t, e, ada, org, hookURL+"/c")
	p1, err := ada.wh.ListWebhooks(ctx, connect.NewRequest(&rpmgrv1.ListWebhooksRequest{OrgId: org, PageSize: 2}))
	if err != nil || len(p1.Msg.GetWebhooks()) != 2 || p1.Msg.GetNextPageToken() == "" || p1.Msg.GetWebhooks()[0].GetId() != w.GetId() {
		t.Fatalf("page 1: %v %v", p1, err)
	}
	p2, err := ada.wh.ListWebhooks(ctx, connect.NewRequest(&rpmgrv1.ListWebhooksRequest{OrgId: org, PageSize: 2, PageToken: p1.Msg.GetNextPageToken()}))
	if err != nil || len(p2.Msg.GetWebhooks()) != 1 || p2.Msg.GetWebhooks()[0].GetId() != third.GetId() || p2.Msg.GetNextPageToken() != "" {
		t.Fatalf("page 2: %v %v (second %s)", p2, err, second.GetId())
	}
	if _, err := ada.wh.ListWebhooks(ctx, connect.NewRequest(&rpmgrv1.ListWebhooksRequest{OrgId: org, PageToken: "forged"})); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a forged page token: %v", err)
	}

	// Roles: an Admin manages, an Operator and a Viewer cannot even read (a URL may hold a token).
	if err := ada.stepUp(pw, ""); err != nil { // inviting an Admin
		t.Fatal(err)
	}
	adm, _ := e.join(t, ada, org, "adm@example.com", "admin")
	if _, err := adm.wh.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: w.GetId()})); err != nil {
		t.Errorf("an Admin reads: %v", err)
	}
	for _, role := range []string{"operator", "viewer"} {
		u, _ := e.join(t, ada, org, role+"@example.com", role)
		if _, err := u.wh.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: w.GetId()})); code(err) != connect.CodePermissionDenied {
			t.Errorf("a %s reads: %v", role, err)
		}
		if _, err := u.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org, Webhook: &rpmgrv1.Webhook{Url: hookURL}})); code(err) != connect.CodePermissionDenied {
			t.Errorf("a %s creates: %v", role, err)
		}
		if _, err := u.wh.ListWebhooks(ctx, connect.NewRequest(&rpmgrv1.ListWebhooksRequest{OrgId: org})); code(err) != connect.CodePermissionDenied {
			t.Errorf("a %s lists: %v", role, err)
		}
	}

	// Deleting removes the endpoint and its deliveries, and only its own.
	for _, h := range []string{w.GetId(), second.GetId()} {
		e.db.Client().WebhookDelivery.Create().SetWebhookID(h).SetOrgID(org).SetEventID("evt_x").SetAttempt(1).SetSentAt(e.clock).ExecX(e.sys)
	}
	if _, err := ada.wh.DeleteWebhook(ctx, connect.NewRequest(&rpmgrv1.DeleteWebhookRequest{WebhookId: w.GetId(), Etag: "1"})); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a delete with a stale etag: %v", err)
	}
	if _, err := ada.wh.DeleteWebhook(ctx, connect.NewRequest(&rpmgrv1.DeleteWebhookRequest{WebhookId: w.GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.wh.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: w.GetId()})); code(err) != connect.CodeNotFound {
		t.Errorf("a deleted endpoint: %v", err)
	}
	if n := e.db.Client().WebhookDelivery.Query().Where(webhookdelivery.WebhookID(w.GetId())).CountX(e.sys); n != 0 {
		t.Errorf("%d deliveries outlive their endpoint", n)
	}
	if n := e.db.Client().WebhookDelivery.Query().Where(webhookdelivery.WebhookID(second.GetId())).CountX(e.sys); n != 1 {
		t.Errorf("another endpoint's deliveries: %d", n)
	}
	if _, err := ada.wh.DeleteWebhook(ctx, connect.NewRequest(&rpmgrv1.DeleteWebhookRequest{WebhookId: w.GetId()})); code(err) != connect.CodeNotFound {
		t.Errorf("a second delete: %v", err)
	}
}

// TestWebhooks_OtherOrg: every method answers NOT_FOUND (or PERMISSION_DENIED where the caller
// names the org) for another org's endpoint, and changes nothing.
func TestWebhooks_OtherOrg(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	w, _ := newHook(t, e, ada, org, hookURL)
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	own, _ := newHook(t, e, bob, orgB, "https://bob.example.com/hook")
	id := w.GetId()
	calls := map[string]func() error{
		"get": func() error {
			_, err := bob.wh.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: id}))
			return err
		},
		"update": func() error {
			_, err := updateHook(bob, &rpmgrv1.Webhook{Id: id, Url: "https://bob.example.com/x"}, "", "url")
			return err
		},
		"delete": func() error {
			_, err := bob.wh.DeleteWebhook(ctx, connect.NewRequest(&rpmgrv1.DeleteWebhookRequest{WebhookId: id}))
			return err
		},
		"rotate": func() error {
			_, err := bob.wh.RotateWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateWebhookSecretRequest{WebhookId: id}))
			return err
		},
		"deliveries": func() error {
			_, err := bob.wh.ListWebhookDeliveries(ctx, connect.NewRequest(&rpmgrv1.ListWebhookDeliveriesRequest{WebhookId: id}))
			return err
		},
		"test": func() error {
			_, err := bob.wh.TestWebhook(ctx, connect.NewRequest(&rpmgrv1.TestWebhookRequest{WebhookId: id}))
			return err
		},
	}
	for name, call := range calls {
		if c := code(call()); c != connect.CodeNotFound {
			t.Errorf("%s: %v", name, c)
		}
	}
	for name, call := range map[string]func() error{
		"create in the org": func() error {
			_, err := bob.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org, Webhook: &rpmgrv1.Webhook{Url: hookURL}}))
			return err
		},
		"list the org": func() error {
			_, err := bob.wh.ListWebhooks(ctx, connect.NewRequest(&rpmgrv1.ListWebhooksRequest{OrgId: org}))
			return err
		},
	} {
		if c := code(call()); c != connect.CodePermissionDenied && c != connect.CodeNotFound {
			t.Errorf("%s: %v", name, c)
		}
	}
	// Bob sees only his own, and Ada's endpoint is untouched.
	l, err := bob.wh.ListWebhooks(ctx, connect.NewRequest(&rpmgrv1.ListWebhooksRequest{OrgId: orgB}))
	if err != nil || len(l.Msg.GetWebhooks()) != 1 || l.Msg.GetWebhooks()[0].GetId() != own.GetId() {
		t.Fatalf("bob's list: %v %v", l, err)
	}
	if got, err := ada.wh.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: id})); err != nil ||
		got.Msg.GetWebhook().GetUrl() != hookURL || got.Msg.GetWebhook().GetEtag() != "1" {
		t.Fatalf("ada's endpoint: %v %v", got, err)
	}
}

// TestWebhooks_DisableAndEnable (D143): a person disables an endpoint, which says so; enabling it
// again clears the disable of either reason and its failing period, and events count from then on.
func TestWebhooks_DisableAndEnable(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	w, _ := newHook(t, e, ada, org, hookURL)
	off, err := updateHook(ada, &rpmgrv1.Webhook{Id: w.GetId(), Enabled: false}, "", "enabled")
	if err != nil || off.GetEnabled() || off.GetDisabledReason() != rpmgrv1.WebhookDisabledReason_WEBHOOK_DISABLED_REASON_PERSON {
		t.Fatalf("disabled by a person: %v %v", off, err)
	}
	// The job disabled it for failing.
	e.db.Client().Webhook.UpdateOneID(w.GetId()).SetEnabled(false).SetDisabledReason("failing").SetFailingSince(e.clock.Add(-4 * 24 * time.Hour)).ExecX(e.sys)
	got, _ := ada.wh.GetWebhook(context.Background(), connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: w.GetId()}))
	if got.Msg.GetWebhook().GetDisabledReason() != rpmgrv1.WebhookDisabledReason_WEBHOOK_DISABLED_REASON_FAILING ||
		got.Msg.GetWebhook().GetFailingSinceTime() == nil {
		t.Fatalf("disabled for failing: %v", got.Msg.GetWebhook())
	}
	// Changing another field leaves it disabled.
	if still, err := updateHook(ada, &rpmgrv1.Webhook{Id: w.GetId(), Url: hookURL + "/new", Enabled: false}, "", "url", "enabled"); err != nil || still.GetEnabled() {
		t.Fatalf("still disabled: %v %v", still, err)
	}
	e.clock = e.clock.Add(time.Minute)
	on, err := updateHook(ada, &rpmgrv1.Webhook{Id: w.GetId(), Enabled: true}, "", "enabled")
	if err != nil || !on.GetEnabled() || on.GetDisabledReason() != 0 || on.GetFailingSinceTime() != nil {
		t.Fatalf("enabled again: %v %v", on, err)
	}
	row := e.db.Client().Webhook.GetX(e.sys, w.GetId())
	if row.DisabledReason != nil || row.FailingSince != nil || row.EnabledAt.Before(e.clock.Add(-time.Second)) {
		t.Fatalf("the row after enabling: %+v", row)
	}
}

// TestWebhooks_Rotation (TestWebhook_SignatureAndReplayWindow, rotation clause): after a rotation
// a delivery carries two v1 values, one per secret, for 24 hours and one afterwards, the new
// secret's; the endpoint says until when the old one signs.
func TestWebhooks_Rotation(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	type signed struct {
		sig  string
		body []byte
	}
	sigs := make(chan signed, 4)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sigs <- signed{r.Header.Get(webhook.HeaderSignature), b}
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	e.webhooks.Sender = &webhook.Sender{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Now: func() time.Time { return e.clock },
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}}
	e.webhooks.Policy = func(*ent.Webhook) egress.Policy { return egress.Policy{Internal: true} }
	w, first := newHook(t, e, ada, org, "https://example.com:"+port+"/hook")

	test := func(secrets ...string) string {
		t.Helper()
		r, err := ada.wh.TestWebhook(ctx, connect.NewRequest(&rpmgrv1.TestWebhookRequest{WebhookId: w.GetId()}))
		if err != nil || !r.Msg.GetDelivered() || r.Msg.GetStatusCode() != 200 || r.Msg.GetError() != "" {
			t.Fatalf("test send: %v %v", r, err)
		}
		got := <-sigs
		for _, k := range secrets {
			if err := webhook.Verify(got.sig, got.body, k, e.clock); err != nil {
				t.Errorf("the signature does not verify with %s...: %v", k[:14], err)
			}
		}
		return got.sig
	}
	if s := test(first); strings.Count(s, "v1=") != 1 {
		t.Fatalf("before a rotation: %s", s)
	}
	rot, err := ada.wh.RotateWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateWebhookSecretRequest{WebhookId: w.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	second := rot.Msg.GetSecret()
	e.logs.Secret(second)
	if !rot.Msg.GetWebhook().GetPreviousSecretSigns() || !rot.Msg.GetWebhook().GetPreviousSecretUntil().AsTime().Equal(e.clock.UTC().Add(webhook.PreviousSigns)) {
		t.Fatalf("the rotated endpoint: %v", rot.Msg.GetWebhook())
	}
	if s := test(first, second); strings.Count(s, "v1=") != 2 {
		t.Fatalf("during the rotation: %s", s)
	}
	// 24 hours later, the old secret has stopped signing.
	e.db.Client().Webhook.UpdateOneID(w.GetId()).SetPreviousUntil(e.clock.Add(-time.Second)).ExecX(e.sys)
	if s := test(second); strings.Count(s, "v1=") != 1 {
		t.Fatalf("after the rotation: %s", s)
	}
	got, _ := ada.wh.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: w.GetId()}))
	if got.Msg.GetWebhook().GetPreviousSecretSigns() {
		t.Error("the endpoint says the old secret still signs")
	}
	// Two rotations in a row: the secret of the first is gone at once, the second's is previous.
	if _, err := ada.wh.RotateWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateWebhookSecretRequest{WebhookId: w.GetId()})); err != nil {
		t.Fatal(err)
	}
	if s := test(); strings.Count(s, "v1=") != 2 {
		t.Fatalf("after a second rotation: %s", s)
	}
}

// TestWebhooks_Test: a test send is signed, sent through the egress guard, audited and not
// queued as an event; a refused receiver, a failing receiver and a secret that cannot be opened
// are reported without the URL or the secret.
func TestWebhooks_Test(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	var status atomic.Int32
	status.Store(200)
	var got atomic.Pointer[http.Request]
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		got.Store(r)
		rw.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	e.webhooks.Sender = &webhook.Sender{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}}
	w, sec := newHook(t, e, ada, org, "https://example.com:"+port+"/hook?token=receiver-token")
	test := func(id string) (*rpmgrv1.TestWebhookResponse, error) {
		r, err := ada.wh.TestWebhook(ctx, connect.NewRequest(&rpmgrv1.TestWebhookRequest{WebhookId: id}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}

	// The guard: the receiver is on loopback, which an org endpoint never reaches.
	r, err := test(w.GetId())
	if err != nil || r.GetDelivered() || !strings.Contains(r.GetError(), "egress guard") || strings.Contains(r.GetError(), "127.0.0.1") ||
		strings.Contains(r.GetError(), "receiver-token") {
		t.Fatalf("a receiver on loopback: %v %v", r, err)
	}
	if got.Load() != nil {
		t.Fatal("the guard let the request through")
	}
	// Admitted by a test policy: delivered and signed with the shown secret.
	e.webhooks.Policy = func(*ent.Webhook) egress.Policy { return egress.Policy{Internal: true} }
	r, err = test(w.GetId())
	if err != nil || !r.GetDelivered() || r.GetStatusCode() != 200 {
		t.Fatalf("a test send: %v %v", r, err)
	}
	req := got.Load()
	if req.Header.Get(webhook.HeaderEventType) != "webhook.test" || !strings.HasPrefix(req.Header.Get(webhook.HeaderEventID), "evt_") ||
		req.URL.Query().Get("token") != "receiver-token" || req.Header.Get(webhook.HeaderSignature) == "" {
		t.Fatalf("the request: %v", req.Header)
	}
	// A failing receiver.
	status.Store(500)
	if r, err = test(w.GetId()); err != nil || r.GetDelivered() || r.GetStatusCode() != 500 || !strings.Contains(r.GetError(), "500") ||
		strings.Contains(r.GetError(), "receiver-token") {
		t.Fatalf("a failing receiver: %v %v", r, err)
	}
	// Audited each time, with the result; the test is its own event and no outbox event.
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.WebhookService.TestWebhook"), auditentry.ResultEQ("success"),
		auditentry.TargetID(w.GetId())).CountX(e.sys); n != 3 {
		t.Errorf("%d audit entries of the tests, want 3", n)
	}
	if n := e.db.Client().Event.Query().Where(event.Type("webhook.test")).CountX(e.sys); n != 0 {
		t.Errorf("%d queued webhook.test events", n)
	}
	// A secret that cannot be opened: an error that tells nothing.
	e.db.Client().Webhook.UpdateOneID(w.GetId()).SetSecretEnc([]byte("not sealed at all")).ExecX(e.sys)
	if _, err := test(w.GetId()); code(err) != connect.CodeInternal || strings.Contains(err.Error(), sec) {
		t.Fatalf("an unsealable secret: %v", err)
	}
	// No sender: refused, not crashed.
	e.webhooks.Sender = nil
	if _, err := test(w.GetId()); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("no sender: %v", err)
	}
}

// TestWebhooks_Deliveries: an endpoint's deliveries are listed newest first, in pages, with their
// status and next retry, and never another endpoint's.
func TestWebhooks_Deliveries(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	w, _ := newHook(t, e, ada, org, hookURL)
	other, _ := newHook(t, e, ada, org, hookURL+"/other")
	empty, err := ada.wh.ListWebhookDeliveries(ctx, connect.NewRequest(&rpmgrv1.ListWebhookDeliveriesRequest{WebhookId: w.GetId()}))
	if err != nil || len(empty.Msg.GetDeliveries()) != 0 || empty.Msg.GetNextPageToken() != "" {
		t.Fatalf("no deliveries: %v %v", empty, err)
	}
	for i := 1; i <= 3; i++ {
		c := e.db.Client().WebhookDelivery.Create().SetWebhookID(w.GetId()).SetOrgID(org).SetEventID(fmt.Sprintf("evt_%d", i)).SetEventType("route.update").
			SetAttempt(i).SetStatusCode(500).SetError("the receiver answered 500").SetSentAt(e.clock)
		if i == 3 {
			c.SetNextAttemptAt(e.clock.Add(time.Minute))
		}
		c.ExecX(e.sys)
	}
	e.db.Client().WebhookDelivery.Create().SetWebhookID(other.GetId()).SetOrgID(org).SetEventID("evt_o").SetAttempt(1).SetSentAt(e.clock).ExecX(e.sys)
	p1, err := ada.wh.ListWebhookDeliveries(ctx, connect.NewRequest(&rpmgrv1.ListWebhookDeliveriesRequest{WebhookId: w.GetId(), PageSize: 2}))
	if err != nil || len(p1.Msg.GetDeliveries()) != 2 || p1.Msg.GetDeliveries()[0].GetAttempt() != 3 || p1.Msg.GetDeliveries()[0].GetNextAttemptTime() == nil ||
		p1.Msg.GetDeliveries()[1].GetNextAttemptTime() != nil || p1.Msg.GetDeliveries()[0].GetStatusCode() != 500 ||
		p1.Msg.GetDeliveries()[0].GetEventType() != "route.update" || p1.Msg.GetNextPageToken() == "" {
		t.Fatalf("page 1: %v %v", p1, err)
	}
	p2, err := ada.wh.ListWebhookDeliveries(ctx, connect.NewRequest(&rpmgrv1.ListWebhookDeliveriesRequest{WebhookId: w.GetId(), PageSize: 2,
		PageToken: p1.Msg.GetNextPageToken()}))
	if err != nil || len(p2.Msg.GetDeliveries()) != 1 || p2.Msg.GetDeliveries()[0].GetAttempt() != 1 || p2.Msg.GetNextPageToken() != "" {
		t.Fatalf("page 2: %v %v", p2, err)
	}
	if _, err := ada.wh.ListWebhookDeliveries(ctx, connect.NewRequest(&rpmgrv1.ListWebhookDeliveriesRequest{WebhookId: w.GetId(), PageSize: -1})); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a negative page size: %v", err)
	}
}
