// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

func newInstanceHook(t *testing.T, e *env, b *browser, url string, types ...string) (*rpmgrv1.Webhook, string) {
	t.Helper()
	r, err := b.iwh.CreateInstanceWebhook(context.Background(), connect.NewRequest(&rpmgrv1.CreateInstanceWebhookRequest{
		Webhook: &rpmgrv1.Webhook{Url: url, EventTypes: types}}))
	if err != nil {
		t.Fatal(err)
	}
	e.logs.Secret(r.Msg.GetSecret())
	return r.Msg.GetWebhook(), r.Msg.GetSecret()
}

// TestInstanceWebhooks: the Instance Admin makes, reads, lists, changes, rotates, tests and
// deletes the instance's endpoints; an endpoint of no org may name a receiver on loopback; the
// secret is shown once and is in no audit entry or event.
func TestInstanceWebhooks(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	w, sec := newInstanceHook(t, e, ada, "https://localhost:8443/rpmgr", "release.*")
	if w.GetOrgId() != "" || !w.GetEnabled() || !w.GetSecretSet() || !strings.HasPrefix(sec, webhook.SecretPrefix) {
		t.Fatalf("the instance endpoint: %v", w)
	}
	row := e.db.Client().Webhook.GetX(e.sys, w.GetId())
	if row.OrgID != nil {
		t.Fatalf("stored with org %s", *row.OrgID)
	}
	orgHook, _ := newHook(t, e, ada, org, hookURL)
	g, err := ada.iwh.GetInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.GetInstanceWebhookRequest{WebhookId: w.GetId()}))
	if err != nil || g.Msg.GetWebhook().GetUrl() != "https://localhost:8443/rpmgr" {
		t.Fatalf("get: %v %v", g, err)
	}
	l, err := ada.iwh.ListInstanceWebhooks(ctx, connect.NewRequest(&rpmgrv1.ListInstanceWebhooksRequest{}))
	if err != nil || len(l.Msg.GetWebhooks()) != 1 || l.Msg.GetWebhooks()[0].GetId() != w.GetId() {
		t.Fatalf("the list holds an org's endpoint or misses the instance's: %v %v", l, err)
	}
	ol, _ := ada.wh.ListWebhooks(ctx, connect.NewRequest(&rpmgrv1.ListWebhooksRequest{OrgId: org}))
	if len(ol.Msg.GetWebhooks()) != 1 || ol.Msg.GetWebhooks()[0].GetId() != orgHook.GetId() {
		t.Fatalf("the org's list: %v", ol)
	}
	up, err := ada.iwh.UpdateInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.UpdateInstanceWebhookRequest{
		Webhook: &rpmgrv1.Webhook{Id: w.GetId(), Enabled: false}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"enabled"}}, Etag: "1"}))
	if err != nil || up.Msg.GetWebhook().GetEnabled() || up.Msg.GetWebhook().GetDisabledReason() != rpmgrv1.WebhookDisabledReason_WEBHOOK_DISABLED_REASON_PERSON {
		t.Fatalf("update: %v %v", up, err)
	}
	rot, err := ada.iwh.RotateInstanceWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateInstanceWebhookSecretRequest{WebhookId: w.GetId()}))
	if err != nil || rot.Msg.GetSecret() == sec || !rot.Msg.GetWebhook().GetPreviousSecretSigns() {
		t.Fatalf("rotate: %v %v", rot, err)
	}
	e.logs.Secret(rot.Msg.GetSecret())
	if _, err := ada.iwh.ListInstanceWebhookDeliveries(ctx, connect.NewRequest(&rpmgrv1.ListInstanceWebhookDeliveriesRequest{WebhookId: w.GetId()})); err != nil {
		t.Fatalf("deliveries: %v", err)
	}
	e.webhooks.Sender = &webhook.Sender{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}}
	tr, err := ada.iwh.TestInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.TestInstanceWebhookRequest{WebhookId: w.GetId()}))
	if err != nil || tr.Msg.GetDelivered() || !strings.Contains(tr.Msg.GetError(), "link-local") {
		t.Fatalf("test: an instance endpoint never reaches a link-local address: %v %v", tr, err)
	}
	// The secrets are in no audit entry and no event.
	all := everythingStored(t, e)
	for _, s := range []string{sec, rot.Msg.GetSecret()} {
		if strings.Contains(all, s) || strings.Contains(all, strings.TrimPrefix(s, webhook.SecretPrefix)) {
			t.Fatal("a secret is in an audit entry or an event")
		}
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.InstanceWebhookService.CreateInstanceWebhook"),
		auditentry.ResultEQ("success")).CountX(e.sys); n != 1 {
		t.Errorf("%d audit entries of the creation, want 1", n)
	}
	if _, err := ada.iwh.DeleteInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.DeleteInstanceWebhookRequest{WebhookId: w.GetId(), Etag: "1"})); code(err) != connect.CodeAborted &&
		code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a delete with a stale etag: %v", err)
	}
	if _, err := ada.iwh.DeleteInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.DeleteInstanceWebhookRequest{WebhookId: w.GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.iwh.GetInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.GetInstanceWebhookRequest{WebhookId: w.GetId()})); code(err) != connect.CodeNotFound {
		t.Errorf("after the delete: %v", err)
	}
	// A bad URL is refused for an instance endpoint too.
	_, err = ada.iwh.CreateInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateInstanceWebhookRequest{Webhook: &rpmgrv1.Webhook{Url: "http://localhost/x"}}))
	if code(err) != connect.CodeInvalidArgument {
		t.Errorf("an http URL: %v", err)
	}
}

// TestInstanceWebhooks_Boundary: an org Owner neither lists nor manages the instance's endpoints,
// whichever service they ask; the instance service does not serve an org's endpoints; and each
// service answers NOT_FOUND for the other's.
func TestInstanceWebhooks_Boundary(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	inst, _ := newInstanceHook(t, e, ada, "https://localhost:8443/rpmgr")
	orgHook, _ := newHook(t, e, ada, org, hookURL)
	bob, _ := e.addOwner(t, org, "bob@example.com")
	denied := map[string]func() error{
		"create": func() error {
			_, err := bob.iwh.CreateInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateInstanceWebhookRequest{Webhook: &rpmgrv1.Webhook{Url: hookURL}}))
			return err
		},
		"get": func() error {
			_, err := bob.iwh.GetInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.GetInstanceWebhookRequest{WebhookId: inst.GetId()}))
			return err
		},
		"list": func() error {
			_, err := bob.iwh.ListInstanceWebhooks(ctx, connect.NewRequest(&rpmgrv1.ListInstanceWebhooksRequest{}))
			return err
		},
		"update": func() error {
			_, err := bob.iwh.UpdateInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.UpdateInstanceWebhookRequest{
				Webhook: &rpmgrv1.Webhook{Id: inst.GetId(), Url: hookURL}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"url"}}}))
			return err
		},
		"delete": func() error {
			_, err := bob.iwh.DeleteInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.DeleteInstanceWebhookRequest{WebhookId: inst.GetId()}))
			return err
		},
		"rotate": func() error {
			_, err := bob.iwh.RotateInstanceWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateInstanceWebhookSecretRequest{WebhookId: inst.GetId()}))
			return err
		},
		"deliveries": func() error {
			_, err := bob.iwh.ListInstanceWebhookDeliveries(ctx, connect.NewRequest(&rpmgrv1.ListInstanceWebhookDeliveriesRequest{WebhookId: inst.GetId()}))
			return err
		},
		"test": func() error {
			_, err := bob.iwh.TestInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.TestInstanceWebhookRequest{WebhookId: inst.GetId()}))
			return err
		},
		// The org service does not reach the instance's endpoint either.
		"org get": func() error {
			_, err := bob.wh.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: inst.GetId()}))
			return err
		},
		"org rotate": func() error {
			_, err := bob.wh.RotateWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateWebhookSecretRequest{WebhookId: inst.GetId()}))
			return err
		},
		"org create without org": func() error {
			_, err := bob.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{Webhook: &rpmgrv1.Webhook{Url: hookURL}}))
			return err
		},
	}
	for name, call := range denied {
		if c := code(call()); c != connect.CodePermissionDenied && c != connect.CodeNotFound && c != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, c)
		}
		if err := call(); err == nil {
			t.Errorf("%s: an org Owner succeeded", name)
		}
	}
	// The Instance Admin's two services keep to their own endpoints.
	wrong := map[string]func() error{
		"instance get of an org's": func() error {
			_, err := ada.iwh.GetInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.GetInstanceWebhookRequest{WebhookId: orgHook.GetId()}))
			return err
		},
		"instance delete of an org's": func() error {
			_, err := ada.iwh.DeleteInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.DeleteInstanceWebhookRequest{WebhookId: orgHook.GetId()}))
			return err
		},
		"instance rotate of an org's": func() error {
			_, err := ada.iwh.RotateInstanceWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateInstanceWebhookSecretRequest{WebhookId: orgHook.GetId()}))
			return err
		},
		"instance test of an org's": func() error {
			_, err := ada.iwh.TestInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.TestInstanceWebhookRequest{WebhookId: orgHook.GetId()}))
			return err
		},
		"org get of the instance's": func() error {
			_, err := ada.wh.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: inst.GetId()}))
			return err
		},
		"no such endpoint": func() error {
			_, err := ada.iwh.GetInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.GetInstanceWebhookRequest{WebhookId: "whk_none"}))
			return err
		},
	}
	for name, call := range wrong {
		if c := code(call()); c != connect.CodeNotFound {
			t.Errorf("%s: %v", name, c)
		}
	}
	if n := e.db.Client().Webhook.Query().CountX(e.sys); n != 2 {
		t.Errorf("%d endpoints, want the 2 that were made", n)
	}
}

// TestWebhooks_PrivateRanges is the allow-list clause of TestWebhook_EgressGuard: a private
// receiver of an org is refused, naming its range, until the Instance Admin lists the range;
// then it is admitted. A listed range never admits loopback, link-local or metadata addresses.
// The change of the list is audited, and a list that is not a list of prefixes is refused.
func TestWebhooks_PrivateRanges(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	var resolved netip.Addr
	e.webhooks.Sender = &webhook.Sender{Lookup: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{resolved}, nil }}
	e.webhooks.Private = func(context.Context) ([]netip.Prefix, error) {
		inst, _, err := settings.Instance(e.sys, e.db.ReadClient())
		return settings.PrivateRanges(inst), err
	}
	w, _ := newHook(t, e, ada, org, "https://nas.example.com:9/hook")
	list := func(ranges ...string) error {
		_, err := ada.set.UpdateInstanceSettings(ctx, connect.NewRequest(&rpmgrv1.UpdateInstanceSettingsRequest{
			Settings: &rpmgrv1.InstanceSettings{WebhookPrivateRanges: ranges}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"webhook_private_ranges"}}}))
		return err
	}
	test := func(addr string) string {
		t.Helper()
		resolved = netip.MustParseAddr(addr)
		e.clock = e.clock.Add(time.Minute) // keeps clear of the test rate limit
		r, err := ada.wh.TestWebhook(ctx, connect.NewRequest(&rpmgrv1.TestWebhookRequest{WebhookId: w.GetId()}))
		if err != nil {
			t.Fatal(err)
		}
		if g := r.Msg.GetError(); strings.Contains(g, "egress guard") && strings.Contains(g, addr) {
			t.Errorf("the error names the address: %s", r.Msg.GetError())
		}
		return r.Msg.GetError()
	}
	if got := test("10.1.2.3"); !strings.Contains(got, "egress guard") || !strings.Contains(got, "listing 10.0.0.0/8 in webhook_private_ranges") {
		t.Fatalf("a private receiver, not listed: %q", got)
	}
	if err := list("10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	// Admitted: the dial goes on, and nothing listens there.
	if got := test("10.1.2.3"); strings.Contains(got, "egress guard") {
		t.Fatalf("a listed range: %q", got)
	}
	if got := test("192.168.1.1"); !strings.Contains(got, "listing 192.168.0.0/16") {
		t.Fatalf("an unlisted range: %q", got)
	}
	// A listed range never admits an always-denied address, however wide it is.
	if err := list("0.0.0.0/0", "::/0", "127.0.0.0/8", "169.254.0.0/16"); err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]string{"127.0.0.1": "loopback", "::1": "loopback", "169.254.169.254": "link-local",
		"169.254.1.1": "link-local", "224.0.0.1": "multicast", "100.100.100.200": "metadata", "::ffff:127.0.0.1": "loopback"} {
		if got := test(addr); !strings.Contains(got, "egress guard") || !strings.Contains(got, want) {
			t.Errorf("%s with the widest list: %q, want refused as %s", addr, got, want)
		}
	}
	// The change is audited, in the instance chain.
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.SettingsService.UpdateInstanceSettings"),
		auditentry.ResultEQ("success")).CountX(e.sys); n < 2 {
		t.Errorf("%d audit entries of the list changes, want 2", n)
	}
	// Only prefixes, without host bits, at most 32, each once.
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	for name, ranges := range map[string][]string{"a word": {"lan"}, "an address": {"10.0.0.1"}, "host bits": {"10.0.0.1/8"}, "twice": {"10.0.0.0/8", "10.0.0.0/8"},
		"33 entries": many, "empty": {""}, "a range with a name": {"nas/24"}} {
		if err := list(ranges...); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := list(); err != nil {
		t.Errorf("an empty list: %v", err)
	}
	if got := test("10.1.2.3"); !strings.Contains(got, "egress guard") {
		t.Errorf("after the list is emptied: %q", got)
	}
}

// TestWebhooks_URLRules: an org's endpoint may not name localhost or a loopback, link-local or
// unspecified address; an instance endpoint may name the first two. An endpoint made before a
// rule stays editable in its other fields.
func TestWebhooks_URLRules(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	for _, u := range []string{"https://localhost/x", "https://LOCALHOST:8443/x", "https://localhost./x", "https://hooks.localhost/x", "https://127.0.0.1/x",
		"https://127.1.2.3:9/x", "https://[::1]/x", "https://[::ffff:127.0.0.1]/x", "https://169.254.169.254/x", "https://[fe80::1]/x", "https://0.0.0.0/x", "https://[::]/x"} {
		_, err := ada.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org, Webhook: &rpmgrv1.Webhook{Url: u}}))
		if code(err) != connect.CodeInvalidArgument {
			t.Errorf("org create %s: %v", u, err)
		}
	}
	for _, u := range []string{"https://hooks.example.com/x", "https://nas.home.arpa/x", "https://10.1.2.3/x", "https://localhost.example.com/x", "https://[2001:db8::1]/x"} {
		if _, err := ada.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org, Webhook: &rpmgrv1.Webhook{Url: u}})); err != nil {
			t.Errorf("org create %s: %v", u, err)
		}
	}
	w, _ := newHook(t, e, ada, org, "https://hooks.example.com/y")
	if _, err := updateHook(ada, &rpmgrv1.Webhook{Id: w.GetId(), Url: "https://localhost/y"}, "", "url"); code(err) != connect.CodeInvalidArgument {
		t.Errorf("an update to localhost: %v", err)
	}
	// A stored URL from before the rule: other fields can still be changed.
	e.db.Client().Webhook.UpdateOneID(w.GetId()).SetURL("https://localhost/legacy").ExecX(e.sys)
	if _, err := updateHook(ada, &rpmgrv1.Webhook{Id: w.GetId(), Url: "https://localhost/legacy", Enabled: false}, "", "enabled"); err != nil {
		t.Errorf("disabling an endpoint with an old URL: %v", err)
	}
	for _, u := range []string{"https://localhost/x", "https://127.0.0.1:8443/x"} {
		if _, err := ada.iwh.CreateInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateInstanceWebhookRequest{Webhook: &rpmgrv1.Webhook{Url: u}})); err != nil {
			t.Errorf("instance create %s: %v", u, err)
		}
	}
}

// TestWebhooks_Cap: an org has at most webhook.MaxPerOrg endpoints, and so has the instance,
// counted apart; deleting one makes room.
func TestWebhooks_Cap(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	orgB := storetest.Org(t, e.db, "org-b")
	var last *rpmgrv1.Webhook
	for i := range webhook.MaxPerOrg {
		last, _ = newHook(t, e, ada, org, fmt.Sprintf("https://hooks.example.com/%d", i))
		newInstanceHook(t, e, ada, fmt.Sprintf("https://hooks.example.com/i%d", i))
	}
	_, err := ada.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org, Webhook: &rpmgrv1.Webhook{Url: hookURL}}))
	if code(err) != connect.CodeResourceExhausted {
		t.Fatalf("the %dth endpoint of an org: %v", webhook.MaxPerOrg+1, err)
	}
	_, err = ada.iwh.CreateInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateInstanceWebhookRequest{Webhook: &rpmgrv1.Webhook{Url: hookURL}}))
	if code(err) != connect.CodeResourceExhausted {
		t.Fatalf("the %dth endpoint of the instance: %v", webhook.MaxPerOrg+1, err)
	}
	if n := e.db.Client().Webhook.Query().CountX(e.sys); n != 2*webhook.MaxPerOrg {
		t.Errorf("%d endpoints", n)
	}
	// Another org is not affected; a delete makes room.
	if _, err := e.db.Client().Webhook.Create().SetID(ids.New("whk")).SetOrgID(orgB).SetURL(hookURL).SetSecretEnc([]byte("x")).Save(e.sys); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.wh.DeleteWebhook(ctx, connect.NewRequest(&rpmgrv1.DeleteWebhookRequest{WebhookId: last.GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org, Webhook: &rpmgrv1.Webhook{Url: hookURL}})); err != nil {
		t.Errorf("after a delete: %v", err)
	}
}

// TestWebhooks_TestRateLimit: a caller's test sends are limited to a burst, then one every
// webhook.TestEvery, whichever service sends them; another caller has their own allowance.
func TestWebhooks_TestRateLimit(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	e.webhooks.Sender = &webhook.Sender{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}
	w, _ := newHook(t, e, ada, org, hookURL)
	inst, _ := newInstanceHook(t, e, ada, "https://localhost:9/x")
	bob, _ := e.addOwner(t, org, "bob@example.com")
	send := func(b *browser) error {
		_, err := b.wh.TestWebhook(ctx, connect.NewRequest(&rpmgrv1.TestWebhookRequest{WebhookId: w.GetId()}))
		return err
	}
	for i := range webhook.TestBurst - 1 {
		if err := send(ada); err != nil {
			t.Fatalf("test %d: %v", i+1, err)
		}
	}
	if _, err := ada.iwh.TestInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.TestInstanceWebhookRequest{WebhookId: inst.GetId()})); err != nil {
		t.Fatalf("the last of the burst, through the instance service: %v", err)
	}
	if err := send(ada); code(err) != connect.CodeResourceExhausted {
		t.Fatalf("a test past the burst: %v", err)
	}
	if _, err := ada.iwh.TestInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.TestInstanceWebhookRequest{WebhookId: inst.GetId()})); code(err) != connect.CodeResourceExhausted {
		t.Fatalf("the instance service shares the allowance: %v", err)
	}
	if err := send(bob); err != nil {
		t.Errorf("another caller: %v", err)
	}
	e.clock = e.clock.Add(webhook.TestEvery)
	if err := send(ada); err != nil {
		t.Errorf("after the refill: %v", err)
	}
	if err := send(ada); code(err) != connect.CodeResourceExhausted {
		t.Errorf("one token was refilled, not two: %v", err)
	}
}
