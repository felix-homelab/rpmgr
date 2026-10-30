// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditsink"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

const (
	sinkKey  = "sink-signing-secret-for-tests"  //nolint:gosec // G101: a test secret
	sinkKey2 = "another-signing-secret-4-tests" //nolint:gosec // G101: a test secret
)

// sinkReceiver is a TLS receiver on loopback that answers with status and records the last
// delivery; the controller's sender is pointed at it as at a public host.
type sinkReceiver struct {
	mu     sync.Mutex
	status int
	header http.Header
	body   []byte
	url    string
}

func newSinkReceiver(t *testing.T, e *env) *sinkReceiver {
	t.Helper()
	r := &sinkReceiver{status: http.StatusNoContent}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.header, r.body = req.Header.Clone(), b
		code := r.status
		r.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	r.url = "https://example.com:" + port + "/audit"
	e.sinks.Sender = &webhook.Sender{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		Now: func() time.Time { return e.clock }}
	return r
}

// TestAuditSinks (#654; docs/04-security.md, "Audit log"): the Instance Admin creates, reads,
// changes, tests and deletes sinks after a step-up; nobody else can; the secret is write-only,
// sealed under the KEK and redacted in the audit log; the status shows the backlog per chain; a
// refused request changes nothing.
func TestAuditSinks(t *testing.T) {
	e := newEnv(t)
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c := e.db.Client()
	recv := newSinkReceiver(t, e)
	create := func(b *browser, in *rpmgrv1.AuditSink) (*rpmgrv1.AuditSink, error) {
		r, err := b.sink.CreateAuditSink(ctx, connect.NewRequest(&rpmgrv1.CreateAuditSinkRequest{AuditSink: in}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetAuditSink(), nil
	}
	good := &rpmgrv1.AuditSink{Name: "siem", Kind: rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_WEBHOOK, Url: recv.url, Secret: sinkKey, Entries: true}

	// A step-up first, and an Owner who is no Instance Admin gets nothing.
	if _, err := create(ada, good); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("create without a step-up: %v", err)
	}
	bob, _ := e.addOwner(t, storetest.Org(t, e.db, "org-b"), "bob@example.com")
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := create(bob, good); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Owner creates a sink: %v", err)
	}
	if _, err := bob.sink.ListAuditSinks(ctx, connect.NewRequest(&rpmgrv1.ListAuditSinksRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Owner lists sinks: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}

	// Refused requests create nothing.
	for name, in := range map[string]*rpmgrv1.AuditSink{
		"no kind":         {Name: "a", Url: recv.url, Secret: sinkKey},
		"no name":         {Kind: good.Kind, Url: recv.url, Secret: sinkKey},
		"a bad name":      {Name: "Not A Name", Kind: good.Kind, Url: recv.url, Secret: sinkKey},
		"no url":          {Name: "a", Kind: good.Kind, Secret: sinkKey},
		"plain http":      {Name: "a", Kind: good.Kind, Url: "http://example.com/x", Secret: sinkKey},
		"credentials":     {Name: "a", Kind: good.Kind, Url: "https://user:pw@example.com/x", Secret: sinkKey}, //nolint:gosec // G101: a test URL
		"no host":         {Name: "a", Kind: good.Kind, Url: "https:///x", Secret: sinkKey},
		"no secret":       {Name: "a", Kind: good.Kind, Url: recv.url},
		"a short secret":  {Name: "a", Kind: good.Kind, Url: recv.url, Secret: "short"},
		"a long url":      {Name: "a", Kind: good.Kind, Url: "https://example.com/" + strings.Repeat("x", 2048), Secret: sinkKey},
		"an unknown kind": {Name: "a", Kind: rpmgrv1.AuditSinkKind(99), Url: recv.url, Secret: sinkKey},
	} {
		if _, err := create(ada, in); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := c.AuditSink.Query().CountX(e.sys); n != 0 {
		t.Fatalf("%d sinks after refused requests", n)
	}

	s, err := create(ada, good)
	if err != nil {
		t.Fatal(err)
	}
	if !s.GetEnabled() || !s.GetSecretSet() || s.GetSecret() != "" || s.GetUrl() != recv.url || !s.GetEntries() || s.GetEtag() == "" ||
		!strings.HasPrefix(s.GetId(), "ask_") || strings.Contains(s.String(), sinkKey) {
		t.Fatalf("the new sink: %v", s)
	}
	if _, err := create(ada, good); code(err) != connect.CodeAlreadyExists {
		t.Errorf("a second sink of the name: %v", err)
	}
	// The secret is sealed under the KEK, bound to its row, and opens to what was given.
	row := c.AuditSink.GetX(e.sys, s.GetId())
	if row.SecretEnc == nil || strings.Contains(string(*row.SecretEnc), sinkKey) {
		t.Fatal("the secret is stored in the clear")
	}
	// The sealed secret is bound to its row: it opens there and nowhere else.
	if _, err := e.sealer.Open(secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: row.ID}, *row.SecretEnc); err != nil {
		t.Fatalf("the sealed secret does not open: %v", err)
	}
	if _, err := e.sealer.Open(secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: "ask_other"}, *row.SecretEnc); err == nil {
		t.Fatal("the sealed secret opens for another row")
	}

	// Reads never return the secret and carry the status: the create itself is an entry of the
	// instance chain that the sink has not got.
	got, err := ada.sink.GetAuditSink(ctx, connect.NewRequest(&rpmgrv1.GetAuditSinkRequest{AuditSinkId: s.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	st := got.Msg.GetAuditSink().GetStatus()
	if strings.Contains(got.Msg.String(), sinkKey) || st.GetBacklog() < 1 || st.GetOldestUnshippedTime() == nil || st.GetLastSuccessTime() != nil ||
		len(st.GetChains()) == 0 || st.GetChains()[0].GetChain() != "instance" || st.GetChains()[0].GetEntrySeq() != 0 {
		t.Fatalf("the status: %v", st)
	}
	if _, err := ada.sink.GetAuditSink(ctx, connect.NewRequest(&rpmgrv1.GetAuditSinkRequest{AuditSinkId: "ask_nope"})); code(err) != connect.CodeNotFound {
		t.Errorf("an unknown sink: %v", err)
	}
	second, err := create(ada, &rpmgrv1.AuditSink{Name: "archive", Kind: good.Kind, Url: recv.url + "2", Secret: sinkKey2})
	if err != nil {
		t.Fatal(err)
	}
	list, err := ada.sink.ListAuditSinks(ctx, connect.NewRequest(&rpmgrv1.ListAuditSinksRequest{PageSize: 1}))
	if err != nil || len(list.Msg.GetAuditSinks()) != 1 || list.Msg.GetNextPageToken() == "" || list.Msg.GetAuditSinks()[0].GetId() != s.GetId() {
		t.Fatalf("the first page: %v %v", list, err)
	}
	list, err = ada.sink.ListAuditSinks(ctx, connect.NewRequest(&rpmgrv1.ListAuditSinksRequest{PageSize: 1, PageToken: list.Msg.GetNextPageToken()}))
	if err != nil || len(list.Msg.GetAuditSinks()) != 1 || list.Msg.GetNextPageToken() != "" || list.Msg.GetAuditSinks()[0].GetId() != second.GetId() ||
		strings.Contains(list.Msg.String(), sinkKey2) {
		t.Fatalf("the second page: %v %v", list, err)
	}

	// test sends a test item; verify checks that the receiver got it signed with key.
	test := func(id string) *rpmgrv1.TestAuditSinkResponse {
		t.Helper()
		r, err := ada.sink.TestAuditSink(ctx, connect.NewRequest(&rpmgrv1.TestAuditSinkRequest{AuditSinkId: id}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg
	}
	verify := func(id, key string) {
		t.Helper()
		recv.mu.Lock()
		recv.status = http.StatusNoContent
		recv.mu.Unlock()
		if r := test(id); !r.GetOk() {
			t.Fatalf("a test: %v", r)
		}
		recv.mu.Lock()
		defer recv.mu.Unlock()
		if recv.header.Get(webhook.HeaderEventType) != "audit.test" || webhook.Verify(recv.header.Get(webhook.HeaderSignature), recv.body, key, e.clock) != nil {
			t.Fatalf("the test item is not signed with the sink's secret: %v %s", recv.header, recv.body)
		}
	}
	verify(s.GetId(), sinkKey)

	// Updates: only the masked fields change; the kind never does; a stale etag is refused.
	update := func(id string, in *rpmgrv1.AuditSink, etag string, paths ...string) (*rpmgrv1.AuditSink, error) {
		in.Id = id
		r, err := ada.sink.UpdateAuditSink(ctx, connect.NewRequest(&rpmgrv1.UpdateAuditSinkRequest{AuditSink: in,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}, Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetAuditSink(), nil
	}
	for name, c := range map[string]struct {
		in    *rpmgrv1.AuditSink
		paths []string
	}{
		"an empty mask":    {&rpmgrv1.AuditSink{Name: "x"}, nil},
		"the kind":         {&rpmgrv1.AuditSink{}, []string{"kind"}},
		"the status":       {&rpmgrv1.AuditSink{}, []string{"status"}},
		"an unknown field": {&rpmgrv1.AuditSink{}, []string{"nope"}},
		"an http url":      {&rpmgrv1.AuditSink{Url: "http://example.com"}, []string{"url"}},
		"a cleared url":    {&rpmgrv1.AuditSink{}, []string{"url"}},
		"a cleared name":   {&rpmgrv1.AuditSink{}, []string{"name"}},
		"a short secret":   {&rpmgrv1.AuditSink{Secret: "short"}, []string{"secret"}},
		"a cleared secret": {&rpmgrv1.AuditSink{}, []string{"secret"}},
	} {
		if _, err := update(s.GetId(), c.in, "", c.paths...); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := update(s.GetId(), &rpmgrv1.AuditSink{Name: "archive"}, "", "name"); code(err) != connect.CodeAlreadyExists {
		t.Errorf("a taken name: %v", err)
	}
	if _, err := update("ask_nope", &rpmgrv1.AuditSink{Name: "x"}, "", "name"); code(err) != connect.CodeNotFound {
		t.Errorf("an unknown sink: %v", err)
	}
	if after := c.AuditSink.GetX(e.sys, s.GetId()); after.Name != "siem" || after.Settings["url"] != recv.url || !after.Entries || !after.Enabled ||
		string(*after.SecretEnc) != string(*row.SecretEnc) {
		t.Fatalf("refused updates changed the sink: %v", after)
	}
	up, err := update(s.GetId(), &rpmgrv1.AuditSink{Name: "siem-eu", Url: recv.url + "/v2"}, s.GetEtag(), "name", "url", "entries", "enabled")
	if err != nil || up.GetName() != "siem-eu" || up.GetUrl() != recv.url+"/v2" || up.GetEntries() || up.GetEnabled() || up.GetEtag() == s.GetEtag() ||
		!up.GetSecretSet() {
		t.Fatalf("an update: %v %v", up, err)
	}
	verify(s.GetId(), sinkKey)
	if _, err := update(s.GetId(), &rpmgrv1.AuditSink{Enabled: true}, s.GetEtag(), "enabled"); reason(err) != api.ReasonEtagMismatch {
		t.Errorf("a stale etag: %v", err)
	}
	up, err = update(s.GetId(), &rpmgrv1.AuditSink{Enabled: true, Secret: sinkKey2}, up.GetEtag(), "enabled", "secret")
	if err != nil || !up.GetEnabled() || up.GetSecret() != "" {
		t.Fatalf("a new secret: %v %v", up, err)
	}
	verify(s.GetId(), sinkKey2)

	recv.mu.Lock()
	recv.status = http.StatusNotFound
	recv.mu.Unlock()
	if r := test(s.GetId()); r.GetOk() || !strings.Contains(r.GetError(), "404") || strings.Contains(r.GetError(), "example.com") || strings.Contains(r.GetError(), sinkKey2) {
		t.Fatalf("a refusing receiver: %v", r)
	}
	if st := c.AuditSink.GetX(e.sys, s.GetId()); st.LastError != "" || st.LastSuccessAt != nil {
		t.Error("a test changed the sink's status")
	}
	broken := c.AuditSink.Create().SetKind(auditsink.KindWebhook).SetName("broken").SetSettings(map[string]string{"url": recv.url}).
		SetSecretEnc([]byte("sealed under another key")).SaveX(e.sys)
	if r := test(broken.ID); r.GetOk() || !strings.Contains(r.GetError(), "cannot be opened") {
		t.Fatalf("an unopenable secret: %v", r)
	}
	if _, err := ada.sink.TestAuditSink(ctx, connect.NewRequest(&rpmgrv1.TestAuditSinkRequest{AuditSinkId: "ask_nope"})); code(err) != connect.CodeNotFound {
		t.Errorf("testing an unknown sink: %v", err)
	}

	// Deleting needs the current etag when one is given, and takes the cursors along.
	c.AuditSinkCursor.Create().SetSinkID(second.GetId()).SetChain("instance").SetEntrySeq(1).SaveX(e.sys)
	del := func(id, etag string) error {
		_, err := ada.sink.DeleteAuditSink(ctx, connect.NewRequest(&rpmgrv1.DeleteAuditSinkRequest{AuditSinkId: id, Etag: etag}))
		return err
	}
	if err := del(second.GetId(), "stale"); reason(err) != api.ReasonEtagMismatch {
		t.Errorf("a stale etag: %v", err)
	}
	if err := del("ask_nope", ""); code(err) != connect.CodeNotFound {
		t.Errorf("an unknown sink: %v", err)
	}
	if err := del(second.GetId(), second.GetEtag()); err != nil {
		t.Fatal(err)
	}
	if c.AuditSink.Query().Where(auditsink.ID(second.GetId())).CountX(e.sys) != 0 || c.AuditSinkCursor.Query().CountX(e.sys) != 0 {
		t.Error("the sink or its cursor is left")
	}
	e.clock = e.clock.Add(api.StepUpWindow + 1)
	if err := del(s.GetId(), ""); reason(err) != api.ReasonStepUpRequired {
		t.Errorf("a delete after the step-up window: %v", err)
	}

	// Every change is audited, in the instance chain, and no entry holds a secret.
	n := 0
	for _, a := range c.AuditEntry.Query().Where(auditentry.ActionHasPrefix("rpmgr.v1.AuditSinkService.")).AllX(e.sys) {
		n++
		if strings.Contains(a.Diff, sinkKey) || strings.Contains(a.Diff, sinkKey2) {
			t.Fatalf("the audit log holds a secret: %s", a.Diff)
		}
	}
	if n < 8 {
		t.Errorf("%d audit entries of sink requests", n)
	}
}
