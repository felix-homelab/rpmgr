// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestServer_Audit: a state-changing request is recorded once, with who, from where, what and
// the redacted request: in the transaction of its change when it makes one, in a transaction of
// its own when it changes nothing, fails or is refused. A refused request goes to the chain of the
// org the caller is a member of, else to the instance chain. A failed change leaves neither the
// change nor a success. A method without side effects is not recorded. Both chains verify.
func TestServer_Audit(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	orgA, orgB := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
	session := func(id string, roles map[string]string) *api.Caller {
		return &api.Caller{Principal: authz.Principal{UserID: id, Memberships: roles}, CredentialID: "ses_" + id, AuthMethod: "session"}
	}
	srv, err := api.New(api.Options{DB: db, Resolver: api.StoreResolver(db, sys), OperatorsMayEnroll: api.StoreOperatorsMayEnroll(db, sys),
		Authenticator: bearer{
			"owner":   session("usr_owner", map[string]string{orgA: authz.RoleOwner}),
			"viewer":  session("usr_viewer", map[string]string{orgA: authz.RoleViewer}),
			"outside": session("usr_outside", map[string]string{orgB: authz.RoleOwner}),
		}})
	if err != nil {
		t.Fatal(err)
	}
	write := &rpmgrv1.Authz{Permission: authz.PermRoutesWrite, ResourceField: "org_id"}
	sd := testFile(t, "audit", method{name: "Change", authz: write}, method{name: "Touch", authz: write},
		method{name: "Break", authz: write}, method{name: "Twice", authz: write},
		method{name: "Look", authz: &rpmgrv1.Authz{Permission: authz.PermOrgRead, ResourceField: "org_id"}, readOnly: true})
	group := func(ctx context.Context, req *dynamicpb.Message, fail bool) error {
		s, _ := authz.FromContext(ctx)
		name := req.Get(req.Descriptor().Fields().ByName("name")).String()
		_, err := store.ConfigTx(ctx, db, func(tx *ent.Tx) ([]string, error) {
			err := tx.GatewayGroup.Create().SetOrgID(s.OrgID()).SetName(name).Exec(ctx)
			if err == nil && fail {
				err = errors.New("the change cannot complete")
			}
			return []string{s.OrgID()}, err
		})
		return err
	}
	mux := http.NewServeMux()
	if err := srv.Mount(mux, sd, handlersWith(sd, func(ctx context.Context, method string, req *dynamicpb.Message) error {
		switch method {
		case "Change":
			return group(ctx, req, false)
		case "Break":
			if err := group(ctx, req, true); err != nil {
				return connect.NewError(connect.CodeInternal, err)
			}
		case "Twice":
			if err := group(ctx, req, false); err != nil {
				return err
			}
			return connect.NewError(connect.CodeAborted, errors.New("the second step failed"))
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	send := func(token, method, org, name, requestID string) connect.Code {
		t.Helper()
		md := sd.Methods().ByName(protoreflect.Name(method))
		in := dynamicpb.NewMessage(md.Input())
		f := md.Input().Fields()
		in.Set(f.ByName("org_id"), protoreflect.ValueOfString(org))
		in.Set(f.ByName("name"), protoreflect.ValueOfString(name))
		in.Set(f.ByName("request_id"), protoreflect.ValueOfString(requestID))
		in.Set(f.ByName("secret"), protoreflect.ValueOfString("hunter2"))
		client := connect.NewClient[dynamicpb.Message, dynamicpb.Message](http.DefaultClient,
			hs.URL+"/"+string(sd.FullName())+"/"+method, connect.WithSchema(md), connect.WithResponseInitializer(initializer(md.Output())))
		req := connect.NewRequest(in)
		req.Header().Set("User-Agent", "audit-test/1")
		if token != "" {
			req.Header().Set("Authorization", "Bearer "+token)
		}
		_, err := client.CallUnary(context.Background(), req)
		if err == nil {
			return 0
		}
		return connect.CodeOf(err)
	}
	entries := func(requestID string) []*ent.AuditEntry {
		t.Helper()
		es, err := db.Client().AuditEntry.Query().Where(auditentry.RequestID(requestID)).Order(ent.Asc(auditentry.FieldTs)).All(sys)
		if err != nil {
			t.Fatal(err)
		}
		return es
	}
	groups := func(name string) int {
		return db.Client().GatewayGroup.Query().Where(gatewaygroup.Name(name)).CountX(sys)
	}
	org := func(e *ent.AuditEntry) string {
		if e.OrgID == nil {
			return audit.InstanceChain
		}
		return *e.OrgID
	}

	if code := send("owner", "Change", orgA, "made", "req-1"); code != 0 {
		t.Fatalf("Change: %v", code)
	}
	es := entries("req-1")
	if len(es) != 1 || groups("made") != 1 {
		t.Fatalf("a change: %d entries, %d groups", len(es), groups("made"))
	}
	e := es[0]
	if org(e) != orgA || e.Result != auditentry.ResultSuccess || e.ActorType != auditentry.ActorTypeUser || e.ActorID != "usr_owner" ||
		e.CredentialID != "ses_usr_owner" || e.AuthMethod != "session" || e.IP != "127.0.0.1" || e.UserAgent != "audit-test/1" ||
		e.Action != string(sd.FullName())+".Change" || e.TargetType != "org" || e.TargetID != orgA {
		t.Errorf("the change's entry: %+v", e)
	}
	if strings.Contains(e.Diff, "hunter2") || !strings.Contains(e.Diff, `"secret":"`+api.Redacted+`"`) || !strings.Contains(e.Diff, `"name":"made"`) {
		t.Errorf("the diff: %s", e.Diff)
	}

	for _, c := range []struct {
		token, method, org, name, requestID, chain string
		code                                       connect.Code
		result                                     auditentry.Result
		reason                                     string
	}{
		{"owner", "Touch", orgA, "", "req-2", orgA, 0, auditentry.ResultSuccess, ""},
		{"owner", "Break", orgA, "broken", "req-3", orgA, connect.CodeInternal, auditentry.ResultFailure, "internal"},
		{"viewer", "Change", orgA, "viewed", "req-4", orgA, connect.CodePermissionDenied, auditentry.ResultDenied, "permission_denied"},
		{"outside", "Change", orgA, "outside", "req-5", audit.InstanceChain, connect.CodeNotFound, auditentry.ResultDenied, "not_found"},
		{"", "Change", orgA, "anon", "req-6", audit.InstanceChain, connect.CodeUnauthenticated, auditentry.ResultDenied, "unauthenticated"},
		{"owner", "Change", orgA, "too long a name", "req-7", orgA, connect.CodeInvalidArgument, auditentry.ResultFailure, "invalid_argument"},
	} {
		if code := send(c.token, c.method, c.org, c.name, c.requestID); code != c.code {
			t.Errorf("%s: %v, want %v", c.requestID, code, c.code)
			continue
		}
		es := entries(c.requestID)
		if len(es) != 1 || org(es[0]) != c.chain || es[0].Result != c.result || es[0].Reason != c.reason {
			t.Errorf("%s: %d entries, first %+v", c.requestID, len(es), es)
		}
		if c.name != "" && c.result != auditentry.ResultSuccess && groups(c.name) != 0 {
			t.Errorf("%s: the refused or failed change was made", c.requestID)
		}
	}
	if es := entries("req-6"); len(es) == 1 && (es[0].ActorType != auditentry.ActorTypeAnonymous || es[0].ActorID != "") {
		t.Errorf("an anonymous caller: %+v", es[0])
	}
	// A change that commits before the request fails keeps its success, and the failure follows.
	if code := send("owner", "Twice", orgA, "twice", "req-8"); code != connect.CodeAborted {
		t.Fatalf("Twice: %v", code)
	}
	if es := entries("req-8"); len(es) != 2 || es[0].Result != auditentry.ResultSuccess || es[1].Result != auditentry.ResultFailure ||
		groups("twice") != 1 {
		t.Errorf("a change, then a failure: %+v", es)
	}
	if code := send("owner", "Look", orgA, "", "req-9"); code != 0 || len(entries("req-9")) != 0 {
		t.Errorf("a method without side effects: %v, %d entries", code, len(entries("req-9")))
	}
	for _, chain := range []string{orgA, ""} {
		if _, err := audit.Verify(sys, db, chain); err != nil {
			t.Errorf("chain %q: %v", chain, err)
		}
	}
}

// TestRedact: sensitive fields are redacted in nested messages, oneofs, lists and maps; strings
// show that a value was given, bytes are cleared, unset fields stay unset; the original is
// untouched. Go's protojson prints a debug_redact field as it is (VB-04), so Redact is needed.
func TestRedact(t *testing.T) {
	params := &rpmgrv1.PolicyRuleParams{Params: &rpmgrv1.PolicyRuleParams_BasicAuth{BasicAuth: &rpmgrv1.BasicAuthParams{
		Users: []*rpmgrv1.BasicAuthUser{{Name: "alice", PasswordHash: "not-a-real-hash"}, {Name: "bob"}}}}} //nolint:gosec // G101: a test value
	r := api.Redact(params).(*rpmgrv1.PolicyRuleParams)
	users := r.GetBasicAuth().GetUsers()
	if users[0].GetName() != "alice" || users[0].GetPasswordHash() != api.Redacted || users[1].GetPasswordHash() != "" {
		t.Errorf("a list in a oneof: %v", r)
	}
	if params.GetBasicAuth().GetUsers()[0].GetPasswordHash() != "not-a-real-hash" {
		t.Error("the original was changed")
	}
	item := api.Redact(&agentv1.CertificateItem{Chain: [][]byte{{1, 2}}, PrivateKey: []byte("key")}).(*agentv1.CertificateItem)
	if item.GetPrivateKey() != nil || len(item.GetChain()) != 1 {
		t.Errorf("bytes: %v", item)
	}

	sd := testFile(t, "redact", method{name: "M", authz: &rpmgrv1.Authz{Permission: authz.PermPublic}})
	in := sd.Methods().Get(0).Input()
	msg := dynamicpb.NewMessage(in)
	ref := func(token, note string) protoreflect.Value {
		m := dynamicpb.NewMessage(in.Fields().ByName("ref").Message())
		m.Set(m.Descriptor().Fields().ByName("id"), protoreflect.ValueOfString("rt_1"))
		m.Set(m.Descriptor().Fields().ByName("token"), protoreflect.ValueOfString(token))
		m.Set(m.Descriptor().Fields().ByName("note"), protoreflect.ValueOfString(note))
		return protoreflect.ValueOfMessage(m)
	}
	msg.Set(in.Fields().ByName("ref"), ref("tok-nested", "visible-note"))
	msg.Mutable(in.Fields().ByName("by_name")).Map().Set(protoreflect.ValueOfString("k").MapKey(), ref("tok-in-map", "n"))
	plain, err := protojson.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), "visible-note") || !strings.Contains(string(plain), "tok-nested") {
		t.Fatalf("protojson redacted on its own (VB-04 changed): %s", plain)
	}
	redacted, err := protojson.Marshal(api.Redact(msg))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redacted), "tok-") || strings.Count(string(redacted), api.Redacted) != 2 ||
		!strings.Contains(string(redacted), "rt_1") {
		t.Errorf("nested and map values: %s", redacted)
	}
}
