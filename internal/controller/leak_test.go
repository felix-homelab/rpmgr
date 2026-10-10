// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	entschema "entgo.io/ent/dialect/sql/schema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/migrate"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// leakSkip are the methods the suite does not call: the ones that end the caller's own session,
// which the suite needs to the end.
var leakSkip = []string{"rpmgr.v1.AuthService.Logout"}

// TestCrossTenantLeaks (docs/12-testing-and-quality.md, "Security testing"): generated from the
// service registry, so a new method is covered without changing it. A user who is Owner of org B,
// stepped up, calls every method of every rpmgr.v1 service but the public ones, its request filled
// with the IDs of org A's resources and members. Every method on an org of A's answers NOT_FOUND,
// not PERMISSION_DENIED, so existence does not leak; called on org B with A's other IDs, no answer
// holds anything of org A, and a method outside orgs never succeeds on A's IDs; and afterwards no
// row of org A has changed.
func TestCrossTenantLeaks(t *testing.T) {
	var link string
	r := startRunWith(t, runSetup{prepare: func(r *running) { link = r.firstUserLink }})
	ctx := context.Background()
	_, tok, _ := strings.Cut(link, "#")
	const pw = "correct horse battery staple"
	signedIn := func(email string) (*http.Client, *rpmgrv1.GetSessionResponse) {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar, Transport: r.client.Transport, Timeout: 10 * time.Second}
		auth := rpmgrv1connect.NewAuthServiceClient(c, r.url)
		if _, err := auth.Login(ctx, connect.NewRequest(&rpmgrv1.LoginRequest{Email: email, Password: pw})); err != nil {
			t.Fatal(err)
		}
		if _, err := auth.StepUp(ctx, connect.NewRequest(&rpmgrv1.StepUpRequest{Password: pw})); err != nil {
			t.Fatal(err)
		}
		s, err := auth.GetSession(ctx, connect.NewRequest(&rpmgrv1.GetSessionRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return c, s.Msg
	}

	// Org A: Ada, the first user, with a token and an invitation; org B: Bob, its Owner.
	if _, err := rpmgrv1connect.NewAuthServiceClient(r.client, r.url).CompletePasswordReset(ctx, connect.NewRequest(
		&rpmgrv1.CompletePasswordResetRequest{Token: tok, NewPassword: pw, Email: "ada@example.com", DisplayName: "Ada"})); err != nil {
		t.Fatal(err)
	}
	adaClient, ada := signedIn("ada@example.com")
	orgA := ada.GetMemberships()[0].GetOrgId()
	adaToken, err := rpmgrv1connect.NewTokenServiceClient(adaClient, r.url).CreateAPIToken(ctx, connect.NewRequest(
		&rpmgrv1.CreateAPITokenRequest{OrgId: orgA, Name: "a", Scopes: []string{authz.PermOrgRead}}))
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := rpmgrv1connect.NewOrgServiceClient(adaClient, r.url).CreateInvitation(ctx, connect.NewRequest(
		&rpmgrv1.CreateInvitationRequest{OrgId: orgA, Email: "eve@example.com", Role: "viewer"}))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenSQLite(ctx, r.h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sys := storetest.SystemCtx(t)
	orgB := storetest.Org(t, db, "org-b")
	bob := addUser(t, db, sys, orgB, "bob@example.com", pw)
	bobClient, bobSession := signedIn("bob@example.com")

	// What org A has: every ID a request could name, and what no answer to Bob may hold.
	groupA := db.Client().GatewayGroup.Create().SetOrgID(orgA).SetName("eu").SaveX(sys)
	gatewayA := db.Client().Gateway.Create().SetOrgID(orgA).SetGatewayGroupID(groupA.ID).SetName("gw1").
		SetTunnelEndpoints([]string{"gw1.org-a.example:443"}).SaveX(sys)
	poolA := db.Client().PortPool.Create().SetOrgID(orgA).SetGatewayGroupID(groupA.ID).SetProtocol("tcp").SetPortFrom(20000).
		SetPortTo(20099).SaveX(sys)
	quotaA := db.Client().PortQuota.Create().SetOrgID(orgA).SetGatewayGroupID(groupA.ID).SetProtocol("tcp").SetMaxPorts(7).SaveX(sys)
	connectorA := db.Client().Connector.Create().SetOrgID(orgA).SetName("nas").SetSpiffeID("spiffe://leak/org/" + orgA + "/connector/x").
		SetPubkeySha256("leak").SaveX(sys)
	tokenA := db.Client().EnrollmentToken.Create().SetOrgID(orgA).SetTokenHash([]byte("leak")).SetRole("connector").
		SetExpiresAt(time.Now().Add(time.Hour)).SetCreatedBy(ada.GetUserId()).SaveX(sys)
	domainA := db.Client().Domain.Create().SetOrgID(orgA).SetFqdn("org-a.example").SetChallengeValue("leak").SaveX(sys)
	routeA := db.Client().Route.Create().SetOrgID(orgA).SetName("web-a").SetType("tls_passthrough").SetGatewayGroupID(groupA.ID).SaveX(sys)
	targetA := db.Client().RouteTarget.Create().SetOrgID(orgA).SetRouteID(routeA.ID).SetConnectorID(connectorA.ID).SetKind("address").
		SetHost("10.0.0.5").SetPort(5432).SaveX(sys)
	policyA := db.Client().AccessPolicy.Create().SetOrgID(orgA).SetName("office-a").SaveX(sys)
	certA := db.Client().Certificate.Create().SetOrgID(orgA).SetSource("acme").SetSans([]string{"shop.org-a.example"}).SetStatus("failed").
		SetLastError("leak").SaveX(sys)
	bundleA := db.Client().CABundle.Create().SetOrgID(orgA).SetName("internal-a").SetPem([]byte("leak")).SaveX(sys)
	fill := map[string]string{
		"org_id": orgA, "user_id": ada.GetUserId(), "token_id": adaToken.Msg.GetApiToken().GetId(),
		"session_id": ada.GetSession().GetId(), "gateway_group_id": groupA.ID, "gateway_id": gatewayA.ID,
		"port_pool_id": poolA.ID, "port_quota_id": quotaA.ID, "connector_id": connectorA.ID, "domain_id": domainA.ID, "route_id": routeA.ID, "route_target_id": targetA.ID, "target_id": targetA.ID, "enrollment_token_id": tokenA.ID,
		"access_policy_id": policyA.ID, "certificate_id": certA.ID, "ca_bundle_id": bundleA.ID,
	}
	secrets := []string{orgA, groupA.ID, gatewayA.ID, "gw1.org-a.example", poolA.ID, quotaA.ID, connectorA.ID, domainA.ID, "org-a.example", routeA.ID, "web-a", targetA.ID, "10.0.0.5", tokenA.ID, policyA.ID, "office-a", certA.ID, "shop.org-a.example", bundleA.ID, "internal-a", ada.GetUserId(), "ada@example.com", adaToken.Msg.GetApiToken().GetId(), ada.GetSession().GetId(),
		invitation.Msg.GetUrl()[strings.Index(invitation.Msg.GetUrl(), "#")+1:]}
	before := orgRows(t, db, orgA)

	services, calls := 0, 0
	protoregistry.GlobalFiles.RangeFilesByPackage("rpmgr.v1", func(fd protoreflect.FileDescriptor) bool {
		for i := range fd.Services().Len() {
			sd := fd.Services().Get(i)
			services++
			for j := range sd.Methods().Len() {
				md := sd.Methods().Get(j)
				a, _ := proto.GetExtension(md.Options(), rpmgrv1.E_Authz).(*rpmgrv1.Authz)
				if a.GetPermission() == authz.PermPublic || slices.Contains(leakSkip, string(md.FullName())) {
					continue
				}
				orgScoped := authz.OrgPermission(a.GetPermission())
				orgs := []string{orgA, orgB}
				if !orgScoped {
					orgs = orgs[:1] // a method outside orgs takes no org: one pass with A's IDs
				}
				for _, org := range orgs {
					ids := map[string]string{}
					for k, v := range fill {
						ids[k] = v
					}
					ids["org_id"] = org
					req, missing, named := request(md.Input(), ids)
					if missing != "" {
						t.Errorf("%s: no org A value for %s; add one to the suite's fixtures", md.FullName(), missing)
						continue
					}
					code, body := call(ctx, bobClient, r.url, sd, md, req)
					calls++
					label := fmt.Sprintf("%s on %s", md.FullName(), map[bool]string{true: "org A", false: "org B"}[org == orgA])
					switch {
					case orgScoped && org == orgA && code != connect.CodeNotFound:
						t.Errorf("%s: %v, want NOT_FOUND", label, code)
					case !orgScoped && named && code == 0:
						t.Errorf("%s: succeeded on org A's IDs", label)
					case slices.ContainsFunc(secrets, func(s string) bool { return s != "" && strings.Contains(body, s) }):
						t.Errorf("%s: the answer holds org A's data: %s", label, body)
					}
				}
			}
		}
		return true
	})
	if services < 4 {
		t.Fatalf("%d services in the registry", services)
	}
	t.Logf("%d calls to %d services", calls, services)
	if after := orgRows(t, db, orgA); after != before {
		t.Fatalf("org A's rows changed:\nbefore %s\nafter  %s", before, after)
	}
	if _, err := rpmgrv1connect.NewAuthServiceClient(bobClient, r.url).GetSession(ctx, connect.NewRequest(&rpmgrv1.GetSessionRequest{})); err != nil ||
		bobSession.GetUserId() != bob {
		t.Fatalf("Bob's session did not last the suite: %v", err)
	}
}

// request is a request of a method's input type with every ID field the suite knows filled in,
// in nested messages too; missing names an ID field it has no value for; named reports whether any
// field was filled.
func request(md protoreflect.MessageDescriptor, ids map[string]string) (_ *dynamicpb.Message, missing string, named bool) {
	m := dynamicpb.NewMessage(md)
	fields := md.Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		name := string(fd.Name())
		switch {
		case fd.Kind() == protoreflect.StringKind && !fd.IsList() && strings.HasSuffix(name, "_id") && name != "request_id":
			v, ok := ids[name]
			if !ok {
				return nil, string(fd.FullName()), false
			}
			m.Set(fd, protoreflect.ValueOfString(v))
			named = true
		case fd.Kind() == protoreflect.MessageKind && !fd.IsList() && !fd.IsMap() && fd.Message().Fields().ByName("id") != nil:
			v, ok := ids[name+"_id"]
			if !ok {
				return nil, string(fd.FullName()) + ".id", false
			}
			sub := m.Mutable(fd).Message()
			sub.Set(sub.Descriptor().Fields().ByName("id"), protoreflect.ValueOfString(v))
			named = true
		}
	}
	return m, "", named
}

// call invokes a method with a dynamic request and returns its code, 0 for success, and the
// answer as JSON.
func call(ctx context.Context, c *http.Client, base string, sd protoreflect.ServiceDescriptor, md protoreflect.MethodDescriptor,
	req *dynamicpb.Message) (connect.Code, string) {
	url := base + "/" + string(sd.FullName()) + "/" + string(md.Name())
	init := func(_ connect.Spec, m any) error {
		*m.(*dynamicpb.Message) = *dynamicpb.NewMessage(md.Output())
		return nil
	}
	client := connect.NewClient[dynamicpb.Message, dynamicpb.Message](c, url, connect.WithSchema(md), connect.WithResponseInitializer(init))
	var out []string
	var err error
	if md.IsStreamingServer() {
		var s *connect.ServerStreamForClient[dynamicpb.Message]
		if s, err = client.CallServerStream(ctx, connect.NewRequest(req)); err == nil {
			for s.Receive() {
				b, _ := protojson.Marshal(s.Msg())
				out = append(out, string(b))
			}
			err = s.Err()
			_ = s.Close()
		}
	} else {
		var resp *connect.Response[dynamicpb.Message]
		if resp, err = client.CallUnary(ctx, connect.NewRequest(req)); err == nil {
			b, _ := protojson.Marshal(resp.Msg)
			out = append(out, string(b))
		}
	}
	if err != nil {
		return connect.CodeOf(err), err.Error()
	}
	return 0, strings.Join(out, "\n")
}

// orgRows is every row of an org in the org-owned tables, as text.
func orgRows(t *testing.T, db *store.DB, orgID string) string {
	t.Helper()
	var b strings.Builder
	err := store.ReadTx(storetest.SystemCtx(t), db, func(tx *ent.Tx, _ store.Revision) error {
		for _, table := range migrate.Tables {
			if !slices.ContainsFunc(table.Columns, func(c *entschema.Column) bool { return c.Name == "org_id" }) {
				continue
			}
			rows, err := tx.QueryContext(storetest.SystemCtx(t), "SELECT * FROM "+table.Name+" WHERE org_id = $1 ORDER BY 1", orgID)
			if err != nil {
				return err
			}
			if err := dump(&b, table.Name, rows); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func dump(b *strings.Builder, table string, rows *sql.Rows) error {
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		fmt.Fprintf(b, "%s%v;", table, vals)
	}
	return rows.Err()
}

// addUser creates an active user who is Owner of an org, with a password.
func addUser(t *testing.T, db *store.DB, sys context.Context, orgID, email, pw string) string {
	t.Helper()
	h, err := password.Hash(context.Background(), pw, password.LowMemory)
	if err != nil {
		t.Fatal(err)
	}
	u := db.Client().User.Create().SetEmail(email).SetDisplayName(email).SetPasswordHash(h).SaveX(sys)
	db.Client().Membership.Create().SetOrgID(orgID).SetUserID(u.ID).SetRole("owner").SetCreatedBy("test").ExecX(sys)
	return u.ID
}
