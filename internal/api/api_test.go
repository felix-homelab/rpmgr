// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// testSealer returns a sealer under a random KEK.
func testSealer(t testing.TB) *secret.Sealer {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	kek, err := secret.NewKEK(key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := secret.NewSealer(kek)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// method describes one method of a test service.
type method struct {
	name     string
	authz    *rpmgrv1.Authz // nil: no option
	stream   string         // "server", "client" or ""
	readOnly bool           // idempotency_level = NO_SIDE_EFFECTS
}

// testFile builds rpmgr/apitest/<name>.proto with a service TestService of the given methods, all
// taking Request and returning Reply. Request has org_id, ref (a Ref), name (at most 8
// characters), tags (repeated), secret (sensitive), request_id, by_name (a map of Refs),
// page_token and page_size; a Ref has id, token (sensitive) and note (debug_redact). Reply has
// the caller and the org of the scope.
func testFile(t *testing.T, name string, methods ...method) protoreflect.ServiceDescriptor {
	t.Helper()
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()
	msg := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum()
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	field := func(name string, n int32, typ *descriptorpb.FieldDescriptorProto_Type, label *descriptorpb.FieldDescriptorProto_Label,
		typeName string, opts *descriptorpb.FieldOptions) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(n), Type: typ, Label: label,
			JsonName: proto.String(name), Options: opts}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	maxLen := &descriptorpb.FieldOptions{}
	proto.SetExtension(maxLen, validate.E_Field, &validate.FieldRules{Type: &validate.FieldRules_String_{
		String_: &validate.StringRules{MaxLen: proto.Uint64(8)}}})
	sensitive := &descriptorpb.FieldOptions{}
	proto.SetExtension(sensitive, rpmgrv1.E_Sensitive, true)
	debugRedact := &descriptorpb.FieldOptions{DebugRedact: proto.Bool(true)}
	pkg := "rpmgr.apitest." + name
	svc := &descriptorpb.ServiceDescriptorProto{Name: proto.String("TestService")}
	for _, m := range methods {
		opts := &descriptorpb.MethodOptions{}
		if m.readOnly {
			opts.IdempotencyLevel = descriptorpb.MethodOptions_NO_SIDE_EFFECTS.Enum()
		}
		if m.authz != nil {
			proto.SetExtension(opts, rpmgrv1.E_Authz, m.authz)
		}
		svc.Method = append(svc.Method, &descriptorpb.MethodDescriptorProto{Name: proto.String(m.name),
			InputType: proto.String("." + pkg + ".Request"), OutputType: proto.String("." + pkg + ".Reply"), Options: opts,
			ServerStreaming: proto.Bool(m.stream == "server"), ClientStreaming: proto.Bool(m.stream == "client")})
	}
	fdp := &descriptorpb.FileDescriptorProto{
		Name: proto.String("rpmgr/apitest/" + name + ".proto"), Package: proto.String(pkg), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Ref"), Field: []*descriptorpb.FieldDescriptorProto{
				field("id", 1, str, optional, "", nil),
				field("token", 2, str, optional, "", sensitive),
				field("note", 3, str, optional, "", debugRedact),
			}},
			{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{
				field("org_id", 1, str, optional, "", nil),
				field("ref", 2, msg, optional, "."+pkg+".Ref", nil),
				field("name", 3, str, optional, "", maxLen),
				field("tags", 4, str, repeated, "", nil),
				field("secret", 5, str, optional, "", sensitive),
				field("request_id", 6, str, optional, "", nil),
				field("by_name", 7, msg, repeated, "."+pkg+".Request.ByNameEntry", nil),
				field("page_token", 8, str, optional, "", nil),
				field("page_size", 9, descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(), optional, "", nil),
			}, NestedType: []*descriptorpb.DescriptorProto{{Name: proto.String("ByNameEntry"),
				Field: []*descriptorpb.FieldDescriptorProto{
					field("key", 1, str, optional, "", nil),
					field("value", 2, msg, optional, "."+pkg+".Ref", nil),
				}, Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)}}}},
			{Name: proto.String("Reply"), Field: []*descriptorpb.FieldDescriptorProto{
				field("caller", 1, str, optional, "", nil),
				field("org", 2, str, optional, "", nil),
			}},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{svc},
	}
	fd, err := protodesc.NewFile(fdp, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	return fd.Services().Get(0)
}

// handlers serves every method of sd with dynamic messages: each answers with the caller and the
// org of its scope.
func handlers(sd protoreflect.ServiceDescriptor) func(...connect.HandlerOption) (string, http.Handler) {
	return handlersWith(sd, nil)
}

// handlersWith is handlers, with do run first by every method; its error is the method's.
func handlersWith(sd protoreflect.ServiceDescriptor,
	do func(ctx context.Context, method string, req *dynamicpb.Message) error) func(...connect.HandlerOption) (string, http.Handler) {
	return func(opts ...connect.HandlerOption) (string, http.Handler) {
		mux := http.NewServeMux()
		for i := range sd.Methods().Len() {
			md := sd.Methods().Get(i)
			procedure := "/" + string(sd.FullName()) + "/" + string(md.Name())
			o := append([]connect.HandlerOption{connect.WithSchema(md), connect.WithRequestInitializer(initializer(md.Input()))}, opts...)
			reply := func(ctx context.Context) *dynamicpb.Message {
				m := dynamicpb.NewMessage(md.Output())
				if c := api.CallerFrom(ctx); c != nil {
					m.Set(md.Output().Fields().ByName("caller"), protoreflect.ValueOfString(c.UserID))
				}
				if s, ok := authz.FromContext(ctx); ok {
					m.Set(md.Output().Fields().ByName("org"), protoreflect.ValueOfString(s.OrgID()))
				}
				return m
			}
			if md.IsStreamingServer() {
				mux.Handle(procedure, connect.NewServerStreamHandler(procedure,
					func(ctx context.Context, req *connect.Request[dynamicpb.Message], s *connect.ServerStream[dynamicpb.Message]) error {
						if do != nil {
							if err := do(ctx, string(md.Name()), req.Msg); err != nil {
								return err
							}
						}
						return s.Send(reply(ctx))
					}, o...))
				continue
			}
			mux.Handle(procedure, connect.NewUnaryHandler(procedure,
				func(ctx context.Context, req *connect.Request[dynamicpb.Message]) (*connect.Response[dynamicpb.Message], error) {
					if do != nil {
						if err := do(ctx, string(md.Name()), req.Msg); err != nil {
							return nil, err
						}
					}
					return connect.NewResponse(reply(ctx)), nil
				}, o...))
		}
		return "/" + string(sd.FullName()) + "/", mux
	}
}

func initializer(md protoreflect.MessageDescriptor) func(connect.Spec, any) error {
	return func(_ connect.Spec, m any) error {
		*m.(*dynamicpb.Message) = *dynamicpb.NewMessage(md)
		return nil
	}
}

// bearer authenticates "Bearer <name>" from a fixed set of callers.
type bearer map[string]*api.Caller

func (b bearer) Authenticate(_ context.Context, h http.Header) (*api.Caller, error) {
	v := h.Get("Authorization")
	if v == "" {
		return nil, nil
	}
	c, ok := b[strings.TrimPrefix(v, "Bearer ")]
	if !ok {
		return nil, errors.New("unknown token")
	}
	return c, nil
}

// call is one request to a test server.
type call struct {
	token, method      string
	orgID, ref, name   string
	wantCode           connect.Code // 0: success
	wantOrg, wantError string
}

// TestServer_Authorization: every permission kind against callers of every kind; a caller who is
// no member of the resource's org finds nothing, whether the resource exists or not; a missing
// permission names it; step-up holds for 10 minutes; a token's scopes narrow its roles; validation
// runs after authorization; streams are admitted like unary calls.
func TestServer_Authorization(t *testing.T) {
	orgA, orgB := ids.New("org"), ids.New("org")
	routeA, routeB, gone := ids.New("rt"), ids.New("rt"), ids.New("rt")
	now := time.Now()
	user := func(id string, roles map[string]string) *api.Caller {
		return &api.Caller{Principal: authz.Principal{UserID: id, Memberships: roles}, AuthMethod: "session"}
	}
	stepped := user("usr_stepped", map[string]string{orgA: authz.RoleOwner})
	stepped.StepUpAt = now.Add(-9 * time.Minute)
	stale := user("usr_stale", map[string]string{orgA: authz.RoleOwner})
	stale.StepUpAt = now.Add(-StepUpPlus)
	admin := user("usr_admin", nil)
	admin.InstanceAdmin = true
	token := user("usr_token", map[string]string{orgA: authz.RoleOwner})
	token.AuthMethod, token.Scopes = "token", []string{authz.PermOrgRead}
	callers := bearer{
		"owner": user("usr_owner", map[string]string{orgA: authz.RoleOwner}), "viewer": user("usr_viewer", map[string]string{orgA: authz.RoleViewer}),
		"operator": user("usr_operator", map[string]string{orgA: authz.RoleOperator, orgB: authz.RoleOperator}),
		"ownerB":   user("usr_ownerB", map[string]string{orgB: authz.RoleOwner}), "stepped": stepped, "stale": stale, "admin": admin,
		"token": token,
	}
	sd := testFile(t, "authz",
		method{name: "Public", authz: &rpmgrv1.Authz{Permission: authz.PermPublic}},
		method{name: "Me", authz: &rpmgrv1.Authz{Permission: authz.PermAuthenticated}},
		method{name: "Instance", authz: &rpmgrv1.Authz{Permission: authz.PermInstanceAdmin}},
		method{name: "Read", authz: &rpmgrv1.Authz{Permission: authz.PermOrgRead, ResourceField: "org_id"}},
		method{name: "Write", authz: &rpmgrv1.Authz{Permission: authz.PermRoutesWrite, ResourceField: "ref.id"}},
		method{name: "Enroll", authz: &rpmgrv1.Authz{Permission: authz.PermConnectorsWrite, ResourceField: "org_id"}},
		method{name: "Members", authz: &rpmgrv1.Authz{Permission: authz.PermMembersWrite, ResourceField: "org_id", StepUp: true}},
		method{name: "Watch", authz: &rpmgrv1.Authz{Permission: authz.PermOrgRead, ResourceField: "org_id"}, stream: "server"},
	)
	srv, err := api.New(api.Options{DB: storetest.Migrated(t, store.SQLite), Sys: storetest.SystemCtx(t), Sealer: testSealer(t), Authenticator: callers, Now: func() time.Time { return now },
		Resolver: func(_ context.Context, id string) (string, error) {
			switch id {
			case routeA:
				return orgA, nil
			case routeB:
				return orgB, nil
			case "rt_broken":
				return "", errors.New("the database is down")
			}
			return "", api.ErrNotFound
		},
		OperatorsMayEnroll: func(_ context.Context, org string) (bool, error) { return org == orgB, nil }})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := srv.Mount(mux, sd, handlers(sd)); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	for _, c := range []call{
		{method: "Public"},
		{token: "nobody", method: "Public"},
		{token: "nobody", method: "Me", wantCode: connect.CodeUnauthenticated},
		{method: "Me", wantCode: connect.CodeUnauthenticated},
		{token: "viewer", method: "Me"},
		{token: "token", method: "Me", wantCode: connect.CodePermissionDenied},
		{token: "owner", method: "Instance", wantCode: connect.CodePermissionDenied, wantError: authz.PermInstanceAdmin},
		{token: "admin", method: "Instance"},
		{method: "Read", orgID: orgA, wantCode: connect.CodeUnauthenticated},
		{token: "viewer", method: "Read", orgID: orgA, wantOrg: orgA},
		{token: "viewer", method: "Read", orgID: orgB, wantCode: connect.CodeNotFound},
		{token: "viewer", method: "Read", orgID: ids.New("org"), wantCode: connect.CodeNotFound},
		{token: "viewer", method: "Read", wantCode: connect.CodeInvalidArgument, wantError: "org_id is required"},
		{token: "admin", method: "Read", orgID: orgA, wantCode: connect.CodeNotFound},
		{token: "viewer", method: "Write", ref: routeA, wantCode: connect.CodePermissionDenied, wantError: authz.PermRoutesWrite},
		{token: "operator", method: "Write", ref: routeA, wantOrg: orgA},
		{token: "owner", method: "Write", ref: routeB, wantCode: connect.CodeNotFound},
		{token: "owner", method: "Write", ref: gone, wantCode: connect.CodeNotFound},
		{token: "owner", method: "Write", ref: "not an ID", wantCode: connect.CodeNotFound},
		{token: "owner", method: "Write", ref: "rt_broken", wantCode: connect.CodeInternal},
		{token: "operator", method: "Enroll", orgID: orgA, wantCode: connect.CodePermissionDenied},
		{token: "operator", method: "Enroll", orgID: orgB, wantOrg: orgB},
		{token: "owner", method: "Enroll", orgID: orgA, wantOrg: orgA},
		{token: "owner", method: "Members", orgID: orgA, wantCode: connect.CodeUnauthenticated, wantError: "step-up"},
		{token: "stale", method: "Members", orgID: orgA, wantCode: connect.CodeUnauthenticated, wantError: "step-up"},
		{token: "stepped", method: "Members", orgID: orgA, wantOrg: orgA},
		{token: "viewer", method: "Members", orgID: orgA, wantCode: connect.CodePermissionDenied},
		{token: "token", method: "Read", orgID: orgA, wantOrg: orgA},
		{token: "token", method: "Write", ref: routeA, wantCode: connect.CodePermissionDenied},
		{token: "viewer", method: "Read", orgID: orgA, name: "nine char", wantCode: connect.CodeInvalidArgument},
		{token: "viewer", method: "Read", orgID: orgB, name: "nine char", wantCode: connect.CodeNotFound},
		{token: "viewer", method: "Watch", orgID: orgA, wantOrg: orgA},
		{token: "ownerB", method: "Watch", orgID: orgA, wantCode: connect.CodeNotFound},
	} {
		code, org, err := invoke(hs.URL, sd, c)
		label := c.token + " " + c.method + " " + c.orgID + c.ref
		switch {
		case code != c.wantCode:
			t.Errorf("%s: %v, want %v (%v)", label, code, c.wantCode, err)
		case c.wantCode == 0 && org != c.wantOrg:
			t.Errorf("%s: scope %q, want %q", label, org, c.wantOrg)
		case c.wantError != "" && (err == nil || !strings.Contains(err.Error(), c.wantError)):
			t.Errorf("%s: error %v, want it to name %q", label, err, c.wantError)
		}
	}
}

// StepUpPlus is just past the step-up window.
const StepUpPlus = api.StepUpWindow + time.Second

// invoke calls a method of the test service and returns the error code, 0 on success, with the
// org of the handler's scope.
func invoke(base string, sd protoreflect.ServiceDescriptor, c call) (connect.Code, string, error) {
	md := sd.Methods().ByName(protoreflect.Name(c.method))
	in := dynamicpb.NewMessage(md.Input())
	if c.orgID != "" {
		in.Set(md.Input().Fields().ByName("org_id"), protoreflect.ValueOfString(c.orgID))
	}
	if c.ref != "" {
		ref := in.Mutable(md.Input().Fields().ByName("ref")).Message()
		ref.Set(ref.Descriptor().Fields().ByName("id"), protoreflect.ValueOfString(c.ref))
	}
	if c.name != "" {
		in.Set(md.Input().Fields().ByName("name"), protoreflect.ValueOfString(c.name))
	}
	url := base + "/" + string(sd.FullName()) + "/" + string(md.Name())
	opts := []connect.ClientOption{connect.WithSchema(md), connect.WithResponseInitializer(initializer(md.Output()))}
	client := connect.NewClient[dynamicpb.Message, dynamicpb.Message](http.DefaultClient, url, opts...)
	req := connect.NewRequest(in)
	if c.token != "" {
		req.Header().Set("Authorization", "Bearer "+c.token)
	}
	var out *dynamicpb.Message
	if md.IsStreamingServer() {
		stream, err := client.CallServerStream(context.Background(), req)
		if err != nil {
			return connect.CodeOf(err), "", err
		}
		defer func() { _ = stream.Close() }()
		if !stream.Receive() {
			return connect.CodeOf(stream.Err()), "", stream.Err()
		}
		out = stream.Msg()
	} else {
		resp, err := client.CallUnary(context.Background(), req)
		if err != nil {
			return connect.CodeOf(err), "", err
		}
		out = resp.Msg
	}
	return 0, out.Get(md.Output().Fields().ByName("org")).String(), nil
}

// TestServer_ErrorDetails: a missing permission carries its name, a missing step-up its reason,
// and a request that is not valid its field violations.
func TestServer_ErrorDetails(t *testing.T) {
	org := ids.New("org")
	sd := testFile(t, "details",
		method{name: "Write", authz: &rpmgrv1.Authz{Permission: authz.PermRoutesWrite, ResourceField: "org_id"}},
		method{name: "Members", authz: &rpmgrv1.Authz{Permission: authz.PermMembersWrite, ResourceField: "org_id", StepUp: true}},
	)
	srv, err := api.New(api.Options{DB: storetest.Migrated(t, store.SQLite), Sys: storetest.SystemCtx(t), Sealer: testSealer(t),
		Authenticator: bearer{
			"viewer": {Principal: authz.Principal{UserID: "usr_v", Memberships: map[string]string{org: authz.RoleViewer}}},
			"owner":  {Principal: authz.Principal{UserID: "usr_o", Memberships: map[string]string{org: authz.RoleOwner}}},
		},
		Resolver:           func(context.Context, string) (string, error) { return "", api.ErrNotFound },
		OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil }})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := srv.Mount(mux, sd, handlers(sd)); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	info := func(err error) *errdetails.ErrorInfo {
		var cerr *connect.Error
		if !errors.As(err, &cerr) {
			return nil
		}
		for _, d := range cerr.Details() {
			if v, derr := d.Value(); derr == nil {
				if ei, ok := v.(*errdetails.ErrorInfo); ok {
					return ei
				}
			}
		}
		return nil
	}
	_, _, err = invoke(hs.URL, sd, call{token: "viewer", method: "Write", orgID: org})
	if ei := info(err); ei == nil || ei.GetReason() != api.ReasonPermissionMissing || ei.GetDomain() != api.ErrorDomain ||
		ei.GetMetadata()["permission"] != authz.PermRoutesWrite {
		t.Errorf("a missing permission: %v", ei)
	}
	_, _, err = invoke(hs.URL, sd, call{token: "owner", method: "Members", orgID: org})
	if ei := info(err); ei == nil || ei.GetReason() != api.ReasonStepUpRequired {
		t.Errorf("a missing step-up: %v", ei)
	}
	_, _, err = invoke(hs.URL, sd, call{token: "owner", method: "Write", orgID: org, name: "far too long"})
	var cerr *connect.Error
	var violations *validate.Violations
	if errors.As(err, &cerr) {
		for _, d := range cerr.Details() {
			if v, derr := d.Value(); derr == nil {
				violations, _ = v.(*validate.Violations)
			}
		}
	}
	if violations == nil || len(violations.GetViolations()) != 1 ||
		violations.GetViolations()[0].GetField().GetElements()[0].GetFieldName() != "name" {
		t.Errorf("validation details: %v", violations)
	}
}

// TestCheck: a service is mounted only if every method's authorization can be enforced.
func TestCheck(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	ok := &rpmgrv1.Authz{Permission: authz.PermOrgRead, ResourceField: "org_id"}
	for name, m := range map[string]method{
		"without_option":        {name: "M"},
		"unknown_permission":    {name: "M", authz: &rpmgrv1.Authz{Permission: "routes.update", ResourceField: "org_id"}},
		"empty_permission":      {name: "M", authz: &rpmgrv1.Authz{}},
		"org_without_field":     {name: "M", authz: &rpmgrv1.Authz{Permission: authz.PermOrgRead}},
		"missing_field":         {name: "M", authz: &rpmgrv1.Authz{Permission: authz.PermOrgRead, ResourceField: "route.id"}},
		"message_field":         {name: "M", authz: &rpmgrv1.Authz{Permission: authz.PermOrgRead, ResourceField: "ref"}},
		"through_a_string":      {name: "M", authz: &rpmgrv1.Authz{Permission: authz.PermOrgRead, ResourceField: "name.id"}},
		"repeated_field":        {name: "M", authz: &rpmgrv1.Authz{Permission: authz.PermOrgRead, ResourceField: "tags"}},
		"step_up_on_public":     {name: "M", authz: &rpmgrv1.Authz{Permission: authz.PermPublic, StepUp: true}},
		"token_on_org_read":     {name: "M", authz: &rpmgrv1.Authz{Permission: authz.PermOrgRead, ResourceField: "org_id", AllowToken: true}},
		"client_stream":         {name: "M", authz: ok, stream: "client"},
		"public_with_bad_field": {name: "M", authz: &rpmgrv1.Authz{Permission: authz.PermPublic, ResourceField: "nope"}},
	} {
		sd := testFile(t, "check_"+name, method{name: "Good", authz: ok}, m)
		srv, err := api.New(api.Options{DB: db, Sys: storetest.SystemCtx(t), Sealer: testSealer(t), Resolver: func(context.Context, string) (string, error) { return "", api.ErrNotFound },
			OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil }})
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Mount(http.NewServeMux(), sd, handlers(sd)); err == nil {
			t.Errorf("%s: mounted", name)
		}
	}
	sd := testFile(t, "check_good", method{name: "Good", authz: ok}, method{name: "Watch", authz: ok, stream: "server"},
		method{name: "Deep", authz: &rpmgrv1.Authz{Permission: authz.PermRoutesWrite, ResourceField: "ref.id"}})
	if err := api.Check(sd); err != nil {
		t.Fatal(err)
	}
	srv, _ := api.New(api.Options{DB: db, Sys: storetest.SystemCtx(t), Sealer: testSealer(t), Resolver: func(context.Context, string) (string, error) { return "", api.ErrNotFound },
		OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil }})
	if err := srv.Mount(http.NewServeMux(), sd, func(o ...connect.HandlerOption) (string, http.Handler) {
		_, h := handlers(sd)(o...)
		return "/rpmgr.other.v1.OtherService/", h
	}); err == nil {
		t.Fatal("mounted a handler on another service's path")
	}
	if _, err := api.New(api.Options{DB: db, Sys: storetest.SystemCtx(t), Sealer: testSealer(t)}); err == nil {
		t.Fatal("a server without a resolver")
	}
	if _, err := api.New(api.Options{Resolver: func(context.Context, string) (string, error) { return "", api.ErrNotFound },
		OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil }}); err == nil {
		t.Fatal("a server without a database for the audit log")
	}
	if _, err := api.New(api.Options{DB: db, Sealer: testSealer(t), Resolver: func(context.Context, string) (string, error) { return "", api.ErrNotFound },
		OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil }}); err == nil {
		t.Fatal("a server without the system scope")
	}
}

// TestAnnotations walks every service of rpmgr.v1 in the registry: each method's authorization
// can be enforced (docs/12-testing-and-quality.md, "Security testing"). New services are covered
// without changing this test.
func TestAnnotations(t *testing.T) {
	_ = rpmgrv1.File_rpmgr_v1_options_proto // the generated package registers every rpmgr.v1 file
	services := 0
	protoregistry.GlobalFiles.RangeFilesByPackage("rpmgr.v1", func(fd protoreflect.FileDescriptor) bool {
		for i := range fd.Services().Len() {
			services++
			if err := api.Check(fd.Services().Get(i)); err != nil {
				t.Error(err)
			}
		}
		return true
	})
	t.Logf("%d services checked", services)
}

// TestServer_HidesInternalErrors: an error a handler did not write for the client becomes
// INTERNAL without its text; a connect error passes as it is.
func TestServer_HidesInternalErrors(t *testing.T) {
	sd := testFile(t, "internal", method{name: "Fail", authz: &rpmgrv1.Authz{Permission: authz.PermPublic}},
		method{name: "Refuse", authz: &rpmgrv1.Authz{Permission: authz.PermPublic}},
		method{name: "Stream", authz: &rpmgrv1.Authz{Permission: authz.PermPublic}, stream: "server"})
	srv, err := api.New(api.Options{DB: storetest.Migrated(t, store.SQLite), Sys: storetest.SystemCtx(t), Sealer: testSealer(t),
		Resolver:           func(context.Context, string) (string, error) { return "", api.ErrNotFound },
		OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil }})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := srv.Mount(mux, sd, handlersWith(sd, func(_ context.Context, method string, _ *dynamicpb.Message) error {
		if method == "Refuse" {
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("the domain is not verified"))
		}
		return errors.New("pq: relation org_b_secrets does not exist")
	})); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)
	for _, m := range []string{"Fail", "Stream"} {
		code, _, err := invoke(hs.URL, sd, call{method: m})
		if code != connect.CodeInternal || err == nil || strings.Contains(err.Error(), "org_b") {
			t.Errorf("%s: %v %v", m, code, err)
		}
	}
	if code, _, err := invoke(hs.URL, sd, call{method: "Refuse"}); code != connect.CodeFailedPrecondition ||
		!strings.Contains(err.Error(), "not verified") {
		t.Errorf("a connect error: %v %v", code, err)
	}
}

// TestServer_RequireMFA: in an org that requires a second factor, a member signed in without one
// is refused with MFA_REQUIRED, one with it passes; other orgs and methods outside orgs are
// unaffected.
func TestServer_RequireMFA(t *testing.T) {
	strict, lax := ids.New("org"), ids.New("org")
	roles := map[string]string{strict: authz.RoleOwner, lax: authz.RoleOwner}
	sd := testFile(t, "mfa", method{name: "Read", authz: &rpmgrv1.Authz{Permission: authz.PermOrgRead, ResourceField: "org_id"}},
		method{name: "Me", authz: &rpmgrv1.Authz{Permission: authz.PermAuthenticated}})
	srv, err := api.New(api.Options{DB: storetest.Migrated(t, store.SQLite), Sys: storetest.SystemCtx(t), Sealer: testSealer(t),
		Authenticator: bearer{
			"password": {Principal: authz.Principal{UserID: "usr_p", Memberships: roles}},
			"mfa":      {Principal: authz.Principal{UserID: "usr_m", Memberships: roles}, MFA: true},
		},
		Resolver:           func(context.Context, string) (string, error) { return "", api.ErrNotFound },
		OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil },
		RequireMFA:         func(_ context.Context, org string) (bool, error) { return org == strict, nil }})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := srv.Mount(mux, sd, handlers(sd)); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)
	for _, c := range []call{
		{token: "password", method: "Read", orgID: strict, wantCode: connect.CodePermissionDenied, wantError: "second factor"},
		{token: "mfa", method: "Read", orgID: strict, wantOrg: strict},
		{token: "password", method: "Read", orgID: lax, wantOrg: lax},
		{token: "password", method: "Me"},
	} {
		code, org, err := invoke(hs.URL, sd, c)
		if code != c.wantCode || c.wantCode == 0 && org != c.wantOrg || c.wantError != "" && !strings.Contains(err.Error(), c.wantError) {
			t.Errorf("%s %s %s: %v %q %v", c.token, c.method, c.orgID, code, org, err)
		}
	}
}

// TestServer_RestoreReview: in an org in restore review, a method that changes state is refused
// with RESTORE_REVIEW unless it stays available during the review, and a read passes; an instance
// method is refused while the instance is in review; a review that cannot be read refuses.
func TestServer_RestoreReview(t *testing.T) {
	inReview, open, broken := ids.New("org"), ids.New("org"), ids.New("org")
	roles := map[string]string{inReview: authz.RoleOwner, open: authz.RoleOwner, broken: authz.RoleOwner}
	sd := testFile(t, "review",
		method{name: "Write", authz: &rpmgrv1.Authz{Permission: authz.PermRoutesWrite, ResourceField: "org_id"}},
		method{name: "Revoke", authz: &rpmgrv1.Authz{Permission: authz.PermMembersWrite, ResourceField: "org_id", DuringRestoreReview: true}},
		method{name: "Read", authz: &rpmgrv1.Authz{Permission: authz.PermOrgRead, ResourceField: "org_id"}, readOnly: true},
		method{name: "Instance", authz: &rpmgrv1.Authz{Permission: authz.PermInstanceAdmin}},
		method{name: "Me", authz: &rpmgrv1.Authz{Permission: authz.PermAuthenticated}})
	srv, err := api.New(api.Options{DB: storetest.Migrated(t, store.SQLite), Sys: storetest.SystemCtx(t), Sealer: testSealer(t),
		Authenticator:      bearer{"admin": {Principal: authz.Principal{UserID: "usr_a", Memberships: roles}, InstanceAdmin: true}},
		Resolver:           func(context.Context, string) (string, error) { return "", api.ErrNotFound },
		OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil },
		RestoreReview: func(_ context.Context, org string) (bool, error) {
			if org == broken {
				return false, errors.New("the database is gone")
			}
			return org == inReview || org == "", nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := srv.Mount(mux, sd, handlers(sd)); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)
	for _, c := range []call{
		{token: "admin", method: "Write", orgID: inReview, wantCode: connect.CodeFailedPrecondition, wantError: "restore review"},
		{token: "admin", method: "Revoke", orgID: inReview, wantOrg: inReview},
		{token: "admin", method: "Read", orgID: inReview, wantOrg: inReview},
		{token: "admin", method: "Write", orgID: open, wantOrg: open},
		{token: "admin", method: "Write", orgID: broken, wantCode: connect.CodeInternal},
		{token: "admin", method: "Instance", wantCode: connect.CodeFailedPrecondition, wantError: "restore review"},
		{token: "admin", method: "Me"},
	} {
		code, org, err := invoke(hs.URL, sd, c)
		if code != c.wantCode || c.wantCode == 0 && org != c.wantOrg || c.wantError != "" && !strings.Contains(err.Error(), c.wantError) {
			t.Errorf("%s %s: %v %q %v", c.method, c.orgID, code, org, err)
		}
	}
}
