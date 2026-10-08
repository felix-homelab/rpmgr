// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func helperServer(t *testing.T, key []byte) *api.Server {
	t.Helper()
	s, err := api.New(api.Options{DB: storetest.Migrated(t, store.SQLite), Sys: storetest.SystemCtx(t), Sealer: testSealer(t), PageKey: key,
		Resolver:           func(context.Context, string) (string, error) { return "", api.ErrNotFound },
		OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// request returns a test Request with the given fields set: names to values.
func request(t *testing.T, sd protoreflect.ServiceDescriptor, fields map[string]any) *dynamicpb.Message {
	t.Helper()
	in := sd.Methods().Get(0).Input()
	m := dynamicpb.NewMessage(in)
	for name, v := range fields {
		m.Set(in.Fields().ByName(protoreflect.Name(name)), protoreflect.ValueOf(v))
	}
	return m
}

// TestPageSize: the default for 0, the maximum for more, an error for a negative size.
func TestPageSize(t *testing.T) {
	for in, want := range map[int32]int{0: api.DefaultPageSize, 1: 1, 500: 500, 501: api.MaxPageSize, 1 << 30: api.MaxPageSize} {
		if got, err := api.PageSize(in); err != nil || got != want {
			t.Errorf("%d: %d %v", in, got, err)
		}
	}
	if _, err := api.PageSize(-1); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("-1: %v", err)
	}
}

// TestPageToken: a token continues the query it was made for, whatever the page size, and with
// the same key after a restart; a tampered or truncated token, one for another query and one made
// under another key are INVALID_ARGUMENT.
func TestPageToken(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	s := helperServer(t, key)
	sd := testFile(t, "page", method{name: "List", authz: &rpmgrv1.Authz{Permission: authz.PermPublic}})
	query := request(t, sd, map[string]any{"org_id": "org_a", "name": "x", "page_size": int32(10)})
	tok := s.PageToken("rt_last", query)
	if after, err := s.AfterPage("", query); err != nil || after != "" {
		t.Fatalf("no token: %q %v", after, err)
	}
	same := request(t, sd, map[string]any{"org_id": "org_a", "name": "x", "page_size": int32(500), "page_token": tok})
	for name, srv := range map[string]*api.Server{"same server": s, "restarted": helperServer(t, key)} {
		if after, err := srv.AfterPage(tok, same); err != nil || after != "rt_last" {
			t.Errorf("%s: %q %v", name, after, err)
		}
	}
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	flip := func(i int) string {
		b := append([]byte(nil), raw...)
		b[i] ^= 1
		return base64.RawURLEncoding.EncodeToString(b)
	}
	for name, c := range map[string]struct {
		token string
		query proto.Message
		srv   *api.Server
	}{
		"key changed":        {flip(3), query, s},
		"mac changed":        {flip(len(raw) - 1), query, s},
		"length changed":     {flip(0), query, s},
		"truncated":          {tok[:len(tok)-4], query, s},
		"longer":             {tok + "AAAA", query, s},
		"not base64":         {"%%%", query, s},
		"empty after decode": {"AA", query, s},
		"another filter":     {tok, request(t, sd, map[string]any{"org_id": "org_a", "name": "y"}), s},
		"another org":        {tok, request(t, sd, map[string]any{"org_id": "org_b", "name": "x"}), s},
		"another key":        {tok, query, helperServer(t, nil)},
	} {
		if _, err := c.srv.AfterPage(c.token, c.query); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestCheckEtag: no etag or the stored one passes; another is FAILED_PRECONDITION with
// ETAG_MISMATCH and the current resource, redacted.
func TestCheckEtag(t *testing.T) {
	current := &rpmgrv1.BasicAuthUser{Name: "alice", PasswordHash: "stored-hash"}
	if api.CheckEtag("", 7, current) != nil || api.CheckEtag(api.Etag(7), 7, current) != nil {
		t.Fatal("a matching or empty etag")
	}
	err := api.CheckEtag("6", 7, current)
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != connect.CodeFailedPrecondition {
		t.Fatalf("a stale etag: %v", err)
	}
	var reason string
	var got *rpmgrv1.BasicAuthUser
	for _, d := range cerr.Details() {
		v, derr := d.Value()
		if derr != nil {
			t.Fatal(derr)
		}
		switch v := v.(type) {
		case *errdetails.ErrorInfo:
			reason = v.GetReason()
		case *rpmgrv1.BasicAuthUser:
			got = v
		}
	}
	if reason != api.ReasonEtagMismatch || got.GetName() != "alice" || got.GetPasswordHash() != api.Redacted {
		t.Errorf("details: %q %v", reason, got)
	}
}

// TestApplyMask: only the named fields change, nested ones included, and a field the source
// leaves unset is cleared; an empty mask, an unknown path, a path through a field that is not a
// singular message, a field outside the allowed ones and two message types are refused.
func TestApplyMask(t *testing.T) {
	sd := testFile(t, "mask", method{name: "Update", authz: &rpmgrv1.Authz{Permission: authz.PermPublic}})
	in := sd.Methods().Get(0).Input()
	refOf := func(m *dynamicpb.Message) protoreflect.Message { return m.Mutable(in.Fields().ByName("ref")).Message() }
	set := func(m protoreflect.Message, name, v string) {
		m.Set(m.Descriptor().Fields().ByName(protoreflect.Name(name)), protoreflect.ValueOfString(v))
	}
	get := func(m protoreflect.Message, name string) string {
		return m.Get(m.Descriptor().Fields().ByName(protoreflect.Name(name))).String()
	}
	stored := func() *dynamicpb.Message {
		m := request(t, sd, map[string]any{"name": "old", "org_id": "org_a", "request_id": "keep"})
		set(refOf(m), "id", "rt_old")
		set(refOf(m), "token", "old-token")
		return m
	}
	update := request(t, sd, map[string]any{"name": "new", "org_id": "org_b"})
	set(refOf(update), "id", "rt_new")
	allowed := []string{"name", "ref", "request_id", "tags", "page_token"}

	dst := stored()
	if err := api.ApplyMask(dst, update, &fieldmaskpb.FieldMask{Paths: []string{"name", "ref.id", "request_id"}}, allowed...); err != nil {
		t.Fatal(err)
	}
	if get(dst, "name") != "new" || get(refOf(dst), "id") != "rt_new" || get(refOf(dst), "token") != "old-token" ||
		get(dst, "org_id") != "org_a" || get(dst, "request_id") != "" {
		t.Errorf("after the mask: %v", dst)
	}
	dst = stored()
	if err := api.ApplyMask(dst, update, &fieldmaskpb.FieldMask{Paths: []string{"ref"}}, allowed...); err != nil ||
		get(refOf(dst), "token") != "" || get(refOf(dst), "id") != "rt_new" {
		t.Errorf("a whole message: %v %v", err, dst)
	}
	dst = stored()
	if err := api.ApplyMask(dst, request(t, sd, nil), &fieldmaskpb.FieldMask{Paths: []string{"ref.token"}}, allowed...); err != nil ||
		get(refOf(dst), "token") != "" || get(refOf(dst), "id") != "rt_old" {
		t.Errorf("a nested field the source leaves unset: %v %v", err, dst)
	}
	for name, paths := range map[string][]string{
		"empty":                   nil,
		"unknown":                 {"nickname"},
		"unknown nested":          {"ref.nickname"},
		"through a string":        {"name.x"},
		"through a list":          {"tags.x"},
		"not allowed":             {"org_id"},
		"not allowed among other": {"name", "org_id"},
	} {
		if err := api.ApplyMask(stored(), update, &fieldmaskpb.FieldMask{Paths: paths}, allowed...); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := api.ApplyMask(stored(), &rpmgrv1.BasicAuthUser{}, &fieldmaskpb.FieldMask{Paths: []string{"name"}}, allowed...); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("two message types: %v", err)
	}
}

// FuzzAfterPage: no token makes AfterPage panic, and one it accepts is the one PageToken makes.
func FuzzAfterPage(f *testing.F) {
	s, err := api.New(api.Options{DB: &store.DB{} /* never used: no request is served */, Sys: storetest.SystemCtx(f), Sealer: testSealer(f),
		PageKey:            []byte("fuzz-key"),
		Resolver:           func(context.Context, string) (string, error) { return "", api.ErrNotFound },
		OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil }})
	if err != nil {
		f.Fatal(err)
	}
	query := &rpmgrv1.BasicAuthUser{Name: "q"}
	f.Add(s.PageToken("rt_1", query))
	f.Add("")
	f.Add("AA")
	f.Fuzz(func(t *testing.T, token string) {
		after, err := s.AfterPage(token, query)
		if err == nil && token != "" && s.PageToken(after, query) != token {
			t.Fatalf("accepted %q for %q", token, after)
		}
	})
}
