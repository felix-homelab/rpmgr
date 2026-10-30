// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/objstore/objstoretest"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
)

// The AWS documentation's example secret keys, which the repository's secret scan allows.
const (
	awsKey1 = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" //nolint:gosec // G101: the AWS documentation's example
	awsKey2 = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" //nolint:gosec // G101: the AWS documentation's example
)

// TestAuditSinks_S3 (#656; docs/04-security.md, "Audit log"): an object-storage sink is checked
// against its bucket when it is created and when its settings or key change, and what the store
// cannot do is refused with nothing saved: a bucket without Object Lock, a store without conditional
// create or one that does not enforce the lock, wrong credentials, settings no client can use. A
// store that cannot be reached is Unavailable. The secret key is write-only everywhere.
func TestAuditSinks_S3(t *testing.T) {
	e := newEnv(t)
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c := e.db.Client()
	srv := objstoretest.New(t)
	kind := rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_S3
	good := func() *rpmgrv1.AuditSink {
		return &rpmgrv1.AuditSink{Name: "vault", Kind: kind, Endpoint: srv.URL, Region: objstoretest.Region, Bucket: objstoretest.Bucket,
			AccessKeyId: objstoretest.AccessKeyID, Secret: awsKey1, RetentionDays: 60, Entries: true}
	}
	create := func(in *rpmgrv1.AuditSink) (*rpmgrv1.AuditSink, error) {
		r, err := ada.sink.CreateAuditSink(ctx, connect.NewRequest(&rpmgrv1.CreateAuditSinkRequest{AuditSink: in}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetAuditSink(), nil
	}
	with := func(mod func(*rpmgrv1.AuditSink)) *rpmgrv1.AuditSink {
		in := good()
		mod(in)
		return in
	}

	// Settings no client can use, and fields of another kind, are refused without a request.
	for name, in := range map[string]*rpmgrv1.AuditSink{
		"no endpoint":          with(func(s *rpmgrv1.AuditSink) { s.Endpoint = "" }),
		"http off loopback":    with(func(s *rpmgrv1.AuditSink) { s.Endpoint = "http://s3.example.com" }),
		"credentials in a URL": with(func(s *rpmgrv1.AuditSink) { s.Endpoint = "https://user:pw@s3.example.com" }), //nolint:gosec // G101: a test URL
		"a path in the URL":    with(func(s *rpmgrv1.AuditSink) { s.Endpoint = "https://s3.example.com/bucket" }),
		"no region":            with(func(s *rpmgrv1.AuditSink) { s.Region = "" }),
		"a bad bucket":         with(func(s *rpmgrv1.AuditSink) { s.Bucket = "Not_A_Bucket" }),
		"no access key":        with(func(s *rpmgrv1.AuditSink) { s.AccessKeyId = "" }),
		"no secret key":        with(func(s *rpmgrv1.AuditSink) { s.Secret = "" }),
		"a short secret key":   with(func(s *rpmgrv1.AuditSink) { s.Secret = "short" }),
		"a lock of 29 days":    with(func(s *rpmgrv1.AuditSink) { s.RetentionDays = 29 }),
		"a lock of 3651 days":  with(func(s *rpmgrv1.AuditSink) { s.RetentionDays = 3651 }),
		"a negative lock":      with(func(s *rpmgrv1.AuditSink) { s.RetentionDays = -1 }),
		"a url":                with(func(s *rpmgrv1.AuditSink) { s.Url = "https://example.com/x" }),
		"an address":           with(func(s *rpmgrv1.AuditSink) { s.Address = "logs.example.com:6514" }),
		"a bad CA bundle":      with(func(s *rpmgrv1.AuditSink) { s.CaBundle = "nope" }),
		"a webhook with a bucket": {Name: "a", Kind: rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_WEBHOOK, Url: "https://example.com/x", Secret: sinkKey,
			Bucket: objstoretest.Bucket},
		"a syslog sink with a region": {Name: "a", Kind: rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_SYSLOG, Address: "logs.example.com:6514", Region: "x"},
	} {
		if _, err := create(in); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := srv.Count("PUT"); n != 0 {
		t.Fatalf("%d requests for settings that were refused before any", n)
	}

	// What the bucket cannot do.
	for name, c := range map[string]struct {
		set  func(*objstoretest.Server)
		code connect.Code
		text string
	}{
		"no Object Lock":          {func(s *objstoretest.Server) { s.NoLock = true }, connect.CodeInvalidArgument, "Object Lock"},
		"no conditional create":   {func(s *objstoretest.Server) { s.NoConditional = true }, connect.CodeInvalidArgument, "If-None-Match"},
		"a lock that is not kept": {func(s *objstoretest.Server) { s.NoEnforce = true }, connect.CodeInvalidArgument, "does not enforce"},
		"no versioning":           {func(s *objstoretest.Server) { s.NoVersions = true }, connect.CodeInvalidArgument, "not versioned"},
		"another access key": {func(s *objstoretest.Server) {
			s.Fault = func(string, string) (int, time.Duration) { return http.StatusForbidden, 0 }
		}, connect.CodeInvalidArgument, "403"},
		"a store that fails": {func(s *objstoretest.Server) {
			s.Fault = func(string, string) (int, time.Duration) { return http.StatusServiceUnavailable, 0 }
		}, connect.CodeUnavailable, "was not saved"},
	} {
		bad := objstoretest.New(t)
		c.set(bad)
		in := good()
		in.Endpoint = bad.URL
		_, err := create(in)
		if code(err) != c.code || !strings.Contains(err.Error(), c.text) || strings.Contains(err.Error(), awsKey1) || strings.Contains(err.Error(), bad.URL) {
			t.Errorf("%s: %v", name, err)
		}
	}
	down := objstoretest.New(t)
	in := good()
	in.Endpoint = down.URL
	down.Close()
	if _, err := create(in); code(err) != connect.CodeUnavailable || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("a store that is down: %v", err)
	}
	if n := c.AuditSink.Query().CountX(e.sys); n != 0 {
		t.Fatalf("%d sinks after refused requests", n)
	}

	// A good bucket: the sink is saved with the key sealed and never returned.
	s, err := create(good())
	if err != nil {
		t.Fatal(err)
	}
	if s.GetKind() != kind || s.GetEndpoint() != srv.URL || s.GetRegion() != objstoretest.Region || s.GetBucket() != objstoretest.Bucket ||
		s.GetAccessKeyId() != objstoretest.AccessKeyID || s.GetRetentionDays() != 60 || !s.GetSecretSet() || s.GetSecret() != "" ||
		strings.Contains(s.String(), awsKey1) || !s.GetEnabled() || s.GetUrl() != "" {
		t.Fatalf("the new sink: %v", s)
	}
	row := c.AuditSink.GetX(e.sys, s.GetId())
	if row.SecretEnc == nil || strings.Contains(string(*row.SecretEnc), awsKey1) {
		t.Fatal("the secret key is stored in the clear")
	}
	if v, err := e.sealer.Open(secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: row.ID}, *row.SecretEnc); err != nil || !v.EqualString(awsKey1) {
		t.Fatalf("the sealed key: %v", err)
	}
	if keys := srv.Keys(); len(keys) != 1 || !strings.HasPrefix(keys[0], "audit/probe/") {
		t.Fatalf("the check left %v", keys)
	}
	got, err := ada.sink.GetAuditSink(ctx, connect.NewRequest(&rpmgrv1.GetAuditSinkRequest{AuditSinkId: s.GetId()}))
	if err != nil || strings.Contains(got.Msg.String(), awsKey1) || got.Msg.GetAuditSink().GetBucket() != objstoretest.Bucket {
		t.Fatalf("get: %v %v", got, err)
	}
	list, err := ada.sink.ListAuditSinks(ctx, connect.NewRequest(&rpmgrv1.ListAuditSinksRequest{}))
	if err != nil || strings.Contains(list.Msg.String(), awsKey1) {
		t.Fatalf("list: %v %v", list, err)
	}

	update := func(in *rpmgrv1.AuditSink, paths ...string) (*rpmgrv1.AuditSink, error) {
		in.Id = s.GetId()
		r, err := ada.sink.UpdateAuditSink(ctx, connect.NewRequest(&rpmgrv1.UpdateAuditSinkRequest{AuditSink: in,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetAuditSink(), nil
	}
	// A change that does not touch the store's settings asks the store nothing.
	puts := srv.Count("PUT")
	up, err := update(&rpmgrv1.AuditSink{Name: "vault2", Entries: false, Enabled: false}, "name", "entries", "enabled")
	if err != nil || up.GetName() != "vault2" || up.GetEntries() || up.GetEnabled() || srv.Count("PUT") != puts {
		t.Fatalf("a rename: %v %v, %d requests", up, err, srv.Count("PUT")-puts)
	}
	// A change of a setting checks the bucket again, and a bucket that fails keeps the sink as it was.
	if up, err = update(&rpmgrv1.AuditSink{Region: "eu-test-2", RetentionDays: 90}, "region", "retention_days"); err != nil ||
		up.GetRegion() != "eu-test-2" || up.GetRetentionDays() != 90 || srv.Count("PUT") != puts+2 {
		t.Fatalf("a new region: %v %v, %d requests", up, err, srv.Count("PUT")-puts)
	}
	srv.NoLock = true
	before := c.AuditSink.GetX(e.sys, s.GetId())
	for name, c := range map[string]struct {
		in    *rpmgrv1.AuditSink
		paths []string
	}{
		"a bucket without a lock": {&rpmgrv1.AuditSink{Bucket: "another-bucket"}, []string{"bucket"}},
		"a new key":               {&rpmgrv1.AuditSink{Secret: awsKey2}, []string{"secret"}},
		"a short key":             {&rpmgrv1.AuditSink{Secret: "short"}, []string{"secret"}},
		"a bad endpoint":          {&rpmgrv1.AuditSink{Endpoint: "http://s3.example.com"}, []string{"endpoint"}},
		"a cleared region":        {&rpmgrv1.AuditSink{}, []string{"region"}},
		"a lock of 10 days":       {&rpmgrv1.AuditSink{RetentionDays: 10}, []string{"retention_days"}},
		"a url":                   {&rpmgrv1.AuditSink{Url: "https://example.com"}, []string{"url"}},
		"an address":              {&rpmgrv1.AuditSink{Address: "logs.example.com:6514"}, []string{"address"}},
		"the kind":                {&rpmgrv1.AuditSink{Kind: rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_WEBHOOK}, []string{"kind"}},
	} {
		if _, err := update(c.in, c.paths...); err == nil || strings.Contains(err.Error(), awsKey2) {
			t.Errorf("%s: %v", name, err)
		}
	}
	after := c.AuditSink.GetX(e.sys, s.GetId())
	if string(*after.SecretEnc) != string(*before.SecretEnc) || after.Settings["bucket"] != objstoretest.Bucket || after.Settings["region"] != "eu-test-2" {
		t.Fatalf("a refused update changed the sink: %v", after.Settings)
	}
	// The bucket is well again; a new key is checked, sealed and never returned.
	srv.NoLock = false
	if up, err = update(&rpmgrv1.AuditSink{Secret: awsKey2}, "secret"); err != nil || up.GetSecret() != "" || !up.GetSecretSet() || strings.Contains(up.String(), awsKey2) {
		t.Fatalf("a new key: %v %v", up, err)
	}
	row = c.AuditSink.GetX(e.sys, s.GetId())
	if v, err := e.sealer.Open(secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: row.ID}, *row.SecretEnc); err != nil || !v.EqualString(awsKey2) {
		t.Fatalf("the replaced key: %v", err)
	}

	// A test checks the bucket and answers in words that name neither the store nor the key.
	test := func() *rpmgrv1.TestAuditSinkResponse {
		r, err := ada.sink.TestAuditSink(ctx, connect.NewRequest(&rpmgrv1.TestAuditSinkRequest{AuditSinkId: s.GetId()}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg
	}
	if r := test(); !r.GetOk() {
		t.Fatalf("a test of a good bucket: %v", r)
	}
	srv.NoConditional = true
	if r := test(); r.GetOk() || !strings.Contains(r.GetError(), "If-None-Match") || strings.Contains(r.GetError(), srv.URL) || strings.Contains(r.GetError(), awsKey2) {
		t.Fatalf("a test of a store without conditional create: %v", r)
	}
	srv.NoConditional = false

	// No audit entry of these requests holds a key.
	n := 0
	for _, a := range c.AuditEntry.Query().Where(auditentry.ActionHasPrefix("rpmgr.v1.AuditSinkService.")).AllX(e.sys) {
		n++
		if strings.Contains(a.Diff, awsKey1) || strings.Contains(a.Diff, awsKey2) {
			t.Fatalf("the audit log holds a secret key: %s", a.Diff)
		}
	}
	if n < 5 {
		t.Errorf("%d audit entries of sink requests", n)
	}
}
