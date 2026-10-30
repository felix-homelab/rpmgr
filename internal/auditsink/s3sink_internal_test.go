// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/objstore"
	"github.com/felix-homelab/rpmgr/internal/objstore/objstoretest"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// The AWS documentation's example secret key, which the repository's secret scan allows.
const awsExampleSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" //nolint:gosec // G101: the AWS documentation's example

func s3Client(t *testing.T, endpoint string, timeout time.Duration) *objstore.Client {
	t.Helper()
	c, err := objstore.New(objstore.Config{Endpoint: endpoint, Region: objstoretest.Region, Bucket: objstoretest.Bucket, Timeout: timeout,
		Credentials: objstore.Credentials{AccessKeyID: objstoretest.AccessKeyID, SecretAccessKey: secret.New(awsExampleSecret)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func s3TestSink(t *testing.T, srv *objstoretest.Server, timeout time.Duration) *s3Sink {
	t.Helper()
	return &s3Sink{client: s3Client(t, srv.URL, timeout), lockDays: 30, now: time.Now, batchTimeout: S3BatchTimeout}
}

func cpItem(chain string, seq int64) Item {
	return Item{ID: "acp_" + chain, Type: EventCheckpoint, Chain: chain, Seq: seq, Body: []byte(`{"seq":` + string(rune('0'+seq%10)) + `}`)}
}

func entryOf(chain string, seq int64) Item {
	return Item{ID: "aud_x", Type: EventEntry, Chain: chain, Seq: seq, Body: []byte(`{"entry":true}`)}
}

// TestS3Sink_KeysAndLock (#656): every item is one object under a key that depends on its chain,
// its kind and its seq alone, written with a compliance lock for the sink's lock days.
func TestS3Sink_KeysAndLock(t *testing.T) {
	srv := objstoretest.New(t)
	k := s3TestSink(t, srv, 0)
	ctx := context.Background()
	for _, it := range []Item{cpItem("org_a", 7), entryOf("org_a", 3), cpItem("instance", 12), entryOf("instance", 1234567)} {
		if err := k.Ship(ctx, it); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"audit/instance/checkpoints/00000000000000000012",
		"audit/instance/entries/00000000000001234567",
		"audit/org_a/checkpoints/00000000000000000007",
		"audit/org_a/entries/00000000000000000003",
	}
	if got := srv.Keys(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("keys %v, want %v", got, want)
	}
	if b, _ := srv.Get(want[3]); string(b) != `{"entry":true}` {
		t.Fatalf("body %q", b)
	}
	mode, retain := srv.Lock(want[2])
	until, err := time.Parse("2006-01-02T15:04:05.000Z", retain)
	if mode != "COMPLIANCE" || err != nil || until.Before(time.Now().Add(29*24*time.Hour)) || until.After(time.Now().Add(31*24*time.Hour)) {
		t.Fatalf("lock %q until %q (%v)", mode, retain, err)
	}
	if err := k.Ship(ctx, Item{Type: EventTest, Chain: "x"}); err == nil {
		t.Error("a test item was written to the store")
	}
}

// TestS3Sink_ResendIsIdempotent (#656): a key that is taken holds the item if it holds the same
// bytes, so a resend after a crash before the cursor moved changes nothing; other bytes under the
// key are never taken for the item, and never overwritten.
func TestS3Sink_ResendIsIdempotent(t *testing.T) {
	srv := objstoretest.New(t)
	k := s3TestSink(t, srv, 0)
	ctx := context.Background()
	it := cpItem("org_a", 5)
	for range 3 {
		if err := k.Ship(ctx, it); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(srv.Keys()); n != 1 || srv.Count("PUT") != 3 || srv.Count("GET") != 2 {
		t.Fatalf("%d objects, %d PUT, %d GET", n, srv.Count("PUT"), srv.Count("GET"))
	}
	other := it
	other.Body = []byte(`{"seq":6}`)
	err := k.Ship(ctx, other)
	var perm *PermanentError
	if !errors.As(err, &perm) || !strings.Contains(err.Error(), "audit/org_a/checkpoints/00000000000000000005") || !strings.Contains(err.Error(), "other bytes") {
		t.Fatalf("other bytes under the key: %v", err)
	}
	if b, _ := srv.Get("audit/org_a/checkpoints/00000000000000000005"); string(b) != string(it.Body) {
		t.Fatalf("the object was replaced by %q", b)
	}
	// A store that ignored the condition would overwrite; the sink then writes what it has, and the
	// check of the bucket is what refuses such a store when the sink is saved.
}

// TestS3Sink_StoreAnswers (#656): what each answer of the store does to an item. A 4xx is a
// permanent refusal that names the store's code; 5xx, 408, 429, a store that is down and one that
// is slow fail the item without the permanent mark; no text names the store's address or the key.
func TestS3Sink_StoreAnswers(t *testing.T) {
	for name, c := range map[string]struct {
		status    int
		permanent bool
		want      string
	}{
		"forbidden":       {http.StatusForbidden, true, "403 Fault"},
		"bad request":     {http.StatusBadRequest, true, "400 Fault"},
		"not found":       {http.StatusNotFound, true, "404 Fault"},
		"server error":    {http.StatusInternalServerError, false, "500 Fault"},
		"unavailable":     {http.StatusServiceUnavailable, false, "503 Fault"},
		"slow down":       {http.StatusTooManyRequests, false, "429 Fault"},
		"request timeout": {http.StatusRequestTimeout, false, "408 Fault"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := objstoretest.New(t)
			srv.Fault = func(string, string) (int, time.Duration) { return c.status, 0 }
			err := s3TestSink(t, srv, 0).Ship(context.Background(), cpItem("org_a", 1))
			var perm *PermanentError
			if err == nil || errors.As(err, &perm) != c.permanent || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v (permanent %v)", err, errors.As(err, &perm))
			}
			if len(srv.Keys()) != 0 {
				t.Error("an object was written")
			}
			if text := Describe(err); strings.Contains(text, "127.0.0.1") || strings.Contains(text, awsExampleSecret) {
				t.Errorf("the status text names the store or the key: %s", text)
			}
		})
	}

	t.Run("down", func(t *testing.T) {
		srv := objstoretest.New(t)
		k := s3TestSink(t, srv, 0)
		srv.Close()
		err := k.Ship(context.Background(), cpItem("org_a", 1))
		var perm *PermanentError
		if err == nil || errors.As(err, &perm) || !strings.Contains(err.Error(), "could not be reached") || strings.Contains(Describe(err), "127.0.0.1") {
			t.Fatalf("a store that is down: %v", err)
		}
	})
	t.Run("slow", func(t *testing.T) {
		srv := objstoretest.New(t)
		srv.Fault = func(string, string) (int, time.Duration) { return 0, 2 * time.Second }
		err := s3TestSink(t, srv, 100*time.Millisecond).Ship(context.Background(), cpItem("org_a", 1))
		var perm *PermanentError
		if err == nil || errors.As(err, &perm) || !strings.Contains(err.Error(), "did not answer in time") {
			t.Fatalf("a store that is slow: %v", err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		srv := objstoretest.New(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := s3TestSink(t, srv, 0).Ship(ctx, cpItem("org_a", 1)); err == nil || len(srv.Keys()) != 0 {
			t.Fatalf("a cancelled shipment: %v", err)
		}
	})
}

// TestS3Sink_BatchDeadline (#656; docs/03-connections.md): a batch that is not written within its
// time stops at the item in hand: the items before it are acknowledged, the item is not written,
// and the next batch, after Flush, goes on.
func TestS3Sink_BatchDeadline(t *testing.T) {
	srv := objstoretest.New(t)
	srv.Fault = func(string, string) (int, time.Duration) { return 0, 60 * time.Millisecond }
	k := s3TestSink(t, srv, 0)
	k.batchTimeout = 200 * time.Millisecond
	ctx := context.Background()
	shipped := 0
	var err error
	for seq := int64(1); seq <= 10 && err == nil; seq++ {
		if err = k.Ship(ctx, cpItem("org_a", seq)); err == nil {
			shipped++
		}
	}
	if !errors.Is(err, errBatchTime) || shipped < 1 || shipped > 4 || len(srv.Keys()) != shipped {
		t.Fatalf("shipped %d, %d objects, error %v", shipped, len(srv.Keys()), err)
	}
	if text := Describe(err); !strings.Contains(text, "time allowed for a batch") {
		t.Fatalf("status text %q", text)
	}
	// Still out of time until the batch ends; then it starts again.
	if err := k.Ship(ctx, cpItem("org_a", 20)); !errors.Is(err, errBatchTime) {
		t.Fatalf("after the deadline: %v", err)
	}
	if err := k.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := k.Ship(ctx, cpItem("org_a", int64(shipped)+1)); err != nil {
		t.Fatalf("the next batch: %v", err)
	}

	// An item in hand when the time runs out is not written and is not blamed on the store.
	srv2 := objstoretest.New(t)
	srv2.Fault = func(string, string) (int, time.Duration) { return 0, 2 * time.Second }
	k2 := s3TestSink(t, srv2, 0)
	k2.batchTimeout = 100 * time.Millisecond
	if err := k2.Ship(ctx, cpItem("org_a", 1)); !errors.Is(err, errBatchTime) || len(srv2.Keys()) != 0 {
		t.Fatalf("an item past the deadline: %v", err)
	}
}

// TestCheckBucket (#656; VB-24): a bucket is accepted only if it keeps a locked object, answers a
// second conditional create with "exists" and refuses to delete the locked version; every other
// store is refused with the reason, apart from one that could not be reached.
func TestCheckBucket(t *testing.T) {
	now := time.Now()
	for name, c := range map[string]struct {
		set         func(*objstoretest.Server)
		want        string
		unreachable bool
	}{
		"a good bucket":               {func(*objstoretest.Server) {}, "", false},
		"no Object Lock":              {func(s *objstoretest.Server) { s.NoLock = true }, "refused a write with Object Lock in compliance mode", false},
		"no conditional create":       {func(s *objstoretest.Server) { s.NoConditional = true }, "does not support If-None-Match", false},
		"a lock that is not enforced": {func(s *objstoretest.Server) { s.NoEnforce = true }, "does not enforce Object Lock", false},
		"no versioning":               {func(s *objstoretest.Server) { s.NoVersions = true }, "not versioned", false},
		"an unknown key": {func(s *objstoretest.Server) {
			s.Fault = func(string, string) (int, time.Duration) { return http.StatusForbidden, 0 }
		}, "refused a write", false},
		"a store that fails": {func(s *objstoretest.Server) {
			s.Fault = func(string, string) (int, time.Duration) { return http.StatusInternalServerError, 0 }
		}, "could not complete", true},
		"a store that is slow": {func(s *objstoretest.Server) {
			s.Fault = func(string, string) (int, time.Duration) { return 0, 2 * time.Second }
		}, "did not answer in time", true},
	} {
		t.Run(name, func(t *testing.T) {
			srv := objstoretest.New(t)
			c.set(srv)
			err := CheckBucket(context.Background(), s3Client(t, srv.URL, 200*time.Millisecond), now)
			var un *UnreachableError
			switch {
			case c.want == "" && err != nil:
				t.Fatal(err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("got %v, want %q", err, c.want)
			case errors.As(err, &un) != c.unreachable:
				t.Fatalf("unreachable %v: %v", errors.As(err, &un), err)
			}
			if err != nil && (strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), awsExampleSecret)) {
				t.Errorf("the failure names the store or the key: %v", err)
			}
		})
	}

	// The probe is locked for a day, so a good check leaves one locked object.
	srv := objstoretest.New(t)
	if err := CheckBucket(context.Background(), s3Client(t, srv.URL, 0), now); err != nil {
		t.Fatal(err)
	}
	keys := srv.Keys()
	if len(keys) != 1 || !strings.HasPrefix(keys[0], "audit/probe/") {
		t.Fatalf("keys after a check: %v", keys)
	}
	if mode, _ := srv.Lock(keys[0]); mode != "COMPLIANCE" {
		t.Errorf("the probe's lock mode %q", mode)
	}

	// A store that is down.
	down := objstoretest.New(t)
	c := s3Client(t, down.URL, 0)
	down.Close()
	var un *UnreachableError
	if err := CheckBucket(context.Background(), c, now); !errors.As(err, &un) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("a store that is down: %v", err)
	}
}

// TestCheckS3Settings (#656): settings the store's client or the lock rules cannot use are refused
// before any request.
func TestCheckS3Settings(t *testing.T) {
	good := S3Settings{Endpoint: "https://s3.example.com", Region: "eu-central-1", Bucket: "audit-bucket", AccessKeyID: "AKIAIOSFODNN7EXAMPLE"}
	if err := CheckS3Settings(good, awsExampleSecret); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		mod func(*S3Settings)
		key string
	}{
		"no endpoint":           {func(s *S3Settings) { s.Endpoint = "" }, awsExampleSecret},
		"http off loopback":     {func(s *S3Settings) { s.Endpoint = "http://s3.example.com" }, awsExampleSecret},
		"credentials in a URL":  {func(s *S3Settings) { s.Endpoint = "https://user:pw@s3.example.com" }, awsExampleSecret}, //nolint:gosec // G101: a test URL
		"a path":                {func(s *S3Settings) { s.Endpoint = "https://s3.example.com/bucket" }, awsExampleSecret},
		"ftp":                   {func(s *S3Settings) { s.Endpoint = "ftp://s3.example.com" }, awsExampleSecret},
		"no region":             {func(s *S3Settings) { s.Region = "" }, awsExampleSecret},
		"a region with a slash": {func(s *S3Settings) { s.Region = "eu/1" }, awsExampleSecret},
		"a short bucket":        {func(s *S3Settings) { s.Bucket = "ab" }, awsExampleSecret},
		"a bucket in capitals":  {func(s *S3Settings) { s.Bucket = "Audit-Bucket" }, awsExampleSecret},
		"no access key":         {func(s *S3Settings) { s.AccessKeyID = "" }, awsExampleSecret},
		"no secret key":         {func(*S3Settings) {}, ""},
		"a key with a space":    {func(*S3Settings) {}, "a key with a space in it"},
		"a lock of 29 days":     {func(s *S3Settings) { s.LockDays = 29 }, awsExampleSecret},
		"a lock of 3651 days":   {func(s *S3Settings) { s.LockDays = 3651 }, awsExampleSecret},
		"a negative lock":       {func(s *S3Settings) { s.LockDays = -1 }, awsExampleSecret},
		"a bad bundle":          {func(s *S3Settings) { s.CA = "nope" }, awsExampleSecret},
	} {
		s := good
		c.mod(&s)
		err := CheckS3Settings(s, c.key)
		if name == "a bad bundle" {
			// The bundle is read when the client is built for a request.
			_, err = s.client(secret.New(c.key), nil)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), awsExampleSecret) {
			t.Errorf("%s: the error holds the key: %v", name, err)
		}
	}
	for _, days := range []int{0, 30, 3650} {
		s := good
		s.LockDays = days
		if err := CheckS3Settings(s, awsExampleSecret); err != nil {
			t.Errorf("%d days: %v", days, err)
		}
	}
	if (S3Settings{}).Days() != DefaultLockDays || (S3Settings{LockDays: 40}).Days() != 40 {
		t.Error("Days")
	}
	round := S3SettingsOf(S3Settings{Endpoint: "e", Region: "r", Bucket: "b", AccessKeyID: "k", CA: "c", LockDays: 40}.Map())
	if round != (S3Settings{Endpoint: "e", Region: "r", Bucket: "b", AccessKeyID: "k", CA: "c", LockDays: 40}) {
		t.Errorf("settings do not survive the row: %+v", round)
	}
}

// TestS3Sink_IgnoresEnvironmentProxy (#656): a proxy in the environment would hide the address
// that is dialled from the egress guard, so the sink never uses one, and a metadata address is
// refused with the proxy in place and never asked.
func TestS3Sink_IgnoresEnvironmentProxy(t *testing.T) {
	var asked atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(proxy.Close)
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		t.Setenv(k, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	for _, endpoint := range []string{"https://169.254.169.254", "https://[fe80::1]", "https://224.0.0.1"} {
		s := S3Settings{Endpoint: endpoint, Region: "eu-central-1", Bucket: "audit-bucket", AccessKeyID: "AKIAIOSFODNN7EXAMPLE"}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := CheckSettingsAndBucket(ctx, s, awsExampleSecret, time.Now)
		cancel()
		if err == nil {
			t.Errorf("%s: accepted", endpoint)
		}
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("the proxy was asked %d times", n)
	}
}
