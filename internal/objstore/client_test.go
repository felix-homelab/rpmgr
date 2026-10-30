// SPDX-License-Identifier: Apache-2.0

package objstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSecret = "s3cr3t-key-that-must-never-leak"

// put is Put without the version ID, which most tests do not look at.
func put(ctx context.Context, c *Client, key string, body []byte, o PutOptions) error {
	_, err := c.Put(ctx, key, body, o)
	return err
}

func testCreds() Credentials { return creds("AKIDTEST", testSecret) }

// store is a fake bucket that keeps objects, honours If-None-Match and records requests.
type store struct {
	mu   sync.Mutex
	objs map[string][]byte
	reqs []*http.Request
	fail func(w http.ResponseWriter, r *http.Request) bool
}

func (s *store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, r)
	if s.fail != nil && s.fail(w, r) {
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/bkt/")
	switch {
	case r.Method == http.MethodPut:
		if _, ok := s.objs[key]; ok && r.Header.Get("If-None-Match") == "*" {
			xmlError(w, 412, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
			return
		}
		b, _ := io.ReadAll(r.Body)
		s.objs[key] = b
	case r.Method == http.MethodGet && r.URL.Path == "/bkt/":
		fmt.Fprint(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>tok</NextContinuationToken>`+
			`<Contents><Key>a/1</Key><Size>3</Size></Contents><Contents><Key>a/2</Key><Size>4</Size></Contents></ListBucketResult>`)
	case r.Method == http.MethodGet:
		b, ok := s.objs[key]
		if !ok {
			xmlError(w, 404, "NoSuchKey", "The specified key does not exist.")
			return
		}
		_, _ = w.Write(b)
	case r.Method == http.MethodDelete:
		xmlError(w, 400, "InvalidRequest", "locked")
	}
}

func xmlError(w http.ResponseWriter, status int, code, msg string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, msg)
}

func newTLSClient(t *testing.T, h http.Handler, mod func(*Config)) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	cfg := Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "bkt", Credentials: testCreds(), RootCAs: pool}
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestPutGetListSigned(t *testing.T) {
	s := &store{objs: map[string][]byte{}}
	c := newTLSClient(t, s, nil)
	ctx := context.Background()
	until := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := put(ctx, c, "chain 1/00000001", []byte("hello"), PutOptions{IfNoneMatch: true, LockMode: "COMPLIANCE", RetainUntil: until}); err != nil {
		t.Fatal(err)
	}
	r := s.reqs[0]
	if r.URL.EscapedPath() != "/bkt/chain%201/00000001" || r.Header.Get("If-None-Match") != "*" ||
		r.Header.Get("X-Amz-Object-Lock-Mode") != "COMPLIANCE" ||
		r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date") != "2030-01-02T03:04:05.000Z" ||
		r.Header.Get("X-Amz-Content-Sha256") != hexSHA256([]byte("hello")) ||
		!strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDTEST/") {
		t.Errorf("request not as expected: %v %v", r.URL, r.Header)
	}
	got, err := c.Get(ctx, "chain 1/00000001")
	if err != nil || string(got) != "hello" {
		t.Fatalf("get: %q, %v", got, err)
	}
	p, err := c.List(ctx, "a/", "", 2)
	if err != nil || len(p.Objects) != 2 || p.Objects[1] != (Object{"a/2", 4}) || p.Next != "tok" {
		t.Fatalf("list: %+v, %v", p, err)
	}
	if q := s.reqs[2].URL.RawQuery; q != "list-type=2&max-keys=2&prefix=a%2F" {
		t.Errorf("list query %q", q)
	}
}

func TestConditionalCreateConflict(t *testing.T) {
	s := &store{objs: map[string][]byte{}}
	c := newTLSClient(t, s, nil)
	o := PutOptions{IfNoneMatch: true}
	if err := put(context.Background(), c, "k", []byte("one"), o); err != nil {
		t.Fatal(err)
	}
	err := put(context.Background(), c, "k", []byte("two"), o)
	if !errors.Is(err, ErrExists) || Retryable(err) || !Refused(err) {
		t.Errorf("second create: %v", err)
	}
	if got, _ := c.Get(context.Background(), "k"); string(got) != "one" {
		t.Errorf("object overwritten: %q", got)
	}
}

func TestErrorAnswers(t *testing.T) {
	for _, tc := range []struct {
		name            string
		status          int
		code            string
		retryable, refd bool
	}{
		{"forbidden", 403, "AccessDenied", false, true},
		{"unavailable", 503, "SlowDown", true, false},
		{"internal", 500, "InternalError", true, false},
		{"throttled", 429, "TooManyRequests", true, false},
		{"concurrent conditional write", 409, "ConditionalRequestConflict", true, false},
		{"lock refusal as SILO answers it", 400, "InvalidRequest", false, true},
		{"redirect", 301, "PermanentRedirect", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &store{objs: map[string][]byte{}, fail: func(w http.ResponseWriter, r *http.Request) bool {
				xmlError(w, tc.status, tc.code, "text")
				return true
			}}
			c := newTLSClient(t, s, nil)
			err := put(context.Background(), c, "k", []byte("x"), PutOptions{})
			var e *Error
			if !errors.As(err, &e) || e.Status != tc.status || e.Code != tc.code {
				t.Fatalf("got %v", err)
			}
			if Retryable(err) != tc.retryable || Refused(err) != tc.refd {
				t.Errorf("retryable %v refused %v", Retryable(err), Refused(err))
			}
			if tc.status == 301 && len(s.reqs) != 1 {
				t.Errorf("a redirect was followed: %d requests", len(s.reqs))
			}
		})
	}
}

func TestNotFoundAndNonXMLError(t *testing.T) {
	s := &store{objs: map[string][]byte{}}
	c := newTLSClient(t, s, nil)
	if _, err := c.Get(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing key: %v", err)
	}
	s.fail = func(w http.ResponseWriter, r *http.Request) bool {
		http.Error(w, "<html>bad gateway", http.StatusBadGateway)
		return true
	}
	err := c.Delete(context.Background(), "k", "")
	var e *Error
	if !errors.As(err, &e) || e.Status != 502 || e.Code != "" || !Retryable(err) {
		t.Errorf("non-XML 502: %v", err)
	}
}

func TestTimeout(t *testing.T) {
	block := make(chan struct{})
	c := newTLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }),
		func(c *Config) { c.Timeout = 50 * time.Millisecond })
	defer close(block)
	err := put(context.Background(), c, "k", []byte("x"), PutOptions{})
	if err == nil || !Retryable(err) {
		t.Errorf("timeout: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Get(ctx, "k"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestGetBoundedAndMalformedList(t *testing.T) {
	s := &store{objs: map[string][]byte{"big": bytes.Repeat([]byte("x"), MaxObject+1), "ok": bytes.Repeat([]byte("x"), MaxObject)}}
	c := newTLSClient(t, s, nil)
	if _, err := c.Get(context.Background(), "big"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversize object: %v", err)
	}
	if b, err := c.Get(context.Background(), "ok"); err != nil || len(b) != MaxObject {
		t.Errorf("object at the limit: %d, %v", len(b), err)
	}
	s.fail = func(w http.ResponseWriter, r *http.Request) bool { fmt.Fprint(w, "not xml"); return true }
	if _, err := c.List(context.Background(), "", "", 0); err == nil {
		t.Error("malformed list accepted")
	}
	s.fail = func(w http.ResponseWriter, r *http.Request) bool {
		fmt.Fprint(w, "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>")
		return true
	}
	if _, err := c.List(context.Background(), "", "", 0); err == nil {
		t.Error("truncated list without a token accepted")
	}
}

func TestVirtualHostAddressing(t *testing.T) {
	var host, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { host, path = r.Host, r.URL.Path }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c, err := New(Config{Endpoint: srv.URL, Region: "eu-1", Bucket: "bkt", Credentials: testCreds(), VirtualHost: true,
		// the bucket's name is not resolvable; the proxy hook sends the request to the test server
		Proxy: func(*http.Request) (*url.URL, error) { return u, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := put(context.Background(), c, "a/b", nil, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if host != "bkt."+u.Host || path != "/a/b" {
		t.Errorf("host %q path %q", host, path)
	}
}

func TestProxyIsUsed(t *testing.T) {
	var line, auth string
	px := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { line, auth = r.RequestURI, r.Header.Get("Authorization") }))
	defer px.Close()
	pu, _ := url.Parse(px.URL)
	c, err := New(Config{Endpoint: "http://127.0.0.1:9", Region: "us-east-1", Bucket: "bkt", Credentials: testCreds(),
		Proxy: func(*http.Request) (*url.URL, error) { return pu, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := put(context.Background(), c, "k", []byte("x"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if line != "http://127.0.0.1:9/bkt/k" || !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Errorf("proxy saw %q, %q", line, auth)
	}
}

func TestNewRefuses(t *testing.T) {
	ok := Config{Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "bkt", Credentials: testCreds()}
	if _, err := New(ok); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"plain http to a remote host": func(c *Config) { c.Endpoint = "http://s3.example.com" },
		"userinfo":                    func(c *Config) { c.Endpoint = "https://u:p@s3.example.com" },
		"a path":                      func(c *Config) { c.Endpoint = "https://s3.example.com/x" },
		"a query":                     func(c *Config) { c.Endpoint = "https://s3.example.com?x=1" },
		"ftp":                         func(c *Config) { c.Endpoint = "ftp://s3.example.com" },
		"no host":                     func(c *Config) { c.Endpoint = "https://" },
		"no region":                   func(c *Config) { c.Region = "" },
		"bad bucket":                  func(c *Config) { c.Bucket = "Bad_Bucket" },
		"short bucket":                func(c *Config) { c.Bucket = "ab" },
		"no credentials":              func(c *Config) { c.Credentials = Credentials{} },
		"control char in key id":      func(c *Config) { c.Credentials = creds("AK\nID", "x") },
	} {
		t.Run(name, func(t *testing.T) {
			c := ok
			mod(&c)
			if _, err := New(c); err == nil {
				t.Error("accepted")
			}
		})
	}
	if _, err := New(Config{Endpoint: "http://localhost:9000", Region: "r", Bucket: "bkt", Credentials: testCreds()}); err != nil {
		t.Errorf("loopback http: %v", err)
	}
}

func TestRequestArgumentsRefused(t *testing.T) {
	s := &store{objs: map[string][]byte{}}
	c := newTLSClient(t, s, nil)
	ctx := context.Background()
	until := time.Now().Add(time.Hour)
	for name, err := range map[string]error{
		"empty key":         put(ctx, c, "", nil, PutOptions{}),
		"leading slash":     put(ctx, c, "/k", nil, PutOptions{}),
		"long key":          put(ctx, c, strings.Repeat("k", MaxKey+1), nil, PutOptions{}),
		"invalid UTF-8":     put(ctx, c, "\xff", nil, PutOptions{}),
		"lock without date": put(ctx, c, "k", nil, PutOptions{LockMode: "COMPLIANCE"}),
		"date without lock": put(ctx, c, "k", nil, PutOptions{RetainUntil: until}),
		"unknown lock mode": put(ctx, c, "k", nil, PutOptions{LockMode: "FOREVER", RetainUntil: until}),
		"get with bad key":  func() error { _, e := c.Get(ctx, ""); return e }(),
		"delete bad key":    c.Delete(ctx, "", ""),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(s.reqs) != 0 {
		t.Errorf("%d requests sent for refused arguments", len(s.reqs))
	}
}

func TestSecretNeverInLogsOrErrors(t *testing.T) {
	c := testCreds()
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%v %+v %#v %s", c, c, c, c.SecretAccessKey)} {
		if strings.Contains(s, testSecret) {
			t.Errorf("formatted value leaks the secret: %s", s)
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("store", "credentials", c)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("store", "credentials", c)
	if strings.Contains(buf.String(), testSecret) || !strings.Contains(buf.String(), "AKIDTEST") {
		t.Errorf("log output: %s", buf.String())
	}
	// Errors of the store and of the transport.
	s := &store{objs: map[string][]byte{}, fail: func(w http.ResponseWriter, r *http.Request) bool {
		xmlError(w, 403, "SignatureDoesNotMatch", "line\nbreak")
		return true
	}}
	cl := newTLSClient(t, s, nil)
	err := put(context.Background(), cl, "k", []byte("x"), PutOptions{})
	if err == nil || strings.Contains(err.Error(), testSecret) || strings.ContainsAny(err.Error(), "\n") {
		t.Errorf("store error: %q", err)
	}
	dead, _ := New(Config{Endpoint: "http://127.0.0.1:1", Region: "r", Bucket: "bkt", Credentials: testCreds(), Timeout: time.Second})
	err = put(context.Background(), dead, "k", []byte("x"), PutOptions{})
	if err == nil || strings.Contains(err.Error(), testSecret) || !Retryable(err) {
		t.Errorf("transport error: %v", err)
	}
	// The secret is not in any request header either, only its signature.
	for _, r := range s.reqs {
		for k, v := range r.Header {
			if strings.Contains(strings.Join(v, ","), testSecret) {
				t.Errorf("header %s carries the secret", k)
			}
		}
	}
}

func TestClipLongMessage(t *testing.T) {
	if got := clip(strings.Repeat("é", 300)); len(got) > 210 || strings.ContainsRune(got, '�') {
		t.Errorf("clip: %d bytes", len(got))
	}
}

// TestPutTooLarge: an object larger than MaxObject is refused before any request, as there is no
// multipart upload and one request carries it within the request timeout.
func TestPutTooLarge(t *testing.T) {
	c, err := New(Config{Endpoint: "http://127.0.0.1:9", Region: "us-east-1", Bucket: "bkt", Credentials: testCreds()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(context.Background(), "big", make([]byte, MaxObject+1), PutOptions{}); err == nil {
		t.Fatal("an object over MaxObject was not refused")
	}
}
