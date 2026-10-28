// SPDX-License-Identifier: Apache-2.0

package webhook_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

const key = "rpmgr_whs_testtesttesttesttesttesttesttesttest01" //nolint:gosec // G101: a test secret

// receiver is a TLS receiver on loopback; only instance policies (Internal) reach it.
func receiver(t *testing.T, h http.HandlerFunc) (*httptest.Server, *webhook.Sender, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	// The test certificate names example.com, which the lookup resolves to the server.
	s := &webhook.Sender{RootCAs: pool, Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}
	return srv, s, "https://example.com:" + port + "/hook"
}

var internal = egress.Policy{Internal: true}

// TestWebhook_SignatureAndReplayWindow (#648): every delivery carries a valid Rpmgr-Signature
// over its timestamp and body, with the event's ID and type; with a previous secret both sign;
// the documented receiver check refuses a signature past the maximum age, a changed body and a
// wrong secret.
func TestWebhook_SignatureAndReplayWindow(t *testing.T) {
	var got atomic.Pointer[http.Request]
	var body atomic.Pointer[[]byte]
	_, s, u := receiver(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store(r)
		body.Store(&b)
	})
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	e := events.Event{ID: "evt_1", OrgID: "org_1", Type: "route.update", Time: now, ActorType: "user", ActorID: "usr_1",
		SubjectType: "route", SubjectID: "rte_1", SubjectName: "web", Summary: "route.update route web"}
	b, err := webhook.Body(e)
	if err != nil {
		t.Fatal(err)
	}
	old := "rpmgr_whs_oldoldoldoldoldoldoldoldoldoldoldold01" //nolint:gosec // G101: a test secret
	code, err := s.Send(context.Background(), webhook.Delivery{URL: u, EventID: e.ID, EventType: e.Type, Body: b,
		Secrets: []secret.Value{secret.New(key), secret.New(old)}, Policy: internal})
	if err != nil || code != 200 {
		t.Fatalf("send: %d %v", code, err)
	}
	r, rb := got.Load(), *body.Load()
	sig := r.Header.Get(webhook.HeaderSignature)
	if r.Header.Get(webhook.HeaderEventID) != "evt_1" || r.Header.Get(webhook.HeaderEventType) != "route.update" ||
		r.Header.Get("Content-Type") != "application/json" || strings.Count(sig, "v1=") != 2 || !strings.HasPrefix(sig, "t=1793016000,") {
		t.Fatalf("headers %v", r.Header)
	}
	for _, k := range []string{key, old} {
		if err := webhook.Verify(sig, rb, k, now.Add(webhook.MaxAge)); err != nil {
			t.Errorf("secret %s: %v", k[:14], err)
		}
	}
	for name, err := range map[string]error{
		"too old":      webhook.Verify(sig, rb, key, now.Add(webhook.MaxAge+time.Second)),
		"future":       webhook.Verify(sig, rb, key, now.Add(-webhook.MaxAge-time.Second)),
		"other secret": webhook.Verify(sig, rb, "rpmgr_whs_other", now),
		"other body":   webhook.Verify(sig, append([]byte(" "), rb...), key, now),
		"no timestamp": webhook.Verify(strings.SplitN(sig, ",", 2)[1], rb, key, now),
		"garbage":      webhook.Verify("v1=zz", rb, key, now),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// After the rotation period only the new secret signs.
	if one := webhook.Sign(now, rb, key); strings.Count(one, "v1=") != 1 || webhook.Verify(one, rb, old, now) == nil {
		t.Fatal("the old secret still verifies a signature made without it")
	}

	// The envelope is the thin one: no resource body, and an instance event's org is null.
	var env map[string]any
	if err := json.Unmarshal(rb, &env); err != nil {
		t.Fatal(err)
	}
	if len(env) != 8 || env["org_id"] != "org_1" || env["subject"].(map[string]any)["name"] != "web" {
		t.Fatalf("envelope %s", rb)
	}
	inst, _ := webhook.Body(events.Event{ID: "evt_2", Type: "release.create", Time: now, ActorType: "system"})
	if !strings.Contains(string(inst), `"org_id":null`) || !strings.Contains(string(inst), `"changed":[]`) {
		t.Fatalf("instance envelope %s", inst)
	}
}

// TestWebhook_EgressGuard (#648): a delivery never connects to a loopback, unspecified,
// link-local, metadata, multicast or own address, in IPv4-mapped form too, nor to one a name
// resolves to at the moment of the delivery, whatever it resolved to before; it follows no
// redirect and sends nothing to an http:// URL. Through a proxy it asks for the checked address.
func TestWebhook_EgressGuard(t *testing.T) {
	var hits atomic.Int32
	srv, s, u := receiver(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "https://example.com/elsewhere", http.StatusFound)
	})
	org := egress.Policy{Private: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Own: []netip.Addr{netip.MustParseAddr("8.8.4.4")}}
	ctx := context.Background()
	send := func(s *webhook.Sender, rawURL string, p egress.Policy) error {
		_, err := s.Send(ctx, webhook.Delivery{URL: rawURL, EventID: "evt_1", EventType: "x", Body: []byte("{}"), Secrets: []secret.Value{secret.New(key)}, Policy: p})
		return err
	}
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	for _, host := range []string{"127.0.0.1", "[::1]", "[::ffff:127.0.0.1]", "0.0.0.0", "169.254.169.254", "[fe80::1]", "224.0.0.1",
		"100.100.100.200", "8.8.4.4"} {
		err := send(&webhook.Sender{}, "https://"+host+":"+port+"/", org)
		var re *egress.RefusedError
		if !errors.Is(err, webhook.ErrNotDelivered) || !errors.As(err, &re) {
			t.Errorf("%s: %v, want refused by the guard", host, err)
		}
	}
	// DNS rebinding: the name resolved to a public address before, to loopback now.
	var lookups atomic.Int32
	rebind := &webhook.Sender{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}
	_, _ = rebind.Lookup(ctx, "example.com") // what an earlier check saw
	var re *egress.RefusedError
	if err := send(rebind, u, org); !errors.As(err, &re) {
		t.Fatalf("rebinding: %v, want refused", err)
	}
	// A private receiver: refused, naming its range, until its range is listed.
	private := &webhook.Sender{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.7.7")}, nil
	}}
	if err := send(private, "https://nas.home.arpa/", org); !errors.As(err, &re) || re.Range.String() != "192.168.0.0/16" {
		t.Fatalf("private: %v", err)
	}
	for _, bad := range []string{"http://example.com/", "ftp://example.com/", "https://user:pw@example.com/", "https:///x", "://"} {
		if err := send(s, bad, internal); !errors.Is(err, webhook.ErrNotDelivered) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("a refused delivery reached the receiver")
	}
	// A redirect is an answer that is no success, and is not followed.
	code, err := s.Send(ctx, webhook.Delivery{URL: u, EventID: "evt_1", Body: []byte("{}"), Secrets: []secret.Value{secret.New(key)}, Policy: internal})
	if code != http.StatusFound || !errors.Is(err, webhook.ErrNotDelivered) || hits.Load() != 1 {
		t.Fatalf("redirect: %d %v, %d requests", code, err, hits.Load())
	}
	// Too large a body is not sent.
	if _, err := s.Send(ctx, webhook.Delivery{URL: u, Body: make([]byte, webhook.MaxBody+1), Policy: internal}); !errors.Is(err, webhook.ErrNotDelivered) ||
		hits.Load() != 1 {
		t.Fatalf("oversized: %v", err)
	}

	// Through a proxy, the proxy is asked for the checked address and never sees a refused one.
	var asked atomic.Value
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Store(r.Host)
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		up, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		conn, rw, _ := w.(http.Hijacker).Hijack()
		_, _ = rw.WriteString("HTTP/1.1 200 OK\r\n\r\n")
		_ = rw.Flush()
		go func() { _, _ = io.Copy(up, conn) }()
		_, _ = io.Copy(conn, bufio.NewReader(up))
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	via := *s
	via.Proxy = func(*http.Request) (*url.URL, error) { return pu, nil }
	via.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if code, err := via.Send(ctx, webhook.Delivery{URL: u, EventID: "evt_1", Body: []byte("{}"), Secrets: []secret.Value{secret.New(key)}, Policy: internal}); code != http.StatusFound ||
		asked.Load() != "127.0.0.1:"+port {
		t.Fatalf("via proxy: %d %v, proxy asked for %v", code, err, asked.Load())
	}
	asked.Store("")
	if err := send(&via, u, org); !errors.As(err, &re) || asked.Load() != "" {
		t.Fatalf("via proxy, refused address: %v, proxy asked for %v", err, asked.Load())
	}
	socks := via
	socks.Proxy = func(*http.Request) (*url.URL, error) { return url.Parse("socks5://127.0.0.1:1") }
	if err := send(&socks, u, internal); err == nil || !strings.Contains(err.Error(), "http:// and https:// proxies") {
		t.Fatalf("socks proxy: %v", err)
	}
}

// TestWebhook_Timeout (#648): a receiver that does not answer within the timeout is a failure,
// and so is one that answers 5xx; at most MaxAnswer bytes of an answer are read.
func TestWebhook_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the delivery timeout")
	}
	release := make(chan struct{})
	_, s, u := receiver(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("do") {
		case "hang":
			<-release
		case "fail":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "big":
			_, _ = w.Write(make([]byte, 10*webhook.MaxAnswer))
		}
	})
	defer close(release)
	ctx := context.Background()
	start := time.Now()
	if _, err := s.Send(ctx, webhook.Delivery{URL: u + "?do=hang", Body: []byte("{}"), Policy: internal}); !errors.Is(err, webhook.ErrNotDelivered) {
		t.Fatalf("hang: %v", err)
	}
	if d := time.Since(start); d < webhook.Timeout || d > webhook.Timeout+3*time.Second {
		t.Fatalf("gave up after %s, want %s", d, webhook.Timeout)
	}
	if code, err := s.Send(ctx, webhook.Delivery{URL: u + "?do=fail", Body: []byte("{}"), Policy: internal}); code != 503 || err == nil {
		t.Fatalf("5xx: %d %v", code, err)
	}
	if code, err := s.Send(ctx, webhook.Delivery{URL: u + "?do=big", Body: []byte("{}"), Policy: internal}); code != 200 || err != nil {
		t.Fatalf("big answer: %d %v", code, err)
	}
}
