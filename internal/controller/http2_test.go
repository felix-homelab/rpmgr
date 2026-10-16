// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/acme/acmetest"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/controller"
)

// onlyHTTP returns a client that trusts roots, offers only HTTP/major, 1 or 2, and fails every
// answer of another version, so a request that succeeds used that one: a Transport that offers
// only h2 still speaks HTTP/1.1 when the server negotiates no ALPN. With addr set it connects there
// whatever the URL's host, and with sni set it sends that server name whatever the URL's host.
func onlyHTTP(major int, roots *x509.CertPool, addr, sni string) *http.Client {
	p := new(http.Protocols)
	p.SetHTTP1(major == 1)
	p.SetHTTP2(major == 2)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: sni}, Protocols: p}
	if addr != "" {
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: versionCheck{major: major, next: tr}}
}

// versionCheck fails every response that is not of HTTP/major.
type versionCheck struct {
	major int
	next  http.RoundTripper
}

func (v versionCheck) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := v.next.RoundTrip(req)
	if err == nil && resp.ProtoMajor != v.major {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("answered over %s, want HTTP/%d", resp.Proto, v.major)
	}
	return resp, err
}

// TestRun_HTTP2 (#559, D92): the public listener offers HTTP/2 before HTTP/1.1. Over HTTP/2 a
// Connect, a gRPC-Web and a grpc-go client call the public API, the last only with a valid token;
// over HTTP/1.1 Connect and gRPC-Web clients still do. The UI keeps its CSP and HSTS, and the API
// its cross-origin and content-type checks, over HTTP/2. ALPN picks h2, http/1.1, http/1.0 or
// none as the client offers, and an HTTP/1.0 client, such as curl --http1.0, gets its answer; a
// client that offers only protocols the controller does not speak, acme-tls/1 without ACME among
// them, gets no handshake.
func TestRun_HTTP2(t *testing.T) {
	var link string
	r := startRunWith(t, runSetup{prepare: func(r *running) { link = r.firstUserLink }})
	ctx := context.Background()
	h1, h2 := onlyHTTP(1, r.ca.pool, "", ""), onlyHTTP(2, r.ca.pool, "", "")

	// The first user is set up, signs in and makes a token, all over HTTP/2 with Connect.
	_, setup, _ := strings.Cut(link, "#")
	const pw = "correct horse battery staple"
	if _, err := rpmgrv1connect.NewAuthServiceClient(h2, r.url).CompletePasswordReset(ctx, connect.NewRequest(
		&rpmgrv1.CompletePasswordResetRequest{Token: setup, NewPassword: pw, Email: "ada@example.com", DisplayName: "Ada"})); err != nil {
		t.Fatalf("a public method over HTTP/2: %v", err)
	}
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Transport: h2.Transport, Timeout: 10 * time.Second}
	auth := rpmgrv1connect.NewAuthServiceClient(browser, r.url)
	if _, err := auth.Login(ctx, connect.NewRequest(&rpmgrv1.LoginRequest{Email: "ada@example.com", Password: pw})); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.StepUp(ctx, connect.NewRequest(&rpmgrv1.StepUpRequest{Password: pw})); err != nil {
		t.Fatal(err)
	}
	session, err := auth.GetSession(ctx, connect.NewRequest(&rpmgrv1.GetSessionRequest{}))
	if err != nil {
		t.Fatalf("a session cookie over HTTP/2: %v", err)
	}
	org := session.Msg.GetMemberships()[0].GetOrgId()
	created, err := rpmgrv1connect.NewTokenServiceClient(browser, r.url).CreateAPIToken(ctx, connect.NewRequest(
		&rpmgrv1.CreateAPITokenRequest{OrgId: org, Name: "h2", Scopes: []string{authz.PermOrgRead}}))
	if err != nil {
		t.Fatal(err)
	}
	bearer := "Bearer " + created.Msg.GetToken()

	// Connect and gRPC-Web over either version; connect-go's gRPC client works over HTTP/1.1 too,
	// so the gRPC protocol is checked with grpc-go below, which insists on h2.
	for _, c := range []struct {
		name   string
		client *http.Client
		opts   []connect.ClientOption
	}{
		{"Connect over HTTP/2", h2, nil},
		{"Connect JSON over HTTP/2", h2, []connect.ClientOption{connect.WithProtoJSON()}},
		{"gRPC-Web over HTTP/2", h2, []connect.ClientOption{connect.WithGRPCWeb()}},
		{"Connect over HTTP/1.1", h1, nil},
		{"gRPC-Web over HTTP/1.1", h1, []connect.ClientOption{connect.WithGRPCWeb()}},
	} {
		req := connect.NewRequest(&rpmgrv1.GetOrgRequest{OrgId: org})
		req.Header().Set("Authorization", bearer)
		got, err := rpmgrv1connect.NewOrgServiceClient(c.client, r.url, c.opts...).GetOrg(ctx, req)
		if err != nil || got.Msg.GetOrg().GetId() != org {
			t.Errorf("%s: %v %v", c.name, got, err)
		}
	}

	// grpc-go, a plain gRPC client: it needs ALPN h2.
	cc, err := grpc.NewClient("passthrough:///"+r.https,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: r.ca.pool, MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	grpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out rpmgrv1.GetOrgResponse
	err = cc.Invoke(metadata.AppendToOutgoingContext(grpcCtx, "authorization", bearer), rpmgrv1connect.OrgServiceGetOrgProcedure,
		&rpmgrv1.GetOrgRequest{OrgId: org}, &out)
	if err != nil || out.GetOrg().GetId() != org {
		t.Fatalf("grpc-go: %v %v", &out, err)
	}
	for name, md := range map[string][]string{"no token": nil, "a wrong token": {"authorization", "Bearer rpmgr_pat_wrong"}} {
		err := cc.Invoke(metadata.AppendToOutgoingContext(grpcCtx, md...), rpmgrv1connect.OrgServiceGetOrgProcedure,
			&rpmgrv1.GetOrgRequest{OrgId: org}, &out)
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("grpc-go with %s: %v", name, err)
		}
	}

	// The UI's headers and the API's request checks over HTTP/2.
	resp, err := h2.Get(r.url + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		resp.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatalf("the UI over HTTP/2: %s %s %v", resp.Proto, resp.Status, resp.Header)
	}
	post := func(header ...string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, r.url+rpmgrv1connect.OrgServiceGetOrgProcedure, strings.NewReader(`{"orgId":"`+org+`"}`))
		req.Header.Set("Authorization", bearer)
		for i := 0; i+1 < len(header); i += 2 {
			req.Header.Set(header[i], header[i+1])
		}
		resp, err := h2.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("answered over %s", resp.Proto)
		}
		return resp.StatusCode
	}
	for name, c := range map[string]struct {
		header []string
		want   int
	}{
		"same origin":       {[]string{"Content-Type", "application/json", "Sec-Fetch-Site", "same-origin"}, http.StatusOK},
		"cross-site":        {[]string{"Content-Type", "application/json", "Sec-Fetch-Site", "cross-site"}, http.StatusForbidden},
		"a foreign origin":  {[]string{"Content-Type", "application/json", "Origin", "https://evil.example"}, http.StatusForbidden},
		"a form's type":     {[]string{"Content-Type", "text/plain"}, http.StatusUnsupportedMediaType},
		"no content type":   {nil, http.StatusUnsupportedMediaType},
		"a form, same-site": {[]string{"Content-Type", "application/x-www-form-urlencoded", "Sec-Fetch-Site", "same-origin"}, http.StatusUnsupportedMediaType},
	} {
		if got := post(c.header...); got != c.want {
			t.Errorf("POST over HTTP/2, %s: %d, want %d", name, got, c.want)
		}
	}

	// ALPN as the client offers it; no ALPN at all is HTTP/1.1.
	for _, c := range []struct {
		offer []string
		want  string // "" with ok: no ALPN negotiated
		ok    bool
	}{
		{[]string{"h2", "http/1.1"}, "h2", true},
		{[]string{"http/1.1", "h2"}, "h2", true}, // the server's preference
		{[]string{"http/1.1"}, "http/1.1", true},
		{[]string{"http/1.0"}, "http/1.0", true},
		{[]string{"http/1.0", "http/1.1"}, "http/1.1", true},
		{nil, "", true},
		{[]string{"acme-tls/1"}, "", false}, // certificate files: no ACME, so no TLS-ALPN-01
		{[]string{"spdy/3.1"}, "", false},
	} {
		conn, err := tls.Dial("tcp", r.https, &tls.Config{RootCAs: r.ca.pool, MinVersion: tls.VersionTLS13, NextProtos: c.offer})
		if !c.ok {
			if err == nil {
				_ = conn.Close()
				t.Errorf("offering %q: a handshake, ALPN %q", c.offer, conn.ConnectionState().NegotiatedProtocol)
			}
			continue
		}
		if err != nil {
			t.Errorf("offering %q: %v", c.offer, err)
			continue
		}
		if got := conn.ConnectionState().NegotiatedProtocol; got != c.want {
			t.Errorf("offering %q: ALPN %q, want %q", c.offer, got, c.want)
		}
		_ = conn.Close()
	}
	plain := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := tls.Dialer{Config: &tls.Config{RootCAs: r.ca.pool, MinVersion: tls.VersionTLS13}} // no NextProtos
			return d.DialContext(ctx, network, addr)
		}}}
	resp, err = plain.Get(r.url + "/.well-known/rpmgr/trust-bundle")
	if err != nil {
		t.Fatalf("a client without ALPN: %v", err)
	}
	_ = resp.Body.Close()
	if resp.ProtoMajor != 1 || resp.StatusCode != http.StatusOK {
		t.Fatalf("a client without ALPN: %s %s", resp.Proto, resp.Status)
	}
	conn, err := tls.Dial("tcp", r.https, &tls.Config{RootCAs: r.ca.pool, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.0"}})
	if err != nil {
		t.Fatalf("an HTTP/1.0 client: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /.well-known/rpmgr/trust-bundle HTTP/1.0\r\nHost: %s\r\n\r\n", r.https); err != nil {
		t.Fatal(err)
	}
	resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("an HTTP/1.0 client: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Fatalf("an HTTP/1.0 client: %s %q", resp.Status, body)
	}

	// The server's first SETTINGS limit the requests open at once on an HTTP/2 connection.
	h2conn, err := tls.Dial("tcp", r.https, &tls.Config{RootCAs: r.ca.pool, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h2conn.Close() }()
	_ = h2conn.SetDeadline(time.Now().Add(10 * time.Second))
	fr := http2.NewFramer(h2conn, h2conn)
	if _, err := io.WriteString(h2conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	settings, ok := f.(*http2.SettingsFrame)
	if !ok {
		t.Fatalf("the server's first frame: %v", f)
	}
	if v, ok := settings.Value(http2.SettingMaxConcurrentStreams); !ok || v != controller.WebMaxStreams {
		t.Fatalf("SETTINGS_MAX_CONCURRENT_STREAMS %d (%v), want %d", v, ok, controller.WebMaxStreams)
	}
}

// TestRun_Misdirected (D92): a request whose Host names another host than the server name of its
// connection gets 421 on every path of the web server, so a browser that reuses an HTTP/2
// connection for another name the certificate covers asks again on a connection of its own; over
// HTTP/1.1 the connection closes after it. The connection's own name, in any case, with a final dot
// or another port, is served over HTTP/2 and HTTP/1.1. A connection without a server name, as to an
// IP address, has no name to differ from and is served whatever its Host.
func TestRun_Misdirected(t *testing.T) {
	r := startRunWith(t, runSetup{prepare: func(r *running) {
		r.ca.issue(t, r.certFile, r.keyFile, "names", "panel.example.test", "*.example.test")
	}})
	_, port, _ := net.SplitHostPort(r.https)
	paths := []string{"/", "/routes/rt_1", "/.well-known/rpmgr/trust-bundle", "/install.sh", "/dl/0.1.0/manifest.json"}
	// answer is what a request got; the body is read and closed.
	type answer struct {
		status int
		header http.Header
		close  bool
	}
	do := func(c *http.Client, method, url, host string) answer {
		t.Helper()
		var body io.Reader
		if method == http.MethodPost {
			body = strings.NewReader("{}")
		}
		req, _ := http.NewRequest(method, url, body)
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		if host != "" {
			req.Host = host
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s %s (Host %q): %v", method, url, host, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return answer{status: resp.StatusCode, header: resp.Header, close: resp.Close}
	}
	api := rpmgrv1connect.AuthServiceGetSessionProcedure

	for _, major := range []int{2, 1} {
		named := onlyHTTP(major, r.ca.pool, r.https, "panel.example.test")
		// Another name the certificate covers, on the controller's connection.
		for _, path := range paths {
			got := do(named, http.MethodGet, "https://other.example.test:"+port+path, "")
			if got.status != http.StatusMisdirectedRequest || got.header.Get("Content-Security-Policy") != "" ||
				got.header.Get("Strict-Transport-Security") != "" {
				t.Errorf("HTTP/%d, another name, %s: %d %v", major, path, got.status, got.header)
			}
			if major == 1 && !got.close {
				t.Errorf("HTTP/1.1, another name, %s: the connection stays open", path)
			}
		}
		if got := do(named, http.MethodPost, "https://other.example.test:"+port+api, ""); got.status != http.StatusMisdirectedRequest {
			t.Errorf("HTTP/%d, another name, the API: %d", major, got.status)
		}
		// The connection's own name, however written.
		for _, host := range []string{"panel.example.test:" + port, "PANEL.Example.TEST.:" + port, "panel.example.test", "panel.example.test:8443"} {
			for _, path := range paths[:3] {
				if got := do(named, http.MethodGet, "https://panel.example.test:"+port+path, host); got.status != http.StatusOK {
					t.Errorf("HTTP/%d, Host %q, %s: %d", major, host, path, got.status)
				}
			}
			// The API answers; unauthenticated is its own answer, not the guard's.
			if got := do(named, http.MethodPost, "https://panel.example.test:"+port+api, host); got.status != http.StatusUnauthorized {
				t.Errorf("HTTP/%d, Host %q, the API: %d", major, host, got.status)
			}
		}
		// No server name: by IP address, whatever the Host says.
		byIP := onlyHTTP(major, r.ca.pool, "", "")
		for _, host := range []string{"", "other.example.test", "panel.example.test"} {
			if got := do(byIP, http.MethodGet, r.url+"/.well-known/rpmgr/trust-bundle", host); got.status != http.StatusOK {
				t.Errorf("HTTP/%d without a server name, Host %q: %d", major, host, got.status)
			}
		}
	}
}

// TestRun_HTTP2_TLSALPN01 (D92): the listener that offers h2 first still answers the controller's
// own TLS-ALPN-01 challenge. A controller without port 80, so HTTP-01 is not offered, and whose CA
// cannot reach a port 80 anyway, obtains its certificate on port 443 and then serves it over
// HTTP/2 and HTTP/1.1, with HSTS. Without a pending challenge, a ClientHello that offers only
// acme-tls/1 gets no handshake, and one that offers h2 too gets h2 and the ACME certificate.
func TestRun_HTTP2_TLSALPN01(t *testing.T) {
	dns, err := acmetest.StartDNS([]string{"example.com"}, func(string) []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dns.Close)
	https, nothing := freeAddr(t), freeAddr(t)
	pebble, err := acmetest.Start(acmetest.Options{HTTPPort: portOf(nothing), TLSPort: portOf(https), Resolver: dns.Addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pebble.Close)
	r := startRunWith(t, runSetup{host: "panel.example.com", https: https, noHTTP: true, acmeRoots: pebble.ServerRoots,
		prepare: func(r *running) { setACMEDirectory(t, r, pebble.DirectoryURL) }})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	roots, err := pebble.IssuanceRoots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, major := range []int{2, 1} {
		client := onlyHTTP(major, roots, https, "")
		var (
			resp *http.Response
			err  error
		)
		for deadline := time.Now().Add(time.Minute); ; time.Sleep(100 * time.Millisecond) {
			if resp, err = client.Get(r.url + "/.well-known/rpmgr/trust-bundle"); err == nil || time.Now().After(deadline) {
				break
			}
		}
		if err != nil {
			t.Fatalf("HTTP/%d with the ACME certificate: %v", major, err)
		}
		_ = resp.Body.Close()
		if resp.ProtoMajor != major || resp.StatusCode != http.StatusOK || resp.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
			t.Fatalf("HTTP/%d with the ACME certificate: %s %s %v", major, resp.Proto, resp.Status, resp.Header)
		}
	}

	// No challenge is pending now. A ClientHello that offers only acme-tls/1 is a CA's: it gets no
	// handshake, so no HTTP either. One that offers h2 as well is a client's like any other: it gets
	// h2 with the ACME certificate.
	dial := func(protos ...string) (*tls.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", https,
			&tls.Config{ServerName: "panel.example.com", RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: protos})
	}
	var unverified *tls.CertificateVerificationError
	if c, err := dial("acme-tls/1"); err == nil {
		_ = c.Close()
		t.Errorf("acme-tls/1 alone without a challenge: a handshake, ALPN %q", c.ConnectionState().NegotiatedProtocol)
	} else if errors.As(err, &unverified) {
		t.Errorf("acme-tls/1 alone without a challenge: a certificate for %v", unverified.UnverifiedCertificates[0].DNSNames)
	}
	c, err := dial("acme-tls/1", "h2")
	if err != nil {
		t.Fatalf("acme-tls/1 and h2: %v", err)
	}
	_ = c.Close()
	if got := c.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("acme-tls/1 and h2: ALPN %q", got)
	}
}
