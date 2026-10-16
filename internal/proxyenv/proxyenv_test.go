// SPDX-License-Identifier: Apache-2.0

package proxyenv_test

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/proxyenv"
)

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

// TestRequests_Selection (D93): https:// URLs go through HTTPS_PROXY, else ALL_PROXY; http:// URLs
// through HTTP_PROXY, else ALL_PROXY; the upper-case name wins over the lower-case one; NO_PROXY
// exempts and loopback goes direct; a value without a scheme is an http:// proxy.
func TestRequests_Selection(t *testing.T) {
	const ca, challenge = "https://acme.example/directory", "http://www.example.org/.well-known/rpmgr"
	for _, tc := range []struct {
		name string
		env  map[string]string
		url  string
		want string // the proxy URL, or "" for direct
	}{
		{"none", nil, ca, ""},
		{"ALL_PROXY alone, https", map[string]string{"ALL_PROXY": "socks5://socks:1080"}, ca, "socks5://socks:1080"},
		{"ALL_PROXY alone, http", map[string]string{"ALL_PROXY": "socks5h://socks:1080"}, challenge, "socks5h://socks:1080"},
		{"lower-case all_proxy", map[string]string{"all_proxy": "http://lower:3128"}, ca, "http://lower:3128"},
		{"upper case wins", map[string]string{"all_proxy": "http://lower:3128", "ALL_PROXY": "http://upper:3128"}, ca, "http://upper:3128"},
		{"HTTPS_PROXY wins", map[string]string{"ALL_PROXY": "socks5://socks:1080", "HTTPS_PROXY": "http://proxy:3128"}, ca, "http://proxy:3128"},
		{"ALL_PROXY for http beside HTTPS_PROXY", map[string]string{"ALL_PROXY": "socks5://socks:1080", "HTTPS_PROXY": "http://proxy:3128"}, challenge, "socks5://socks:1080"},
		{"HTTP_PROXY wins", map[string]string{"ALL_PROXY": "socks5://socks:1080", "HTTP_PROXY": "http://plain:3128"}, challenge, "http://plain:3128"},
		{"HTTP_PROXY is not for https", map[string]string{"HTTP_PROXY": "http://plain:3128"}, ca, ""},
		{"an https:// proxy", map[string]string{"HTTPS_PROXY": "https://proxy:8443"}, ca, "https://proxy:8443"},
		{"no scheme", map[string]string{"HTTPS_PROXY": "proxy.lan:3128"}, ca, "http://proxy.lan:3128"},
		{"NO_PROXY", map[string]string{"ALL_PROXY": "socks5://socks:1080", "NO_PROXY": "acme.example"}, ca, ""},
		{"no_proxy domain", map[string]string{"ALL_PROXY": "socks5://socks:1080", "no_proxy": ".example"}, ca, ""},
		{"NO_PROXY other", map[string]string{"ALL_PROXY": "socks5://socks:1080", "NO_PROXY": "other.example"}, ca, "socks5://socks:1080"},
		{"loopback", map[string]string{"ALL_PROXY": "socks5://socks:1080"}, "https://127.0.0.1:14000/dir", ""},
	} {
		use, err := proxyenv.Requests(env(tc.env))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		req, err := http.NewRequest(http.MethodGet, tc.url, nil) //nolint:noctx // never sent
		if err != nil {
			t.Fatal(err)
		}
		got, err := use(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		s := "" // direct
		if got != nil {
			s = got.String()
		}
		if s != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, s, tc.want)
		}
	}
}

// TestRequests_Refuses (D93): a variable that is no proxy URL is an error that names it and never
// repeats its value, which may hold credentials, as is one the caller cannot use.
func TestRequests_Refuses(t *testing.T) {
	for _, name := range []string{"HTTPS_PROXY", "http_proxy", "ALL_PROXY"} {
		for _, bad := range []string{"ftp://ops:s3cret@proxy", "http://ops:s3cret@", "socks4://ops:s3cret@proxy", "%zz:s3cret", "http://[::1:s3cret"} {
			_, err := proxyenv.Requests(env(map[string]string{name: bad}))
			if err == nil || !strings.HasPrefix(err.Error(), name+" is not an http://, https://, socks5:// or socks5h:// URL") ||
				strings.Contains(err.Error(), "s3cret") {
				t.Errorf("%s=%q: %v", name, bad, err)
			}
		}
	}
	// The connector cannot use an https:// proxy.
	_, _, err := proxyenv.For(env(map[string]string{"ALL_PROXY": "https://proxy:8443"}), "https", "http", "socks5", "socks5h")
	if err == nil || err.Error() != "ALL_PROXY is not an http://, socks5:// or socks5h:// URL with a host" {
		t.Errorf("an https:// proxy for the connector: %v", err)
	}
	if _, ok, err := proxyenv.For(env(nil), "https", "http"); ok || err != nil {
		t.Errorf("no proxy: %v %v", ok, err)
	}
}

// TestFromEnvironment: the process's environment, with a value that is no proxy URL, fails every
// request without repeating it. It is the only test that reads the process's environment, which
// FromEnvironment reads once.
func TestFromEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "ftp://ops:s3cret@proxy")
	req, err := http.NewRequest(http.MethodGet, "https://acme.example/", nil) //nolint:noctx // never sent
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proxyenv.FromEnvironment(req); err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("%v", err)
	}
}

// recorder records what a test proxy was asked for.
type recorder struct {
	mu   sync.Mutex
	seen []string // the target, then the credentials
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, s)
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seen)
}

// serveProxy accepts connections on a loopback listener, lets handle answer the proxy protocol and
// name the target, and then connects the client to upstream, whatever the target.
func serveProxy(t *testing.T, upstream string, handle func(c net.Conn, br *bufio.Reader) bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				if !handle(c, br) {
					return
				}
				up, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				go func() { _, _ = io.Copy(up, br) }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

// TestRequests_ThroughProxies (D93): with ALL_PROXY alone, an https:// request goes through an HTTP
// CONNECT proxy and an http:// request through a SOCKS5 proxy, each with its credentials, and the
// TLS inside the tunnel is the server's own.
func TestRequests_ThroughProxies(t *testing.T) {
	answer := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "token") })
	tlsSrv := httptest.NewTLSServer(answer)
	t.Cleanup(tlsSrv.Close)
	plain := httptest.NewServer(answer)
	t.Cleanup(plain.Close)

	var connect, socks recorder
	connectAddr := serveProxy(t, tlsSrv.Listener.Addr().String(), func(c net.Conn, br *bufio.Reader) bool {
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return false
		}
		connect.add(req.Host + " " + req.Header.Get("Proxy-Authorization"))
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		return true
	})
	socksAddr := serveProxy(t, plain.Listener.Addr().String(), func(c net.Conn, br *bufio.Reader) bool {
		read := func(n int) []byte {
			b := make([]byte, n)
			if _, err := io.ReadFull(br, b); err != nil {
				return nil
			}
			return b
		}
		hello := read(2)
		if hello == nil || hello[0] != 5 || !slices.Contains(read(int(hello[1])), 2) {
			_, _ = c.Write([]byte{5, 0xff})
			return false
		}
		_, _ = c.Write([]byte{5, 2})
		auth := read(2)
		if auth == nil {
			return false
		}
		user := read(int(auth[1]))
		pl := read(1)
		if pl == nil {
			return false
		}
		pass := read(int(pl[0]))
		_, _ = c.Write([]byte{1, 0})
		req := read(4)
		if req == nil || req[1] != 1 || req[3] != 3 {
			return false
		}
		host := string(read(int(read(1)[0])))
		port := binary.BigEndian.Uint16(read(2))
		socks.add(net.JoinHostPort(host, strconv.Itoa(int(port))) + " " + string(user) + ":" + string(pass))
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		return true
	})

	get := func(vars map[string]string, u string) string {
		t.Helper()
		use, err := proxyenv.Requests(env(vars))
		if err != nil {
			t.Fatal(err)
		}
		tr := tlsSrv.Client().Transport.(*http.Transport).Clone() //nolint:forcetypeassert // httptest's
		tr.Proxy = use
		tr.TLSClientConfig = &tls.Config{RootCAs: tlsSrv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, //nolint:forcetypeassert // httptest's
			MinVersion: tls.VersionTLS13}
		c := &http.Client{Transport: tr}
		resp, err := c.Get(u) //nolint:noctx // a test request
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	// httptest's certificate is for example.com, which the CONNECT proxy sends to the server.
	if got := get(map[string]string{"ALL_PROXY": "http://ops:pa55@" + connectAddr}, "https://example.com/dir"); got != "token" {
		t.Errorf("through CONNECT: %q", got)
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("ops:pa55"))
	if got := connect.all(); !slices.Equal(got, []string{"example.com:443 " + auth}) {
		t.Errorf("the CONNECT proxy saw %q", got)
	}
	if got := get(map[string]string{"ALL_PROXY": "socks5h://ops:pa55@" + socksAddr}, "http://www.example.org/token"); got != "token" {
		t.Errorf("through SOCKS5: %q", got)
	}
	if got := socks.all(); !slices.Equal(got, []string{"www.example.org:80 ops:pa55"}) {
		t.Errorf("the SOCKS5 proxy saw %q", got)
	}
}
