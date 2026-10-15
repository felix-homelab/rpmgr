// SPDX-License-Identifier: Apache-2.0

package setup_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/setup"
)

// testProxy is a proxy URL with a made-up password.
const testProxy = "http://ops:s3cret@proxy.lan:3128" //nolint:gosec // G101: a made-up test password

// connectProxy is an HTTP CONNECT proxy that records what it was asked for and with which
// credentials, and plays the server behind every tunnel itself: an HTTP request in the tunnel gets
// "bundle". So the tests need no reachable server, and the addresses they ask for need not be
// loopback, which a proxy is never used for (x/net/http/httpproxy).
type connectProxy struct {
	ln   net.Listener
	mu   sync.Mutex
	seen []string // host:port, then the Proxy-Authorization header
}

func startConnectProxy(t *testing.T) *connectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &connectProxy{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *connectProxy) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	p.mu.Lock()
	p.seen = append(p.seen, req.Host+" "+req.Header.Get("Proxy-Authorization"))
	p.mu.Unlock()
	_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
	if _, err := http.ReadRequest(br); err != nil {
		return
	}
	_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nbundle")
}

func (p *connectProxy) asked() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

// TestPlan_EnrollsThroughTheProxy (#557): with a proxy, setup's own enrollment takes the proxy
// the connector's service will take, with its credentials, for the controller and for the trust
// bundle alike, and the bundle's download keeps a time limit; without it, the enrollment keeps the
// default dialers. The plan shows neither the proxy's password nor its user name.
func TestPlan_EnrollsThroughTheProxy(t *testing.T) {
	proxy := startConnectProxy(t)
	const target = "192.0.2.1:443" // TEST-NET-1: never dialled, the proxy answers
	f := &fakeHost{}
	h := newHost(t, f)
	p, err := setup.New(setup.Values{Role: setup.Connector, ControllerURL: "https://panel.example.com", Pin: pin(t), Token: newToken(t),
		Proxy: "http://ops:s3cret@" + proxy.ln.Addr().String()}, h)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range p.Summary() {
		if strings.Contains(kv[1], "s3cret") || strings.Contains(kv[1], "ops") {
			t.Errorf("the plan shows the proxy's credentials: %q", kv)
		}
	}
	if r, err := p.Run(context.Background(), nil); err != nil {
		t.Fatalf("run: %v (wrote %v)", err, r.Written)
	}
	f.mu.Lock()
	o := f.enrolled[0]
	f.mu.Unlock()
	if o.Dial == nil || o.HTTPClient == nil {
		t.Fatal("the enrollment does not take the proxy")
	}
	if o.HTTPClient.Timeout <= 0 {
		t.Error("the bundle's download through the proxy has no time limit")
	}
	c, err := o.Dial(context.Background(), target)
	if err != nil {
		t.Fatalf("dial through the proxy: %v", err)
	}
	_ = c.Close()
	resp, err := o.HTTPClient.Get("http://" + target + "/bundle")
	if err != nil {
		t.Fatalf("download through the proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "bundle" {
		t.Fatalf("download: %q", body)
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("ops:s3cret"))
	if got := proxy.asked(); len(got) != 2 || got[0] != target+" "+auth || got[1] != target+" "+auth {
		t.Fatalf("the proxy was asked for %q, want the controller and the bundle through it, with the credentials", got)
	}

	// Without a proxy the enrollment keeps its default dialers.
	f2 := &fakeHost{}
	h2 := newHost(t, f2)
	p2, err := setup.New(setup.Values{Role: setup.Connector, ControllerURL: "https://panel.example.com", Pin: pin(t), Token: newToken(t)}, h2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.Run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if o := f2.enrolled[0]; o.Dial != nil || o.HTTPClient != nil {
		t.Fatal("an enrollment without a proxy got a proxy")
	}
}

// TestPlan_ProxyFileReplaced (#557): setup replaces an existing environment file, never writes the
// password into a file with a wider mode, and replaces a symbolic link in its place rather than
// writing through it.
func TestPlan_ProxyFileReplaced(t *testing.T) {
	for _, link := range []bool{false, true} {
		f := &fakeHost{}
		h := newHost(t, f)
		if err := os.MkdirAll(h.Paths.Etc, 0o755); err != nil { //nolint:gosec // G301: as setup makes it
			t.Fatal(err)
		}
		envFile := filepath.Join(h.Paths.Etc, "connector-proxy.env")
		decoy := filepath.Join(t.TempDir(), "decoy")
		if err := os.WriteFile(decoy, []byte("old\n"), 0o644); err != nil { //nolint:gosec // G306: a file anyone reads, on purpose
			t.Fatal(err)
		}
		if link {
			if err := os.Symlink(decoy, envFile); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(envFile, []byte("HTTPS_PROXY=http://proxy.lan:3128\n"), 0o644); err != nil { //nolint:gosec // G306: as an operator may have made it
			t.Fatal(err)
		}
		p, err := setup.New(setup.Values{Role: setup.Connector, ControllerURL: "https://panel.example.com", Pin: pin(t), Token: newToken(t),
			Proxy: testProxy}, h)
		if err != nil {
			t.Fatal(err)
		}
		if r, err := p.Run(context.Background(), nil); err != nil {
			t.Fatalf("link %v: run: %v (wrote %v)", link, err, r.Written)
		}
		fi, err := os.Lstat(envFile)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Errorf("link %v: %s: %v %v", link, envFile, fi, err)
		}
		if b, err := os.ReadFile(envFile); err != nil || string(b) != "HTTPS_PROXY="+testProxy+"\n" { //nolint:gosec // G304: the test's own file
			t.Errorf("link %v: %q %v", link, b, err)
		}
		if b, err := os.ReadFile(decoy); err != nil || string(b) != "old\n" { //nolint:gosec // G304: the test's own file
			t.Errorf("link %v: the link's target became %q %v", link, b, err)
		}
	}
}

// TestCheckProxy_Refuses (#557): what the connector cannot use, and what systemd's environment file
// would read differently, is refused with the reason, and the error never repeats the URL.
func TestCheckProxy_Refuses(t *testing.T) {
	const encode, notURL = "percent-encode", "not an http://"
	for s, want := range map[string]string{
		"https://ops:s3cret@proxy:3128": notURL,
		"ftp://ops:s3cret@proxy:21":     notURL,
		"http://":                       notURL,
		`http://ops:s3"cret@proxy:3128`: encode,
		`http://ops:s3'cret@proxy:3128`: encode,
		`http://ops:s3\cret@proxy:3128`: encode,
		"http://ops:s3 cret@proxy:3128": encode,
		"http://ops:s3cret@proxy:3128 ": encode, // systemd would strip it
		"http://ops:s3\tcret@proxy:31":  encode,
		"http://ops:s3cret@prøxy:3128":  encode, // not ASCII
		"http://ops:s3cret@proxy\xff:1": encode, // not UTF-8, which systemd refuses
		"http://proxy:3128/a b":         encode,
	} {
		err := setup.CheckProxy(s)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "s3") {
			t.Errorf("%q: %v, want %q", s, err, want)
		}
	}
}

// TestReadProxyFile (#557): --proxy-file's URL is read without its line end, a file other users
// may read draws a warning, and a missing file is an error that names no content.
func TestReadProxyFile(t *testing.T) {
	d := t.TempDir()
	private, open := filepath.Join(d, "private"), filepath.Join(d, "open")
	if err := os.WriteFile(private, []byte(testProxy+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(open, []byte(" socks5h://proxy:1080 \n"), 0o644); err != nil { //nolint:gosec // G306: a file other users may read, on purpose
		t.Fatal(err)
	}
	var warned []string
	warn := func(w string) { warned = append(warned, w) }
	if got, err := setup.ReadProxyFile(private, warn); err != nil || got != testProxy || len(warned) != 0 {
		t.Errorf("private: %q %v %q", got, err, warned)
	}
	if got, err := setup.ReadProxyFile(open, warn); err != nil || got != "socks5h://proxy:1080" || len(warned) != 1 || !strings.Contains(warned[0], "0644") {
		t.Errorf("open: %q %v %q", got, err, warned)
	}
	if _, err := setup.ReadProxyFile(filepath.Join(d, "none"), nil); err == nil {
		t.Error("a missing file: no error")
	}
	if !setup.ProxyHasCredentials(testProxy) || !setup.ProxyHasCredentials("http://token@proxy:3128") ||
		setup.ProxyHasCredentials("http://proxy:3128") || setup.ProxyHasCredentials("") {
		t.Error("ProxyHasCredentials")
	}
}
