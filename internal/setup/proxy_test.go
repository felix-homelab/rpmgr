// SPDX-License-Identifier: Apache-2.0

package setup_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/setup"
)

// connectProxy is an HTTP CONNECT proxy that records the addresses it was asked for.
type connectProxy struct {
	ln   net.Listener
	mu   sync.Mutex
	seen []string
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
	p.seen = append(p.seen, req.Host)
	p.mu.Unlock()
	up, err := net.Dial("tcp", req.Host)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer func() { _ = up.Close() }()
	_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
	go func() { _, _ = io.Copy(up, br) }()
	_, _ = io.Copy(c, up)
}

func (p *connectProxy) asked() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

// TestPlan_EnrollsThroughTheProxy (#557): with --proxy, setup's own enrollment takes the proxy
// the connector's service will take, for the controller and for the trust bundle alike; without
// it, the enrollment keeps the default dialers. The plan never shows the proxy's password.
func TestPlan_EnrollsThroughTheProxy(t *testing.T) {
	proxy := startConnectProxy(t)
	// A proxy is never used for loopback addresses (x/net/http/httpproxy), so the target listens
	// on an address of one of the host's other interfaces.
	ln, err := net.Listen("tcp", net.JoinHostPort(hostAddr(t), "0"))
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "bundle") }))
	_ = target.Listener.Close()
	target.Listener = ln
	target.Start()
	t.Cleanup(target.Close)
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	f := &fakeHost{}
	h := newHost(t, f)
	p, err := setup.New(setup.Values{Role: setup.Connector, ControllerURL: "https://panel.example.com", Pin: pin(t), Token: newToken(t),
		Proxy: "http://ops:s3cret@" + proxy.ln.Addr().String()}, h)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range p.Summary() {
		if strings.Contains(kv[1], "s3cret") {
			t.Errorf("the plan shows the proxy's password: %q", kv)
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
	c, err := o.Dial(context.Background(), targetAddr)
	if err != nil {
		t.Fatalf("dial through the proxy: %v", err)
	}
	_ = c.Close()
	resp, err := o.HTTPClient.Get(target.URL)
	if err != nil {
		t.Fatalf("download through the proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "bundle" {
		t.Fatalf("download: %q", body)
	}
	if got := proxy.asked(); len(got) != 2 || got[0] != targetAddr || got[1] != targetAddr {
		t.Fatalf("the proxy was asked for %v, want the controller and the bundle through it", got)
	}

	// Without --proxy the enrollment keeps its default dialers.
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
		t.Fatal("an enrollment without --proxy got a proxy")
	}
}

// hostAddr is an IPv4 address of one of the host's interfaces other than loopback.
func hostAddr(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	t.Skip("the host has no IPv4 address other than loopback")
	return ""
}

// TestCheckProxy_HidesThePassword (#557): a refused proxy URL is never repeated in the error.
func TestCheckProxy_HidesThePassword(t *testing.T) {
	for _, s := range []string{"https://ops:s3cret@proxy:3128", "ftp://ops:s3cret@proxy:21", `http://ops:s3"cret@proxy:3128`} {
		if err := setup.CheckProxy(s); err == nil || strings.Contains(err.Error(), "s3") {
			t.Errorf("%s: %v", s, err)
		}
	}
	var _ agent.EnrollOptions // the fake host records these
}
