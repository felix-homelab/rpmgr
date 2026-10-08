// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/connector"
)

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

// TestProxyDialer_Selection: which proxy a gateway address goes through, by environment.
func TestProxyDialer_Selection(t *testing.T) {
	errDirect := errors.New("recorded")
	for _, tc := range []struct {
		name string
		env  map[string]string
		addr string
		want string // the address dialled directly: the proxy's or the gateway's
	}{
		{"none", nil, "gw.example:443", "gw.example:443"},
		{"HTTPS_PROXY", map[string]string{"HTTPS_PROXY": "http://proxy:3128"}, "gw.example:443", "proxy:3128"},
		{"lower case", map[string]string{"https_proxy": "http://lower:3128"}, "gw.example:443", "lower:3128"},
		{"upper case wins", map[string]string{"https_proxy": "http://lower:3128", "HTTPS_PROXY": "http://upper:3128"}, "gw.example:443", "upper:3128"},
		{"http default port", map[string]string{"HTTPS_PROXY": "http://proxy"}, "gw.example:443", "proxy:80"},
		{"ALL_PROXY", map[string]string{"ALL_PROXY": "socks5://socks"}, "gw.example:443", "socks:1080"},
		{"HTTPS_PROXY wins", map[string]string{"ALL_PROXY": "socks5://socks:1080", "HTTPS_PROXY": "http://proxy:3128"}, "gw.example:443", "proxy:3128"},
		{"NO_PROXY", map[string]string{"HTTPS_PROXY": "http://proxy:3128", "NO_PROXY": "gw.example"}, "gw.example:443", "gw.example:443"},
		{"NO_PROXY domain", map[string]string{"HTTPS_PROXY": "http://proxy:3128", "no_proxy": ".example"}, "gw.example:443", "gw.example:443"},
		{"NO_PROXY other", map[string]string{"HTTPS_PROXY": "http://proxy:3128", "NO_PROXY": "other.example"}, "gw.example:443", "proxy:3128"},
		{"loopback", map[string]string{"HTTPS_PROXY": "http://proxy:3128"}, "127.0.0.1:443", "127.0.0.1:443"},
	} {
		var dialled []string
		d, err := connector.NewProxyDialer(env(tc.env), func(_ context.Context, _, addr string) (net.Conn, error) {
			dialled = append(dialled, addr)
			return nil, errDirect
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if _, err := d(context.Background(), tc.addr); !errors.Is(err, errDirect) {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !slices.Equal(dialled, []string{tc.want}) {
			t.Errorf("%s: dialled %v, want %s", tc.name, dialled, tc.want)
		}
	}
	for _, bad := range []string{"https://proxy:443", "ftp://proxy", "http://user:s3cret@", "socks4://proxy", "%zz"} {
		_, err := connector.ProxyDialer(env(map[string]string{"HTTPS_PROXY": bad}))
		if err == nil {
			t.Errorf("%q accepted", bad)
		} else if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("the error repeats the credentials: %v", err)
		}
	}
}

// testProxy is a proxy that sends gw.test to the loopback address.
type testProxy struct {
	addr    string
	mu      sync.Mutex
	targets []string
	refuse  atomic.Bool
}

func (p *testProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.targets)
}

func splice(a, b net.Conn, br io.Reader) {
	go func() {
		_, _ = io.Copy(b, br)
		_ = b.Close()
	}()
	_, _ = io.Copy(a, b)
	_ = a.Close()
}

func loopback(target string) string {
	host, port, _ := net.SplitHostPort(target)
	if host == "gw.test" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func startProxy(t *testing.T, handle func(c net.Conn, br *bufio.Reader) (string, bool)) *testProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	p := &testProxy{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				br := bufio.NewReader(c)
				target, ok := handle(c, br)
				if !ok {
					_ = c.Close()
					return
				}
				p.mu.Lock()
				p.targets = append(p.targets, target)
				p.mu.Unlock()
				up, err := net.Dial("tcp", loopback(target))
				if err != nil {
					_ = c.Close()
					return
				}
				splice(c, up, br)
			}()
		}
	}()
	return p
}

// startCONNECTProxy is an HTTP CONNECT proxy that wants the Basic credentials user and pass.
func startCONNECTProxy(t *testing.T, user, pass string) *testProxy {
	var p *testProxy
	p = startProxy(t, func(c net.Conn, br *bufio.Reader) (string, bool) {
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return "", false
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
		if p.refuse.Load() || req.Header.Get("Proxy-Authorization") != want {
			_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
			return "", false
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		return req.Host, true
	})
	return p
}

// startSOCKS5Proxy is a SOCKS5 proxy (RFC 1928) that wants the credentials user and pass
// (RFC 1929).
func startSOCKS5Proxy(t *testing.T, user, pass string) *testProxy {
	return startProxy(t, func(c net.Conn, br *bufio.Reader) (string, bool) {
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
			return "", false
		}
		_, _ = c.Write([]byte{5, 2})
		auth := read(2)
		if auth == nil {
			return "", false
		}
		u := read(int(auth[1]))
		pl := read(1)
		if pl == nil {
			return "", false
		}
		if pw := read(int(pl[0])); string(u) != user || string(pw) != pass {
			_, _ = c.Write([]byte{1, 1})
			return "", false
		}
		_, _ = c.Write([]byte{1, 0})
		req := read(4)
		if req == nil || req[1] != 1 {
			return "", false
		}
		var host string
		switch req[3] {
		case 1:
			host = net.IP(read(4)).String()
		case 3:
			host = string(read(int(read(1)[0])))
		case 4:
			host = net.IP(read(16)).String()
		}
		port := binary.BigEndian.Uint16(read(2))
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		return net.JoinHostPort(host, strconv.Itoa(int(port))), true
	})
}

// throughProxy runs the world's connector with the proxy in HTTPS_PROXY and checks that it holds
// both TCP connections to a gateway named gw.test through the proxy.
func throughProxy(t *testing.T, proxyURL string, p *testProxy) {
	t.Helper()
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	dial, err := connector.ProxyDialer(env(map[string]string{"HTTPS_PROXY": proxyURL}))
	if err != nil {
		t.Fatal(err)
	}
	m := connector.New(connector.Options{TLS: w.clientTLS, Dial: dial})
	t.Cleanup(m.Close)
	_, port, _ := net.SplitHostPort(g.addr)
	ep := net.JoinHostPort("gw.test", port)
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{ep}, Transports: []string{connector.TransportH2}}})
	eventually(t, "no session through the proxy", func() bool { return g.sessions.Load().Count()["h2"] == 2 })
	if got := p.seen(); !slices.Equal(got, []string{ep, ep}) {
		t.Fatalf("the proxy carried %v, want both connections to %s", got, ep)
	}
}

// TestProxy_CONNECT: the TCP transport through an HTTP CONNECT proxy with credentials; a refusing
// proxy fails the dial without repeating the password.
func TestProxy_CONNECT(t *testing.T) {
	p := startCONNECTProxy(t, "rpmgr", "pa ss")
	throughProxy(t, "http://rpmgr:pa%20ss@"+p.addr, p)

	p.refuse.Store(true)
	dial, _ := connector.ProxyDialer(env(map[string]string{"HTTPS_PROXY": "http://rpmgr:pa%20ss@" + p.addr}))
	_, err := dial(context.Background(), "gw.test:443")
	if err == nil || !strings.Contains(err.Error(), "407") || strings.Contains(err.Error(), "pa ss") || strings.Contains(err.Error(), "pa%20ss") {
		t.Fatalf("a refusing proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dial(ctx, "gw.test:443"); err == nil {
		t.Fatal("a cancelled dial succeeded")
	}
}

// TestProxy_SOCKS5: the TCP transport through a SOCKS5 proxy in ALL_PROXY with credentials; wrong
// credentials fail the dial.
func TestProxy_SOCKS5(t *testing.T) {
	p := startSOCKS5Proxy(t, "rpmgr", "secret")
	throughProxy(t, "socks5h://rpmgr:secret@"+p.addr, p)

	dial, err := connector.ProxyDialer(env(map[string]string{"ALL_PROXY": "socks5://rpmgr:wrong@" + p.addr}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dial(context.Background(), "gw.test:443"); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("wrong SOCKS5 credentials: %v", err)
	}
}
