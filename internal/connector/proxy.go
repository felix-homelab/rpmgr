// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/proxy"
)

// ProxyDialer returns the dial function for the TCP transport (Options.Dial): through the proxy
// that HTTPS_PROXY, or else ALL_PROXY, names, unless NO_PROXY excludes the gateway, and directly
// otherwise (docs/03-connections.md, "Transports and fallback"). A proxy is an http:// URL (HTTP
// CONNECT) or a socks5:// or socks5h:// URL, with optional credentials. Each variable is also
// read in lower case, which the upper case one overrides.
func ProxyDialer(getenv func(string) string) (func(ctx context.Context, addr string) (net.Conn, error), error) {
	d := &net.Dialer{KeepAlive: tcpKeepAlive}
	return newProxyDialer(getenv, d.DialContext)
}

// direct dials a TCP connection without a proxy.
type direct func(ctx context.Context, network, addr string) (net.Conn, error)

func (d direct) Dial(network, addr string) (net.Conn, error) {
	return d(context.Background(), network, addr)
}

func (d direct) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d(ctx, network, addr)
}

func newProxyDialer(getenv func(string) string, dial direct) (func(ctx context.Context, addr string) (net.Conn, error), error) {
	env := func(name string) (string, string) {
		for _, n := range []string{name, strings.ToLower(name)} {
			if v := getenv(n); v != "" {
				return n, v
			}
		}
		return "", ""
	}
	name, raw := env("HTTPS_PROXY")
	if raw == "" {
		name, raw = env("ALL_PROXY")
	}
	if raw == "" {
		return func(ctx context.Context, addr string) (net.Conn, error) { return dial(ctx, "tcp", addr) }, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "socks5" && u.Scheme != "socks5h") {
		// The value may hold credentials: it is never repeated.
		return nil, fmt.Errorf("connector: %s is not an http://, socks5:// or socks5h:// URL with a host", name)
	}
	_, noProxy := env("NO_PROXY")
	use := (&httpproxy.Config{HTTPSProxy: u.String(), NoProxy: noProxy}).ProxyFunc()
	return func(ctx context.Context, addr string) (net.Conn, error) {
		p, err := use(&url.URL{Scheme: "https", Host: addr})
		switch {
		case err != nil:
			return nil, err
		case p == nil:
			return dial(ctx, "tcp", addr)
		case u.Scheme == "http":
			return connectHTTP(ctx, dial, u, addr)
		}
		return connectSOCKS5(ctx, dial, u, addr)
	}, nil
}

// proxyAddr is the proxy's host:port, with the scheme's default port.
func proxyAddr(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "http" {
		return net.JoinHostPort(u.Hostname(), "80")
	}
	return net.JoinHostPort(u.Hostname(), "1080")
}

// connectHTTP opens a tunnel to addr with HTTP CONNECT.
func connectHTTP(ctx context.Context, dial direct, u *url.URL, addr string) (net.Conn, error) {
	c, err := dial(ctx, "tcp", proxyAddr(u))
	if err != nil {
		return nil, fmt.Errorf("connector: the proxy %s: %w", u.Redacted(), err)
	}
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr,
		Header: http.Header{"User-Agent": {"rpmgr"}}}
	if u.User != nil {
		pw, _ := u.User.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pw)))
	}
	br := bufio.NewReader(c)
	err = req.Write(c)
	var resp *http.Response
	if err == nil {
		resp, err = http.ReadResponse(br, req)
	}
	if !stop() {
		err = errors.Join(ctx.Err(), err)
	}
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("the proxy answered %s", resp.Status)
		}
	}
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("connector: CONNECT %s through %s: %w", addr, u.Redacted(), err)
	}
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: c, r: br}, nil
	}
	return c, nil
}

// bufferedConn returns the bytes a proxy sent after its answer before the connection's.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// connectSOCKS5 opens a tunnel to addr through a SOCKS5 proxy, which resolves the name.
func connectSOCKS5(ctx context.Context, dial direct, u *url.URL, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if u.User != nil {
		pw, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pw}
	}
	d, err := proxy.SOCKS5("tcp", proxyAddr(u), auth, dial)
	if err != nil {
		return nil, err
	}
	c, err := d.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connector: SOCKS5 %s through %s: %w", addr, u.Redacted(), err)
	}
	return c, nil
}
