// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// The TCP transport's timing (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	// dialTimeout bounds a TCP connect, through a proxy if one is set, and the TLS handshake.
	dialTimeout  = 10 * time.Second
	tcpKeepAlive = 15 * time.Second
)

// dialQUIC opens a QUIC session to the endpoint ep, trying each of its addresses.
func (m *Sessions) dialQUIC(ctx context.Context, ep string, cfg *tls.Config) (tunnel.Session, error) {
	if m.o.QUIC == nil {
		return nil, errors.New("connector: no UDP socket for QUIC")
	}
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("connector: the port of %q: %w", ep, err)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, a := range addrs {
		addr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(a.Unmap(), uint16(port)))
		s, err := tunnel.DialQUIC(ctx, m.o.QUIC, addr, cfg, m.o.Budget)
		if err == nil {
			return s, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// dial opens a TCP connection to addr, directly or through Options.Dial.
func (m *Sessions) dial(ctx context.Context, addr string) (net.Conn, error) {
	if m.o.Dial != nil {
		return m.o.Dial(ctx, addr)
	}
	d := &net.Dialer{KeepAlive: tcpKeepAlive}
	return d.DialContext(ctx, "tcp", addr)
}

// dialH2 opens a TCP connection to the endpoint ep, directly or through Options.Dial, and serves
// reverse HTTP/2 on it.
func (m *Sessions) dialH2(ctx context.Context, ep string, cfg *tls.Config) (tunnel.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	raw, err := m.dial(ctx, ep)
	if err != nil {
		return nil, err
	}
	return m.serveH2(ctx, raw, cfg)
}

// errNoWSSHostname fails the WSS transport to a gateway without a WSS hostname.
var errNoWSSHostname = errors.New("connector: the gateway has no WSS hostname")

// dialWSS opens the WSS transport to the gateway's WSS hostname (docs/03-connections.md,
// "Transport selection"): TCP to its port 443, directly or through Options.Dial; the outer TLS,
// verified against Options.PublicRoots as any website's; an HTTP/1.1 upgrade at tunnel.WSSPath;
// and inside the WebSocket the data session's own TLS, pinned to the controller's root, and
// reverse HTTP/2 as over TCP. A proxy that ends the outer TLS sees only the inner one.
func (m *Sessions) dialWSS(ctx context.Context, host string, cfg *tls.Config) (tunnel.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	hc := &http.Client{Transport: &http.Transport{
		DialContext:       func(ctx context.Context, _, addr string) (net.Conn, error) { return m.dial(ctx, addr) },
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: m.o.PublicRoots},
		DisableKeepAlives: true,
	}}
	ws, resp, err := websocket.Dial(ctx, "wss://"+net.JoinHostPort(host, "443")+tunnel.WSSPath, &websocket.DialOptions{HTTPClient: hc})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	// The inner session's own PINGs keep it alive; the WebSocket adds none. NetConn lifts the read
	// limit, so the limit is set after it.
	nc := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	ws.SetReadLimit(tunnel.WSSMessageLimit)
	return m.serveH2(ctx, nc, cfg)
}

// dialMemory opens a connection to the in-process gateway and serves reverse HTTP/2 on it, after
// the same TLS handshake as over TCP.
func (m *Sessions) dialMemory(ctx context.Context, cfg *tls.Config) (tunnel.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	raw, err := m.o.InProcess.Dial(ctx)
	if err != nil {
		return nil, err
	}
	return m.serveH2(ctx, raw, cfg)
}

// handshakeError is a failed TLS handshake of a data session, or its wrong ALPN, after the
// connection was open: what a proxy that intercepts TLS causes, after which auto tries WSS.
type handshakeError struct{ err error }

func (e *handshakeError) Error() string { return "the TLS handshake: " + e.err.Error() }
func (e *handshakeError) Unwrap() error { return e.err }

// serveH2 completes the TLS handshake on raw with ALPN rpmgr-tunnel-h2/1 and serves reverse
// HTTP/2 on it with windows admitted against the budget; it closes raw if it fails.
func (m *Sessions) serveH2(ctx context.Context, raw net.Conn, cfg *tls.Config) (tunnel.Session, error) {
	cfg = cfg.Clone()
	cfg.NextProtos = []string{tunnel.ALPNH2}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, &handshakeError{err}
	}
	if p := tc.ConnectionState().NegotiatedProtocol; p != tunnel.ALPNH2 {
		_ = tc.Close()
		return nil, &handshakeError{fmt.Errorf("connector: the gateway chose ALPN %q, not %s", p, tunnel.ALPNH2)}
	}
	w, release, err := m.o.Budget.AdmitH2(tunnel.DefaultH2Windows())
	if err != nil {
		_ = tc.Close()
		return nil, err
	}
	s := tunnel.ServeH2Connector(tc, w)
	go func() {
		<-s.Done()
		release()
	}()
	return s, nil
}
