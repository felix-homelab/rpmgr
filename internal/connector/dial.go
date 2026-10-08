// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

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

// dialH2 opens a TLS connection to the endpoint ep, directly or through Options.Dial, and serves
// reverse HTTP/2 on it with windows admitted against the budget.
func (m *Sessions) dialH2(ctx context.Context, ep string, cfg *tls.Config) (tunnel.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	dial := m.o.Dial
	if dial == nil {
		d := &net.Dialer{KeepAlive: tcpKeepAlive}
		dial = func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) }
	}
	raw, err := dial(ctx, ep)
	if err != nil {
		return nil, err
	}
	cfg = cfg.Clone()
	cfg.NextProtos = []string{tunnel.ALPNH2}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if p := tc.ConnectionState().NegotiatedProtocol; p != tunnel.ALPNH2 {
		_ = tc.Close()
		return nil, fmt.Errorf("connector: the gateway chose ALPN %q, not %s", p, tunnel.ALPNH2)
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
