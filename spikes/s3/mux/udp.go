// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Budget bounds the connection receive windows granted to one ALPN, through quic-go's
// AllowConnectionWindowIncrease (docs/03-connections.md, "QUIC parameters").
type Budget struct {
	Limit   int64
	used    atomic.Int64
	granted atomic.Int64 // number of increases allowed
	denied  atomic.Int64 // number of increases refused
}

func (b *Budget) take(delta int64) bool {
	for {
		u := b.used.Load()
		if u+delta > b.Limit {
			b.denied.Add(1)
			return false
		}
		if b.used.CompareAndSwap(u, u+delta) {
			b.granted.Add(1)
			return true
		}
	}
}

// BudgetStats is a snapshot of one budget.
type BudgetStats struct {
	Limit, Used, Granted, Denied int64
}

// UDPMux is one quic-go Transport and one listener on UDP/443 serving public HTTP/3 and tunnel
// sessions, dispatched on the negotiated ALPN.
type UDPMux struct {
	Transport *quic.Transport
	Listener  *quic.Listener
	H3        *http3.Server

	budgets map[string]*Budget // per ALPN, plus "" for connections not yet dispatched
	conns   sync.Map           // *quic.Conn → *connAccount

	mu     sync.Mutex
	events []string
	wg     sync.WaitGroup
}

type connAccount struct {
	alpn    string
	budget  *Budget
	granted atomic.Int64
}

// UDPConfig configures NewUDPMux.
type UDPConfig struct {
	Certs           *Certs
	HTTPHostnames   map[string]tls.Certificate
	TunnelBudget    int64
	H3Budget        int64
	PendingBudget   int64 // windows granted before the ALPN is known (normally none are needed)
	StreamWindowMax uint64
	ConnWindowMax   uint64
}

// NewUDPMux listens on pc. The listener's tls.Config offers both ALPNs; GetConfigForClient
// returns a per-ALPN configuration: mutual TLS with the gateway certificate for tunnels, the
// route's public certificate and no client certificate for h3.
func NewUDPMux(pc net.PacketConn, cfg UDPConfig) (*UDPMux, error) {
	m := &UDPMux{budgets: map[string]*Budget{
		ALPNTunnelQUIC: {Limit: cfg.TunnelBudget},
		http3.NextProtoH3: {Limit: cfg.H3Budget},
		"":             {Limit: cfg.PendingBudget},
	}}
	td := TestTrustDomain
	tunnelName := strings.ToLower(TunnelName())
	internal := cfg.Certs.Internal.Pool()
	tunnelTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cfg.Certs.Gateway},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    internal,
		NextProtos:   []string{ALPNTunnelQUIC},
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, err := SPIFFEFromChain(cs.VerifiedChains)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(id, "spiffe://"+td+"/org/") || !strings.Contains(id, "/connector/") {
				return fmt.Errorf("tunnel: %s is not a connector", id)
			}
			return nil
		},
	}
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{http3.NextProtoH3, ALPNTunnelQUIC},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			sni := strings.ToLower(chi.ServerName)
			if sni == tunnelName && slices.Contains(chi.SupportedProtos, ALPNTunnelQUIC) {
				return tunnelTLS, nil
			}
			if cert, ok := cfg.HTTPHostnames[sni]; ok && slices.Contains(chi.SupportedProtos, http3.NextProtoH3) {
				return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
					NextProtos: []string{http3.NextProtoH3}}, nil
			}
			m.event(fmt.Sprintf("udp443 refused sni=%q alpn=%v", chi.ServerName, chi.SupportedProtos))
			return nil, fmt.Errorf("no route for %q with ALPN %v", chi.ServerName, chi.SupportedProtos)
		},
	}
	quicConf := &quic.Config{
		HandshakeIdleTimeout:       5 * time.Second,
		MaxIdleTimeout:             30 * time.Second,
		MaxIncomingStreams:         1000,
		EnableDatagrams:            true,
		MaxStreamReceiveWindow:     cfg.StreamWindowMax,
		MaxConnectionReceiveWindow: cfg.ConnWindowMax,
		AllowConnectionWindowIncrease: func(c *quic.Conn, delta uint64) bool {
			// Calling methods of c here is not allowed (quic-go interface.go:149-150), so the
			// ALPN comes from what the accept loop registered for this connection.
			acc := m.account(c)
			if !acc.budget.take(int64(delta)) {
				return false
			}
			acc.granted.Add(int64(delta))
			return true
		},
	}
	m.Transport = &quic.Transport{Conn: pc}
	var err error
	if m.Listener, err = m.Transport.Listen(tlsConf, quicConf); err != nil {
		return nil, err
	}
	m.H3 = &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			n, _ := io.Copy(io.Discard, r.Body)
			fmt.Fprintf(w, "h3 host=%s proto=%s read=%d\n", r.Host, r.Proto, n)
			return
		}
		fmt.Fprintf(w, "h3 host=%s proto=%s\n", r.Host, r.Proto)
		m.event(fmt.Sprintf("h3 served host=%s proto=%s ua=%q", r.Host, r.Proto, r.UserAgent()))
	})}
	go m.acceptLoop()
	return m, nil
}

func (m *UDPMux) account(c *quic.Conn) *connAccount {
	if v, ok := m.conns.Load(c); ok {
		return v.(*connAccount)
	}
	v, _ := m.conns.LoadOrStore(c, &connAccount{budget: m.budgets[""]})
	return v.(*connAccount)
}

func (m *UDPMux) acceptLoop() {
	for {
		c, err := m.Listener.Accept(context.Background())
		if err != nil {
			return
		}
		alpn := c.ConnectionState().TLS.NegotiatedProtocol
		b, ok := m.budgets[alpn]
		if !ok {
			_ = c.CloseWithError(0x100, "unknown ALPN")
			continue
		}
		// Move the connection to its ALPN's budget, carrying over anything granted before.
		acc := m.account(c)
		pending := acc.granted.Load()
		if pending > 0 {
			m.budgets[""].used.Add(-pending)
			b.used.Add(pending)
		}
		acc.alpn, acc.budget = alpn, b
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			defer func() {
				// Release the connection's windows when it ends.
				acc.budget.used.Add(-acc.granted.Load())
				m.conns.Delete(c)
			}()
			switch alpn {
			case http3.NextProtoH3:
				_ = m.H3.ServeQUICConn(c)
			case ALPNTunnelQUIC:
				m.serveTunnel(c)
			}
		}()
	}
}

// serveTunnel stands in for the QUIC data session: every stream gets a header line, then echo.
func (m *UDPMux) serveTunnel(c *quic.Conn) {
	cs := c.ConnectionState()
	id, _ := SPIFFEFromChain(cs.TLS.VerifiedChains)
	m.event(fmt.Sprintf("tunnel-quic session alpn=%s peer=%s", cs.TLS.NegotiatedProtocol, id))
	for {
		s, err := c.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			defer s.Close()
			fmt.Fprintf(s, "tunnel-quic peer=%s\n", id)
			_, _ = io.Copy(s, s)
		}()
	}
}

// Stats returns a snapshot of the per-ALPN budgets.
func (m *UDPMux) Stats() map[string]BudgetStats {
	out := map[string]BudgetStats{}
	for k, b := range m.budgets {
		name := k
		if name == "" {
			name = "pending"
		}
		out[name] = BudgetStats{Limit: b.Limit, Used: b.used.Load(), Granted: b.granted.Load(), Denied: b.denied.Load()}
	}
	return out
}

// Events returns what the UDP side saw.
func (m *UDPMux) Events() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.events...)
}

func (m *UDPMux) event(s string) {
	m.mu.Lock()
	m.events = append(m.events, s)
	m.mu.Unlock()
}

// Close stops the listener and the transport.
func (m *UDPMux) Close() error {
	_ = m.H3.Close()
	err := m.Listener.Close()
	_ = m.Transport.Close()
	if errors.Is(err, quic.ErrServerClosed) {
		return nil
	}
	return err
}
