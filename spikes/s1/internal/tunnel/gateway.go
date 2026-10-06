// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http2"
)

// Gateway holds the connector's data sessions and serves public TCP listeners, one per route.
type Gateway struct {
	mu       sync.Mutex
	sessions []Session
	next     atomic.Uint64
	ready    chan struct{}
	once     sync.Once
}

// NewGateway returns a gateway without sessions.
func NewGateway() *Gateway { return &Gateway{ready: make(chan struct{})} }

// AddSession registers a data session. The benchmark has one connector, so a new QUIC session
// means the connector restarted and replaces every older session, and a new h2 connection
// replaces QUIC sessions and all but the newest h2 connection (two per connector).
func (g *Gateway) AddSession(s Session) {
	g.mu.Lock()
	var keep []Session
	if _, isH2 := s.(H2Session); isH2 {
		for i := len(g.sessions) - 1; i >= 0 && len(keep) < 1; i-- {
			if _, ok := g.sessions[i].(H2Session); ok {
				keep = append(keep, g.sessions[i])
			}
		}
	}
	for _, old := range g.sessions {
		if len(keep) == 0 || old != keep[0] {
			_ = old.Close()
		}
	}
	g.sessions = append(keep, s)
	g.mu.Unlock()
	g.once.Do(func() { close(g.ready) })
}

// Ready is closed once the first session is up.
func (g *Gateway) Ready() <-chan struct{} { return g.ready }

// open picks the sessions round robin and returns the first stream that opens. With two TCP
// connections per connector this spreads streams across both (docs/03-connections.md).
func (g *Gateway) open() (Stream, error) {
	g.mu.Lock()
	live := g.sessions[:0]
	for _, s := range g.sessions {
		if !s.Closed() {
			live = append(live, s)
		}
	}
	g.sessions = live
	sessions := append([]Session(nil), live...)
	g.mu.Unlock()
	if len(sessions) == 0 {
		return nil, errors.New("tunnel: no data session")
	}
	start := g.next.Add(1)
	var lastErr error
	for i := range sessions {
		st, err := sessions[(int(start)+i)%len(sessions)].OpenStream()
		if err == nil {
			return st, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// ServeRoute accepts public connections on ln and tunnels each to the route.
func (g *Gateway) ServeRoute(ln net.Listener, route string) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go g.handle(c.(*net.TCPConn), route)
	}
}

func (g *Gateway) handle(c *net.TCPConn, route string) {
	st, err := g.open()
	if err != nil {
		_ = c.SetLinger(0)
		_ = c.Close()
		return
	}
	// StreamOpen goes out at once; client bytes follow without waiting for StreamResult.
	if err := WriteMessage(st, []byte(route)); err != nil {
		_ = st.Close()
		_ = c.Close()
		return
	}
	Splice(TCPStream{c}, &resultStream{Stream: st})
}

// resultStream consumes StreamResult before the first service byte reaches the client.
type resultStream struct {
	Stream
	once sync.Once
	err  error
}

func (r *resultStream) Read(p []byte) (int, error) {
	r.once.Do(func() {
		msg, err := ReadMessage(r.Stream)
		switch {
		case err != nil:
			r.err = err
		case len(msg) != 1 || msg[0] != ResultOK:
			r.err = fmt.Errorf("tunnel: stream result %v", msg)
		}
	})
	if r.err != nil {
		return 0, r.err
	}
	return r.Stream.Read(p)
}

// AcceptH2 accepts the connector's TLS connections for the reverse-HTTP/2 transport and turns
// each into a client connection of the gateway.
func (g *Gateway) AcceptH2(ln net.Listener, tlsConf *tls.Config, t *http2.Transport) error {
	tlsConf = tlsConf.Clone()
	tlsConf.NextProtos = []string{ALPNH2}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			tc := tls.Server(c, tlsConf)
			if err := tc.HandshakeContext(context.Background()); err != nil {
				slog.Warn("h2 handshake", "err", err)
				_ = c.Close()
				return
			}
			if tc.ConnectionState().NegotiatedProtocol != ALPNH2 {
				_ = c.Close()
				return
			}
			cc, err := t.NewClientConn(tc)
			if err != nil {
				_ = c.Close()
				return
			}
			g.AddSession(H2Session{CC: cc, Conn: tc})
		}()
	}
}
