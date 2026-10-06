// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Connector dials the targets of its routes.
type Connector struct {
	Routes map[string]string // route ID → target address

	mu       sync.Mutex
	sessions []io.Closer
}

func (c *Connector) track(s io.Closer) {
	c.mu.Lock()
	c.sessions = append(c.sessions, s)
	c.mu.Unlock()
}

// Close closes every data session, so the gateway notices at once instead of after the idle
// timeout.
func (c *Connector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.sessions {
		_ = s.Close()
	}
	c.sessions = nil
}

// Dial dials the target of a route with the 5 s upstream timeout of 03.
func (c *Connector) Dial(route string) (Stream, byte) {
	target, ok := c.Routes[route]
	if !ok {
		return nil, ResultRouteUnknown
	}
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return nil, ResultRefused
	}
	return TCPStream{conn.(*net.TCPConn)}, ResultOK
}

// HandleStream serves one gateway-opened stream of the QUIC transport.
func (c *Connector) HandleStream(st Stream) {
	route, err := ReadMessage(st)
	if err != nil {
		_ = st.Close()
		return
	}
	target, code := c.Dial(string(route))
	if err := WriteMessage(st, []byte{code}); err != nil || code != ResultOK {
		if target != nil {
			_ = target.Close()
		}
		_ = st.CloseWrite()
		_ = st.Close()
		return
	}
	Splice(st, target)
}

// RunQUIC dials the gateway over QUIC and serves its streams until the session ends.
func (c *Connector) RunQUIC(ctx context.Context, addr string, tlsConf *tls.Config) error {
	conn, err := DialQUIC(ctx, addr, tlsConf)
	if err != nil {
		return err
	}
	c.track(QUICSession{Conn: conn})
	return ServeQUIC(ctx, conn, c.HandleStream)
}

// RunH2 dials one TLS connection to the gateway and serves HTTP/2 on it; the gateway is the
// HTTP/2 client. It returns when the connection ends.
func (c *Connector) RunH2(ctx context.Context, addr string, tlsConf *tls.Config) error {
	tlsConf = tlsConf.Clone()
	tlsConf.NextProtos = []string{ALPNH2}
	d := &tls.Dialer{NetDialer: &net.Dialer{KeepAlive: 15 * time.Second}, Config: tlsConf}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	c.track(conn)
	H2Server().ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: H2Handler(c.Dial)})
	return nil
}
