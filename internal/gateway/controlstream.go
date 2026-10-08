// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net"
	"sync"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/tlspeek"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// maxControlStreams is how many control sessions one connector may carry through this gateway's
// data sessions at a time (docs/03-connections.md, "Control sessions through a data session").
const maxControlStreams = 4

// ControlStreams splices the control sessions that connectors carry through their data sessions
// (CONTROL_PASSTHROUGH, ADR-0006) to the controller, at layer 4: TLS runs from the connector to
// the controller, so the gateway can neither read nor alter them. Its Decide is
// SessionsOptions.OnOpenRequest.
type ControlStreams struct {
	to func(net.Conn)

	mu   sync.Mutex
	open map[string]int // by connector
}

// NewControlStreams hands each carried control session to to, which connects it to the controller
// and closes it when done.
func NewControlStreams(to func(net.Conn)) *ControlStreams {
	return &ControlStreams{to: to, open: map[string]int{}}
}

// Decide answers a connector's request for a stream, an OpenRequest on HTTP/2 or a stream it
// opened on QUIC: CONTROL_PASSTHROUGH is accepted while the connector carries fewer than
// maxControlStreams, any other kind is refused.
func (c *ControlStreams) Decide(connector string, r *tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream)) {
	switch {
	case r.GetKind() != tunnelv1.StreamKind_STREAM_KIND_CONTROL_PASSTHROUGH:
		return tunnelv1.ResultCode_RESULT_CODE_PROTOCOL, nil
	case c.Open(connector) >= maxControlStreams:
		return tunnelv1.ResultCode_RESULT_CODE_OVERLOADED, nil
	}
	first := r.GetFirstChunk()
	return tunnelv1.ResultCode_RESULT_CODE_NO_ERROR, func(st tunnel.Stream) {
		// Counted from here, where the stream exists: a stream that never opens leaves no count.
		c.mu.Lock()
		over := c.open[connector] >= maxControlStreams
		if !over {
			c.open[connector]++
		}
		c.mu.Unlock()
		if over {
			st.Abort()
			return
		}
		var conn net.Conn = &countedConn{Conn: tunnel.Conn(st, tunnel.StreamAddr("gateway"), tunnel.StreamAddr("connector "+connector)),
			done: func() { c.release(connector) }}
		if len(first) > 0 {
			conn = tlspeek.NewReplayConn(conn, first)
		}
		c.to(conn)
	}
}

func (c *ControlStreams) release(connector string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open[connector]--; c.open[connector] <= 0 {
		delete(c.open, connector)
	}
}

// Open returns how many control sessions the connector carries through this gateway.
func (c *ControlStreams) Open(connector string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.open[connector]
}

// countedConn calls done once, when it is closed.
type countedConn struct {
	net.Conn
	once sync.Once
	done func()
}

func (c *countedConn) Close() error {
	c.once.Do(c.done)
	return c.Conn.Close()
}

// CloseWrite passes a half-close on to the stream.
func (c *countedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
