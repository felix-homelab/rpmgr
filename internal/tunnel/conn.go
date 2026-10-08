// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"errors"
	"net"
	"sync"
	"time"
)

// Conn returns st as a net.Conn, for a protocol that runs over one stream: the control session a
// connector carries through a data session (CONTROL_PASSTHROUGH), and its other end at the gateway.
// Close and CloseWrite are the stream's. On QUIC a deadline is the stream's own; on HTTP/2, whose
// streams have none, a deadline that passes resets the stream, which is what callers that bound
// their shutdown with deadlines (grpc-go) need.
func Conn(st Stream, local, remote net.Addr) net.Conn {
	return &streamConn{Stream: st, local: local, remote: remote}
}

// StreamAddr is the address of either end of a stream used as a Conn.
type StreamAddr string

// Network implements net.Addr.
func (a StreamAddr) Network() string { return "rpmgr-stream" }

func (a StreamAddr) String() string { return string(a) }

type deadliner interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type streamConn struct {
	Stream
	local, remote net.Addr

	mu     sync.Mutex
	timers [2]*time.Timer // read, write
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

func (c *streamConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	if d, ok := deadlinerOf(c.Stream); ok {
		return d.SetReadDeadline(t)
	}
	c.arm(0, t)
	return nil
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	if d, ok := deadlinerOf(c.Stream); ok {
		return d.SetWriteDeadline(t)
	}
	c.arm(1, t)
	return nil
}

// arm resets the stream when t passes; the zero time disarms.
func (c *streamConn) arm(i int, t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timers[i] != nil {
		c.timers[i].Stop()
		c.timers[i] = nil
	}
	if !t.IsZero() {
		c.timers[i] = time.AfterFunc(time.Until(t), c.Abort)
	}
}

func (c *streamConn) Close() error {
	c.arm(0, time.Time{})
	c.arm(1, time.Time{})
	return c.Stream.Close()
}

// deadlinerOf finds deadlines on st or a stream it wraps.
func deadlinerOf(st Stream) (deadliner, bool) {
	for {
		switch s := st.(type) {
		case deadliner:
			return s, true
		case interface{ Unwrap() Stream }:
			st = s.Unwrap()
		default:
			return nil, false
		}
	}
}
