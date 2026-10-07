// SPDX-License-Identifier: Apache-2.0

package s2

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// Params are the HTTP/2 parameters of one data session (docs/03-connections.md, "Transports and
// fallback"; docs/adr/0005-reverse-http2-fallback.md).
type Params struct {
	MaxConcurrentStreams int           // set by the connector, the HTTP/2 server
	StreamWindow         int           // receive window per stream, both sides
	ConnWindow           int           // receive window per connection, both sides
	SendPingTimeout      time.Duration // ReadIdleTimeout: idle time before a PING is sent
	PingTimeout          time.Duration // time to wait for the PING ACK
	// MaxReadFrameSize is the largest frame a side accepts (SETTINGS_MAX_FRAME_SIZE). The peer's
	// value sizes the HTTP/2 client's per-request body buffer: min(value, 512 KiB).
	MaxReadFrameSize int
}

// RPMGRParams are the values from 03 and ADR-0005, plus the frame size this spike found.
func RPMGRParams() Params {
	return Params{
		MaxConcurrentStreams: 10000,
		StreamWindow:         16 << 20,
		ConnWindow:           256 << 20,
		SendPingTimeout:      15 * time.Second,
		PingTimeout:          10 * time.Second,
		MaxReadFrameSize:     16 << 10,
	}
}

// Client is the gateway's HTTP/2 client connection over the connection the connector dialled.
type Client interface {
	// TryReserve reserves a stream slot without blocking; false means the session is at its
	// stream limit (or closed), and the caller must use another session.
	TryReserve() bool
	// RoundTrip sends a request on a reserved slot.
	RoundTrip(*http.Request) (*http.Response, error)
	// Active is the number of streams in flight, including reservations.
	Active() int
	Close() error
}

// Impl is one HTTP/2 implementation under test.
type Impl interface {
	Name() string
	// Serve runs the HTTP/2 server on conn until the connection ends.
	Serve(conn net.Conn, h http.Handler, p Params) error
	// NewClient creates an HTTP/2 client on conn, which was accepted, not dialled.
	NewClient(conn net.Conn, p Params) (Client, error)
}

// plainConn hides the *tls.Conn type from net/http, so that it speaks HTTP/2 with prior
// knowledge on the already-authenticated connection instead of looking for ALPN "h2". The ALPN
// rpmgr-tunnel-h2/1 was checked by the caller.
type plainConn struct{ net.Conn }

// TLSState returns the TLS state of conn, or nil.
func TLSState(conn net.Conn) *tls.ConnectionState {
	if pc, ok := conn.(plainConn); ok {
		conn = pc.Conn
	}
	if tc, ok := conn.(*tls.Conn); ok {
		cs := tc.ConnectionState()
		return &cs
	}
	return nil
}

var quietLog = log.New(io.Discard, "", 0)

// ---------------------------------------------------------------------------------------------
// stdlib: net/http's HTTP/2 (Go 1.27), the non-deprecated API.

// Stdlib uses http.Server and http.Transport.NewClientConn.
type Stdlib struct{}

func (Stdlib) Name() string { return "stdlib" }

func h2cOnly() *http.Protocols {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	return &p
}

// oneConnListener hands out one connection, then blocks until closed.
type oneConnListener struct {
	conn   net.Conn
	once   sync.Once
	served atomic.Bool
	done   chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if !l.served.Swap(true) {
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneConnListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func (Stdlib) Serve(conn net.Conn, h http.Handler, p Params) error {
	l := &oneConnListener{conn: plainConn{conn}, done: make(chan struct{})}
	srv := &http.Server{
		Handler:   h,
		Protocols: h2cOnly(),
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          p.MaxConcurrentStreams,
			MaxReceiveBufferPerStream:     p.StreamWindow,
			MaxReceiveBufferPerConnection: p.ConnWindow,
			SendPingTimeout:               p.SendPingTimeout,
			PingTimeout:                   p.PingTimeout,
			MaxReadFrameSize:              p.MaxReadFrameSize,
		},
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				l.Close()
			}
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
		ErrorLog: quietLog,
	}
	err := srv.Serve(l)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

type connKey struct{}

type stdlibClient struct{ cc *http.ClientConn }

func (Stdlib) NewClient(conn net.Conn, p Params) (Client, error) {
	var used atomic.Bool
	tr := &http.Transport{
		Protocols: h2cOnly(),
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerStream:     p.StreamWindow,
			MaxReceiveBufferPerConnection: p.ConnWindow,
			SendPingTimeout:               p.SendPingTimeout,
			PingTimeout:                   p.PingTimeout,
			MaxReadFrameSize:              p.MaxReadFrameSize,
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if used.Swap(true) {
				return nil, errors.New("the session's connection was already used")
			}
			return plainConn{conn}, nil
		},
	}
	cc, err := tr.NewClientConn(context.Background(), "http", "rpmgr-session:1")
	if err != nil {
		return nil, err
	}
	return stdlibClient{cc}, nil
}

func (c stdlibClient) TryReserve() bool                                  { return c.cc.Reserve() == nil }
func (c stdlibClient) RoundTrip(r *http.Request) (*http.Response, error) { return c.cc.RoundTrip(r) }
func (c stdlibClient) Active() int                                       { return c.cc.InFlight() }
func (c stdlibClient) Close() error                                      { return c.cc.Close() }

// ---------------------------------------------------------------------------------------------
// xnet: golang.org/x/net/http2, the API ADR-0005 names. Since Go 1.27 it is a deprecated wrapper
// around net/http's implementation; with -tags http2legacy it is x/net's own implementation.

// XNet uses http2.Server.ServeConn and http2.Transport.NewClientConn.
type XNet struct{}

func (XNet) Name() string { return "xnet" }

func (XNet) Serve(conn net.Conn, h http.Handler, p Params) error {
	srv := &http2.Server{
		MaxConcurrentStreams:         uint32(p.MaxConcurrentStreams),
		MaxUploadBufferPerStream:     int32(p.StreamWindow),
		MaxUploadBufferPerConnection: int32(p.ConnWindow),
		ReadIdleTimeout:              p.SendPingTimeout,
		PingTimeout:                  p.PingTimeout,
		MaxReadFrameSize:             uint32(p.MaxReadFrameSize),
	}
	pc := plainConn{conn}
	srv.ServeConn(pc, &http2.ServeConnOpts{
		Handler: h,
		BaseConfig: &http.Server{
			ErrorLog: quietLog,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, connKey{}, pc)
			},
		},
		Context: context.WithValue(context.Background(), connKey{}, net.Conn(pc)),
	})
	return nil
}

type xnetClient struct{ cc *http2.ClientConn }

func (XNet) NewClient(conn net.Conn, p Params) (Client, error) {
	// x/net's Transport has no fields for its receive windows; they come from the net/http
	// Transport it is configured for.
	t1 := &http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerStream:     p.StreamWindow,
		MaxReceiveBufferPerConnection: p.ConnWindow,
	}}
	t2, err := http2.ConfigureTransports(t1)
	if err != nil {
		return nil, err
	}
	t2.ReadIdleTimeout = p.SendPingTimeout
	t2.PingTimeout = p.PingTimeout
	t2.MaxReadFrameSize = uint32(p.MaxReadFrameSize)
	t2.AllowHTTP = true
	cc, err := t2.NewClientConn(plainConn{conn})
	if err != nil {
		return nil, err
	}
	return xnetClient{cc}, nil
}

func (c xnetClient) TryReserve() bool                                  { return c.cc.ReserveNewRequest() }
func (c xnetClient) RoundTrip(r *http.Request) (*http.Response, error) { return c.cc.RoundTrip(r) }
func (c xnetClient) Active() int {
	st := c.cc.State()
	return st.StreamsActive + st.StreamsReserved
}
func (c xnetClient) Close() error { return c.cc.Close() }
