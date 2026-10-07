// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// The reverse HTTP/2 transport (docs/03-connections.md, "Transports and fallback"; ADR-0005): the
// connector dials the gateway and serves HTTP/2 on that connection; the gateway is the HTTP/2
// client and opens every stream as a request. The request body carries the gateway's bytes, its
// END_STREAM being the gateway's FIN; the response body carries the connector's bytes as chunks
// (ChunkWriter), whose zero-length chunk is the connector's FIN.

// The HTTP/2 parameters of 03.
const (
	h2MaxStreams   = 10000
	h2StreamWindow = 16 << 20
	h2ConnWindow   = 256 << 20
	h2FrameSize    = 16 << 10
	h2SendPing     = 15 * time.Second
	h2PingTimeout  = 10 * time.Second

	pathControl = "/control"
	pathStream  = "/stream"
)

// Errors of the HTTP/2 transport.
var (
	// ErrNotSupported is returned for what the HTTP/2 transport cannot do: the gateway accepts no
	// stream and the connector opens none; the connector asks with OpenRequest instead.
	ErrNotSupported = errors.New("tunnel: not possible on the HTTP/2 transport")
	// ErrControlFirst is returned for a stream opened before the session control stream.
	ErrControlFirst = errors.New("tunnel: the session control stream must be the first stream")
	errAborted      = errors.New("tunnel: stream aborted")
	errStreamGone   = errors.New("tunnel: stream ended")
)

// H2Windows are a session's receive windows; 4.5 lowers them when the window budget is tight.
type H2Windows struct {
	Stream, Conn int
	maxStreams   int // tests only; 0 is 10 000
}

// DefaultH2Windows are the windows of 03: 16 MiB per stream and 256 MiB per connection.
func DefaultH2Windows() H2Windows { return H2Windows{Stream: h2StreamWindow, Conn: h2ConnWindow} }

func (w H2Windows) config(server bool) *http.HTTP2Config {
	c := &http.HTTP2Config{
		MaxReceiveBufferPerStream:     w.Stream,
		MaxReceiveBufferPerConnection: w.Conn,
		MaxReadFrameSize:              h2FrameSize,
		SendPingTimeout:               h2SendPing,
		PingTimeout:                   h2PingTimeout,
	}
	if server {
		c.MaxConcurrentStreams = h2MaxStreams
		if w.maxStreams > 0 {
			c.MaxConcurrentStreams = w.maxStreams
		}
	}
	return c
}

func h2cOnly() *http.Protocols {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	return &p
}

// plainConn hides the *tls.Conn type from net/http, so that it speaks HTTP/2 with prior knowledge
// on the authenticated connection, whose ALPN rpmgr-tunnel-h2/1 the caller checked.
type plainConn struct{ net.Conn }

// H2Gateway is the gateway's side of a data session over reverse HTTP/2.
type H2Gateway struct {
	cc       *http.ClientConn
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	doneOnce sync.Once
	control  atomic.Bool
}

// NewH2Gateway starts the HTTP/2 client on conn, which the connector dialled and the gateway
// accepted. The first stream must be the session control stream (Control).
func NewH2Gateway(conn net.Conn, w H2Windows) (*H2Gateway, error) {
	var used atomic.Bool
	tr := &http.Transport{
		Protocols: h2cOnly(),
		HTTP2:     w.config(false),
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if used.Swap(true) {
				return nil, errors.New("tunnel: the session's connection is already in use")
			}
			return plainConn{conn}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cc, err := tr.NewClientConn(ctx, "http", "rpmgr-session:1")
	if err != nil {
		cancel()
		return nil, err
	}
	g := &H2Gateway{cc: cc, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	cc.SetStateHook(func(cc *http.ClientConn) {
		if cc.Err() != nil {
			g.doneOnce.Do(func() { close(g.done) })
		}
	})
	return g, nil
}

// Control opens the session control stream; it must be the first stream of the session.
func (g *H2Gateway) Control(context.Context) (Stream, error) {
	if g.control.Swap(true) {
		return nil, errors.New("tunnel: the session control stream is already open")
	}
	return g.open(pathControl)
}

// OpenStream opens a stream without waiting for the connector. It reserves a slot first and never
// blocks at the connector's stream limit: it returns ErrStreamLimit instead.
func (g *H2Gateway) OpenStream(context.Context) (Stream, error) {
	if !g.control.Load() {
		return nil, ErrControlFirst
	}
	return g.open(pathStream)
}

func (g *H2Gateway) open(path string) (Stream, error) {
	if err := g.cc.Reserve(); err != nil {
		if g.cc.Err() != nil {
			return nil, g.cc.Err()
		}
		return nil, ErrStreamLimit
	}
	ctx, cancel := context.WithCancel(g.ctx)
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://rpmgr-session"+path, pr)
	if err != nil {
		cancel()
		g.cc.Release()
		return nil, err
	}
	req.ContentLength = -1
	st := &h2ClientStream{pw: pw, cancel: cancel, ready: make(chan struct{})}
	go func() {
		resp, err := g.cc.RoundTrip(req)
		if err == nil && resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			err = fmt.Errorf("tunnel: the connector refused the stream: %s", resp.Status)
		}
		st.resp, st.respErr = resp, err
		close(st.ready)
	}()
	return st, nil
}

// AcceptStream is not possible: on HTTP/2 the gateway opens every stream.
func (g *H2Gateway) AcceptStream(context.Context) (Stream, error) { return nil, ErrNotSupported }

// Close ends the session.
func (g *H2Gateway) Close() error {
	g.cancel()
	return g.cc.Close()
}

// Done is closed when the session ended.
func (g *H2Gateway) Done() <-chan struct{} { return g.done }

// Transport is "h2".
func (g *H2Gateway) Transport() string { return "h2" }

// h2ClientStream is a stream on the gateway: the request body carries its bytes, the response
// body the connector's chunks.
type h2ClientStream struct {
	pw      *io.PipeWriter
	cancel  context.CancelFunc
	ready   chan struct{}
	resp    *http.Response
	respErr error
	rOnce   sync.Once
	r       io.Reader
}

func (s *h2ClientStream) Read(p []byte) (int, error) {
	<-s.ready
	if s.respErr != nil {
		return 0, s.respErr
	}
	s.rOnce.Do(func() { s.r = NewChunkReader(s.resp.Body) })
	return s.r.Read(p)
}

func (s *h2ClientStream) Write(p []byte) (int, error) { return s.pw.Write(p) }

// CloseWrite ends the request body: END_STREAM.
func (s *h2ClientStream) CloseWrite() error { return s.pw.Close() }

// SetReliableBoundary does nothing: HTTP/2 delivers everything before a reset anyway.
func (s *h2ClientStream) SetReliableBoundary() {}

// Abort resets the stream and closes the response body, which alone returns the stream's unread
// bytes to the connection window [F Go 1.27.1 net/http/internal/http2/transport.go:2402-2421].
func (s *h2ClientStream) Abort() {
	s.cancel()
	_ = s.pw.CloseWithError(errAborted)
	go func() {
		<-s.ready
		if s.respErr == nil {
			_ = s.resp.Body.Close()
		}
	}()
}

// Close releases the stream; a direction that has not ended is reset.
func (s *h2ClientStream) Close() error {
	_ = s.pw.Close()
	select {
	case <-s.ready:
		if s.respErr == nil {
			return s.resp.Body.Close()
		}
		return nil
	default:
		s.Abort()
		return nil
	}
}

// H2Connector is the connector's side of a data session over reverse HTTP/2: the HTTP/2 server on
// the connection it dialled.
type H2Connector struct {
	srv     *http.Server
	l       *oneConnListener
	control chan Stream
	accept  chan *h2ServerStream
	done    chan struct{}

	mu   sync.Mutex
	seen bool // a request arrived
	ok   bool // the first one was the session control stream
}

// ServeH2Connector serves HTTP/2 on conn, which the connector dialled to the gateway with ALPN
// rpmgr-tunnel-h2/1, until the session ends.
func ServeH2Connector(conn net.Conn, w H2Windows) *H2Connector {
	c := &H2Connector{l: &oneConnListener{conn: plainConn{conn}, done: make(chan struct{})},
		control: make(chan Stream, 1), accept: make(chan *h2ServerStream), done: make(chan struct{})}
	c.srv = &http.Server{
		Handler:   c,
		Protocols: h2cOnly(),
		HTTP2:     w.config(true),
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				_ = c.l.Close()
			}
		},
		ErrorLog:          log.New(io.Discard, "", 0),
		ReadHeaderTimeout: h2PingTimeout, // the gateway is authenticated; this only bounds a stuck peer
	}
	go func() {
		_ = c.srv.Serve(c.l)
		close(c.done)
	}()
	return c
}

// Control returns the session control stream, the gateway's first request.
func (c *H2Connector) Control(ctx context.Context) (Stream, error) {
	select {
	case st := <-c.control:
		return st, nil
	case <-c.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// AcceptStream returns the next stream the gateway opened.
func (c *H2Connector) AcceptStream(ctx context.Context) (Stream, error) {
	select {
	case st := <-c.accept:
		return st, nil
	case <-c.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// OpenStream is not possible: the connector asks the gateway with OpenRequest.
func (c *H2Connector) OpenStream(context.Context) (Stream, error) { return nil, ErrNotSupported }

// Close ends the session.
func (c *H2Connector) Close() error { return c.srv.Close() }

// Done is closed when the session ended.
func (c *H2Connector) Done() <-chan struct{} { return c.done }

// Transport is "h2".
func (c *H2Connector) Transport() string { return "h2" }

// ServeHTTP admits the session control stream as the first request and user streams after it;
// anything else is refused.
func (c *H2Connector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	first := !c.seen
	c.seen = true
	if first && r.URL.Path == pathControl {
		c.ok = true
	}
	ok := c.ok
	c.mu.Unlock()
	switch {
	case r.Method != http.MethodPost:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	case r.URL.Path == pathControl && first:
		st := newServerStream(w, r)
		c.control <- st
		st.serve()
	case r.URL.Path == pathControl:
		http.Error(w, "the session has a control stream", http.StatusConflict)
	case r.URL.Path == pathStream && !ok:
		http.Error(w, "the session control stream must be the first stream", http.StatusMisdirectedRequest)
	case r.URL.Path == pathStream:
		st := newServerStream(w, r)
		select {
		case c.accept <- st:
			st.serve()
		case <-r.Context().Done():
		case <-c.done:
		}
	default:
		http.NotFound(w, r)
	}
}

// h2ServerStream is a stream on the connector: it reads the request body and writes chunks on the
// response. The handler returns, ending the response, only after both directions ended or the
// stream was aborted, so the connector's FIN never cuts off the gateway's direction.
type h2ServerStream struct {
	w     http.ResponseWriter
	rc    *http.ResponseController
	r     io.Reader
	ctx   context.Context
	wmu   sync.Mutex
	gone  bool // the handler returned; guarded by wmu
	fin   atomic.Bool
	eof   atomic.Bool
	abort atomic.Bool
	done  chan struct{}
	once  sync.Once
}

func newServerStream(w http.ResponseWriter, r *http.Request) *h2ServerStream {
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	return &h2ServerStream{w: w, rc: rc, r: r.Body, ctx: r.Context(), done: make(chan struct{})}
}

// serve holds the handler until the stream ends.
func (s *h2ServerStream) serve() {
	select {
	case <-s.done:
	case <-s.ctx.Done():
	}
	s.wmu.Lock()
	s.gone = true // no write may touch the ResponseWriter once the handler returned
	s.wmu.Unlock()
	if s.abort.Load() {
		panic(http.ErrAbortHandler) // RST_STREAM
	}
}

func (s *h2ServerStream) finish() { s.once.Do(func() { close(s.done) }) }

func (s *h2ServerStream) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if errors.Is(err, io.EOF) {
		s.eof.Store(true)
		if s.fin.Load() {
			s.finish()
		}
	}
	return n, err
}

func (s *h2ServerStream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	switch {
	case s.gone:
		return 0, errStreamGone
	case s.fin.Load():
		return 0, errors.New("tunnel: write after CloseWrite")
	}
	n, err := ChunkWriter{W: s.w}.Write(p)
	if err == nil {
		err = s.rc.Flush()
	}
	return n, err
}

// CloseWrite writes the zero-length chunk, the connector's FIN.
func (s *h2ServerStream) CloseWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.gone {
		return errStreamGone
	}
	if s.fin.Swap(true) {
		return nil
	}
	if err := (ChunkWriter{W: s.w}).CloseWrite(); err != nil {
		return err
	}
	if err := s.rc.Flush(); err != nil {
		return err
	}
	if s.eof.Load() {
		s.finish()
	}
	return nil
}

// SetReliableBoundary does nothing on HTTP/2.
func (s *h2ServerStream) SetReliableBoundary() {}

// Abort resets the stream.
func (s *h2ServerStream) Abort() {
	s.abort.Store(true)
	s.finish()
}

// Close releases the stream; if a direction has not ended, the stream is reset.
func (s *h2ServerStream) Close() error {
	if !s.fin.Load() || !s.eof.Load() {
		s.abort.Store(true)
	}
	s.finish()
	return nil
}

// oneConnListener hands out one connection, then waits until it is closed.
type oneConnListener struct {
	conn   net.Conn
	served atomic.Bool
	once   sync.Once
	done   chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if !l.served.Swap(true) {
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
