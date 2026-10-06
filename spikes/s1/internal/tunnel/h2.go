// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// ErrStreamLimit is returned when a session has no free stream slot. The gateway never waits
// for one (docs/03-connections.md#transports-and-fallback).
var ErrStreamLimit = errors.New("tunnel: session at its stream limit")

// H2Server is the connector's HTTP/2 server with the parameters of
// docs/03-connections.md#transports-and-fallback.
func H2Server() *http2.Server {
	return &http2.Server{
		MaxConcurrentStreams:         10000,
		MaxUploadBufferPerStream:     16 << 20,
		MaxUploadBufferPerConnection: 256 << 20,
		ReadIdleTimeout:              15 * time.Second,
		PingTimeout:                  10 * time.Second,
	}
}

// H2Transport is the gateway's HTTP/2 client transport. x/net reads the client's receive
// windows only from net/http's HTTP2Config of the wrapped http.Transport
// [F x/net v0.59.0 http2/config.go: fillNetHTTPConfig], so the windows are set there and the
// http2.Transport is derived with ConfigureTransports.
func H2Transport() (*http2.Transport, error) {
	t1 := &http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerConnection: 256 << 20,
		MaxReceiveBufferPerStream:     16 << 20,
		SendPingTimeout:               15 * time.Second,
		PingTimeout:                   10 * time.Second,
	}}
	return http2.ConfigureTransports(t1)
}

// H2Session is a gateway's view of one reverse-HTTP/2 connection of a connector: the gateway is
// the HTTP/2 client on a connection the connector dialled.
type H2Session struct {
	CC   *http2.ClientConn
	Conn net.Conn
}

// OpenStream sends one request whose body carries client→service bytes and whose response
// body carries service→client bytes. It reserves a stream slot first and fails at the limit.
func (s H2Session) OpenStream() (Stream, error) {
	if !s.CC.ReserveNewRequest() {
		return nil, ErrStreamLimit
	}
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://tunnel/", pr)
	if err != nil {
		cancel()
		return nil, err
	}
	st := &h2ClientStream{pw: pw, cancel: cancel, ready: make(chan struct{})}
	go func() {
		st.resp, st.err = s.CC.RoundTrip(req)
		close(st.ready)
	}()
	return st, nil
}

// Closed reports whether the connection has ended or is shutting down.
func (s H2Session) Closed() bool { st := s.CC.State(); return st.Closed || st.Closing }

// Close closes the connection.
func (s H2Session) Close() error { return s.Conn.Close() }

type h2ClientStream struct {
	pw       *io.PipeWriter
	cancel   context.CancelFunc
	ready    chan struct{}
	resp     *http.Response
	err      error
	wroteEnd atomic.Bool
	readEOF  atomic.Bool
}

func (s *h2ClientStream) Read(p []byte) (int, error) {
	<-s.ready
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.resp.Body.Read(p)
	if errors.Is(err, io.EOF) {
		s.readEOF.Store(true)
	}
	return n, err
}

func (s *h2ClientStream) Write(p []byte) (int, error) { return s.pw.Write(p) }

// CloseWrite ends the request body: END_STREAM.
func (s *h2ClientStream) CloseWrite() error {
	s.wroteEnd.Store(true)
	return s.pw.Close()
}

// Close resets the stream unless both directions ended normally.
func (s *h2ClientStream) Close() error {
	if !s.wroteEnd.Load() || !s.readEOF.Load() {
		s.cancel()
		_ = s.pw.CloseWithError(context.Canceled)
	}
	select {
	case <-s.ready:
		if s.resp != nil {
			_ = s.resp.Body.Close()
		}
	default:
	}
	s.cancel()
	return nil
}

// h2ServerStream is the connector's side of one stream. The response ends when the handler
// returns, so CloseWrite only records that the service→client direction is done; the handler
// returns once both directions have ended. Close requests an abort, which the handler turns
// into RST_STREAM.
type h2ServerStream struct {
	body    io.ReadCloser
	w       http.ResponseWriter
	rc      *http.ResponseController
	mu      sync.Mutex
	aborted atomic.Bool
	readEOF atomic.Bool
	wrote   atomic.Bool
}

func (s *h2ServerStream) Read(p []byte) (int, error) {
	n, err := s.body.Read(p)
	if errors.Is(err, io.EOF) {
		s.readEOF.Store(true)
	}
	return n, err
}

func (s *h2ServerStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.w.Write(p)
	if err == nil {
		err = s.rc.Flush()
	}
	return n, err
}

func (s *h2ServerStream) CloseWrite() error { s.wrote.Store(true); return nil }

func (s *h2ServerStream) Close() error {
	if !s.wrote.Load() || !s.readEOF.Load() {
		s.aborted.Store(true)
		return s.body.Close() // unblocks a pending body read
	}
	return nil
}

// H2Handler returns the connector's HTTP/2 handler: it reads StreamOpen from the request body,
// dials the target, writes StreamResult and splices.
func H2Handler(dial func(route string) (Stream, byte)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, err := ReadMessage(r.Body)
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		target, code := dial(string(route))
		w.WriteHeader(http.StatusOK)
		st := &h2ServerStream{body: r.Body, w: w, rc: http.NewResponseController(w)}
		if err := WriteMessage(st, []byte{code}); err != nil || code != ResultOK {
			if target != nil {
				_ = target.Close()
			}
			return
		}
		Splice(st, target)
		if st.aborted.Load() {
			panic(http.ErrAbortHandler)
		}
	})
}
