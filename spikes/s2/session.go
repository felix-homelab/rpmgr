// SPDX-License-Identifier: Apache-2.0

package s2

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Mode is how the connector-to-gateway direction of a stream is half-closed.
type Mode int

const (
	// ModeRaw is the design as written in ADR-0005: the response body carries raw bytes and the
	// connector's FIN is the response's END_STREAM, i.e. the handler returning.
	ModeRaw Mode = iota
	// ModeFramed carries the connector's FIN in-band: the response body is a sequence of
	// length-prefixed chunks, a zero-length chunk is the FIN, and END_STREAM follows only when
	// both directions have ended.
	ModeFramed
)

func (m Mode) String() string {
	if m == ModeFramed {
		return "framed"
	}
	return "raw"
}

var (
	// ErrNoCapacity: the session is at its stream limit; use another session (never block).
	ErrNoCapacity = errors.New("session at its stream limit")
	// ErrOpenTimeout: an OpenRequest was not answered in time (10 s in 03).
	ErrOpenTimeout = errors.New("OpenRequest unanswered")

	errStreamGone = errors.New("stream ended")
)

// OpenRejectedError is the gateway's OpenRejected answer.
type OpenRejectedError struct{ Code int }

func (e OpenRejectedError) Error() string {
	return fmt.Sprintf("OpenRequest rejected, code %d", e.Code)
}

// Stream is one user, relay or diagnostic stream, seen from either side.
type Stream struct {
	Open StreamOpen
	mode Mode

	// Gateway side (HTTP/2 client).
	pw        *io.PipeWriter
	cancel    context.CancelFunc
	respReady chan struct{}
	resp      *http.Response
	respErr   error
	resultMu  sync.Mutex
	resultOK  bool
	result    StreamResult
	resultErr error

	// Connector side (HTTP/2 server).
	w        http.ResponseWriter
	flusher  *http.ResponseController
	wmu      sync.Mutex
	done     chan struct{}
	doneOnce sync.Once
	abortReq atomic.Bool
	gone     bool // handler returned; guarded by wmu
	sendFIN  atomic.Bool
	recvEnd  atomic.Bool
	reqCtx   context.Context

	// Both sides.
	r io.Reader // receive direction after the preamble
}

func (s *Stream) isGateway() bool { return s.pw != nil }

// --- Gateway-side behaviour --------------------------------------------------------------------

func (s *Stream) waitResponse() error {
	<-s.respReady
	return s.respErr
}

// Result waits for the connector's StreamResult. Streams that answer an OpenRequest carry the
// result in StreamOpen instead, and the connector writes none (03).
func (s *Stream) Result() (StreamResult, error) {
	s.resultMu.Lock()
	defer s.resultMu.Unlock()
	if s.resultOK || s.resultErr != nil {
		return s.result, s.resultErr
	}
	if err := s.waitResponse(); err != nil {
		s.resultErr = err
		return s.result, err
	}
	br := bufio.NewReaderSize(s.resp.Body, MaxMessage)
	if s.Open.OpenID == 0 {
		if err := ReadMsg(br, &s.result); err != nil {
			s.resultErr = err
			return s.result, err
		}
	} else {
		s.result = *s.Open.Result
	}
	s.resultOK = true
	if s.mode == ModeFramed {
		s.r = &framedReader{r: br}
	} else {
		s.r = br
	}
	return s.result, nil
}

// --- Common API --------------------------------------------------------------------------------

// Read reads the peer's bytes. io.EOF is the peer's FIN; any other error is an abort.
func (s *Stream) Read(p []byte) (int, error) {
	if s.isGateway() {
		if _, err := s.Result(); err != nil {
			return 0, err
		}
		return s.r.Read(p)
	}
	n, err := s.r.Read(p)
	if err != nil {
		s.recvEnd.Store(true)
		s.maybeDone()
	}
	return n, err
}

// Write sends bytes to the peer.
func (s *Stream) Write(p []byte) (int, error) {
	if s.isGateway() {
		return s.pw.Write(p)
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	total := len(p)
	if s.gone {
		return 0, errStreamGone
	}
	if s.sendFIN.Load() {
		return 0, errors.New("write after CloseWrite")
	}
	select {
	case <-s.done:
		return 0, errors.New("stream ended")
	default:
	}
	var err error
	if s.mode == ModeFramed {
		for len(p) > 0 && err == nil {
			n := min(len(p), MaxMessage)
			err = writeChunk(s.w, p[:n])
			p = p[n:]
		}
	} else {
		_, err = s.w.Write(p)
	}
	if err == nil {
		err = s.flusher.Flush()
	}
	if err != nil {
		return 0, err
	}
	return total, nil
}

// CloseWrite half-closes the sending direction (a TCP FIN from the side's local socket).
func (s *Stream) CloseWrite() error {
	if s.isGateway() {
		return s.pw.Close() // END_STREAM on the request
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.gone {
		return errStreamGone
	}
	if s.sendFIN.Swap(true) {
		return nil
	}
	if s.mode == ModeFramed {
		if err := writeChunk(s.w, nil); err != nil {
			return err
		}
		if err := s.flusher.Flush(); err != nil {
			return err
		}
		s.maybeDone()
		return nil
	}
	// ModeRaw: END_STREAM on the response means returning from the handler.
	s.finish()
	return nil
}

// Abort resets both directions (a TCP RST).
func (s *Stream) Abort() {
	if s.isGateway() {
		s.cancel() // RST_STREAM(CANCEL)
		s.pw.CloseWithError(errors.New("stream aborted"))
		// net/http's HTTP/2 client returns the connection-level window credit of unread bytes
		// only when the response body is closed, not on cancellation.
		go func() {
			if s.waitResponse() == nil {
				s.resp.Body.Close()
			}
		}()
		return
	}
	s.abortReq.Store(true)
	s.finish() // the handler panics with http.ErrAbortHandler: RST_STREAM(INTERNAL_ERROR)
}

// Close releases the stream after use.
func (s *Stream) Close() error {
	if s.isGateway() {
		s.pw.Close()
		if s.waitResponse() == nil {
			return s.resp.Body.Close()
		}
		return nil
	}
	s.finish()
	return nil
}

func (s *Stream) maybeDone() {
	if s.mode == ModeFramed && s.sendFIN.Load() && s.recvEnd.Load() {
		s.finish()
	}
}

func (s *Stream) finish() { s.doneOnce.Do(func() { close(s.done) }) }

// --- Gateway session (HTTP/2 client) ----------------------------------------------------------

// OpenDecision is the gateway's answer to an OpenRequest.
type OpenDecision struct {
	Accept bool
	Code   int           // OpenRejected code when !Accept
	Serve  func(*Stream) // runs with the gateway-opened stream when Accept
}

// GatewaySession is the gateway's side of one reverse-HTTP/2 data session.
type GatewaySession struct {
	client Client
	mode   Mode

	ctrlW  *io.PipeWriter
	ctrlMu sync.Mutex
	hello  Control

	// OnOpenRequest decides about a connector's OpenRequest. It runs in its own goroutine.
	onOpen func(Control) OpenDecision

	mu      sync.Mutex
	openIDs map[uint64]bool

	ended  chan struct{}
	endErr error
	cancel context.CancelFunc
}

// NewGatewaySession starts the HTTP/2 client on conn and opens the session control stream as its
// first request (03, "Establishment").
func NewGatewaySession(conn net.Conn, impl Impl, p Params, mode Mode, onOpen func(Control) OpenDecision) (*GatewaySession, error) {
	client, err := impl.NewClient(conn, p)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &GatewaySession{client: client, mode: mode, onOpen: onOpen, openIDs: map[uint64]bool{},
		ended: make(chan struct{}), cancel: cancel}
	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://rpmgr-session/control", pr)
	req.ContentLength = -1
	if !client.TryReserve() {
		cancel()
		return nil, ErrNoCapacity
	}
	resp, err := client.RoundTrip(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		return nil, fmt.Errorf("control stream refused: %s", resp.Status)
	}
	s.ctrlW = pw
	br := bufio.NewReader(resp.Body)
	if err := ReadMsg(br, &s.hello); err != nil || s.hello.Type != "hello" {
		cancel()
		return nil, fmt.Errorf("no SessionHello: %v", err)
	}
	if err := s.sendCtrl(Control{Type: "welcome"}); err != nil {
		cancel()
		return nil, err
	}
	go s.controlLoop(br)
	return s, nil
}

func (s *GatewaySession) sendCtrl(c Control) error {
	s.ctrlMu.Lock()
	defer s.ctrlMu.Unlock()
	return WriteMsg(s.ctrlW, c)
}

func (s *GatewaySession) controlLoop(br *bufio.Reader) {
	defer close(s.ended)
	for {
		var c Control
		if err := ReadMsg(br, &c); err != nil {
			s.endErr = err
			return
		}
		switch c.Type {
		case "ping":
			_ = s.sendCtrl(Control{Type: "pong", Seq: c.Seq, Pad: c.Pad})
		case "open_request":
			s.mu.Lock()
			dup := s.openIDs[c.OpenID]
			s.openIDs[c.OpenID] = true
			s.mu.Unlock()
			if dup || c.OpenID == 0 || len(c.FirstChunk) > MaxMessage {
				_ = s.sendCtrl(Control{Type: "open_rejected", OpenID: c.OpenID, Code: ResultProto})
				continue
			}
			go s.answerOpen(c)
		}
	}
}

func (s *GatewaySession) answerOpen(c Control) {
	d := OpenDecision{Code: ResultRefused}
	if s.onOpen != nil {
		d = s.onOpen(c)
	}
	if !d.Accept {
		_ = s.sendCtrl(Control{Type: "open_rejected", OpenID: c.OpenID, Code: d.Code})
		return
	}
	st, err := s.OpenStream(context.Background(), StreamOpen{Kind: c.Kind, OpenID: c.OpenID, Result: &StreamResult{Code: ResultOK}})
	if err != nil {
		_ = s.sendCtrl(Control{Type: "open_rejected", OpenID: c.OpenID, Code: ResultProto})
		return
	}
	if d.Serve != nil {
		d.Serve(st)
	}
}

// OpenStream opens a stream and writes its StreamOpen without waiting for an answer, so the
// caller can send the client's first bytes at once (03, "One stream per user connection"). It
// never blocks at the stream limit: it returns ErrNoCapacity instead.
func (s *GatewaySession) OpenStream(ctx context.Context, so StreamOpen) (*Stream, error) {
	if !s.client.TryReserve() {
		return nil, ErrNoCapacity
	}
	sctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(sctx, http.MethodPost, "http://rpmgr-session/stream", pr)
	req.ContentLength = -1
	st := &Stream{Open: so, mode: s.mode, pw: pw, cancel: cancel, respReady: make(chan struct{})}
	go func() {
		resp, err := s.client.RoundTrip(req)
		st.resp, st.respErr = resp, err
		if err == nil && resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			st.respErr = fmt.Errorf("stream refused: %s", resp.Status)
		}
		close(st.respReady)
	}()
	if err := WriteMsg(pw, so); err != nil {
		st.Abort()
		return nil, err
	}
	return st, nil
}

// Active returns the number of streams in flight on the session.
func (s *GatewaySession) Active() int { return s.client.Active() }

// Ended is closed when the session control stream ends.
func (s *GatewaySession) Ended() <-chan struct{} { return s.ended }

// Close closes the session's HTTP/2 connection.
func (s *GatewaySession) Close() error {
	s.cancel()
	return s.client.Close()
}

// --- Connector session (HTTP/2 server) --------------------------------------------------------

type pendingOpen struct {
	stream chan *Stream
	reject chan int
}

// ConnectorSession is the connector's side of one data session. It is the HTTP/2 handler.
type ConnectorSession struct {
	mode Mode
	// OnStream handles a gateway-opened user stream; it must call WriteResult first.
	OnStream func(*Stream)
	// OpenTimeout bounds an unanswered OpenRequest (10 s in 03).
	OpenTimeout time.Duration

	mu         sync.Mutex
	firstSeen  bool
	FirstPath  string
	Violations atomic.Int64 // streams refused because they came before the control stream
	ctrlW      http.ResponseWriter
	ctrlRC     *http.ResponseController
	ctrlMu     sync.Mutex
	ctrlGone   bool // control handler returned; guarded by ctrlMu
	ctrlReady  chan struct{}
	pending    map[uint64]*pendingOpen
	timedOut   map[uint64]bool
	nextOpenID atomic.Uint64
	pingSeq    atomic.Uint64
	pongs      sync.Map // seq → chan struct{}
	ended      chan struct{}
	endOnce    sync.Once
}

// NewConnectorSession returns the handler for one data session.
func NewConnectorSession(mode Mode, onStream func(*Stream)) *ConnectorSession {
	return &ConnectorSession{mode: mode, OnStream: onStream, OpenTimeout: 10 * time.Second,
		ctrlReady: make(chan struct{}), pending: map[uint64]*pendingOpen{}, timedOut: map[uint64]bool{},
		ended: make(chan struct{})}
}

// Ended is closed when the session control stream ends.
func (c *ConnectorSession) Ended() <-chan struct{} { return c.ended }

func (c *ConnectorSession) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	first := !c.firstSeen
	c.firstSeen = true
	if first {
		c.FirstPath = r.URL.Path
	}
	c.mu.Unlock()
	switch {
	case r.URL.Path == "/control" && first:
		c.serveControl(w, r)
	case r.URL.Path == "/control":
		http.Error(w, "second control stream", http.StatusConflict)
	case strings.HasPrefix(r.URL.Path, "/stream"):
		c.mu.Lock()
		controlFirst := c.FirstPath == "/control"
		c.mu.Unlock()
		if !controlFirst {
			// The session control stream must be the gateway's first request (03).
			c.Violations.Add(1)
			http.Error(w, "session control stream must be the first stream", http.StatusMisdirectedRequest)
			return
		}
		// The control stream's handler may not have read SessionWelcome yet.
		select {
		case <-c.ctrlReady:
		case <-r.Context().Done():
			return
		}
		c.serveStream(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (c *ConnectorSession) sendCtrl(m Control) error {
	c.ctrlMu.Lock()
	defer c.ctrlMu.Unlock()
	if c.ctrlGone {
		return errStreamGone
	}
	if err := WriteMsg(c.ctrlW, m); err != nil {
		return err
	}
	return c.ctrlRC.Flush()
}

func (c *ConnectorSession) serveControl(w http.ResponseWriter, r *http.Request) {
	defer c.endOnce.Do(func() { close(c.ended) })
	defer func() {
		c.ctrlMu.Lock()
		c.ctrlGone = true
		c.ctrlMu.Unlock()
	}()
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	c.ctrlW, c.ctrlRC = w, rc
	if err := c.sendCtrl(Control{Type: "hello"}); err != nil {
		return
	}
	br := bufio.NewReader(r.Body)
	var welcome Control
	if err := ReadMsg(br, &welcome); err != nil || welcome.Type != "welcome" {
		return
	}
	close(c.ctrlReady)
	for {
		var m Control
		if err := ReadMsg(br, &m); err != nil {
			return
		}
		switch m.Type {
		case "pong":
			if ch, ok := c.pongs.LoadAndDelete(m.Seq); ok {
				close(ch.(chan struct{}))
			}
		case "open_rejected":
			c.mu.Lock()
			p := c.pending[m.OpenID]
			delete(c.pending, m.OpenID)
			c.mu.Unlock()
			if p != nil {
				p.reject <- m.Code
			}
		}
	}
}

func (c *ConnectorSession) serveStream(w http.ResponseWriter, r *http.Request) {
	br := bufio.NewReaderSize(r.Body, MaxMessage)
	var so StreamOpen
	if err := ReadMsg(br, &so); err != nil {
		http.Error(w, "bad StreamOpen", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		return
	}
	st := &Stream{Open: so, mode: c.mode, w: w, flusher: rc, done: make(chan struct{}), r: br, reqCtx: r.Context()}
	if so.OpenID != 0 {
		c.mu.Lock()
		p := c.pending[so.OpenID]
		delete(c.pending, so.OpenID)
		c.mu.Unlock()
		if p == nil || so.Result == nil {
			panic(http.ErrAbortHandler) // unknown or timed-out open_id: reset the stream
		}
		p.stream <- st
	} else if c.OnStream != nil {
		go c.OnStream(st)
	} else {
		st.Abort()
	}
	select {
	case <-st.done:
	case <-r.Context().Done():
	}
	// No write may touch the ResponseWriter once the handler has returned.
	st.wmu.Lock()
	st.gone = true
	st.wmu.Unlock()
	if st.abortReq.Load() {
		panic(http.ErrAbortHandler)
	}
}

// WriteResult writes the StreamResult on a gateway-opened stream (connector side).
func (s *Stream) WriteResult(code int) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.gone {
		return errStreamGone
	}
	if err := WriteMsg(s.w, StreamResult{Code: code}); err != nil {
		return err
	}
	return s.flusher.Flush()
}

// RequestStream asks the gateway to open a stream (RELAY_OUT, CONTROL_PASSTHROUGH) with an
// OpenRequest on the session control stream, optionally carrying the first chunk.
func (c *ConnectorSession) RequestStream(ctx context.Context, kind int, first []byte) (*Stream, error) {
	id := c.nextOpenID.Add(1)
	return c.requestStream(ctx, id, kind, first)
}

// RequestStreamWithID is RequestStream with a chosen open_id (to test duplicates).
func (c *ConnectorSession) RequestStreamWithID(ctx context.Context, id uint64, kind int, first []byte) (*Stream, error) {
	return c.requestStream(ctx, id, kind, first)
}

func (c *ConnectorSession) requestStream(ctx context.Context, id uint64, kind int, first []byte) (*Stream, error) {
	select {
	case <-c.ctrlReady:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	p := &pendingOpen{stream: make(chan *Stream, 1), reject: make(chan int, 1)}
	c.mu.Lock()
	if _, busy := c.pending[id]; !busy {
		c.pending[id] = p
	}
	c.mu.Unlock()
	if err := c.sendCtrl(Control{Type: "open_request", OpenID: id, Kind: kind, FirstChunk: first}); err != nil {
		return nil, err
	}
	timer := time.NewTimer(c.OpenTimeout)
	defer timer.Stop()
	select {
	case st := <-p.stream:
		return st, nil
	case code := <-p.reject:
		return nil, OpenRejectedError{Code: code}
	case <-timer.C:
		c.mu.Lock()
		if c.pending[id] == p {
			delete(c.pending, id)
		}
		c.timedOut[id] = true
		c.mu.Unlock()
		return nil, ErrOpenTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Ping sends an application Ping (padded to ≥ 64 bytes) and waits for the Pong. It measures RTT
// only; liveness comes from HTTP/2 PING frames (03, "Timeouts, keepalive and backoff").
func (c *ConnectorSession) Ping(ctx context.Context) (time.Duration, error) {
	<-c.ctrlReady
	seq := c.pingSeq.Add(1)
	ch := make(chan struct{})
	c.pongs.Store(seq, ch)
	start := time.Now()
	// The write itself is flow-controlled and can block; the caller's deadline still applies.
	sent := make(chan error, 1)
	go func() { sent <- c.sendCtrl(Control{Type: "ping", Seq: seq, Pad: strings.Repeat(".", 64)}) }()
	select {
	case err := <-sent:
		if err != nil {
			return 0, err
		}
	case <-ctx.Done():
		c.pongs.Delete(seq)
		return 0, ctx.Err()
	}
	select {
	case <-ch:
		return time.Since(start), nil
	case <-ctx.Done():
		c.pongs.Delete(seq)
		return 0, ctx.Err()
	}
}
