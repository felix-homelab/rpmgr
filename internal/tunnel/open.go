// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
)

// OpenRequest (docs/03-connections.md, "Transports and fallback"): on the TCP transport only the
// gateway opens streams, so a connector that needs one (CONTROL_PASSTHROUGH, and RELAY_OUT in Phase
// 2) asks with OpenRequest on the session control stream. The gateway answers with OpenRejected, or
// by opening a stream whose StreamOpen carries the open_id and the result; the connector writes no
// StreamResult on it.

// OpenTimeout is how long the connector waits for an answer to an OpenRequest.
const OpenTimeout = 10 * time.Second

// ErrOpenTimeout is returned for an OpenRequest the gateway did not answer in time.
var ErrOpenTimeout = errors.New("tunnel: the gateway did not answer the OpenRequest")

// OpenRejectedError is the gateway's OpenRejected.
type OpenRejectedError struct{ Code tunnelv1.ResultCode }

func (e *OpenRejectedError) Error() string {
	return fmt.Sprintf("tunnel: the gateway rejected the OpenRequest: %s", e.Code)
}

// OpenRequester is the connector's side: it sends OpenRequests through the session control stream
// and hands each answer to the request that waits for it.
type OpenRequester struct {
	send    func(*tunnelv1.SessionMessage) error
	timeout time.Duration

	mu      sync.Mutex
	next    uint64
	pending map[uint64]chan openAnswer
}

type openAnswer struct {
	st   Stream
	open *tunnelv1.StreamOpen
	code tunnelv1.ResultCode
}

// NewOpenRequester sends through send, which writes a message on the session control stream;
// timeout 0 is OpenTimeout.
func NewOpenRequester(send func(*tunnelv1.SessionMessage) error, timeout time.Duration) *OpenRequester {
	if timeout == 0 {
		timeout = OpenTimeout
	}
	return &OpenRequester{send: send, timeout: timeout, pending: map[uint64]chan openAnswer{}}
}

// Request asks the gateway for a stream of kind for route, with the connector's first bytes, at
// most what fits into one message. It returns the stream with its StreamOpen, an
// *OpenRejectedError, or ErrOpenTimeout.
func (o *OpenRequester) Request(ctx context.Context, kind tunnelv1.StreamKind, route string, first []byte) (Stream, *tunnelv1.StreamOpen, error) {
	o.mu.Lock()
	o.next++
	id := o.next
	ch := make(chan openAnswer, 1)
	o.pending[id] = ch
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		delete(o.pending, id)
		o.mu.Unlock()
	}()
	if err := o.send(&tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_OpenRequest{OpenRequest: &tunnelv1.OpenRequest{
		OpenId: id, Kind: kind, RouteId: route, FirstChunk: first}}}); err != nil {
		return nil, nil, err
	}
	t := time.NewTimer(o.timeout)
	defer t.Stop()
	select {
	case a := <-ch:
		if a.st == nil {
			return nil, nil, &OpenRejectedError{Code: a.code}
		}
		return a.st, a.open, nil
	case <-t.C:
		return nil, nil, ErrOpenTimeout
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

// Rejected takes an OpenRejected from the control stream.
func (o *OpenRequester) Rejected(r *tunnelv1.OpenRejected) {
	o.deliver(r.GetOpenId(), openAnswer{code: r.GetCode()})
}

// Accepted takes a stream the gateway opened whose StreamOpen carries an open_id. A stream that
// answers no waiting request, because it timed out or was never sent, is reset.
func (o *OpenRequester) Accepted(st Stream, open *tunnelv1.StreamOpen) {
	if open.GetResult() == nil || !o.deliver(open.GetOpenId(), openAnswer{st: st, open: open}) {
		st.Abort()
	}
}

func (o *OpenRequester) deliver(id uint64, a openAnswer) bool {
	o.mu.Lock()
	ch := o.pending[id]
	delete(o.pending, id)
	o.mu.Unlock()
	if ch == nil {
		return false
	}
	ch <- a
	return true
}

// OpenResponder is the gateway's side: it answers each OpenRequest once.
type OpenResponder struct {
	send func(*tunnelv1.SessionMessage) error
	open func(context.Context) (Stream, error)
	// Decide answers a request: accept with RESULT_CODE_NO_ERROR and serve the opened stream, or
	// return another code to reject it. It sees the first chunk.
	decide func(*tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(Stream))

	mu   sync.Mutex
	seen map[uint64]bool
}

// NewOpenResponder answers through send on the session control stream and opens streams with open,
// the session's OpenStream.
func NewOpenResponder(send func(*tunnelv1.SessionMessage) error, open func(context.Context) (Stream, error),
	decide func(*tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(Stream))) *OpenResponder {
	return &OpenResponder{send: send, open: open, decide: decide, seen: map[uint64]bool{}}
}

// Handle answers one OpenRequest from the control stream. A repeated or zero open_id, a first chunk
// that does not fit into a message, or a kind Phase 1 does not know gets OpenRejected{PROTOCOL};
// a session at its stream limit gets OVERLOADED, so the connector tries elsewhere at once.
func (o *OpenResponder) Handle(ctx context.Context, req *tunnelv1.OpenRequest) error {
	o.mu.Lock()
	dup := o.seen[req.GetOpenId()]
	o.seen[req.GetOpenId()] = true
	o.mu.Unlock()
	var code tunnelv1.ResultCode
	var serve func(Stream)
	switch {
	case dup || req.GetOpenId() == 0 || len(req.GetFirstChunk()) > MaxChunk:
		code = tunnelv1.ResultCode_RESULT_CODE_PROTOCOL
	case CheckStreamOpen(&tunnelv1.StreamOpen{Kind: req.GetKind(), RouteId: req.GetRouteId()}) != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR:
		code = tunnelv1.ResultCode_RESULT_CODE_PROTOCOL
	default:
		code, serve = o.decide(req)
	}
	if code == tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		st, err := o.open(ctx)
		switch {
		case errors.Is(err, ErrStreamLimit):
			code = tunnelv1.ResultCode_RESULT_CODE_OVERLOADED
		case err != nil:
			return err
		default:
			if err := WriteMessage(st, &tunnelv1.StreamOpen{Kind: req.GetKind(), RouteId: req.GetRouteId(), OpenId: req.GetOpenId(),
				Result: &tunnelv1.StreamResult{Code: tunnelv1.ResultCode_RESULT_CODE_NO_ERROR}}); err != nil {
				st.Abort()
				return err
			}
			if serve != nil {
				go serve(st)
			}
			return nil
		}
	}
	return o.send(&tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_OpenRejected{OpenRejected: &tunnelv1.OpenRejected{
		OpenId: req.GetOpenId(), Code: code}}})
}
