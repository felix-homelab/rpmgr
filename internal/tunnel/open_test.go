// SPDX-License-Identifier: Apache-2.0

package tunnel_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// sender serialises the messages written on a control stream.
func sender(st tunnel.Stream) func(*tunnelv1.SessionMessage) error {
	var mu sync.Mutex
	return func(m *tunnelv1.SessionMessage) error {
		mu.Lock()
		defer mu.Unlock()
		return tunnel.WriteMessage(st, m)
	}
}

// openEnv is a reverse-HTTP/2 session with OpenRequest wired on both sides, as the session layer
// will wire it: the gateway answers requests from its control stream, the connector hands answers
// to its requester.
type openEnv struct {
	gw  *tunnel.H2Gateway
	req *tunnel.OpenRequester
	// decide is the gateway's decision, settable per test.
	mu     sync.Mutex
	decide func(*tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream))
}

func startOpenEnv(t *testing.T, w tunnel.H2Windows, timeout time.Duration) *openEnv {
	t.Helper()
	gw, con, gc, cc := h2Session(t, w)
	e := &openEnv{gw: gw}
	resp := tunnel.NewOpenResponder(sender(gc), gw.OpenStream, func(r *tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream)) {
		e.mu.Lock()
		d := e.decide
		e.mu.Unlock()
		return d(r)
	})
	e.req = tunnel.NewOpenRequester(sender(cc), timeout)
	go func() { // the gateway's control loop
		for {
			m := &tunnelv1.SessionMessage{}
			if err := tunnel.ReadMessage(gc, m); err != nil {
				return
			}
			if r := m.GetOpenRequest(); r != nil {
				go func() { _ = resp.Handle(context.Background(), r) }()
			}
		}
	}()
	go func() { // the connector's control loop
		for {
			m := &tunnelv1.SessionMessage{}
			if err := tunnel.ReadMessage(cc, m); err != nil {
				return
			}
			if r := m.GetOpenRejected(); r != nil {
				e.req.Rejected(r)
			}
		}
	}()
	go func() { // the connector's streams
		for {
			st, err := con.AcceptStream(context.Background())
			if err != nil {
				return
			}
			open := &tunnelv1.StreamOpen{}
			if err := tunnel.ReadMessage(st, open); err != nil || open.GetOpenId() == 0 {
				st.Abort()
				continue
			}
			e.req.Accepted(st, open)
		}
	}()
	return e
}

func (e *openEnv) setDecide(d func(*tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream))) {
	e.mu.Lock()
	e.decide = d
	e.mu.Unlock()
}

func rejectedCode(err error) tunnelv1.ResultCode {
	var r *tunnel.OpenRejectedError
	if errors.As(err, &r) {
		return r.Code
	}
	return -1
}

// TestOpenRequest_Semantics: a request is answered by a gateway-opened stream whose StreamOpen
// carries the open_id and the result, on which the connector writes no StreamResult, or by
// OpenRejected; the first chunk reaches the gateway; an unanswered request times out, and a stream
// that answers it late is reset.
func TestOpenRequest_Semantics(t *testing.T) {
	e := startOpenEnv(t, tunnel.DefaultH2Windows(), 300*time.Millisecond)
	ctx := context.Background()

	firstChunk := make(chan []byte, 1)
	fromConnector := make(chan []byte, 1)
	e.setDecide(func(r *tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream)) {
		firstChunk <- r.GetFirstChunk()
		return tunnelv1.ResultCode_RESULT_CODE_NO_ERROR, func(st tunnel.Stream) {
			_, _ = st.Write([]byte("from the gateway"))
			_ = st.CloseWrite()
			b, _ := io.ReadAll(st)
			fromConnector <- b
		}
	})
	st, open, err := e.req.Request(ctx, tunnelv1.StreamKind_STREAM_KIND_DIAG, "", []byte("first flight"))
	if err != nil {
		t.Fatal(err)
	}
	if open.GetOpenId() == 0 || open.GetResult().GetCode() != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR ||
		open.GetKind() != tunnelv1.StreamKind_STREAM_KIND_DIAG {
		t.Fatalf("StreamOpen %v", open)
	}
	if got := <-firstChunk; string(got) != "first flight" {
		t.Fatalf("the gateway got the first chunk %q", got)
	}
	// The connector writes its bytes at once, no StreamResult.
	if _, err := st.Write([]byte("from the connector")); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseWrite()
	if b, err := io.ReadAll(st); err != nil || string(b) != "from the gateway" {
		t.Fatalf("the connector read %q, %v", b, err)
	}
	if b := <-fromConnector; string(b) != "from the connector" {
		t.Fatalf("the gateway read %q", b)
	}

	e.setDecide(func(*tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream)) {
		return tunnelv1.ResultCode_RESULT_CODE_UNAUTHORIZED, nil
	})
	if _, _, err := e.req.Request(ctx, tunnelv1.StreamKind_STREAM_KIND_DIAG, "", nil); rejectedCode(err) != tunnelv1.ResultCode_RESULT_CODE_UNAUTHORIZED {
		t.Fatalf("a rejected request: %v", err)
	}
	if _, _, err := e.req.Request(ctx, tunnelv1.StreamKind_STREAM_KIND_RELAY_OUT, "svc", nil); rejectedCode(err) != tunnelv1.ResultCode_RESULT_CODE_PROTOCOL {
		t.Fatalf("a kind of Phase 2: %v", err)
	}

	// The gateway answers too late: the request times out, and the late stream is reset.
	release := make(chan struct{})
	late := make(chan error, 1)
	e.setDecide(func(*tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream)) {
		<-release
		return tunnelv1.ResultCode_RESULT_CODE_NO_ERROR, func(st tunnel.Stream) {
			_, err := io.ReadAll(st)
			late <- err
		}
	})
	start := time.Now()
	if _, _, err := e.req.Request(ctx, tunnelv1.StreamKind_STREAM_KIND_DIAG, "", nil); !errors.Is(err, tunnel.ErrOpenTimeout) {
		t.Fatalf("an unanswered request: %v", err)
	}
	if d := time.Since(start); d < 300*time.Millisecond || d > 2*time.Second {
		t.Fatalf("timed out after %v", d)
	}
	close(release)
	select {
	case err := <-late:
		if err == nil {
			t.Fatal("the late stream was not reset")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the late stream stayed open")
	}
}

// TestOpenRequest_Refusals: a repeated or zero open_id is rejected with PROTOCOL, whatever the
// gateway would decide.
func TestOpenRequest_Refusals(t *testing.T) {
	gw, _, gc, cc := h2Session(t, tunnel.DefaultH2Windows())
	resp := tunnel.NewOpenResponder(sender(gc), gw.OpenStream, func(*tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream)) {
		return tunnelv1.ResultCode_RESULT_CODE_UNAUTHORIZED, nil
	})
	ctx := context.Background()
	for _, id := range []uint64{7, 7, 0} {
		if err := resp.Handle(ctx, &tunnelv1.OpenRequest{OpenId: id, Kind: tunnelv1.StreamKind_STREAM_KIND_DIAG}); err != nil {
			t.Fatal(err)
		}
	}
	want := []tunnelv1.ResultCode{tunnelv1.ResultCode_RESULT_CODE_UNAUTHORIZED, tunnelv1.ResultCode_RESULT_CODE_PROTOCOL,
		tunnelv1.ResultCode_RESULT_CODE_PROTOCOL}
	for i, w := range want {
		m := &tunnelv1.SessionMessage{}
		if err := tunnel.ReadMessage(cc, m); err != nil {
			t.Fatal(err)
		}
		if got := m.GetOpenRejected().GetCode(); got != w {
			t.Fatalf("answer %d: %s, want %s", i, got, w)
		}
	}
}

// TestH2_ConnectorInitiatedStreams: on the reverse-HTTP/2 transport the connector never opens a
// stream; it gets one with OpenRequest (DIAG here; CONTROL_PASSTHROUGH in 5.13), and the gateway
// never blocks at the connector's stream limit but rejects with OVERLOADED.
func TestH2_ConnectorInitiatedStreams(t *testing.T) {
	e := startOpenEnv(t, tunnel.WithMaxStreams(tunnel.DefaultH2Windows(), 2), time.Second)
	ctx := context.Background()
	held := make(chan tunnel.Stream, 1)
	e.setDecide(func(*tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream)) {
		return tunnelv1.ResultCode_RESULT_CODE_NO_ERROR, func(st tunnel.Stream) { held <- st }
	})
	st, _, err := e.req.Request(ctx, tunnelv1.StreamKind_STREAM_KIND_DIAG, "", nil)
	if err != nil {
		t.Fatalf("a DIAG stream through OpenRequest: %v", err)
	}
	defer func() { _ = st.Close() }()
	<-held
	// The control stream and this stream fill the limit of 2.
	start := time.Now()
	if _, _, err := e.req.Request(ctx, tunnelv1.StreamKind_STREAM_KIND_DIAG, "", nil); rejectedCode(err) != tunnelv1.ResultCode_RESULT_CODE_OVERLOADED {
		t.Fatalf("at the stream limit: %v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("the gateway waited %v at the stream limit", d)
	}
}
