// SPDX-License-Identifier: Apache-2.0

package control_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	agentv1 "github.com/felix-homelab/rpmgr/spikes/s4/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/spikes/s4/gen/rpmgr/agent/v1/agentv1connect"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/control"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/pki"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/proxy"
)

const td = "rpmgr-s4test01"

type env struct {
	ca   *pki.CA
	svc  *control.Service
	addr string
}

type liveness struct{ readIdle, ping time.Duration }

func newEnv(t *testing.T, live liveness, handlerOpts ...connect.HandlerOption) *env {
	t.Helper()
	ca, err := pki.NewCA(td)
	if err != nil {
		t.Fatal(err)
	}
	return newEnvWithCA(t, ca, live, handlerOpts...)
}

func newEnvWithCA(t *testing.T, ca *pki.CA, live liveness, handlerOpts ...connect.HandlerOption) *env {
	t.Helper()
	cert, err := ca.Leaf("/controller/n1", []string{"controller." + td, "reauth.controller." + td, "n1.controller." + td}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	svc := control.NewService()
	srv := control.NewHTTPServer(svc, control.ServerOptions{
		CA: ca, Cert: cert, SendPingTimeout: live.readIdle, PingTimeout: live.ping, HandlerOptions: handlerOpts,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	control.Serve(srv, ln)
	t.Cleanup(func() { _ = srv.Close() })
	return &env{ca: ca, svc: svc, addr: ln.Addr().String()}
}

func agentID(name string) string { return "spiffe://" + td + "/org/org_1/connector/" + name }

func (e *env) client(t *testing.T, name, addr string, live liveness, opts ...connect.ClientOption) agentv1connect.ControlClient {
	t.Helper()
	cert, err := e.ca.Leaf("/org/org_1/connector/"+name, []string{name + ".connector." + td}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if addr == "" {
		addr = e.addr
	}
	c, tr := control.NewClient(control.ClientOptions{
		CA: e.ca, Cert: cert, Addr: addr, SendPingTimeout: live.readIdle, PingTimeout: live.ping, ClientOptions: opts,
	})
	t.Cleanup(tr.CloseIdleConnections)
	return c
}

type stream = connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.ControllerMessage]

func hello(id, behaviour string) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{AgentId: id, Behaviour: behaviour}}}
}

// open starts a session and returns the stream and the Welcome.
func open(t *testing.T, ctx context.Context, c agentv1connect.ControlClient, id, behaviour string) (*stream, *agentv1.Welcome) {
	t.Helper()
	st := c.Session(ctx)
	if err := st.Send(hello(id, behaviour)); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	m, err := st.Receive()
	if err != nil {
		t.Fatalf("receive welcome: %v", err)
	}
	if m.GetWelcome() == nil {
		t.Fatalf("first message is not Welcome: %v", m)
	}
	return st, m.GetWelcome()
}

func wantCode(t *testing.T, err error, code connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error with code %v, got nil", code)
	}
	if got := connect.CodeOf(err); got != code {
		t.Fatalf("want code %v, got %v (%v)", code, got, err)
	}
}

// (1) Bidirectional streaming, both directions at the same time, with more data than the HTTP/2
// flow-control windows hold, so neither direction can finish without the other progressing.
func TestBidiFullDuplex(t *testing.T) {
	e := newEnv(t, liveness{})
	c := e.client(t, "duplex", "", liveness{})
	const n, size = 2000, 32 << 10 // 62.5 MiB in each direction
	st, w := open(t, t.Context(), c, "duplex", "duplex:"+strconv.Itoa(n)+","+strconv.Itoa(size))
	if w.GetPeerIdentity() != agentID("duplex") {
		t.Fatalf("server saw peer %q", w.GetPeerIdentity())
	}
	var lastSend time.Time
	sendErr := make(chan error, 1)
	go func() {
		payload := make([]byte, size)
		for i := 1; i <= n; i++ {
			if err := st.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{Seq: uint64(i), Payload: payload}}}); err != nil {
				sendErr <- err
				return
			}
		}
		lastSend = time.Now()
		sendErr <- st.CloseRequest()
	}()
	var firstRecv time.Time
	for i := 1; i <= n; i++ {
		m, err := st.Receive()
		if err != nil {
			t.Fatalf("receive %d: %v", i, err)
		}
		if i == 1 {
			firstRecv = time.Now()
		}
		if got := m.GetSnapshot().GetRevision(); got != uint64(i) {
			t.Fatalf("snapshot %d out of order: %d", i, got)
		}
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := st.Receive(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF after the server finished, got %v", err)
	}
	_ = st.CloseResponse()
	rec, _ := e.svc.Record("duplex", time.Second)
	<-rec.Done
	r := rec.Snapshot()
	if r.EndErr != nil || r.Received != n {
		t.Fatalf("server: received %d, end error %v", r.Received, r.EndErr)
	}
	if r.Proto != "HTTP/2.0" {
		t.Fatalf("server saw protocol %q, want HTTP/2.0", r.Proto)
	}
	if !firstRecv.Before(lastSend) || !r.FirstRecv.Before(r.LastSend) {
		t.Fatalf("directions did not overlap: client first receive %v, last send %v; server first receive %v, last send %v",
			firstRecv, lastSend, r.FirstRecv, r.LastSend)
	}
	t.Logf("full duplex: %d MiB each way; client received its first message %v before its last send",
		n*size>>20, lastSend.Sub(firstRecv).Round(time.Millisecond))
}

// The client half-closes; the server reads EOF and keeps sending.
func TestHalfCloseThenServerSends(t *testing.T) {
	e := newEnv(t, liveness{})
	c := e.client(t, "half", "", liveness{})
	st, _ := open(t, t.Context(), c, "half", "after-halfclose:5")
	for i := 1; i <= 3; i++ {
		if err := st.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{Seq: uint64(i)}}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CloseRequest(); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		m, err := st.Receive()
		if err != nil {
			t.Fatalf("receive %d after half-close: %v", i, err)
		}
		if m.GetSnapshot().GetRevision() != uint64(i) {
			t.Fatalf("unexpected message %v", m)
		}
	}
	if _, err := st.Receive(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
	rec, _ := e.svc.Record("half", time.Second)
	<-rec.Done
	if r := rec.Snapshot(); r.Received != 3 || r.EndErr != nil {
		t.Fatalf("server: received %d, end error %v", r.Received, r.EndErr)
	}
}

// receiveAsync runs one Receive in the background, as an agent's reader goroutine does.
func receiveAsync(st *stream) <-chan error {
	ch := make(chan error, 1)
	go func() {
		_, err := st.Receive()
		ch <- err
	}()
	return ch
}

// within returns the error from ch if it arrives within d.
func within(ch <-chan error, d time.Duration) (error, bool) {
	select {
	case err := <-ch:
		return err, true
	case <-time.After(d):
		return nil, false
	}
}

func ended(rec *control.SessionRecord, d time.Duration) bool {
	select {
	case <-rec.Done:
		return true
	case <-time.After(d):
		return false
	}
}

// (2) Cancellation, finding: cancelling the client's context does not end a stream whose client
// waits in Receive, and the server never learns of it. Go's HTTP/2 client stops watching the
// request context once the response headers are in while the request body is still open, and
// connect-go relies on the transport for cancellation.
func TestFinding_CancelDoesNotReachBlockedStream(t *testing.T) {
	e := newEnv(t, liveness{})
	c := e.client(t, "cancel", "", liveness{})
	ctx, cancel := context.WithCancel(t.Context())
	st, _ := open(t, ctx, c, "cancel", "")
	rec, _ := e.svc.Record("cancel", time.Second)
	recv := receiveAsync(st)
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err, ok := within(recv, 2*time.Second); ok {
		t.Fatalf("Receive returned after the cancel (%v): the finding no longer holds", err)
	}
	if ended(rec, 0) {
		t.Fatal("the server saw the cancel: the finding no longer holds")
	}
	// Closing the response side is what ends the call.
	start := time.Now()
	_ = st.CloseResponse()
	err, ok := within(recv, 2*time.Second)
	if !ok {
		t.Fatal("Receive still blocked after CloseResponse")
	}
	if !ended(rec, 2*time.Second) {
		t.Fatal("the server did not end after CloseResponse")
	}
	r := rec.Snapshot()
	t.Logf("2 s after cancel nothing happened; CloseResponse: client %v (code %v); server after %v, end %v, ctx %v",
		err, connect.CodeOf(err), r.Ended.Sub(start).Round(time.Microsecond), r.EndErr, r.CtxErr)
}

// The same finding with golang.org/x/net/http2's Transport instead of net/http's: it is not
// specific to the HTTP/2 code that Go 1.27 moved into net/http.
func TestFinding_CancelDoesNotReachBlockedStreamXNet(t *testing.T) {
	e := newEnv(t, liveness{})
	cert, err := e.ca.Leaf("/org/org_1/connector/xnet", []string{"xnet.connector." + td}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http2.Transport{
		TLSClientConfig: control.ClientTLSConfig(control.ClientOptions{CA: e.ca, Cert: cert}),
		DialTLSContext: func(ctx context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
			return (&tls.Dialer{Config: cfg}).DialContext(ctx, network, e.addr)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	c := agentv1connect.NewControlClient(&http.Client{Transport: tr}, "https://controller."+td, connect.WithGRPC())
	ctx, cancel := context.WithCancel(t.Context())
	st, _ := open(t, ctx, c, "xnet", "")
	rec, _ := e.svc.Record("xnet", time.Second)
	recv := receiveAsync(st)
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err, ok := within(recv, 2*time.Second); ok {
		t.Fatalf("Receive returned after the cancel (%v): the finding no longer holds", err)
	}
	if ended(rec, 0) {
		t.Fatal("the server saw the cancel: the finding no longer holds")
	}
	_ = st.CloseResponse()
	if _, ok := within(recv, 2*time.Second); !ok {
		t.Fatal("Receive still blocked after CloseResponse")
	}
}

// (2) Cancellation with the workaround: the agent closes the response side when its context
// ends. The client's Receive returns at once, and the server's call ends.
func TestCancelWithCloseResponseWorkaround(t *testing.T) {
	e := newEnv(t, liveness{})
	c := e.client(t, "cancel-w", "", liveness{})
	ctx, cancel := context.WithCancel(t.Context())
	st, _ := open(t, ctx, c, "cancel-w", "")
	stop := context.AfterFunc(ctx, func() { _ = st.CloseResponse() })
	defer stop()
	rec, _ := e.svc.Record("cancel-w", time.Second)
	recv := receiveAsync(st)
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	cancel()
	err, ok := within(recv, time.Second)
	if !ok {
		t.Fatal("Receive still blocked 1 s after the cancel")
	}
	clientAfter := time.Since(start)
	if !ended(rec, time.Second) {
		t.Fatal("the server did not end within 1 s")
	}
	r := rec.Snapshot()
	if !errors.Is(r.CtxErr, context.Canceled) {
		t.Fatalf("server call context %v, want context.Canceled", r.CtxErr)
	}
	t.Logf("with CloseResponse on cancel: client after %v (%v, code %v); server after %v (end %v, ctx %v)",
		clientAfter.Round(time.Microsecond), err, connect.CodeOf(err), r.Ended.Sub(start).Round(time.Microsecond), r.EndErr, r.CtxErr)
}

// (2) Cancellation reaches the server once the client touches the stream again. Finding: the
// client first half-closes the request, so the server's Receive returns io.EOF, exactly as for a
// graceful end; its call context may or may not be cancelled by then.
func TestCancelReachesServerOnNextCall(t *testing.T) {
	e := newEnv(t, liveness{})
	c := e.client(t, "cancel-n", "", liveness{})
	ctx, cancel := context.WithCancel(t.Context())
	st, _ := open(t, ctx, c, "cancel-n", "")
	rec, _ := e.svc.Record("cancel-n", time.Second)
	cancel()
	_, err := st.Receive()
	wantCode(t, err, connect.CodeCanceled)
	if !ended(rec, time.Second) {
		t.Fatal("the server did not end within 1 s")
	}
	r := rec.Snapshot()
	if r.EndErr != nil {
		t.Fatalf("server Receive ended with %v; the finding (clean EOF) no longer holds", r.EndErr)
	}
	t.Logf("server saw a clean EOF; its call context error at that moment: %v", r.CtxErr)
}

// (2) Cancellation the other way: a server error reaches the client with its code and message.
func TestServerErrorReachesClient(t *testing.T) {
	e := newEnv(t, liveness{})
	c := e.client(t, "denied", "", liveness{})
	st, _ := open(t, t.Context(), c, "denied", "deny")
	_, err := st.Receive()
	wantCode(t, err, connect.CodePermissionDenied)
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Message() != "spike: agent is not allowed" {
		t.Fatalf("unexpected error %v", err)
	}
	// The request side is closed too: a later Send fails instead of blocking.
	if err := st.Send(&agentv1.AgentMessage{}); err == nil {
		t.Fatal("send after the server ended the call succeeded")
	}
}

// A server that returns nil ends the stream cleanly: the client reads io.EOF.
func TestServerCloseIsEOF(t *testing.T) {
	e := newEnv(t, liveness{})
	c := e.client(t, "close", "", liveness{})
	st, _ := open(t, t.Context(), c, "close", "close")
	if _, err := st.Receive(); !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
}

// (3) Deadlines: the grpc-timeout header carries the client's deadline to the server.
func TestDeadlineHeaderPropagates(t *testing.T) {
	e := newEnv(t, liveness{})
	c := e.client(t, "deadline", "", liveness{})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	clientDeadline, _ := ctx.Deadline()
	st, w := open(t, ctx, c, "deadline", "close")
	serverDeadline := time.Unix(0, w.GetDeadlineUnixNano())
	if d := clientDeadline.Sub(serverDeadline).Abs(); w.GetDeadlineUnixNano() == 0 || d > 50*time.Millisecond {
		t.Fatalf("server deadline %v, client deadline %v", serverDeadline, clientDeadline)
	}
	_, _ = st.Receive()
	st2, w2 := open(t, t.Context(), c, "nodeadline", "close")
	if w2.GetDeadlineUnixNano() != 0 {
		t.Fatal("the server saw a deadline without one being set")
	}
	_, _ = st2.Receive()
	t.Logf("server deadline %v before the client's", clientDeadline.Sub(serverDeadline))
}

// (3) Deadlines, finding: an expired deadline ends neither a client blocked in Receive nor a
// server handler blocked in Receive, although both call contexts have expired.
func TestFinding_DeadlineDoesNotEndBlockedStream(t *testing.T) {
	e := newEnv(t, liveness{})
	c := e.client(t, "deadline-f", "", liveness{})
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	st, _ := open(t, ctx, c, "deadline-f", "")
	rec, _ := e.svc.Record("deadline-f", time.Second)
	recv := receiveAsync(st)
	if err, ok := within(recv, 2*time.Second); ok {
		t.Fatalf("Receive returned at the deadline (%v): the finding no longer holds", err)
	}
	if ended(rec, 0) {
		t.Fatal("the server handler ended at the deadline: the finding no longer holds")
	}
	if !errors.Is(rec.CallContextErr(), context.DeadlineExceeded) || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("call contexts: server %v, client %v", rec.CallContextErr(), ctx.Err())
	}
	_ = st.CloseResponse()
	if _, ok := within(recv, 2*time.Second); !ok || !ended(rec, 2*time.Second) {
		t.Fatal("CloseResponse did not end the call")
	}
}

// (3) Unary calls honour deadlines on both sides.
func TestUnaryDeadline(t *testing.T) {
	e := newEnv(t, liveness{})
	c := e.client(t, "unary", "", liveness{})

	t.Run("unary expires", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := c.Renew(ctx, connect.NewRequest(&agentv1.RenewRequest{DelayMs: 5000}))
		wantCode(t, err, connect.CodeDeadlineExceeded)
		if el := time.Since(start); el > 600*time.Millisecond {
			t.Fatalf("deadline fired after %v", el)
		}
		deadline := time.Now().Add(2 * time.Second)
		for len(e.svc.Renews()) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		// The client resets the stream at its deadline, usually just before the server's own
		// deadline (computed on arrival) fires, so the server sees either error.
		r := e.svc.Renews()
		if len(r) != 1 || r[0].Deadline.IsZero() || r[0].CtxErr == nil {
			t.Fatalf("server renew records %+v", r)
		}
		t.Logf("unary deadline: server call context ended with %v", r[0].CtxErr)
	})

	t.Run("unary within deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		res, err := c.Renew(ctx, connect.NewRequest(&agentv1.RenewRequest{DelayMs: 10}))
		if err != nil || string(res.Msg.GetCertificate()) != "cert" {
			t.Fatalf("renew: %v %v", res, err)
		}
	})
}

// (4) The 4 MiB control-message limit, with gzip off on the server (see the compression finding
// below): exactly 4 MiB passes, one byte more is refused, in both directions, by the sender's
// limit and by the receiver's limit.
func TestMessageSizeLimits(t *testing.T) {
	const limit = control.MaxControlMessage
	noGzip := connect.WithCompression("gzip", nil, nil)
	e := newEnv(t, liveness{}, noGzip)
	// A second controller without a send limit, to show the client's read limit.
	eNoSend := newEnvWithCA(t, e.ca, liveness{}, noGzip, connect.WithSendMaxBytes(0))

	t.Run("client sends exactly 4 MiB", func(t *testing.T) {
		c := e.client(t, "size1", "", liveness{})
		st, _ := open(t, t.Context(), c, "size1", "")
		m := control.AgentBlob(limit)
		if err := st.Send(m); err != nil {
			t.Fatal(err)
		}
		got, err := st.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if got.GetSnapshot().GetRevision() != uint64(len(m.GetBlob().GetData())) {
			t.Fatalf("server echoed %d", got.GetSnapshot().GetRevision())
		}
	})
	t.Run("client send limit refuses 4 MiB + 1", func(t *testing.T) {
		c := e.client(t, "size2", "", liveness{})
		st, _ := open(t, t.Context(), c, "size2", "")
		err := st.Send(control.AgentBlob(limit + 1))
		wantCode(t, err, connect.CodeResourceExhausted)
	})
	t.Run("server read limit refuses 4 MiB + 1", func(t *testing.T) {
		c := e.client(t, "size3", "", liveness{}, connect.WithSendMaxBytes(0))
		st, _ := open(t, t.Context(), c, "size3", "")
		_ = st.Send(control.AgentBlob(limit + 1))
		_, err := st.Receive()
		wantCode(t, err, connect.CodeResourceExhausted)
		rec, _ := e.svc.Record("size3", time.Second)
		<-rec.Done
		wantCode(t, rec.Snapshot().EndErr, connect.CodeResourceExhausted)
	})
	t.Run("server sends exactly 4 MiB", func(t *testing.T) {
		c := e.client(t, "size4", "", liveness{})
		st, _ := open(t, t.Context(), c, "size4", "send-blob:"+strconv.Itoa(limit)+",random")
		m, err := st.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if m.GetBlob() == nil {
			t.Fatalf("unexpected message")
		}
	})
	t.Run("server send limit refuses 4 MiB + 1", func(t *testing.T) {
		c := e.client(t, "size5", "", liveness{})
		st, _ := open(t, t.Context(), c, "size5", "send-blob:"+strconv.Itoa(limit+1)+",random")
		_, err := st.Receive()
		wantCode(t, err, connect.CodeResourceExhausted)
	})
	t.Run("client read limit refuses 4 MiB + 1 when the server ends the call", func(t *testing.T) {
		c := eNoSend.client(t, "size6", eNoSend.addr, liveness{})
		st, _ := open(t, t.Context(), c, "size6", "send-blob:"+strconv.Itoa(limit+1)+",random,close")
		_, err := st.Receive()
		wantCode(t, err, connect.CodeResourceExhausted)
	})
}

// (4) Finding: with gzip negotiated (connect-go clients accept it by default), the server's send
// limit is checked against the compressed size, so a compressible message above 4 MiB is sent.
// The client's read limit, which counts the decompressed size, then rejects it.
func TestFinding_SendLimitCountsCompressedSize(t *testing.T) {
	const limit = control.MaxControlMessage
	e := newEnv(t, liveness{})
	c := e.client(t, "gzip", "", liveness{})
	st, _ := open(t, t.Context(), c, "gzip", "send-blob:"+strconv.Itoa(limit+1)+",close")
	_, err := st.Receive()
	wantCode(t, err, connect.CodeResourceExhausted)
	rec, _ := e.svc.Record("gzip", time.Second)
	<-rec.Done
	if r := rec.Snapshot(); r.EndErr != nil {
		t.Fatalf("the server's Send failed (%v): the finding no longer holds", r.EndErr)
	}
	t.Logf("server sent a %d-byte message despite its 4 MiB send limit; client: %v", limit+1, err)

	// The other way round: an incompressible message of exactly 4 MiB grows under gzip and is
	// refused by the sender.
	c3 := e.client(t, "gzip-exact", "", liveness{})
	st3, _ := open(t, t.Context(), c3, "gzip-exact", "send-blob:"+strconv.Itoa(limit)+",random,close")
	_, err = st3.Receive()
	wantCode(t, err, connect.CodeResourceExhausted)
	t.Logf("exactly 4 MiB of random bytes under gzip: %v", err)

	// Without gzip on the server, the send limit counts the message itself again.
	eNoGzip := newEnvWithCA(t, e.ca, liveness{}, connect.WithCompression("gzip", nil, nil))
	c2 := eNoGzip.client(t, "nogzip", eNoGzip.addr, liveness{})
	st2, _ := open(t, t.Context(), c2, "nogzip", "send-blob:"+strconv.Itoa(limit+1))
	_, err = st2.Receive()
	wantCode(t, err, connect.CodeResourceExhausted)
	rec2, _ := eNoGzip.svc.Record("nogzip", time.Second)
	<-rec2.Done
	wantCode(t, rec2.Snapshot().EndErr, connect.CodeResourceExhausted)
}

// (4) Finding: when the client's read limit rejects a message on a stream the server keeps open,
// Receive does not return: it drains the response body to read the trailers.
func TestFinding_ReadLimitBlocksOnOpenStream(t *testing.T) {
	const limit = control.MaxControlMessage
	e := newEnv(t, liveness{}, connect.WithSendMaxBytes(0))
	c := e.client(t, "readlimit", "", liveness{})
	st, _ := open(t, t.Context(), c, "readlimit", "send-blob:"+strconv.Itoa(limit+1)+",random")
	recv := receiveAsync(st)
	if err, ok := within(recv, 2*time.Second); ok {
		t.Fatalf("Receive returned (%v): the finding no longer holds", err)
	}
	_ = st.CloseResponse()
	err, ok := within(recv, 2*time.Second)
	if !ok {
		t.Fatal("Receive still blocked after CloseResponse")
	}
	t.Logf("Receive blocked until CloseResponse, then returned %v (code %v)", err, connect.CodeOf(err))
}

// (5) HTTP/2 PING liveness: with the path blackholed, both ends close the connection after the
// read-idle timeout plus the ping timeout. Scaled values; TestLivenessRealValues uses 20 s / 10 s.
func TestLivenessBlackhole(t *testing.T) {
	live := liveness{readIdle: time.Second, ping: 500 * time.Millisecond}
	for _, peek := range []bool{false, true} {
		name := map[bool]string{false: "direct proxy", true: "TLS passthrough"}[peek]
		t.Run(name, func(t *testing.T) {
			client, server := blackholeDetection(t, live, peek)
			upper := live.readIdle + live.ping + 750*time.Millisecond
			if client > upper || server > upper || client < live.ping || server < live.ping {
				t.Fatalf("detection after blackhole: client %v, server %v; want between %v and %v", client, server, live.ping, upper)
			}
			t.Logf("%v / %v: client detected after %v, server after %v", live.readIdle, live.ping, client, server)
		})
	}
}

// TestLivenessRealValues runs the blackhole test with the values of docs/03 (ReadIdleTimeout
// 20 s, PingTimeout 10 s). It takes about 35 s, so it runs only with S4_REAL_LIVENESS=1.
func TestLivenessRealValues(t *testing.T) {
	if os.Getenv("S4_REAL_LIVENESS") != "1" {
		t.Skip("set S4_REAL_LIVENESS=1")
	}
	live := liveness{readIdle: 20 * time.Second, ping: 10 * time.Second}
	for _, peek := range []bool{false, true} {
		t.Run("passthrough="+strconv.FormatBool(peek), func(t *testing.T) {
			t.Parallel()
			client, server := blackholeDetection(t, live, peek)
			t.Logf("20 s / 10 s, passthrough=%v: client detected after %v, server after %v", peek, client, server)
			if client > 31*time.Second || server > 31*time.Second || client < live.ping || server < live.ping {
				t.Errorf("detection out of range: client %v, server %v", client, server)
			}
		})
	}
}

// blackholeDetection opens an idle session through a proxy, freezes the proxy and returns how
// long each end needed to notice.
func blackholeDetection(t *testing.T, live liveness, peek bool) (client, server time.Duration) {
	t.Helper()
	e := newEnv(t, live)
	p, err := proxy.New(func(string) (string, bool) { return e.addr, true }, peek)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	name := "live-" + strconv.FormatBool(peek)
	c := e.client(t, name, p.Addr(), live)
	st, _ := open(t, t.Context(), c, name, "")
	rec, _ := e.svc.Record(name, time.Second)

	clientDone := make(chan time.Time, 1)
	go func() {
		_, err := st.Receive()
		t.Logf("client stream ended: %v (code %v)", err, connect.CodeOf(err))
		clientDone <- time.Now()
	}()
	// Let a few ping rounds pass on the healthy path first.
	time.Sleep(live.readIdle / 2)
	frozen := time.Now()
	p.Freeze()
	timeout := time.After(live.readIdle + live.ping + 5*time.Second)
	serverDone := rec.Done
	var cEnd, sEnd time.Time
	for cEnd.IsZero() || sEnd.IsZero() {
		select {
		case cEnd = <-clientDone:
		case <-serverDone:
			sEnd = rec.Snapshot().Ended
			serverDone = nil // a nil channel is never selected again
		case <-timeout:
			t.Fatalf("not detected: client %v, server %v", !cEnd.IsZero(), !sEnd.IsZero())
		}
	}
	t.Logf("server session ended: %v", rec.Snapshot().EndErr)
	return cEnd.Sub(frozen), sEnd.Sub(frozen)
}

// A healthy idle session survives many ping intervals.
func TestIdleSessionSurvivesPings(t *testing.T) {
	live := liveness{readIdle: 200 * time.Millisecond, ping: 100 * time.Millisecond}
	e := newEnv(t, live)
	p, err := proxy.New(func(string) (string, bool) { return e.addr, true }, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	c := e.client(t, "idle", p.Addr(), live)
	st, _ := open(t, t.Context(), c, "idle", "")
	start := len(p.Seen())
	time.Sleep(3 * time.Second) // 15 read-idle intervals
	idleBytes := len(p.Seen()) - start
	if err := st.Send(control.AgentBlob(100)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Receive(); err != nil {
		t.Fatalf("session died while idle: %v", err)
	}
	rec, _ := e.svc.Record("idle", time.Second)
	select {
	case <-rec.Done:
		t.Fatal("server ended the idle session")
	default:
	}
	// A PING frame is 17 bytes, about 39 in a TLS record; expect at least ten while idle.
	if idleBytes < 10*39 {
		t.Fatalf("only %d bytes crossed the proxy while idle; no pings?", idleBytes)
	}
	t.Logf("%d bytes of PING traffic in 3 s of idleness at %v / %v", idleBytes, live.readIdle, live.ping)
}

// (7) Behind a TLS-passthrough route: the proxy routes by SNI only, mutual TLS terminates at the
// controller, the handler sees the agent's identity, and the proxy sees only ciphertext.
func TestTLSPassthrough(t *testing.T) {
	e := newEnv(t, liveness{})
	reauth := newEnvWithCA(t, e.ca, liveness{})
	routes := map[string]string{"controller." + td: e.addr, "reauth.controller." + td: reauth.addr}
	p, err := proxy.New(func(sni string) (string, bool) { a, ok := routes[sni]; return a, ok }, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	c := e.client(t, "pt", p.Addr(), liveness{})
	st, w := open(t, t.Context(), c, "pt", "")
	if w.GetPeerIdentity() != agentID("pt") {
		t.Fatalf("controller saw peer %q through the passthrough", w.GetPeerIdentity())
	}
	marker := []byte("PLAINTEXT-MARKER-0123456789-must-not-be-visible-at-the-proxy")
	payload := bytes.Repeat(marker, 64)
	if err := st.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Blob{Blob: &agentv1.Blob{Data: payload}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Receive(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(p.Seen(), marker) {
		t.Fatal("the passthrough proxy saw plaintext")
	}
	if snis := p.SNIs(); len(snis) != 1 || snis[0] != "controller."+td {
		t.Fatalf("proxy routed SNIs %v", snis)
	}

	t.Run("unknown SNI is closed", func(t *testing.T) {
		conn, err := tls.Dial("tcp", p.Addr(), &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "other.example", RootCAs: e.ca.Roots})
		if err == nil {
			conn.Close()
			t.Fatal("handshake for an unknown SNI succeeded")
		}
	})
	t.Run("not TLS is closed", func(t *testing.T) {
		conn, err := net.Dial("tcp", p.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(7 * time.Second))
		if n, err := conn.Read(make([]byte, 1)); err == nil || n > 0 {
			t.Fatalf("plain HTTP got an answer (%d bytes, %v)", n, err)
		}
	})
}

// Mutual TLS is enforced: wrong CA, wrong role, TLS 1.2 and a missing client certificate fail.
func TestRejectsWrongIdentity(t *testing.T) {
	e := newEnv(t, liveness{})
	call := func(t *testing.T, cfg *tls.Config) error {
		var protocols http.Protocols
		protocols.SetHTTP2(true)
		tr := &http.Transport{TLSClientConfig: cfg, Protocols: &protocols,
			DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, n, e.addr) }}
		defer tr.CloseIdleConnections()
		c := agentv1connect.NewControlClient(&http.Client{Transport: tr}, "https://controller."+td, connect.WithGRPC())
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		_, err := c.Renew(ctx, connect.NewRequest(&agentv1.RenewRequest{}))
		return err
	}
	good, _ := e.ca.Leaf("/org/org_1/connector/ok", []string{"ok.connector." + td}, true, true)
	base := func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: e.ca.Roots, ServerName: "controller." + td, Certificates: []tls.Certificate{good}}
	}
	if err := call(t, base()); err != nil {
		t.Fatalf("baseline call failed: %v", err)
	}
	other, _ := pki.NewCA(td)
	foreign, _ := other.Leaf("/org/org_1/connector/x", []string{"x.connector." + td}, true, true)
	ctrl, _ := e.ca.Leaf("/controller/n2", []string{"n2.controller." + td}, true, true)
	cases := map[string]func(*tls.Config){
		"certificate from another CA": func(c *tls.Config) { c.Certificates = []tls.Certificate{foreign} },
		"controller role as client":   func(c *tls.Config) { c.Certificates = []tls.Certificate{ctrl} },
		"no client certificate":       func(c *tls.Config) { c.Certificates = nil },
		"TLS 1.2":                     func(c *tls.Config) { c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS12 },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			mod(cfg)
			if err := call(t, cfg); err == nil {
				t.Fatal("call succeeded")
			}
		})
	}
}
