// SPDX-License-Identifier: Apache-2.0

package s2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// forEach runs f for every implementation and half-close mode.
func forEach(t *testing.T, modes []Mode, f func(t *testing.T, impl Impl, mode Mode)) {
	for _, impl := range impls() {
		for _, mode := range modes {
			t.Run(impl.Name()+"/"+mode.String(), func(t *testing.T) { f(t, impl, mode) })
		}
	}
}

var bothModes = []Mode{ModeRaw, ModeFramed}

type recvResult struct {
	n    int64
	hash [32]byte
	err  error
}

func hashAll(r io.Reader) recvResult {
	h := sha256.New()
	n, err := io.Copy(h, r)
	var out recvResult
	out.n, out.err = n, err
	copy(out.hash[:], h.Sum(nil))
	return out
}

// --- Criterion 1: 1 GiB in both directions concurrently ---------------------------------------

func TestDuplex(t *testing.T) {
	size := sizeEnv()
	forEach(t, bothModes, func(t *testing.T, impl Impl, mode Mode) {
		conRecv := make(chan recvResult, 1)
		p := newPair(t, impl, pairOpts{params: RPMGRParams(), mode: mode, onStrm: func(st *Stream) {
			st.WriteResult(ResultOK)
			got := make(chan recvResult, 1)
			go func() { got <- hashAll(st) }()
			if _, err := io.CopyN(st, newPattern(2), size); err != nil {
				conRecv <- recvResult{err: err}
				return
			}
			r := <-got // FIN only after the gateway's FIN, so raw mode is not affected (see half-close)
			st.CloseWrite()
			conRecv <- r
		}})
		start := time.Now()
		st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP, RouteID: "duplex"})
		if err != nil {
			t.Fatal(err)
		}
		sent := make(chan error, 1)
		go func() {
			_, err := io.CopyN(st, newPattern(1), size)
			if err == nil {
				err = st.CloseWrite()
			}
			sent <- err
		}()
		if res, err := st.Result(); err != nil || res.Code != ResultOK {
			t.Fatalf("StreamResult %v %v", res, err)
		}
		gwRecv := hashAll(st)
		if err := waitErr(t, sent, 5*time.Minute, "gateway send"); err != nil {
			t.Fatalf("gateway send: %v", err)
		}
		cr := <-conRecv
		elapsed := time.Since(start)
		if cr.err != nil || cr.n != size || cr.hash != patternHash(1, size) {
			t.Fatalf("connector received %d bytes, err %v, hash ok %v", cr.n, cr.err, cr.hash == patternHash(1, size))
		}
		if gwRecv.err != nil || gwRecv.n != size || gwRecv.hash != patternHash(2, size) {
			t.Fatalf("gateway received %d bytes, err %v", gwRecv.n, gwRecv.err)
		}
		st.Close()
		mibs := float64(size) / (1 << 20) / elapsed.Seconds()
		t.Logf("%d MiB each way in %v: %.0f MiB/s per direction (indicative, loopback, shared host)", size>>20, elapsed.Round(time.Millisecond), mibs)
	})
}

// --- Criterion 2: half-close in each direction -------------------------------------------------

// The gateway (public client) sends its FIN first; the connector (service) keeps sending.
func TestHalfClose_GatewayFirst(t *testing.T) {
	const a, b = 1 << 20, 4 << 20
	forEach(t, bothModes, func(t *testing.T, impl Impl, mode Mode) {
		conGot := make(chan recvResult, 1)
		p := newPair(t, impl, pairOpts{params: RPMGRParams(), mode: mode, onStrm: func(st *Stream) {
			st.WriteResult(ResultOK)
			r := hashAll(st) // until the gateway's FIN
			conGot <- r
			if r.err == nil {
				io.CopyN(st, newPattern(4), b) // the service keeps sending after the client's FIN
				st.CloseWrite()
			}
		}})
		st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(st, newPattern(3), a); err != nil {
			t.Fatal(err)
		}
		st.CloseWrite()
		r := <-conGot
		if r.err != nil || r.n != a || r.hash != patternHash(3, a) {
			t.Fatalf("connector got %d bytes, err %v", r.n, r.err)
		}
		g := hashAll(st)
		if g.err != nil || g.n != b || g.hash != patternHash(4, b) {
			t.Fatalf("gateway got %d of %d bytes after its FIN, err %v", g.n, b, g.err)
		}
	})
}

// halfCloseConnectorFirst: the service sends its FIN first; the public client keeps sending.
// It returns what the connector received after its own FIN and the gateway's send error.
func halfCloseConnectorFirst(t *testing.T, impl Impl, mode Mode) (conGot recvResult, gwGot recvResult, gwSendErr error) {
	const a, b = 4 << 20, 1 << 20
	got := make(chan recvResult, 1)
	finSent := make(chan struct{})
	p := newPair(t, impl, pairOpts{params: RPMGRParams(), mode: mode, onStrm: func(st *Stream) {
		st.WriteResult(ResultOK)
		io.CopyN(st, newPattern(5), b)
		st.CloseWrite() // the service's FIN
		close(finSent)
		got <- hashAll(st) // the client's remaining bytes must still arrive
	}})
	st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP})
	if err != nil {
		t.Fatal(err)
	}
	gwGot = hashAll(st) // until the connector's FIN
	<-finSent
	time.Sleep(50 * time.Millisecond)
	_, gwSendErr = io.CopyN(st, newPattern(6), a)
	if gwSendErr == nil {
		gwSendErr = st.CloseWrite()
	}
	select {
	case conGot = <-got:
	case <-time.After(10 * time.Second):
		conGot = recvResult{err: errors.New("connector never saw the end of the client's data")}
	}
	if conGot.err == nil && (conGot.n != a || conGot.hash != patternHash(6, a)) {
		conGot.err = errors.New("connector data mismatch")
	}
	if gwGot.err == nil && (gwGot.n != b || gwGot.hash != patternHash(5, b)) {
		gwGot.err = errors.New("gateway data mismatch")
	}
	return conGot, gwGot, gwSendErr
}

func TestHalfClose_ConnectorFirst_Framed(t *testing.T) {
	forEach(t, []Mode{ModeFramed}, func(t *testing.T, impl Impl, mode Mode) {
		con, gw, sendErr := halfCloseConnectorFirst(t, impl, mode)
		if gw.err != nil || sendErr != nil || con.err != nil {
			t.Fatalf("gateway recv err %v, gateway send err %v, connector recv %d bytes err %v", gw.err, sendErr, con.n, con.err)
		}
	})
}

// The design as written (ADR-0005): the connector's FIN is the end of the HTTP response. This
// test documents that net/http's server then resets the request stream with
// RST_STREAM(NO_ERROR), so the client-to-service direction is cut off.
func TestHalfClose_ConnectorFirst_RawLosesClientData(t *testing.T) {
	forEach(t, []Mode{ModeRaw}, func(t *testing.T, impl Impl, mode Mode) {
		con, gw, sendErr := halfCloseConnectorFirst(t, impl, mode)
		t.Logf("gateway recv err: %v; gateway send err after connector FIN: %v; connector received %d of %d bytes after its FIN, err: %v",
			gw.err, sendErr, con.n, 4<<20, con.err)
		if con.err == nil && sendErr == nil {
			t.Fatal("raw mode delivered the client's data after the connector's FIN; the documented limitation no longer holds")
		}
	})
}

// --- Criterion 3: abort mid-stream in both directions ------------------------------------------

func TestAbort(t *testing.T) {
	for _, who := range []string{"gateway", "connector"} {
		t.Run(who, func(t *testing.T) {
			forEach(t, bothModes, func(t *testing.T, impl Impl, mode Mode) {
				conRead := make(chan error, 1)
				conWrite := make(chan error, 1)
				var conStream atomic.Pointer[Stream]
				received := make(chan struct{})
				p := newPair(t, impl, pairOpts{params: RPMGRParams(), mode: mode, onStrm: func(st *Stream) {
					conStream.Store(st)
					st.WriteResult(ResultOK)
					go func() {
						n := int64(0)
						buf := make([]byte, 32<<10)
						for {
							k, err := st.Read(buf)
							n += int64(k)
							if n >= 4<<20 && who == "connector" {
								select {
								case <-received:
								default:
									close(received)
								}
							}
							if err != nil {
								conRead <- err
								return
							}
						}
					}()
					_, err := io.Copy(st, newPattern(7))
					conWrite <- err
				}})
				st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP})
				if err != nil {
					t.Fatal(err)
				}
				gwWrite := make(chan error, 1)
				go func() { _, err := io.Copy(st, newPattern(8)); gwWrite <- err }()
				gwRead := make(chan error, 1)
				go func() {
					n := int64(0)
					buf := make([]byte, 32<<10)
					for {
						k, err := st.Read(buf)
						n += int64(k)
						if n >= 4<<20 && who == "gateway" {
							select {
							case <-received:
							default:
								close(received)
							}
						}
						if err != nil {
							gwRead <- err
							return
						}
					}
				}()
				<-received
				start := time.Now()
				if who == "gateway" {
					st.Abort()
				} else {
					conStream.Load().Abort()
				}
				for name, ch := range map[string]chan error{"connector read": conRead, "connector write": conWrite, "gateway read": gwRead, "gateway write": gwWrite} {
					err := waitErr(t, ch, 2*time.Second, name)
					if err == nil || errors.Is(err, io.EOF) {
						t.Errorf("%s after %s abort: %v, want a reset error, not EOF", name, who, err)
					}
				}
				t.Logf("%s abort observed on all four ends within %v", who, time.Since(start).Round(time.Millisecond))
			})
		})
	}
}

// --- Criterion 4: control stream first; OpenRequest --------------------------------------------

func TestControlStreamIsFirstRequest(t *testing.T) {
	forEach(t, []Mode{ModeFramed}, func(t *testing.T, impl Impl, mode Mode) {
		p := newPair(t, impl, pairOpts{params: RPMGRParams(), mode: mode, onStrm: func(st *Stream) {
			st.WriteResult(ResultOK)
			st.CloseWrite()
			io.Copy(io.Discard, st)
		}})
		st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP})
		if err != nil {
			t.Fatal(err)
		}
		st.CloseWrite()
		io.Copy(io.Discard, st)
		if p.con.FirstPath != "/control" || p.con.Violations.Load() != 0 {
			t.Fatalf("first request %q, violations %d", p.con.FirstPath, p.con.Violations.Load())
		}
	})
}

// A gateway that opens a user stream before the session control stream is refused.
func TestStreamBeforeControlRefused(t *testing.T) {
	for _, impl := range impls() {
		t.Run(impl.Name(), func(t *testing.T) {
			pki, _ := NewTestPKI("rpmgr-s2test")
			gwCert, _ := pki.Issue(gatewayID)
			conCert, _ := pki.Issue(connID)
			ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.GatewayTLS(gwCert))
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			con := NewConnectorSession(ModeFramed, nil)
			go func() {
				c, err := tls.Dial("tcp", ln.Addr().String(), pki.ConnectorTLS(conCert, gatewayID))
				if err == nil {
					impl.Serve(c, con, RPMGRParams())
				}
			}()
			gc, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			if err := gc.(*tls.Conn).Handshake(); err != nil {
				t.Fatal(err)
			}
			client, err := impl.NewClient(gc, RPMGRParams())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var buf bytes.Buffer
			WriteMsg(&buf, StreamOpen{Kind: KindTCP})
			req, _ := http.NewRequest(http.MethodPost, "http://rpmgr-session/stream", &buf)
			client.TryReserve()
			resp, err := client.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusMisdirectedRequest || con.Violations.Load() != 1 {
				t.Fatalf("status %d, violations %d", resp.StatusCode, con.Violations.Load())
			}
		})
	}
}

func echoServe(st *Stream) {
	io.Copy(st, st)
	st.CloseWrite()
}

func TestOpenRequest_Accepted(t *testing.T) {
	forEach(t, bothModes, func(t *testing.T, impl Impl, mode Mode) {
		p := newPair(t, impl, pairOpts{params: RPMGRParams(), mode: mode, onOpen: func(c Control) OpenDecision {
			return OpenDecision{Accept: true, Serve: func(st *Stream) {
				// The far end of the relay: answer the first chunk at once, then echo.
				st.Write(append([]byte("first:"), c.FirstChunk...))
				echoServe(st)
			}}
		}})
		st, err := p.con.RequestStream(ctxTimeout(t, 5*time.Second), KindRelayOut, []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		if st.Open.OpenID == 0 || st.Open.Result == nil || st.Open.Result.Code != ResultOK || st.Open.Kind != KindRelayOut {
			t.Fatalf("StreamOpen %+v", st.Open)
		}
		// The connector writes no StreamResult: the gateway's first bytes back are payload.
		payload := bytes.Repeat([]byte("x"), 100<<10)
		go st.Write(payload)
		want := append([]byte("first:hello"), payload...)
		got := make([]byte, len(want))
		if _, err := io.ReadFull(st, got); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("read %v, equal %v", err, bytes.Equal(got, want))
		}
		if mode == ModeRaw {
			st.Close() // raw mode cannot half-close from the connector (see TestHalfClose_*)
			return
		}
		st.CloseWrite()
		if rest, err := io.ReadAll(st); err != nil || len(rest) != 0 {
			t.Fatalf("after FIN: %d bytes, %v", len(rest), err)
		}
	})
}

func TestOpenRequest_Rejected(t *testing.T) {
	forEach(t, []Mode{ModeFramed}, func(t *testing.T, impl Impl, mode Mode) {
		p := newPair(t, impl, pairOpts{params: RPMGRParams(), mode: mode, onOpen: func(Control) OpenDecision {
			return OpenDecision{Accept: false, Code: ResultRefused}
		}})
		_, err := p.con.RequestStream(ctxTimeout(t, 5*time.Second), KindRelayOut, nil)
		var rej OpenRejectedError
		if !errors.As(err, &rej) || rej.Code != ResultRefused {
			t.Fatalf("err %v", err)
		}
	})
}

func TestOpenRequest_DuplicateOpenIDRejected(t *testing.T) {
	forEach(t, []Mode{ModeFramed}, func(t *testing.T, impl Impl, mode Mode) {
		var calls atomic.Int32
		p := newPair(t, impl, pairOpts{params: RPMGRParams(), mode: mode, onOpen: func(Control) OpenDecision {
			calls.Add(1)
			return OpenDecision{Accept: true, Serve: echoServe}
		}})
		if _, err := p.con.RequestStreamWithID(ctxTimeout(t, 5*time.Second), 7, KindRelayOut, nil); err != nil {
			t.Fatal(err)
		}
		_, err := p.con.RequestStreamWithID(ctxTimeout(t, 5*time.Second), 7, KindRelayOut, nil)
		var rej OpenRejectedError
		if !errors.As(err, &rej) || rej.Code != ResultProto || calls.Load() != 1 {
			t.Fatalf("err %v, gateway decided %d times", err, calls.Load())
		}
	})
}

func TestOpenRequest_Timeout(t *testing.T) {
	timeouts := []time.Duration{300 * time.Millisecond}
	if !testing.Short() {
		timeouts = append(timeouts, 10*time.Second) // the value from 03
	}
	for _, to := range timeouts {
		t.Run(to.String(), func(t *testing.T) {
			forEach(t, []Mode{ModeFramed}, func(t *testing.T, impl Impl, mode Mode) {
				release := make(chan struct{})
				lateRead := make(chan error, 1)
				p := newPair(t, impl, pairOpts{params: RPMGRParams(), mode: mode, onOpen: func(Control) OpenDecision {
					<-release // the gateway answers only after the connector gave up
					return OpenDecision{Accept: true, Serve: func(st *Stream) {
						_, err := io.ReadAll(st)
						lateRead <- err
					}}
				}})
				p.con.OpenTimeout = to
				start := time.Now()
				_, err := p.con.RequestStream(context.Background(), KindRelayOut, nil)
				el := time.Since(start)
				if !errors.Is(err, ErrOpenTimeout) || el < to || el > to+time.Second {
					t.Fatalf("err %v after %v", err, el)
				}
				close(release)
				// The late stream for the timed-out open_id is reset by the connector.
				if err := waitErr(t, lateRead, 5*time.Second, "late stream"); err == nil {
					t.Fatal("late stream for a timed-out open_id was not reset")
				}
			})
		})
	}
}

// --- Criterion 5 is measured in measure_test.go. -----------------------------------------------

// --- Criterion 6: flow-control pressure --------------------------------------------------------

// stallServer: route "stall" writes until it fails and never reads; route "noread" reads
// nothing; route "echo" echoes. written counts bytes the connector managed to send per route.
type stallServer struct {
	written sync.Map // *Stream → *atomic.Int64
}

func (s *stallServer) onStream(st *Stream) {
	st.WriteResult(ResultOK)
	switch st.Open.RouteID {
	case "stall":
		n := new(atomic.Int64)
		s.written.Store(st, n)
		buf := make([]byte, 16<<10)
		for {
			k, err := st.Write(buf)
			n.Add(int64(k))
			if err != nil {
				return
			}
		}
	case "noread":
		<-st.reqCtx.Done()
	default:
		echoServe(st)
	}
}

func (s *stallServer) total() int64 {
	var t int64
	s.written.Range(func(_, v any) bool { t += v.(*atomic.Int64).Load(); return true })
	return t
}

// echoOnce opens a stream, sends 1 KiB and reads it back.
func echoOnce(gw *GatewaySession, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	st, err := gw.OpenStream(ctx, StreamOpen{Kind: KindTCP, RouteID: "echo"})
	if err != nil {
		return err
	}
	defer st.Close()
	msg := bytes.Repeat([]byte("e"), 1024)
	done := make(chan error, 1)
	go func() {
		if _, err := st.Write(msg); err != nil {
			done <- err
			return
		}
		got := make([]byte, len(msg))
		_, err := io.ReadFull(st, got)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		st.Abort()
		return ctx.Err()
	}
}

// waitStable waits until f stops changing for quiet.
func waitStable(f func() int64, quiet, limit time.Duration) int64 {
	last, since := f(), time.Now()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		if v := f(); v != last {
			last, since = v, time.Now()
		} else if time.Since(since) >= quiet {
			break
		}
	}
	return last
}

func TestFlowControl_StalledStreamsDoNotBlockOthers(t *testing.T) {
	forEach(t, []Mode{ModeFramed}, func(t *testing.T, impl Impl, mode Mode) {
		srv := &stallServer{}
		p := newPair(t, impl, pairOpts{params: RPMGRParams(), mode: mode, onStrm: srv.onStream})
		// Four streams whose public clients stopped reading (gateway does not read) ...
		for i := 0; i < 4; i++ {
			st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP, RouteID: "stall"})
			if err != nil {
				t.Fatal(err)
			}
			st.Result()
		}
		// ... and four whose service stopped reading (connector does not read).
		for i := 0; i < 4; i++ {
			st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP, RouteID: "noread"})
			if err != nil {
				t.Fatal(err)
			}
			go io.Copy(st, newPattern(9))
		}
		held := waitStable(srv.total, 500*time.Millisecond, 20*time.Second)
		t.Logf("stalled streams hold %d MiB towards the gateway", held>>20)
		for i := 0; i < 20; i++ {
			if err := echoOnce(p.gw, 2*time.Second); err != nil {
				t.Fatalf("echo %d blocked by stalled streams: %v", i, err)
			}
		}
		if rtt, err := p.con.Ping(ctxTimeout(t, 2*time.Second)); err != nil {
			t.Fatalf("control stream blocked: %v", err)
		} else {
			t.Logf("control-stream Ping RTT under pressure: %v", rtt)
		}
	})
}

// With the connection window exhausted by stalled streams, other streams and the control
// stream stop; HTTP/2 PING keeps the session alive; the stall detector resets the oldest stalled
// streams and traffic resumes.
func TestFlowControl_StallDetectionUnderWindowPressure(t *testing.T) {
	forEach(t, []Mode{ModeFramed}, func(t *testing.T, impl Impl, mode Mode) {
		params := RPMGRParams()
		params.SendPingTimeout, params.PingTimeout = time.Second, time.Second
		srv := &stallServer{}
		p := newPair(t, impl, pairOpts{params: params, mode: mode, onStrm: srv.onStream})
		det := &StallDetector{Age: 300 * time.Millisecond, StreamWindow: params.StreamWindow, ConnWindow: params.ConnWindow}
		n := params.ConnWindow/params.StreamWindow + 1 // 17: more than the connection window holds
		var order []*Stream
		var resetOrder []int
		var mu sync.Mutex
		for i := 0; i < n; i++ {
			st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP, RouteID: "stall"})
			if err != nil {
				t.Fatal(err)
			}
			st.Result()
			i := i
			det.Track(func() {
				mu.Lock()
				resetOrder = append(resetOrder, i)
				mu.Unlock()
				st.Abort()
			})
			order = append(order, st)
			time.Sleep(5 * time.Millisecond)
		}
		held := waitStable(srv.total, 500*time.Millisecond, 30*time.Second)
		t.Logf("%d stalled streams hold %d MiB; connection window %d MiB", n, held>>20, params.ConnWindow>>20)
		if err := echoOnce(p.gw, time.Second); err == nil {
			t.Fatal("expected the exhausted connection window to block a new stream's data")
		}
		if _, err := p.con.Ping(ctxTimeout(t, time.Second)); err == nil {
			t.Fatal("expected the flow-controlled application Ping to block")
		}
		time.Sleep(3 * time.Second) // > SendPingTimeout + PingTimeout: HTTP/2 PING is not flow-controlled
		select {
		case <-p.gw.Ended():
			t.Fatal("session closed although HTTP/2 PINGs were answered")
		default:
		}
		resets := det.Check(time.Now())
		wantResets := n - (params.ConnWindow/2)/params.StreamWindow
		if resets != wantResets {
			t.Fatalf("detector reset %d streams, want %d", resets, wantResets)
		}
		for i, idx := range resetOrder {
			if idx != i {
				t.Fatalf("reset order %v, want oldest first", resetOrder)
			}
		}
		if err := echoOnce(p.gw, 2*time.Second); err != nil {
			t.Fatalf("traffic did not resume after the resets: %v", err)
		}
		if _, err := p.con.Ping(ctxTimeout(t, 2*time.Second)); err != nil {
			t.Fatalf("control stream did not resume: %v", err)
		}
		t.Logf("detector reset streams %v (oldest first); echo and Ping resumed", resetOrder)
	})
}

// A paused client (suspended ssh, paused download) without window pressure is never reset.
func TestFlowControl_PausedClientNotResetWithoutPressure(t *testing.T) {
	forEach(t, []Mode{ModeFramed}, func(t *testing.T, impl Impl, mode Mode) {
		params := RPMGRParams()
		srv := &stallServer{}
		p := newPair(t, impl, pairOpts{params: params, mode: mode, onStrm: srv.onStream})
		det := &StallDetector{Age: 100 * time.Millisecond, StreamWindow: params.StreamWindow, ConnWindow: params.ConnWindow}
		st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP, RouteID: "stall"})
		if err != nil {
			t.Fatal(err)
		}
		st.Result()
		tr := det.Track(st.Abort)
		stop := make(chan struct{})
		go det.Run(20*time.Millisecond, stop)
		time.Sleep(2 * time.Second) // 20 × Age
		close(stop)
		if det.Resets() != 0 {
			t.Fatal("paused stream was reset without window pressure")
		}
		buf := make([]byte, 1<<20)
		if _, err := io.ReadFull(st, buf); err != nil {
			t.Fatalf("paused stream did not resume: %v", err)
		}
		tr.Progress()
		st.Abort()
	})
}

// --- Window parameters actually applied -----------------------------------------------------

// TestWindowsApplied measures how many bytes a sender can put in flight on one stream whose
// receiver does not read: the receiver's stream window. Default parameters reproduce the x/net
// defaults that 03 cites; RPMGRParams must give 16 MiB in both directions.
func TestWindowsApplied(t *testing.T) {
	cases := []struct {
		name               string
		params             Params
		toGateway, toConn  int64 // expected stream windows
		toGatewayConnLimit int64
	}{
		{"defaults", Params{}, 4 << 20, 1 << 20, 0},
		{"rpmgr", RPMGRParams(), 16 << 20, 16 << 20, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			forEach(t, []Mode{ModeRaw}, func(t *testing.T, impl Impl, mode Mode) {
				srv := &stallServer{}
				p := newPair(t, impl, pairOpts{params: c.params, mode: mode, onStrm: srv.onStream})
				st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP, RouteID: "stall"})
				if err != nil {
					t.Fatal(err)
				}
				st.Result()
				toGw := waitStable(srv.total, 500*time.Millisecond, 20*time.Second)
				st2, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP, RouteID: "noread"})
				if err != nil {
					t.Fatal(err)
				}
				var sent atomic.Int64
				go func() {
					buf := make([]byte, 16<<10)
					for {
						k, err := st2.Write(buf)
						sent.Add(int64(k))
						if err != nil {
							return
						}
					}
				}()
				toCon := waitStable(sent.Load, 500*time.Millisecond, 20*time.Second)
				t.Logf("in flight to a non-reading gateway: %.2f MiB (want ≈ %d MiB); to a non-reading connector: %.2f MiB (want ≈ %d MiB)",
					float64(toGw)/(1<<20), c.toGateway>>20, float64(toCon)/(1<<20), c.toConn>>20)
				const slack = 512 << 10 // frames and writer buffers in flight
				if toGw < c.toGateway-slack || toGw > c.toGateway+slack {
					t.Errorf("gateway stream window ≈ %d bytes, want %d", toGw, c.toGateway)
				}
				if toCon < c.toConn-slack || toCon > c.toConn+slack {
					t.Errorf("connector stream window ≈ %d bytes, want %d", toCon, c.toConn)
				}
			})
		})
	}
}

// --- Criterion 7: stream limit -----------------------------------------------------------------

func TestStreamLimit_NeverBlocks(t *testing.T) {
	forEach(t, []Mode{ModeFramed}, func(t *testing.T, impl Impl, mode Mode) {
		params := RPMGRParams()
		params.MaxConcurrentStreams = 8 // the control stream takes one
		release := make(chan struct{})
		p := newPair(t, impl, pairOpts{params: params, mode: mode, onStrm: func(st *Stream) {
			st.WriteResult(ResultOK)
			<-release
			st.CloseWrite()
			io.Copy(io.Discard, st)
		}})
		var open []*Stream
		for i := 0; i < 7; i++ {
			st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP})
			if err != nil {
				t.Fatalf("stream %d: %v", i, err)
			}
			st.Result()
			open = append(open, st)
		}
		start := time.Now()
		_, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP})
		if !errors.Is(err, ErrNoCapacity) || time.Since(start) > 50*time.Millisecond {
			t.Fatalf("at the limit: err %v after %v, want ErrNoCapacity at once", err, time.Since(start))
		}
		close(release)
		for _, st := range open {
			st.CloseWrite()
			io.Copy(io.Discard, st)
			st.Close()
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP})
			if err == nil {
				st.Abort()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no slot after streams finished: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// With MaxConcurrentStreams 10 000, one session carries 9 999 concurrent user streams (plus the
// control stream), and the next open fails without blocking.
func TestStreamLimit_TenThousand(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("10 000 streams exceed the race detector's goroutine limit")
	}
	for _, frame := range []int{0, 16 << 10} { // 0: default SETTINGS_MAX_FRAME_SIZE (1 MiB)
		t.Run(map[int]string{0: "frame-default", 16 << 10: "frame-16KiB"}[frame], func(t *testing.T) {
			tenThousand(t, frame)
		})
	}
}

func tenThousand(t *testing.T, frame int) {
	forEach(t, []Mode{ModeFramed}, func(t *testing.T, impl Impl, mode Mode) {
		release := make(chan struct{})
		var ready sync.WaitGroup
		params := RPMGRParams()
		params.MaxReadFrameSize = frame
		p := newPair(t, impl, pairOpts{params: params, mode: mode, onStrm: func(st *Stream) {
			st.WriteResult(ResultOK)
			<-release
			echoServe(st)
		}})
		var before runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		streams := make([]*Stream, 0, 9999)
		for i := 0; i < 9999; i++ {
			st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP})
			if err != nil {
				t.Fatalf("stream %d: %v", i, err)
			}
			streams = append(streams, st)
		}
		for _, st := range streams {
			ready.Add(1)
			go func(st *Stream) { defer ready.Done(); st.Result() }(st)
		}
		ready.Wait()
		var after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&after)
		start := time.Now()
		if _, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP}); !errors.Is(err, ErrNoCapacity) || time.Since(start) > 50*time.Millisecond {
			t.Fatalf("stream 10 001: %v", err)
		}
		heap := int64(after.HeapInuse) - int64(before.HeapInuse)
		stacks := int64(after.StackInuse) - int64(before.StackInuse)
		t.Logf("9 999 open idle streams: active %d; after GC, heap +%d MiB (%d KiB per stream, both ends in one process, incl. 2 × 16 KiB harness read buffers), goroutine stacks +%d MiB, goroutines %d",
			p.gw.Active(), heap>>20, heap/9999>>10, stacks>>20, runtime.NumGoroutine())
		close(release)
		var wg sync.WaitGroup
		var failed atomic.Int32
		for _, st := range streams {
			wg.Add(1)
			go func(st *Stream) {
				defer wg.Done()
				msg := []byte("ping-0123456789")
				st.Write(msg)
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(st, got); err != nil || !bytes.Equal(got, msg) {
					failed.Add(1)
				}
				st.CloseWrite()
				io.Copy(io.Discard, st)
				st.Close()
			}(st)
		}
		wg.Wait()
		if failed.Load() != 0 {
			t.Fatalf("%d of 9 999 streams failed", failed.Load())
		}
	})
}

// --- Criterion 8: HTTP/2 PING liveness ---------------------------------------------------------

func TestPingLiveness_Blackhole(t *testing.T) {
	params := RPMGRParams() // SendPingTimeout 15 s, PingTimeout 10 s
	if testing.Short() {
		params.SendPingTimeout, params.PingTimeout = 1500*time.Millisecond, time.Second
	}
	limit := params.SendPingTimeout + params.PingTimeout
	forEach(t, []Mode{ModeFramed}, func(t *testing.T, impl Impl, mode Mode) {
		p := newPair(t, impl, pairOpts{params: params, mode: mode, oneWay: time.Millisecond})
		if _, err := p.con.Ping(ctxTimeout(t, time.Second)); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		p.proxy.Blackhole()
		var gwAt, conAt time.Duration
		gwDone, conDone := p.gw.Ended(), p.serve
		for gwAt == 0 || conAt == 0 {
			select {
			case <-gwDone:
				gwAt, gwDone = time.Since(start), nil
			case <-conDone:
				conAt, conDone = time.Since(start), nil
			case <-time.After(limit + 5*time.Second):
				t.Fatalf("blackholed session not detected within %v (gateway %v, connector %v)", limit+5*time.Second, gwAt, conAt)
			}
		}
		t.Logf("blackhole detected: gateway after %v, connector after %v (SendPingTimeout %v + PingTimeout %v = %v)",
			gwAt.Round(10*time.Millisecond), conAt.Round(10*time.Millisecond), params.SendPingTimeout, params.PingTimeout, limit)
		for _, at := range []time.Duration{gwAt, conAt} {
			if at < params.SendPingTimeout || at > limit+2*time.Second {
				t.Errorf("detection after %v, want between %v and %v", at, params.SendPingTimeout, limit+2*time.Second)
			}
		}
	})
}

// --- Identity check on the TCP transport -------------------------------------------------------

func TestTLS_WrongGatewayIDRejected(t *testing.T) {
	pki, _ := NewTestPKI("rpmgr-s2test")
	gwCert, _ := pki.Issue(gatewayID)
	conCert, _ := pki.Issue(connID)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.GatewayTLS(gwCert))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	other := Identity{Role: "gateway", Org: "org_2", ID: "gw_2"}
	if _, err := tls.Dial("tcp", ln.Addr().String(), pki.ConnectorTLS(conCert, other)); err == nil {
		t.Fatal("connector accepted a valid certificate of a different gateway")
	}
	var nerr net.Error
	_ = nerr
}
