// SPDX-License-Identifier: Apache-2.0

package grpcstack_test

import (
	"context"
	"crypto/rand"
	"net"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/felix-homelab/rpmgr/spikes/s4/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/control"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/grpcstack"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/pki"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/proxy"
)

const td = "rpmgr-s4test02"

func init() { grpcstack.TrustDomain = td }

// server is one of the three server setups the comparison runs against.
type server struct {
	name string
	addr string
	// record returns when the server-side session of agent ended, and how.
	record func(t *testing.T, agent string) (done <-chan struct{}, snapshot func() (time.Time, error, error))
}

type setup struct {
	ca      *pki.CA
	servers []server
}

func newSetup(t *testing.T, ca *pki.CA, so func(*control.ServerOptions), o grpcstack.Options) *setup {
	t.Helper()
	var err error
	if ca == nil {
		if ca, err = pki.NewCA(td); err != nil {
			t.Fatal(err)
		}
	}
	cert, err := ca.Leaf("/controller/n1", []string{"controller." + td}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	sopts := control.ServerOptions{CA: ca, Cert: cert}
	if so != nil {
		so(&sopts)
	}
	listen := func() net.Listener {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return ln
	}
	s := &setup{ca: ca}

	gsvc := grpcstack.NewService()
	grecord := func(svc *grpcstack.Service) func(*testing.T, string) (<-chan struct{}, func() (time.Time, error, error)) {
		return func(t *testing.T, agent string) (<-chan struct{}, func() (time.Time, error, error)) {
			r, err := svc.Record(agent, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			return r.Done, r.Snapshot
		}
	}
	native := grpcstack.NativeServer(gsvc, sopts, o)
	ln := listen()
	go func() { _ = native.Serve(ln) }()
	t.Cleanup(native.Stop)
	s.servers = append(s.servers, server{"grpc-go native server", ln.Addr().String(), grecord(gsvc)})

	hsvc := grpcstack.NewService()
	hs := grpcstack.HTTPServer(hsvc, sopts, o)
	ln2 := listen()
	go func() { _ = hs.ServeTLS(ln2, "", "") }()
	t.Cleanup(func() { _ = hs.Close() })
	s.servers = append(s.servers, server{"grpc-go ServeHTTP on net/http", ln2.Addr().String(), grecord(hsvc)})

	csvc := control.NewService()
	cs := control.NewHTTPServer(csvc, sopts)
	ln3 := listen()
	control.Serve(cs, ln3)
	t.Cleanup(func() { _ = cs.Close() })
	s.servers = append(s.servers, server{"connect-go server", ln3.Addr().String(),
		func(t *testing.T, agent string) (<-chan struct{}, func() (time.Time, error, error)) {
			r, err := csvc.Record(agent, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			return r.Done, func() (time.Time, error, error) { x := r.Snapshot(); return x.Ended, x.EndErr, x.CtxErr }
		}})
	return s
}

func (s *setup) dial(t *testing.T, name, addr string, live [2]time.Duration, o grpcstack.Options, extra ...grpc.DialOption) agentv1.ControlClient {
	t.Helper()
	cert, err := s.ca.Leaf("/org/org_1/connector/"+name, []string{name + ".connector." + td}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := grpcstack.Dial(control.ClientOptions{CA: s.ca, Cert: cert, Addr: addr, SendPingTimeout: live[0], PingTimeout: live[1]}, o, extra...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return agentv1.NewControlClient(cc)
}

type gstream = grpc.BidiStreamingClient[agentv1.AgentMessage, agentv1.ControllerMessage]

func open(t *testing.T, ctx context.Context, c agentv1.ControlClient, id, behaviour string) (gstream, *agentv1.Welcome) {
	t.Helper()
	st, err := c.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{AgentId: id, Behaviour: behaviour}}}); err != nil {
		t.Fatal(err)
	}
	m, err := st.Recv()
	if err != nil {
		t.Fatalf("receive welcome: %v", err)
	}
	return st, m.GetWelcome()
}

func recvAsync(st gstream) <-chan error {
	ch := make(chan error, 1)
	go func() {
		_, err := st.Recv()
		ch <- err
	}()
	return ch
}

func waitErr(ch <-chan error, d time.Duration) (error, bool) {
	select {
	case err := <-ch:
		return err, true
	case <-time.After(d):
		return nil, false
	}
}

func waitDone(ch <-chan struct{}, d time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

// The grpc-go client against all three servers: identity, cancellation and deadline while the
// client waits in Recv.
func TestGRPCClient_CancelAndDeadline(t *testing.T) {
	s := newSetup(t, nil, nil, grpcstack.Options{})
	for i, srv := range s.servers {
		t.Run(srv.name, func(t *testing.T) {
			agent := "g" + strconv.Itoa(i)
			c := s.dial(t, agent, srv.addr, [2]time.Duration{}, grpcstack.Options{})

			// Identity seen by the server.
			st, w := open(t, t.Context(), c, agent+"-id", "send-blob:10,close")
			if w.GetPeerIdentity() != "spiffe://"+td+"/org/org_1/connector/"+agent {
				t.Fatalf("server saw peer %q", w.GetPeerIdentity())
			}
			_, _ = st.Recv()

			// Cancel while the client waits in Recv.
			ctx, cancel := context.WithCancel(t.Context())
			st, _ = open(t, ctx, c, agent+"-cancel", "")
			done, snap := srv.record(t, agent+"-cancel")
			recv := recvAsync(st)
			time.Sleep(50 * time.Millisecond)
			start := time.Now()
			cancel()
			err, ok := waitErr(recv, time.Second)
			if !ok {
				t.Fatal("cancel: client Recv still blocked after 1 s")
			}
			if status.Code(err) != codes.Canceled {
				t.Fatalf("cancel: client got %v", err)
			}
			if !waitDone(done, time.Second) {
				t.Fatal("cancel: server did not end within 1 s")
			}
			ended, endErr, ctxErr := snap()
			t.Logf("cancel: client %v after %v; server after %v (end %v, ctx %v)", status.Code(err),
				time.Since(start).Round(time.Microsecond), ended.Sub(start).Round(time.Microsecond), endErr, ctxErr)

			// Deadline while the client waits in Recv.
			dctx, dcancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer dcancel()
			st, w = open(t, dctx, c, agent+"-deadline", "")
			if w.GetDeadlineUnixNano() == 0 {
				t.Fatal("deadline: server saw no deadline")
			}
			done, snap = srv.record(t, agent+"-deadline")
			deadline, _ := dctx.Deadline()
			err, ok = waitErr(recvAsync(st), 1500*time.Millisecond)
			if !ok {
				t.Fatal("deadline: client Recv still blocked 1 s after the deadline")
			}
			if status.Code(err) != codes.DeadlineExceeded {
				t.Fatalf("deadline: client got %v", err)
			}
			if !waitDone(done, time.Second) {
				t.Fatal("deadline: server did not end within 1 s of the deadline")
			}
			ended, endErr, ctxErr = snap()
			t.Logf("deadline: client %v at %+v; server at %+v (end %v, ctx %v)", status.Code(err),
				time.Since(deadline).Round(time.Millisecond), ended.Sub(deadline).Round(time.Millisecond), endErr, ctxErr)
		})
	}
}

// Full duplex on grpc-go: more data in each direction than the flow-control windows hold.
func TestGRPC_FullDuplex(t *testing.T) {
	s := newSetup(t, nil, nil, grpcstack.Options{})
	native := s.servers[0]
	c := s.dial(t, "duplex", native.addr, [2]time.Duration{}, grpcstack.Options{})
	const n, size = 2000, 32 << 10
	st, _ := open(t, t.Context(), c, "duplex", "duplex:"+strconv.Itoa(n)+","+strconv.Itoa(size))
	sendErr := make(chan error, 1)
	go func() {
		payload := make([]byte, size)
		for i := 1; i <= n; i++ {
			if err := st.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{Seq: uint64(i), Payload: payload}}}); err != nil {
				sendErr <- err
				return
			}
		}
		sendErr <- st.CloseSend()
	}()
	for i := 1; i <= n; i++ {
		m, err := st.Recv()
		if err != nil || m.GetSnapshot().GetRevision() != uint64(i) {
			t.Fatalf("receive %d: %v %v", i, m, err)
		}
	}
	if err := <-sendErr; err != nil {
		t.Fatal(err)
	}
	done, snap := native.record(t, "duplex")
	if !waitDone(done, 5*time.Second) {
		t.Fatal("server did not finish")
	}
	if _, endErr, _ := snap(); endErr != nil {
		t.Fatalf("server: %v", endErr)
	}
}

// grpc-go's message-size limits, including the cases where connect-go misbehaves: a stream the
// server keeps open, and gzip.
func TestGRPC_MessageSizeLimits(t *testing.T) {
	const limit = control.MaxControlMessage
	s := newSetup(t, nil, nil, grpcstack.Options{})
	native := s.servers[0]
	loose := newSetup(t, s.ca, nil, grpcstack.Options{MaxSend: 64 << 20, MaxRecv: 64 << 20}).servers[0]
	strict := grpcstack.Options{}

	t.Run("server sends exactly 4 MiB", func(t *testing.T) {
		c := s.dial(t, "s1", native.addr, [2]time.Duration{}, strict)
		st, _ := open(t, t.Context(), c, "s1", "send-blob:"+strconv.Itoa(limit)+",random")
		if m, err := st.Recv(); err != nil || m.GetBlob() == nil {
			t.Fatalf("got %v, %v", m, err)
		}
	})
	t.Run("server send limit refuses 4 MiB + 1", func(t *testing.T) {
		c := s.dial(t, "s2", native.addr, [2]time.Duration{}, strict)
		st, _ := open(t, t.Context(), c, "s2", "send-blob:"+strconv.Itoa(limit+1)+",random")
		_, err := st.Recv()
		if status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("client read limit on a stream the server keeps open returns at once", func(t *testing.T) {
		c := s.dial(t, "s3", loose.addr, [2]time.Duration{}, strict)
		st, _ := open(t, t.Context(), c, "s3", "send-blob:"+strconv.Itoa(limit+1)+",random")
		err, ok := waitErr(recvAsync(st), 2*time.Second)
		if !ok {
			t.Fatal("Recv still blocked after 2 s")
		}
		if status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("got %v", err)
		}
		done, snap := loose.record(t, "s3")
		if !waitDone(done, time.Second) {
			t.Fatal("server stream did not end")
		}
		_, endErr, _ := snap()
		t.Logf("client: %v; server stream ended with %v", err, endErr)
	})
	t.Run("client send limit refuses 4 MiB + 1", func(t *testing.T) {
		c := s.dial(t, "s4", native.addr, [2]time.Duration{}, strict)
		st, _ := open(t, t.Context(), c, "s4", "")
		err := st.Send(control.AgentBlob(limit + 1))
		if status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("server read limit refuses 4 MiB + 1", func(t *testing.T) {
		c := s.dial(t, "s5", native.addr, [2]time.Duration{}, grpcstack.Options{MaxSend: 64 << 20})
		st, _ := open(t, t.Context(), c, "s5", "")
		_ = st.Send(control.AgentBlob(limit + 1))
		_, err := st.Recv()
		if status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("gzip: the sender counts the compressed size, the receiver the decompressed size", func(t *testing.T) {
		c := s.dial(t, "s6", native.addr, [2]time.Duration{}, strict, grpc.WithDefaultCallOptions(grpc.UseCompressor("gzip")))
		st, _ := open(t, t.Context(), c, "s6", "")
		sendErr := st.Send(control.AgentBlob(limit + 1))
		_, recvErr := st.Recv()
		if status.Code(recvErr) != codes.ResourceExhausted {
			t.Fatalf("compressible 4 MiB + 1: send %v, receive %v", sendErr, recvErr)
		}
		t.Logf("compressible 4 MiB + 1 under gzip: Send returned %v; the server's read limit answered %v", sendErr, recvErr)
		st, _ = open(t, t.Context(), c, "s7", "")
		m := control.AgentBlob(limit)
		_, _ = rand.Read(m.GetBlob().GetData())
		t.Logf("incompressible exactly 4 MiB under gzip: Send returned %v", st.Send(m))
	})
}

// grpc-go keepalive on a blackholed path: the client pings after Time (grpc-go raises anything
// below 10 s to 10 s), the server after its own Time; both close after Timeout.
func TestGRPC_LivenessBlackhole(t *testing.T) {
	s := newSetup(t, nil, nil, grpcstack.Options{Time: time.Second, Timeout: 500 * time.Millisecond, MinTime: 5 * time.Second})
	native := s.servers[0]
	p, err := proxy.New(func(string) (string, bool) { return native.addr, true }, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	c := s.dial(t, "live", p.Addr(), [2]time.Duration{10 * time.Second, time.Second}, grpcstack.Options{})
	st, _ := open(t, t.Context(), c, "live", "")
	done, snap := native.record(t, "live")
	recv := recvAsync(st)
	time.Sleep(2 * time.Second)
	frozen := time.Now()
	p.Freeze()
	if !waitDone(done, 3*time.Second) {
		t.Fatal("server did not detect the dead path within 3 s")
	}
	ended, endErr, _ := snap()
	err, ok := waitErr(recv, 15*time.Second)
	if !ok {
		t.Fatal("client did not detect the dead path within 15 s")
	}
	t.Logf("blackhole: server (1 s / 0.5 s) after %v (%v); client (10 s / 1 s) after %v (%v)",
		ended.Sub(frozen).Round(time.Millisecond), endErr, time.Since(frozen).Round(time.Millisecond), err)
}
