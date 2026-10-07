// SPDX-License-Identifier: Apache-2.0

// Package grpcstack is the S4 rule's fallback, grpc-go, on the same protobuf contract and the same
// TLS configuration as package control. It exists only so the spike can show whether grpc-go
// handles the cases where connect-go on net/http fails.
package grpcstack

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip" // registers gzip for the compression cases
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	agentv1 "github.com/felix-homelab/rpmgr/spikes/s4/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/control"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/pki"
)

// Record is what the server observed about one Session call.
type Record struct {
	Peer     string
	Deadline time.Time
	Done     chan struct{}
	mu       sync.Mutex
	Ended    time.Time
	EndErr   error
	CtxErr   error
}

// Snapshot returns the fields safe to read after Done is closed.
func (r *Record) Snapshot() (ended time.Time, endErr, ctxErr error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Ended, r.EndErr, r.CtxErr
}

// Service implements the Control service with grpc-go.
type Service struct {
	agentv1.UnimplementedControlServer
	mu   sync.Mutex
	recs map[string]*Record
}

// NewService returns an empty Service.
func NewService() *Service { return &Service{recs: map[string]*Record{}} }

// Active returns the number of sessions that have started and not ended.
func (s *Service) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.recs {
		select {
		case <-r.Done:
		default:
			n++
		}
	}
	return n
}

// Record returns the record of agentID's session, waiting up to wait for it to start.
func (s *Service) Record(agentID string, wait time.Duration) (*Record, error) {
	deadline := time.Now().Add(wait)
	for {
		s.mu.Lock()
		r := s.recs[agentID]
		s.mu.Unlock()
		if r != nil {
			return r, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("no session for " + agentID)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func peerID(ctx context.Context, td string) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return ""
	}
	id, err := pki.SPIFFEID(info.State.PeerCertificates[0], td)
	if err != nil {
		return ""
	}
	return id.String()
}

// TrustDomain is the trust domain of the spike's test CA; set by the tests.
var TrustDomain string

// Session implements the control stream: Welcome, then the behaviour named in Hello.
func (s *Service) Session(st agentv1.Control_SessionServer) error {
	ctx := st.Context()
	first, err := st.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "first message must be Hello")
	}
	rec := &Record{Peer: peerID(ctx, TrustDomain), Done: make(chan struct{})}
	if d, ok := ctx.Deadline(); ok {
		rec.Deadline = d
	}
	s.mu.Lock()
	s.recs[hello.GetAgentId()] = rec
	s.mu.Unlock()
	finish := func(err error) error {
		rec.mu.Lock()
		rec.Ended, rec.EndErr, rec.CtxErr = time.Now(), err, ctx.Err()
		rec.mu.Unlock()
		close(rec.Done)
		return err
	}
	w := &agentv1.Welcome{SessionEpoch: "e1", PeerIdentity: rec.Peer, ServerTimeUnixNano: time.Now().UnixNano()}
	if !rec.Deadline.IsZero() {
		w.DeadlineUnixNano = rec.Deadline.UnixNano()
	}
	if err := st.Send(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Welcome{Welcome: w}}); err != nil {
		return finish(err)
	}
	behaviour, arg, _ := strings.Cut(hello.GetBehaviour(), ":")
	if behaviour == "duplex" {
		// arg = "<count>,<payload bytes>": send count snapshots while receiving count statuses.
		cntS, sizeS, _ := strings.Cut(arg, ",")
		cnt, _ := strconv.Atoi(cntS)
		size, _ := strconv.Atoi(sizeS)
		sendErr := make(chan error, 1)
		go func() {
			payload := make([]byte, size)
			for i := 1; i <= cnt; i++ {
				if err := st.Send(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: &agentv1.Snapshot{Revision: uint64(i), Payload: payload}}}); err != nil {
					sendErr <- err
					return
				}
			}
			sendErr <- nil
		}()
		for i := 1; i <= cnt; i++ {
			m, err := st.Recv()
			if err != nil {
				return finish(err)
			}
			if m.GetStatus().GetSeq() != uint64(i) {
				return finish(status.Errorf(codes.DataLoss, "status %d out of order", m.GetStatus().GetSeq()))
			}
		}
		return finish(<-sendErr)
	}
	if behaviour == "send-blob" {
		parts := strings.Split(arg, ",")
		n, err := strconv.Atoi(parts[0])
		if err != nil {
			return finish(status.Error(codes.InvalidArgument, err.Error()))
		}
		m := control.ControllerBlob(n)
		if slices.Contains(parts, "random") {
			_, _ = rand.Read(m.GetBlob().GetData())
		}
		if err := st.Send(m); err != nil {
			return finish(err)
		}
		if slices.Contains(parts, "close") {
			return finish(nil)
		}
	}
	for {
		_, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return finish(nil)
		}
		if err != nil {
			return finish(err)
		}
	}
}

// Renew is not used by the comparison.
func (s *Service) Renew(context.Context, *agentv1.RenewRequest) (*agentv1.RenewResponse, error) {
	return &agentv1.RenewResponse{}, nil
}

// Options configures both server modes and the client.
type Options struct {
	// Keepalive: the server pings after Time without activity and waits Timeout for the answer;
	// MinTime is the enforcement policy for client pings.
	Time, Timeout, MinTime time.Duration
	MaxSend, MaxRecv       int
}

func limits(o Options) (send, recv int) {
	send, recv = control.MaxControlMessage, control.MaxControlMessage
	if o.MaxSend != 0 {
		send = o.MaxSend
	}
	if o.MaxRecv != 0 {
		recv = o.MaxRecv
	}
	return send, recv
}

// NativeServer is grpc-go's own server, with its own HTTP/2 transport, on a TLS listener.
func NativeServer(svc *Service, so control.ServerOptions, o Options) *grpc.Server {
	send, recv := limits(o)
	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(control.ServerTLSConfig(so))),
		grpc.MaxSendMsgSize(send),
		grpc.MaxRecvMsgSize(recv),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: o.MinTime, PermitWithoutStream: true}),
	}
	if o.Time > 0 {
		opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{Time: o.Time, Timeout: o.Timeout}))
	}
	s := grpc.NewServer(opts...)
	agentv1.RegisterControlServer(s, svc)
	return s
}

// HTTPServer mounts a grpc-go server on a net/http server (grpc.Server.ServeHTTP), which keeps
// one HTTP stack on port 443; HTTP/2 and its PINGs are then net/http's.
func HTTPServer(svc *Service, so control.ServerOptions, o Options) *http.Server {
	send, recv := limits(o)
	gs := grpc.NewServer(grpc.MaxSendMsgSize(send), grpc.MaxRecvMsgSize(recv))
	agentv1.RegisterControlServer(gs, svc)
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	return &http.Server{
		Handler:   gs,
		TLSConfig: control.ServerTLSConfig(so),
		Protocols: &protocols,
		HTTP2:     &http.HTTP2Config{SendPingTimeout: so.SendPingTimeout, PingTimeout: so.PingTimeout},
	}
}

// Dial returns a grpc-go client connection to addr with the agent's TLS configuration.
func Dial(co control.ClientOptions, o Options, extra ...grpc.DialOption) (*grpc.ClientConn, error) {
	send, recv := limits(o)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(control.ClientTLSConfig(co))),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(send), grpc.MaxCallRecvMsgSize(recv)),
	}
	if co.SendPingTimeout > 0 {
		opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time: co.SendPingTimeout, Timeout: co.PingTimeout, PermitWithoutStream: true,
		}))
	}
	return grpc.NewClient("passthrough:///"+co.Addr, append(opts, extra...)...)
}
