// SPDX-License-Identifier: Apache-2.0

// Package control is the spike's controller side and agent side of the control session: a
// connect-go handler on a plain net/http server with TLS 1.3 mutual TLS and HTTP/2, and a
// connect-go client speaking the gRPC protocol over HTTP/2, as docs/03-connections.md, "Control
// session", describes.
package control

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/felix-homelab/rpmgr/spikes/s4/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/spikes/s4/gen/rpmgr/agent/v1/agentv1connect"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/pki"
)

// MaxControlMessage is the control-session message limit from docs/03, "Framing".
const MaxControlMessage = 4 << 20

// SessionRecord is what the server observed about one Session call. Tests wait on Done.
type SessionRecord struct {
	AgentID      string
	Peer         string
	Proto        string // HTTP protocol of the call, e.g. "HTTP/2.0"
	Started      time.Time
	Deadline     time.Time // zero if the call had none
	Received     int
	FirstRecv    time.Time
	LastSend     time.Time
	Ended        time.Time
	EndErr       error // what Receive or Send returned when the session ended, nil on a clean end
	CtxErr       error // the call context's error when the session ended
	Done         chan struct{}
	mu           sync.Mutex
	ctx          context.Context
}

// CallContextErr returns the error of the call's context now, while the session may still run.
func (r *SessionRecord) CallContextErr() error { return r.ctx.Err() }

func (r *SessionRecord) finish(ctx context.Context, err error) {
	r.mu.Lock()
	r.Ended = time.Now()
	r.EndErr = err
	r.CtxErr = ctx.Err()
	r.mu.Unlock()
	close(r.Done)
}

// Snapshot returns a copy of the record that is safe to read.
func (r *SessionRecord) Snapshot() SessionRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return SessionRecord{AgentID: r.AgentID, Peer: r.Peer, Proto: r.Proto, Started: r.Started, Deadline: r.Deadline,
		Received: r.Received, FirstRecv: r.FirstRecv, LastSend: r.LastSend, Ended: r.Ended,
		EndErr: r.EndErr, CtxErr: r.CtxErr}
}

// Service implements the Control service. Behaviour is chosen per session by Hello.behaviour.
type Service struct {
	mu       sync.Mutex
	sessions map[string]*SessionRecord
	active   int
	renews   []RenewRecord
}

// RenewRecord is what the server observed about one Renew call.
type RenewRecord struct {
	Deadline time.Time
	CtxErr   error
}

// NewService returns an empty Service.
func NewService() *Service { return &Service{sessions: map[string]*SessionRecord{}} }

// Record returns the record of the session of agentID, waiting up to wait for it to start.
func (s *Service) Record(agentID string, wait time.Duration) (*SessionRecord, error) {
	deadline := time.Now().Add(wait)
	for {
		s.mu.Lock()
		r := s.sessions[agentID]
		s.mu.Unlock()
		if r != nil {
			return r, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no session for %q", agentID)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Active returns the number of sessions currently open.
func (s *Service) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Renews returns the records of all Renew calls.
func (s *Service) Renews() []RenewRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]RenewRecord(nil), s.renews...)
}

type peerKey struct{}

type protoKey struct{}

// PeerFromContext returns the SPIFFE ID of the authenticated client.
func PeerFromContext(ctx context.Context) string {
	p, _ := ctx.Value(peerKey{}).(string)
	return p
}

// Session implements the bidirectional control stream.
func (s *Service) Session(ctx context.Context, st *connect.BidiStream[agentv1.AgentMessage, agentv1.ControllerMessage]) error {
	first, err := st.Receive()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("first message must be Hello"))
	}
	proto, _ := ctx.Value(protoKey{}).(string)
	rec := &SessionRecord{AgentID: hello.GetAgentId(), Peer: PeerFromContext(ctx), Proto: proto, Started: time.Now(), Done: make(chan struct{}), ctx: ctx}
	if d, ok := ctx.Deadline(); ok {
		rec.Deadline = d
	}
	s.mu.Lock()
	s.sessions[rec.AgentID] = rec
	s.active++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		s.mu.Unlock()
	}()

	welcome := &agentv1.Welcome{SessionEpoch: "e1", PeerIdentity: rec.Peer, ServerTimeUnixNano: time.Now().UnixNano()}
	if !rec.Deadline.IsZero() {
		welcome.DeadlineUnixNano = rec.Deadline.UnixNano()
	}
	if err := st.Send(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Welcome{Welcome: welcome}}); err != nil {
		rec.finish(ctx, err)
		return err
	}

	behaviour, arg, _ := strings.Cut(hello.GetBehaviour(), ":")
	err = s.run(ctx, st, rec, behaviour, arg)
	rec.finish(ctx, err)
	return err
}

func (s *Service) run(ctx context.Context, st *connect.BidiStream[agentv1.AgentMessage, agentv1.ControllerMessage], rec *SessionRecord, behaviour, arg string) error {
	switch behaviour {
	case "deny":
		return connect.NewError(connect.CodePermissionDenied, errors.New("spike: agent is not allowed"))
	case "close":
		return nil
	case "send-blob":
		// arg = "<n>[,random][,close]": send one Blob whose encoded ControllerMessage has exactly
		// n bytes (zeros, or random bytes that do not compress), then wait for the client, or
		// end the call at once with "close".
		parts := strings.Split(arg, ",")
		n, err := strconv.Atoi(parts[0])
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
		m := ControllerBlob(n)
		if slices.Contains(parts, "random") {
			_, _ = rand.Read(m.GetBlob().GetData())
		}
		if err := st.Send(m); err != nil {
			return err
		}
		if slices.Contains(parts, "close") {
			return nil
		}
		return s.drain(st, rec)
	case "duplex":
		// arg = "<count>,<payload bytes>": send count snapshots while receiving count statuses.
		cnt, size, err := parsePair(arg)
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
		sendErr := make(chan error, 1)
		go func() {
			payload := make([]byte, size)
			for i := 1; i <= cnt; i++ {
				if err := st.Send(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: &agentv1.Snapshot{Revision: uint64(i), Payload: payload}}}); err != nil {
					sendErr <- err
					return
				}
			}
			rec.mu.Lock()
			rec.LastSend = time.Now()
			rec.mu.Unlock()
			sendErr <- nil
		}()
		for i := 1; i <= cnt; i++ {
			m, err := st.Receive()
			if err != nil {
				return err
			}
			if got := m.GetStatus().GetSeq(); got != uint64(i) {
				return connect.NewError(connect.CodeDataLoss, fmt.Errorf("status %d out of order, want %d", got, i))
			}
			rec.mu.Lock()
			if rec.Received == 0 {
				rec.FirstRecv = time.Now()
			}
			rec.Received++
			rec.mu.Unlock()
		}
		return <-sendErr
	case "after-halfclose":
		// Read until the client half-closes, then keep sending arg snapshots.
		cnt, err := strconv.Atoi(arg)
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
		if err := s.drain(st, rec); err != nil {
			return err
		}
		for i := 1; i <= cnt; i++ {
			if err := st.Send(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: &agentv1.Snapshot{Revision: uint64(i)}}}); err != nil {
				return err
			}
		}
		return nil
	default:
		// Idle session until the stream ends; every received Blob is answered (see drain).
		return s.drain(st, rec)
	}
}

// drain receives until the client half-closes (nil) or the stream fails (the error).
func (s *Service) drain(st *connect.BidiStream[agentv1.AgentMessage, agentv1.ControllerMessage], rec *SessionRecord) error {
	for {
		m, err := st.Receive()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		rec.mu.Lock()
		if rec.Received == 0 {
			rec.FirstRecv = time.Now()
		}
		rec.Received++
		rec.mu.Unlock()
		if b := m.GetBlob(); b != nil {
			if err := st.Send(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: &agentv1.Snapshot{Revision: uint64(len(b.GetData()))}}}); err != nil {
				return err
			}
		}
	}
}

// Renew answers after delay_ms, or fails when the call's context ends first.
func (s *Service) Renew(ctx context.Context, req *connect.Request[agentv1.RenewRequest]) (*connect.Response[agentv1.RenewResponse], error) {
	rec := RenewRecord{}
	if d, ok := ctx.Deadline(); ok {
		rec.Deadline = d
	}
	defer func() {
		rec.CtxErr = ctx.Err()
		s.mu.Lock()
		s.renews = append(s.renews, rec)
		s.mu.Unlock()
	}()
	select {
	case <-time.After(time.Duration(req.Msg.GetDelayMs()) * time.Millisecond):
		return connect.NewResponse(&agentv1.RenewResponse{Certificate: []byte("cert")}), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func parsePair(s string) (int, int, error) {
	a, b, ok := strings.Cut(s, ",")
	if !ok {
		return 0, 0, errors.New("want <a>,<b>")
	}
	x, err := strconv.Atoi(a)
	if err != nil {
		return 0, 0, err
	}
	y, err := strconv.Atoi(b)
	return x, y, err
}

// ServerOptions configures the controller's agent endpoint.
type ServerOptions struct {
	CA   *pki.CA
	Cert tls.Certificate
	// HTTP/2 liveness (docs/03: ReadIdleTimeout 20 s, PingTimeout 10 s). net/http calls the
	// read-idle timeout SendPingTimeout.
	SendPingTimeout time.Duration
	PingTimeout     time.Duration
	HandlerOptions  []connect.HandlerOption
}

// ServerTLSConfig is the agent endpoint's TLS configuration: TLS 1.3 only, client certificates
// required and verified against the pinned root, SPIFFE ID of an agent required.
func ServerTLSConfig(o ServerOptions) *tls.Config {
	td := o.CA.TrustDomain
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{o.Cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    o.CA.Roots,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate")
			}
			id, err := pki.SPIFFEID(cs.PeerCertificates[0], td)
			if err != nil {
				return err
			}
			role, err := pki.Role(id)
			if err != nil {
				return err
			}
			if role != "connector" && role != "gateway" {
				return fmt.Errorf("role %q may not open a control session", role)
			}
			return nil
		},
	}
}

// NewHTTPServer returns the net/http server for the agent endpoint. It serves HTTP/1.1 and HTTP/2
// like the real controller, which also serves browsers; agents negotiate h2.
func NewHTTPServer(svc *Service, o ServerOptions) *http.Server {
	mux := http.NewServeMux()
	opts := append([]connect.HandlerOption{
		connect.WithReadMaxBytes(MaxControlMessage),
		connect.WithSendMaxBytes(MaxControlMessage),
	}, o.HandlerOptions...)
	path, h := agentv1connect.NewControlHandler(svc, opts...)
	mux.Handle(path, h)
	td := o.CA.TrustDomain
	withPeer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		id, err := pki.SPIFFEID(r.TLS.PeerCertificates[0], td)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), peerKey{}, id.String())
		ctx = context.WithValue(ctx, protoKey{}, r.Proto)
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	return &http.Server{
		Handler:           withPeer,
		TLSConfig:         ServerTLSConfig(o),
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: o.SendPingTimeout,
			PingTimeout:     o.PingTimeout,
		},
		ErrorLog: nil,
	}
}

// Serve starts srv on ln in the background.
func Serve(srv *http.Server, ln net.Listener) {
	go func() { _ = srv.ServeTLS(ln, "", "") }()
}

// ControllerBlob returns a ControllerMessage carrying a Blob whose encoded size is exactly n bytes.
func ControllerBlob(n int) *agentv1.ControllerMessage {
	return sized(n, func(b []byte) protoSizer {
		return &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Blob{Blob: &agentv1.Blob{Data: b}}}
	}).(*agentv1.ControllerMessage)
}

// AgentBlob returns an AgentMessage carrying a Blob whose encoded size is exactly n bytes.
func AgentBlob(n int) *agentv1.AgentMessage {
	return sized(n, func(b []byte) protoSizer {
		return &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Blob{Blob: &agentv1.Blob{Data: b}}}
	}).(*agentv1.AgentMessage)
}
