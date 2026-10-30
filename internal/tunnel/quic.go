// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// The QUIC parameters of docs/03-connections.md, "QUIC parameters".
const (
	quicHandshakeIdle   = 5 * time.Second
	quicIdle            = 30 * time.Second
	quicKeepAlive       = 10 * time.Second
	quicStreamWindow    = 512 << 10
	quicStreamWindowMax = 16 << 20
	quicConnWindowMax   = 256 << 20
	// ConnectorIncomingStreams and GatewayIncomingStreams are how many concurrent streams each
	// side lets its peer open.
	ConnectorIncomingStreams = 10000
	GatewayIncomingStreams   = 1000
	// DefaultWindowBudget is the process-wide budget of connection receive windows.
	DefaultWindowBudget = 1 << 30
)

// Stream error codes this package uses when it resets a stream.
const (
	codeAborted quic.StreamErrorCode = 1
	codeClosed  quic.StreamErrorCode = 2
)

// ErrStreamLimit is returned by OpenStream when the peer's stream limit is reached; the caller
// tries another session.
var ErrStreamLimit = errors.New("tunnel: the session's stream limit is reached")

// Budget bounds the connection receive windows of all sessions of one ALPN in this process: a
// session is admitted with its windows or refused (AdmitQUIC, AdmitH2), so many sessions cannot
// exhaust memory.
type Budget struct {
	mu    sync.Mutex
	limit uint64
	used  uint64

	stallAge time.Duration // tests only; 0 is StallAge
}

// NewBudget returns a budget of limit bytes.
func NewBudget(limit uint64) *Budget {
	return &Budget{limit: limit}
}

// The connection windows of sessions (03, "Memory bound"; D124): at most
// maxConnWindow each, a sixteenth of the free budget once that is less, and never less than
// minConnWindow; a session that would get less is refused.
const (
	maxConnWindow = 64 << 20
	minConnWindow = 1 << 20
	budgetShare   = 16
)

// ErrBudget is returned when the window budget has no room for another session.
var ErrBudget = errors.New("tunnel: the window budget is exhausted")

// AdmitQUIC reserves the connection window of a new QUIC session, as AdmitH2 does for a
// reverse-HTTP/2 session, from the maxima of 03: the connection window is set to what is admitted
// from the start and never grows, so the stalled-stream rule knows it and the budget bounds the
// memory the session can hold.
func (b *Budget) AdmitQUIC() (H2Windows, func(), error) {
	return b.AdmitH2(H2Windows{Stream: quicStreamWindowMax, Conn: quicConnWindowMax})
}

// AdmitH2 reserves the connection window of a new reverse-HTTP/2 session, which advertises its
// whole window at once: at most 64 MiB, a sixteenth of the free
// budget once that is less, so that many sessions fit with shrinking windows rather than the first
// few taking all of it, and at least 1 MiB, or ErrBudget. The stream window is at most a sixteenth
// of the connection window. release returns the reservation; call it when the session ends.
func (b *Budget) AdmitH2(want H2Windows) (H2Windows, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	free := uint64(0)
	if b.limit > b.used {
		free = b.limit - b.used
	}
	if free < minConnWindow {
		return H2Windows{}, nil, ErrBudget
	}
	conn := min(uint64(want.Conn), maxConnWindow, max(minConnWindow, free/budgetShare)) //nolint:gosec // G115: a window is positive
	got := want
	got.Conn = int(conn) //nolint:gosec // G115: conn <= want.Conn
	got.Stream = min(want.Stream, got.Conn/16)
	b.used += conn
	var once sync.Once
	return got, func() {
		once.Do(func() {
			b.mu.Lock()
			b.used -= conn
			b.mu.Unlock()
		})
	}, nil
}

// Used returns how many bytes of the budget are taken.
func (b *Budget) Used() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// QUICConfig returns the QUIC configuration of the connector (connector true) or the gateway for
// a session admitted with the windows w (Budget.AdmitQUIC). The connection window is w.Conn from the
// start and its maximum, so it never grows. 0-RTT stays off.
func QUICConfig(connector bool, w H2Windows) *quic.Config {
	incoming := int64(GatewayIncomingStreams)
	if connector {
		incoming = ConnectorIncomingStreams
	}
	win := func(n int) uint64 { return uint64(max(n, 0)) } //nolint:gosec // G115: clamped to positive
	return &quic.Config{
		HandshakeIdleTimeout:             quicHandshakeIdle,
		MaxIdleTimeout:                   quicIdle,
		KeepAlivePeriod:                  quicKeepAlive,
		InitialStreamReceiveWindow:       win(min(quicStreamWindow, w.Stream)),
		MaxStreamReceiveWindow:           win(w.Stream),
		InitialConnectionReceiveWindow:   win(w.Conn),
		MaxConnectionReceiveWindow:       win(w.Conn),
		MaxIncomingStreams:               incoming,
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
	}
}

// LoadResetKey reads the gateway's stateless reset key from path, creating a new random key with
// mode 0600 if there is none. Keeping the key across restarts lets a restarted gateway answer a
// connector's packets with a stateless reset, so the connector notices the restart within one
// session ping instead of after the idle timeout.
func LoadResetKey(path string) (*quic.StatelessResetKey, error) {
	var key quic.StatelessResetKey
	b, err := os.ReadFile(path) //nolint:gosec // G304: the configured state directory
	switch {
	case err == nil && len(b) == len(key):
		copy(key[:], b)
		return &key, nil
	case err == nil:
		return nil, fmt.Errorf("tunnel: %s holds %d bytes, not a %d-byte reset key", path, len(b), len(key))
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the configured state directory
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key[:]); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &key, f.Close()
}

// DialQUIC opens the connector's QUIC data session to a gateway over tr.
func DialQUIC(ctx context.Context, tr *quic.Transport, addr net.Addr, cfg *tls.Config, budget *Budget) (*QUICSession, error) {
	cfg = cfg.Clone()
	cfg.NextProtos = []string{ALPNQUIC}
	w, release, err := budget.AdmitQUIC()
	if err != nil {
		return nil, err
	}
	conn, err := tr.Dial(ctx, addr, cfg, QUICConfig(true, w))
	if err != nil {
		release()
		return nil, err
	}
	return newQUICSession(conn, w, release, budget, true), nil
}

// QUICListener accepts connectors' QUIC data sessions on a gateway.
type QUICListener struct {
	ln     *quic.Listener
	budget *Budget

	mu      sync.Mutex
	pending map[string]*admission // by the remote address of the first packet
}

// admissionExpiry is how long a reservation waits for its handshake: quic-go gives up on a
// connection at twice the handshake idle timeout.
var admissionExpiry = 2*quicHandshakeIdle + time.Second

// admission is a window reserved for a connection that has not completed its handshake.
type admission struct {
	w       H2Windows
	release func()
	timer   *time.Timer
}

// ListenQUIC starts the gateway's QUIC listener for data sessions on tr. Each incoming connection
// is admitted against budget before its handshake (quic-go's GetConfigForClient), with its own
// windows, or refused when the budget has no room.
func ListenQUIC(tr *quic.Transport, cfg *tls.Config, budget *Budget) (*QUICListener, error) {
	cfg = cfg.Clone()
	cfg.NextProtos = []string{ALPNQUIC}
	l := &QUICListener{budget: budget, pending: map[string]*admission{}}
	qc := QUICConfig(false, H2Windows{Stream: quicStreamWindowMax, Conn: quicConnWindowMax})
	qc.GetConfigForClient = l.admit
	ln, err := tr.Listen(cfg, qc)
	if err != nil {
		return nil, err
	}
	l.ln = ln
	return l, nil
}

// admit reserves the windows of a new connection. A connection that never completes its
// handshake gives them back when quic-go gives up on it, at twice the handshake idle timeout.
func (l *QUICListener) admit(info *quic.ClientInfo) (*quic.Config, error) {
	w, release, err := l.budget.AdmitQUIC()
	if err != nil {
		return nil, err
	}
	key := info.RemoteAddr.String()
	a := &admission{w: w, release: release}
	a.timer = time.AfterFunc(admissionExpiry, func() { l.drop(key, a) })
	l.mu.Lock()
	old := l.pending[key]
	l.pending[key] = a
	l.mu.Unlock()
	if old != nil {
		old.timer.Stop()
		old.release()
	}
	return QUICConfig(false, w), nil
}

func (l *QUICListener) drop(key string, a *admission) {
	l.mu.Lock()
	if l.pending[key] == a {
		delete(l.pending, key)
	}
	l.mu.Unlock()
	a.release()
}

// claim takes the admission of a connection whose handshake completed.
func (l *QUICListener) claim(key string) *admission {
	l.mu.Lock()
	a := l.pending[key]
	delete(l.pending, key)
	l.mu.Unlock()
	if a != nil {
		a.timer.Stop()
	}
	return a
}

// Accept returns the next connector session.
func (l *QUICListener) Accept(ctx context.Context) (*QUICSession, error) {
	for {
		conn, err := l.ln.Accept(ctx)
		if err != nil {
			return nil, err
		}
		a := l.claim(conn.RemoteAddr().String())
		if a == nil {
			// Its reservation expired before the connection was taken: it cannot be held to a window.
			_ = conn.CloseWithError(0, "")
			continue
		}
		return newQUICSession(conn, a.w, a.release, l.budget, false), nil
	}
}

// Close stops accepting sessions.
func (l *QUICListener) Close() error { return l.ln.Close() }

// QUICSession is a data session over QUIC.
type QUICSession struct {
	conn      *quic.Conn
	connector bool // the side that dialled
	control   atomic.Bool
	stalls    *Stalls
	dgOnce    sync.Once
	dg        *Datagrams
}

func newQUICSession(conn *quic.Conn, w H2Windows, release func(), budget *Budget, connector bool) *QUICSession {
	context.AfterFunc(conn.Context(), release)
	// The windows are the admitted ones and never grow, so the rule knows how much a stalled
	// stream can hold.
	s := &QUICSession{conn: conn, connector: connector, stalls: NewStalls(w.Stream, w.Conn, budget.stallAge)}
	go s.stalls.Run(conn.Context()) // ends with the connection
	return s
}

// Control returns the session control stream: the connector opens it as the first stream
// ("stream 0"), the gateway accepts it as the first stream.
func (s *QUICSession) Control(ctx context.Context) (Stream, error) {
	if s.control.Swap(true) {
		return nil, errors.New("tunnel: the session control stream is already open")
	}
	// The control stream is not watched: the stalled-stream rule resets a stream, and a reset
	// control stream ends the session, which would turn a rule that frees the session into one that
	// kills it. It carries little, and its reader waits in Read for the session's life.
	if s.connector {
		return s.open()
	}
	return s.accept(ctx)
}

// OpenStream opens a stream without blocking; at the peer's stream limit it returns
// ErrStreamLimit at once.
func (s *QUICSession) OpenStream(context.Context) (Stream, error) {
	st, err := s.open()
	if err != nil {
		return nil, err
	}
	return s.stalls.Watch(st), nil
}

func (s *QUICSession) open() (Stream, error) {
	st, err := s.conn.OpenStream()
	var limit *quic.StreamLimitReachedError
	if errors.As(err, &limit) {
		return nil, ErrStreamLimit
	}
	if err != nil {
		return nil, err
	}
	return &quicStream{st: st}, nil
}

// AcceptStream returns the next stream the peer opened.
func (s *QUICSession) AcceptStream(ctx context.Context) (Stream, error) {
	st, err := s.accept(ctx)
	if err != nil {
		return nil, err
	}
	return s.stalls.Watch(st), nil
}

func (s *QUICSession) accept(ctx context.Context) (Stream, error) {
	st, err := s.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStream{st: st}, nil
}

// Close ends the session.
func (s *QUICSession) Close() error { return s.conn.CloseWithError(0, "") }

// Done is closed when the session ended.
func (s *QUICSession) Done() <-chan struct{} { return s.conn.Context().Done() }

// Err returns why the session ended, such as a stateless reset, or nil while it runs.
func (s *QUICSession) Err() error { return context.Cause(s.conn.Context()) }

// Transport is "quic".
func (s *QUICSession) Transport() string { return "quic" }

// RTT is the session's smoothed round-trip time.
func (s *QUICSession) RTT() time.Duration { return s.conn.ConnectionStats().SmoothedRTT }

// PeerCertificate is the peer's leaf certificate, which TLS verified.
func (s *QUICSession) PeerCertificate() *x509.Certificate {
	if certs := s.conn.ConnectionState().TLS.PeerCertificates; len(certs) > 0 {
		return certs[0]
	}
	return nil
}

// quicStream adapts a quic-go stream. Closing a quic-go stream closes only its send direction
// [F quic-go v0.63.0 stream.go:192], which is CloseWrite here; a reset by the peer is an error from
// Read and Write, never io.EOF.
type quicStream struct {
	st       *quic.Stream
	wroteFIN atomic.Bool
	readEOF  atomic.Bool
}

func (s *quicStream) Read(p []byte) (int, error) {
	n, err := s.st.Read(p)
	if errors.Is(err, io.EOF) {
		s.readEOF.Store(true)
	}
	return n, err
}

func (s *quicStream) Write(p []byte) (int, error) { return s.st.Write(p) }

// CloseWrite sends FIN.
func (s *quicStream) CloseWrite() error {
	s.wroteFIN.Store(true)
	return s.st.Close()
}

// SetReliableBoundary makes what was written so far, the StreamResult, reach the peer even if
// the stream is reset afterwards.
func (s *quicStream) SetReliableBoundary() { s.st.SetReliableBoundary() }

// SetReadDeadline and SetWriteDeadline are the QUIC stream's own, for Conn.
func (s *quicStream) SetReadDeadline(t time.Time) error  { return s.st.SetReadDeadline(t) }
func (s *quicStream) SetWriteDeadline(t time.Time) error { return s.st.SetWriteDeadline(t) }

// Abort resets both directions.
func (s *quicStream) Abort() {
	s.st.CancelWrite(codeAborted)
	s.st.CancelRead(codeAborted)
}

// Close resets the directions that did not end normally.
func (s *quicStream) Close() error {
	if !s.wroteFIN.Load() {
		s.st.CancelWrite(codeClosed)
	}
	if !s.readEOF.Load() {
		s.st.CancelRead(codeClosed)
	}
	return nil
}
