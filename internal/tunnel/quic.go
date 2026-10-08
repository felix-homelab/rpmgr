// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
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
// window grows only while the budget has room, so many sessions cannot exhaust memory.
type Budget struct {
	mu    sync.Mutex
	limit uint64
	used  uint64
	conns map[*quic.Conn]uint64
}

// NewBudget returns a budget of limit bytes.
func NewBudget(limit uint64) *Budget {
	return &Budget{limit: limit, conns: map[*quic.Conn]uint64{}}
}

// allow is quic.Config.AllowConnectionWindowIncrease. It must not call the connection.
func (b *Budget) allow(conn *quic.Conn, delta uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+delta > b.limit {
		return false
	}
	b.used += delta
	b.conns[conn] += delta
	return true
}

// release returns what conn took from the budget; it runs when the session ends.
func (b *Budget) release(conn *quic.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used -= b.conns[conn]
	delete(b.conns, conn)
}

// Used returns how many bytes of the budget are taken.
func (b *Budget) Used() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// QUICConfig returns the QUIC configuration of the connector (connector true) or the gateway,
// with the connection windows bounded by budget. 0-RTT stays off.
func QUICConfig(connector bool, budget *Budget) *quic.Config {
	incoming := int64(GatewayIncomingStreams)
	if connector {
		incoming = ConnectorIncomingStreams
	}
	return &quic.Config{
		HandshakeIdleTimeout:             quicHandshakeIdle,
		MaxIdleTimeout:                   quicIdle,
		KeepAlivePeriod:                  quicKeepAlive,
		InitialStreamReceiveWindow:       quicStreamWindow,
		MaxStreamReceiveWindow:           quicStreamWindowMax,
		MaxConnectionReceiveWindow:       quicConnWindowMax,
		AllowConnectionWindowIncrease:    budget.allow,
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
	conn, err := tr.Dial(ctx, addr, cfg, QUICConfig(true, budget))
	if err != nil {
		return nil, err
	}
	return newQUICSession(conn, budget), nil
}

// QUICListener accepts connectors' QUIC data sessions on a gateway.
type QUICListener struct {
	ln     *quic.Listener
	budget *Budget
}

// ListenQUIC starts the gateway's QUIC listener for data sessions on tr.
func ListenQUIC(tr *quic.Transport, cfg *tls.Config, budget *Budget) (*QUICListener, error) {
	cfg = cfg.Clone()
	cfg.NextProtos = []string{ALPNQUIC}
	ln, err := tr.Listen(cfg, QUICConfig(false, budget))
	if err != nil {
		return nil, err
	}
	return &QUICListener{ln: ln, budget: budget}, nil
}

// Accept returns the next connector session.
func (l *QUICListener) Accept(ctx context.Context) (*QUICSession, error) {
	conn, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return newQUICSession(conn, l.budget), nil
}

// Close stops accepting sessions.
func (l *QUICListener) Close() error { return l.ln.Close() }

// QUICSession is a data session over QUIC.
type QUICSession struct {
	conn *quic.Conn
}

func newQUICSession(conn *quic.Conn, budget *Budget) *QUICSession {
	context.AfterFunc(conn.Context(), func() { budget.release(conn) })
	return &QUICSession{conn: conn}
}

// OpenStream opens a stream without blocking; at the peer's stream limit it returns
// ErrStreamLimit at once.
func (s *QUICSession) OpenStream(context.Context) (Stream, error) {
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
