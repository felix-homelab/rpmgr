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
	"math"
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
	return b.admit(want, math.MaxUint64)
}

// admit is AdmitH2 with an upper bound on the connection window, which a caller sets lower than
// the budget would (never below the 1 MiB floor).
func (b *Budget) admit(want H2Windows, ceiling uint64) (H2Windows, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	free := uint64(0)
	if b.limit > b.used {
		free = b.limit - b.used
	}
	if free < minConnWindow {
		return H2Windows{}, nil, ErrBudget
	}
	conn := min(uint64(want.Conn), maxConnWindow, max(minConnWindow, min(free/budgetShare, ceiling))) //nolint:gosec // G115: a window is positive
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

// A connector that has not completed its handshake holds a reservation (admission) that nobody
// has claimed yet. These bound what unclaimed handshakes can take from the budget, so that
// half-open handshakes cannot exhaust it (03, "QUIC parameters").
const (
	// pendingPrefixShare: the unclaimed admissions of one source prefix (an IPv4 /24, an IPv6 /64)
	// hold at most an eighth of the budget together; an admission is sized to what is left of
	// that, and takes at most half of it, so that a connector that opens several sessions at
	// once gets all of them, with smaller windows.
	pendingPrefixShare = 8
	// maxPendingPerPrefix is how many unclaimed admissions one prefix may hold, as the smallest
	// windows add up.
	maxPendingPerPrefix = 16
	// pendingShare: all unclaimed admissions hold at most half of the budget.
	pendingShare = 2
)

// QUICListener accepts connectors' QUIC data sessions on a gateway.
type QUICListener struct {
	ln     *quic.Listener
	budget *Budget

	mu            sync.Mutex
	admitted      map[*quic.ClientInfo]*admission // between GetConfigForClient and ConnContext
	pendingBytes  uint64                          // of the unclaimed admissions
	prefixBytes   map[string]uint64               // by source prefix
	prefixPending map[string]int
}

// admission is the window reserved for one incoming connection. It travels in the connection's
// context, so that Accept finds exactly the reservation of the connection it returns, whatever the
// connections' addresses are.
type admission struct {
	l       *QUICListener
	w       H2Windows
	release func() // the budget share; once
	prefix  string
	pending sync.Once // leaves the unclaimed count
}

type admissionKey struct{}

// settle takes the admission out of the unclaimed count: it was claimed or its connection ended.
func (a *admission) settle() {
	a.pending.Do(func() {
		n := uint64(a.w.Conn) //nolint:gosec // G115: a window is positive
		a.l.mu.Lock()
		a.l.pendingBytes -= n
		if a.l.prefixBytes[a.prefix] -= n; a.l.prefixBytes[a.prefix] == 0 {
			delete(a.l.prefixBytes, a.prefix)
		}
		if a.l.prefixPending[a.prefix]--; a.l.prefixPending[a.prefix] <= 0 {
			delete(a.l.prefixPending, a.prefix)
		}
		a.l.mu.Unlock()
	})
}

// ErrUnverified is returned for a connection whose source address is not validated.
var ErrUnverified = errors.New("tunnel: the connection's source address is not verified")

// ListenQUIC starts the gateway's QUIC listener for data sessions on tr. It sets
// tr.VerifySourceAddress, which makes every new connection prove its source address with a Retry
// (one extra round trip), and tr.ConnContext, before it starts the listener, and returns an error
// if either is set already or the transport is in use. Each connection is then admitted against
// budget before its handshake (quic-go's GetConfigForClient), with its own windows, or refused:
// for an unverified address, when its source prefix or all unclaimed handshakes together hold
// their share, or when the budget has no room.
func ListenQUIC(tr *quic.Transport, cfg *tls.Config, budget *Budget) (*QUICListener, error) {
	if tr.VerifySourceAddress != nil || tr.ConnContext != nil {
		return nil, errors.New("tunnel: the transport has a source address check or connection context already")
	}
	cfg = cfg.Clone()
	cfg.NextProtos = []string{ALPNQUIC}
	l := &QUICListener{budget: budget, admitted: map[*quic.ClientInfo]*admission{},
		prefixBytes: map[string]uint64{}, prefixPending: map[string]int{}}
	tr.VerifySourceAddress = func(net.Addr) bool { return true }
	tr.ConnContext = l.connContext
	qc := QUICConfig(false, H2Windows{Stream: quicStreamWindowMax, Conn: quicConnWindowMax})
	qc.GetConfigForClient = l.admit
	ln, err := tr.Listen(cfg, qc)
	if err != nil {
		return nil, err
	}
	l.ln = ln
	return l, nil
}

// prefixOf is the source prefix an address counts under: its IPv4 /24 or IPv6 /64.
func prefixOf(a net.Addr) string {
	var ip net.IP
	if u, ok := a.(*net.UDPAddr); ok {
		ip = u.IP
	} else if h, _, err := net.SplitHostPort(a.String()); err == nil {
		ip = net.ParseIP(h)
	}
	if ip == nil {
		return a.String()
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// totalCap and prefixCap are the shares above, at least one smallest window so that a small budget
// still admits one handshake at a time.
func (l *QUICListener) totalCap() uint64 { return max(l.budget.limit/pendingShare, minConnWindow) }

func (l *QUICListener) prefixCap() uint64 {
	return max(l.budget.limit/pendingPrefixShare, minConnWindow)
}

// admit reserves the windows of a new connection.
func (l *QUICListener) admit(info *quic.ClientInfo) (*quic.Config, error) {
	if !info.AddrVerified {
		return nil, ErrUnverified
	}
	prefix := prefixOf(info.RemoteAddr)
	l.mu.Lock()
	var allowance uint64
	if held := l.prefixBytes[prefix]; held < l.prefixCap() {
		allowance = l.prefixCap() - held
	}
	count := l.prefixPending[prefix]
	l.mu.Unlock()
	if count >= maxPendingPerPrefix || allowance < minConnWindow {
		return nil, ErrBudget
	}
	// The window the connection gets is the one admitted here: at most half of what the prefix has
	// left, so that the next handshake of the same connector still fits.
	w, release, err := l.budget.admit(H2Windows{Stream: quicStreamWindowMax, Conn: quicConnWindowMax}, allowance/2)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	n := uint64(w.Conn) //nolint:gosec // G115: a window is positive
	if l.prefixPending[prefix] >= maxPendingPerPrefix || l.prefixBytes[prefix]+n > l.prefixCap() || l.pendingBytes+n > l.totalCap() {
		l.mu.Unlock()
		release()
		return nil, ErrBudget
	}
	a := &admission{l: l, w: w, release: release, prefix: prefix}
	l.pendingBytes += n
	l.prefixBytes[prefix] += n
	l.prefixPending[prefix]++
	l.admitted[info] = a
	l.mu.Unlock()
	return QUICConfig(false, w), nil
}

// connContext runs for the same ClientInfo right after admit [F quic-go v0.64.1 server.go:777-800]
// and attaches the admission to the connection. The connection's context ends when the connection
// does, at the latest when quic-go gives up on the handshake, at twice HandshakeIdleTimeout
// [F quic-go v0.64.1 config.go:17-19, connection.go:695]; that returns the reservation, so a
// handshake that fails or is refused afterwards holds it no longer.
func (l *QUICListener) connContext(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	l.mu.Lock()
	a := l.admitted[info]
	delete(l.admitted, info)
	l.mu.Unlock()
	if a == nil {
		return nil, errors.New("tunnel: a connection without admission")
	}
	context.AfterFunc(ctx, func() { a.settle(); a.release() })
	return context.WithValue(ctx, admissionKey{}, a), nil
}

// Accept returns the next connector session.
func (l *QUICListener) Accept(ctx context.Context) (*QUICSession, error) {
	for {
		conn, err := l.ln.Accept(ctx)
		if err != nil {
			return nil, err
		}
		a, _ := conn.Context().Value(admissionKey{}).(*admission)
		if a == nil { // not made by this listener's admission: not held to any window
			_ = conn.CloseWithError(0, "")
			continue
		}
		a.settle()
		return newQUICSession(conn, a.w, a.release, l.budget, false), nil
	}
}

// Close stops accepting sessions.
func (l *QUICListener) Close() error {
	err := l.ln.Close()
	// quic-go leaves connections whose handshake completed but that nobody accepted in its queue;
	// closing them ends their contexts, which returns their admissions. After Close, Accept never
	// blocks: it drains the queue, then fails.
	for {
		conn, aerr := l.ln.Accept(context.Background())
		if aerr != nil {
			return err
		}
		_ = conn.CloseWithError(0, "")
	}
}

// QUICSession is a data session over QUIC.
type QUICSession struct {
	conn      *quic.Conn
	connector bool // the side that dialled
	control   atomic.Bool
	stalls    *Stalls
	windows   H2Windows
	dgOnce    sync.Once
	dg        *Datagrams
}

func newQUICSession(conn *quic.Conn, w H2Windows, release func(), budget *Budget, connector bool) *QUICSession {
	context.AfterFunc(conn.Context(), release)
	// The windows are the admitted ones and never grow, so the rule knows how much a stalled
	// stream can hold.
	s := &QUICSession{conn: conn, connector: connector, stalls: NewStalls(w.Stream, w.Conn, budget.stallAge), windows: w}
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
