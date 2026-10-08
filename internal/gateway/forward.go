// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// forwardDial bounds the dial to a private controller (docs/03-connections.md, "Timeouts,
// keepalive and backoff").
const forwardDial = 5 * time.Second

// Forward passes connections for the controller's names, still encrypted, to a private controller
// (docs/03-connections.md, "Reaching a private controller"). TLS ends at the controller, so the
// gateway relays bytes it can neither read nor alter, and the agent verifies the controller
// against its pinned root as on a direct path.
type Forward struct {
	addr   func() (string, error)
	dial   func(ctx context.Context, addr string) (net.Conn, error)
	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// NewForward returns the forwarding to the controller at addr (host:port); dial connects to it,
// nil dials TCP.
func NewForward(addr string, dial func(ctx context.Context, addr string) (net.Conn, error), logger *slog.Logger) *Forward {
	return NewForwardTo(func() (string, error) { return addr, nil }, dial, logger)
}

// NewForwardTo is NewForward to the address that addr returns at each connection.
func NewForwardTo(addr func() (string, error), dial func(ctx context.Context, addr string) (net.Conn, error), logger *slog.Logger) *Forward {
	if dial == nil {
		d := &net.Dialer{}
		dial = func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) }
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Forward{addr: addr, dial: dial, logger: logger, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{}}
}

// Serve forwards one connection until both directions have ended; it is Router.Controller. A
// controller that cannot be reached resets the connection, so the agent tries its next endpoint
// at once.
func (f *Forward) Serve(c net.Conn) {
	if !f.track(c, true) {
		abort(c)
		return
	}
	defer f.wg.Done()
	defer f.untrack(c)
	addr, err := f.addr()
	var up net.Conn
	if err == nil {
		ctx, cancel := context.WithTimeout(f.ctx, forwardDial)
		up, err = f.dial(ctx, addr)
		cancel()
	}
	if err != nil {
		f.logger.Warn("the controller does not answer", "address", addr, "error", err)
		abort(c)
		return
	}
	if !f.track(up, false) {
		abort(c)
		_ = up.Close()
		return
	}
	defer f.untrack(up)
	splice(c, up)
}

// track records c unless the forwarding is closed; with serve it also counts a Serve for Close
// to wait for.
func (f *Forward) track(c net.Conn, serve bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	if serve {
		f.wg.Add(1)
	}
	f.conns[c] = struct{}{}
	return true
}

func (f *Forward) untrack(c net.Conn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.conns, c)
}

// Conns returns the number of connections being forwarded, both legs counted.
func (f *Forward) Conns() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.conns)
}

// Close ends every forwarded connection and refuses new ones; the agents move to their next
// controller endpoint.
func (f *Forward) Close() {
	f.cancel()
	f.mu.Lock()
	f.closed = true
	for c := range f.conns {
		_ = c.Close()
	}
	f.mu.Unlock()
	f.wg.Wait()
}

// splice relays between a and b until both directions have ended: the end of one direction is
// passed on as a half-close, an error closes both. (From spike/s4:spikes/s4/internal/proxy/proxy.go,
// without its recording and blackhole.)
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Go(func() { pipe(b, a) })
	wg.Go(func() { pipe(a, b) })
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// pipe copies src to dst; at the end of src it half-closes dst, on an error it closes both.
func pipe(dst, src net.Conn) {
	if _, err := io.Copy(dst, src); err == nil {
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
	}
	_ = dst.Close()
	_ = src.Close()
}
