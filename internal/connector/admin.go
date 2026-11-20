// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/felix-homelab/rpmgr/internal/handoff"
)

// adminListener is the connector's admin listener across restarts with socket hand-off
// (docs/03-connections.md, "Restarts with socket hand-off"). The old process hands it over with
// the sessions; the new process takes it, both hold it until the switch, and then the old one
// retires its copy, as a gateway does. An old process of 0.3.0 or 0.4.0 hands nothing over and
// holds the address until it exits: the new process then binds it once it is free (#1187).
type adminListener struct {
	log *slog.Logger
	// inherited is the listener the old process handed over; nil after a plain start, or if the
	// old process handed none over.
	inherited net.Listener
	// handoff says this process was started by a hand-off.
	handoff bool
	// oldGone is closed once the old process of the hand-off that started this one has exited;
	// until then an address in use is the old process's.
	oldGone  chan struct{}
	goneOnce sync.Once
	retry    time.Duration // how often the bind is tried again while the old process holds it

	mu      sync.Mutex
	held    *handoff.Retirable
	retired bool
}

// adminRetry is how often a new process tries again to bind the admin listener that the old
// process of an earlier release still holds.
const adminRetry = 100 * time.Millisecond

// newAdminListener prepares the admin listener on addr. take is the hand-off's
// (handoff.Handoff.Listener) in a process a hand-off started, nil after a plain start; the listener
// the old process handed over is taken at once, so that the sockets nobody takes can be closed
// later.
func newAdminListener(addr string, take func(netip.AddrPort) (net.Listener, bool, error), log *slog.Logger) (*adminListener, error) {
	a := &adminListener{log: log, oldGone: make(chan struct{}), retry: adminRetry}
	if take == nil {
		return a, nil
	}
	a.handoff = true
	for _, ap := range handoff.AddrPorts(addr) {
		ln, ok, err := take(ap)
		if err != nil {
			return nil, fmt.Errorf("connector: adopting the admin listener on %s: %w", addr, err)
		}
		if ok {
			log.Info("adopted a listener", "name", "admin", "addr", ln.Addr().String())
			a.inherited = ln
			break
		}
	}
	return a, nil
}

// adopted says the old process handed the admin listener over.
func (a *adminListener) adopted() bool { return a.inherited != nil }

// listen returns the admin listener: the handed-over one, else a new one. After a hand-off whose
// old process handed none over, an address in use is the old process's: listen tries again every
// retry until the old process has exited, and then once more, or until ctx ends.
func (a *adminListener) listen(ctx context.Context, addr string) (net.Listener, error) {
	ln := a.inherited
	if ln == nil {
		var err error
		if ln, err = a.bind(ctx, addr); err != nil {
			return nil, err
		}
	}
	r := handoff.NewRetirable(ln)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.retired { // handed over while this process was still waiting for the address
		_ = ln.Close()
		return nil, context.Canceled
	}
	a.held = r
	return r, nil
}

func (a *adminListener) bind(ctx context.Context, addr string) (net.Listener, error) {
	logged := false
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil || !a.handoff || !errors.Is(err, syscall.EADDRINUSE) {
			return ln, err
		}
		select {
		case <-a.oldGone:
			// The old process has exited: an address still in use is somebody else's.
			return net.Listen("tcp", addr)
		default:
		}
		if !logged {
			a.log.Info("the old process of an earlier release holds the admin listener: binding it once the old process lets go", "addr", addr)
			logged = true
		}
		t := time.NewTimer(a.retry)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-a.oldGone:
			t.Stop()
		case <-t.C:
		}
	}
}

// sockets returns a duplicate of the admin listener for a hand-off, none while this process
// does not hold it yet; the caller closes the files.
func (a *adminListener) sockets() ([]handoff.Socket, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.held == nil {
		return nil, nil
	}
	tl, ok := a.held.Listener.(*net.TCPListener)
	if !ok {
		return nil, nil
	}
	f, err := tl.File()
	if err != nil {
		return nil, fmt.Errorf("duplicating the admin listener: %w", err)
	}
	return []handoff.Socket{{Name: "admin", File: f}}, nil
}

// retire stops this process taking connections on the admin listener, which the new process of
// the hand-off now answers alone.
func (a *adminListener) retire() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retired = true
	if a.held != nil {
		a.held.Retire()
	}
}

// gone says the old process of the hand-off that started this one has exited.
func (a *adminListener) gone() { a.goneOnce.Do(func() { close(a.oldGone) }) }
