// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/felix-homelab/rpmgr/internal/handoff"
)

// listeners opens the gateway's TCP listeners and remembers them. After a hand-off it takes the
// ones the old process handed over instead of binding them; the old process builds the sockets
// it hands over from the ones still open (docs/03-connections.md, "Restarts with socket
// hand-off"). The zero value binds every listener itself.
type listeners struct {
	link *handoff.Link
	// take returns the handed-over listener on an address (handoff.Handoff.Listener); nil after a
	// plain start.
	take func(netip.AddrPort) (net.Listener, bool, error)
	log  *slog.Logger

	mu   sync.Mutex
	open []heldListener
}

type heldListener struct {
	name string
	ln   net.Listener
}

// listen returns the listener on addr ("host:port"): the one handed over for that address, else a
// new one. name says what it serves (at most 64 bytes, as in the manifest).
func (l *listeners) listen(name, addr string) (net.Listener, error) {
	ln, err := l.adopt(name, addr)
	if ln == nil && err == nil {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.open = append(l.open, heldListener{name, ln})
	l.mu.Unlock()
	return ln, nil
}

// adopt returns the handed-over listener for addr, nil if there is none. An address with no host
// is the wildcard, which the old process reports as [::] (dual stack) or 0.0.0.0.
func (l *listeners) adopt(name, addr string) (net.Listener, error) {
	if l.take == nil {
		return nil, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil // net.Listen reports it
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, nil
	}
	var hosts []netip.Addr
	if host == "" {
		hosts = []netip.Addr{netip.IPv6Unspecified(), netip.IPv4Unspecified()}
	} else if a, err := netip.ParseAddr(host); err == nil {
		hosts = []netip.Addr{a}
	}
	for _, a := range hosts {
		ln, ok, err := l.take(netip.AddrPortFrom(a, uint16(p)))
		if err != nil {
			return nil, fmt.Errorf("adopting the %s listener on %s: %w", name, addr, err)
		}
		if ok {
			l.log.Info("adopted a listener", "name", name, "addr", ln.Addr().String())
			return ln, nil
		}
	}
	return nil, nil
}

// sockets returns duplicates of the open TCP listeners, for a hand-off; the caller closes the
// files. Closed listeners, such as a removed route's, are left out.
func (l *listeners) sockets() ([]handoff.Socket, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []handoff.Socket
	var keep []heldListener
	for _, h := range l.open {
		tl, ok := h.ln.(*net.TCPListener)
		if !ok {
			continue
		}
		f, err := tl.File()
		if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
			continue
		}
		keep = append(keep, h)
		if err != nil {
			closeSockets(out)
			return nil, fmt.Errorf("duplicating the %s listener: %w", h.name, err)
		}
		out = append(out, handoff.Socket{Name: h.name, File: f})
	}
	l.open = keep
	return out, nil
}

func closeSockets(s []handoff.Socket) {
	for _, x := range s {
		_ = x.File.Close()
	}
}

// start hands the listeners over to a new process (handoff.Link.Serve).
func (l *listeners) start(ctx context.Context) (*handoff.Child, error) {
	socks, err := l.sockets()
	if err != nil {
		return nil, err
	}
	defer closeSockets(socks)
	return handoff.Start(ctx, handoff.Config{Generation: l.link.Generation() + 1}, socks)
}

// routeName names the listener of a route's port.
func routeName(port uint16) string { return "route-" + strconv.Itoa(int(port)) }

// readyEvery is how often ready looks at the control plane.
const readyEvery = 100 * time.Millisecond

// ready reports the gateway ready through link. After a plain start that is as soon as every
// listener is up. A process a hand-off started waits until its control session is up and its
// first snapshot applied, so that it holds the route ports the snapshot needs: the old process
// stops sending it new connections only once it is told it can take over. What the old process
// handed over and the snapshot did not need is closed and logged. It returns nil if ctx ends first.
func (l *listeners) ready(ctx context.Context, link *handoff.Link, rest func() []handoff.Entry, controlReady func(context.Context) error) error {
	if rest != nil {
		t := time.NewTicker(readyEvery)
		defer t.Stop()
		for controlReady(ctx) != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-t.C:
			}
		}
		for _, e := range rest() {
			l.log.Warn("closed a handed-over socket nothing needs", "name", e.Name, "net", e.Net, "addr", e.Addr.String())
		}
	}
	if err := link.Ready(); err != nil {
		return fmt.Errorf("gateway: hand-off: %w", err)
	}
	return nil
}
