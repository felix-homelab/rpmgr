// SPDX-License-Identifier: Apache-2.0

// Package memnet connects the roles that run in one process, all-in-one's
// (docs/02-architecture.md, "All-in-one"): a listener whose connections are in-memory pipes, so
// that the roles still talk only through their public protocols, mutual TLS included (R16).
package memnet

import (
	"context"
	"net"
	"sync"
)

// Listener accepts the connections Dial makes and those Deliver hands over. Its zero value is not
// usable; NewListener returns one.
type Listener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

// NewListener returns an open listener.
func NewListener() *Listener {
	return &Listener{conns: make(chan net.Conn), done: make(chan struct{})}
}

// Accept waits for the next connection; after Close it returns net.ErrClosed.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops Accept, Deliver and Dial; connections already accepted stay open.
func (l *Listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// Addr is the same for every listener: "in-process".
func (l *Listener) Addr() net.Addr { return Addr{} }

// Deliver hands c to the next Accept, or closes it once the listener is closed.
func (l *Listener) Deliver(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.done:
		_ = c.Close()
	}
}

// Dial returns the client end of a new Pipe whose server end the next Accept returns. The address
// is ignored: a listener has only one.
func (l *Listener) Dial(ctx context.Context, _ string) (net.Conn, error) {
	client, server := Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.done:
		_, _ = client.Close(), server.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_, _ = client.Close(), server.Close()
		return nil, ctx.Err()
	}
}

// Addr is a listener's address.
type Addr struct{}

// Network implements net.Addr.
func (Addr) Network() string { return "memory" }

// String implements net.Addr.
func (Addr) String() string { return "in-process" }
