// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"net"
	"strings"
	"sync"

	"github.com/felix-homelab/rpmgr/internal/tlspeek"
)

// Splitter divides the controller's TCP/443 connections by the ClientHello's SNI
// (docs/03-connections.md, "Control session"): the agent names controller.<td> and
// reauth.controller.<td> go to the grpc-go server of the agent protocol, every other name, and no
// name, to the net/http server of the UI and the public API. A connection that does not start
// with a TLS ClientHello within the peek limits is closed without an answer. The handlers get the
// connection with the peeked bytes replayed, so they do the TLS handshake themselves.
type Splitter struct {
	trustDomain string
	agents, web *connListener
}

// NewSplitter returns a Splitter for trust domain td. Serve the agent protocol on Agents() and the
// web server on Web(), then call Serve.
func NewSplitter(td string, addr net.Addr) *Splitter {
	return &Splitter{trustDomain: td, agents: newConnListener(addr), web: newConnListener(addr)}
}

// Agents is the listener of the agent names.
func (s *Splitter) Agents() net.Listener { return s.agents }

// Web is the listener of every other name.
func (s *Splitter) Web() net.Listener { return s.web }

// IsAgentName reports whether sni is one of the controller's agent names.
func IsAgentName(sni, td string) bool {
	return strings.EqualFold(sni, "controller."+td) || strings.EqualFold(sni, "reauth.controller."+td)
}

// Serve accepts connections from ln until it fails, and closes both handler listeners then.
func (s *Splitter) Serve(ln net.Listener) error {
	defer func() { _ = s.agents.Close(); _ = s.web.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.route(c)
	}
}

func (s *Splitter) route(c net.Conn) {
	hello, err := tlspeek.Peek(c, tlspeek.MaxBytes, tlspeek.Timeout)
	if err != nil {
		_ = c.Close()
		return
	}
	to := s.web
	if IsAgentName(hello.ServerName, s.trustDomain) {
		to = s.agents
	}
	if !to.deliver(tlspeek.NewReplayConn(c, hello.Raw)) {
		_ = c.Close()
	}
}

// connListener is a net.Listener fed by the Splitter.
type connListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{addr: addr, conns: make(chan net.Conn), closed: make(chan struct{})}
}

// deliver hands c to Accept, or reports false if the listener is closed.
func (l *connListener) deliver(c net.Conn) bool {
	select {
	case l.conns <- c:
		return true
	case <-l.closed:
		return false
	}
}

// Accept returns the next routed connection.
func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close stops Accept; connections already accepted stay open.
func (l *connListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// Addr returns the address of the TCP listener.
func (l *connListener) Addr() net.Addr { return l.addr }

var _ net.Listener = (*connListener)(nil)
