// SPDX-License-Identifier: Apache-2.0

// Package proxy is a TCP relay for the spike. It can route by the SNI of the TLS ClientHello
// without terminating TLS (a TLS-passthrough route, docs/03-connections.md, "Reaching a private
// controller"), and it can blackhole all traffic: bytes are read and dropped, no FIN or RST is
// sent, so neither end learns that the path is dead except through its own liveness checks.
package proxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var errPeeked = errors.New("proxy: ClientHello read")

// Proxy relays TCP connections from its listener to a backend.
type Proxy struct {
	ln     net.Listener
	route  func(sni string) (string, bool)
	peek   bool
	frozen atomic.Bool

	mu    sync.Mutex
	seen  bytes.Buffer
	snis  []string
	conns []net.Conn
}

const seenLimit = 64 << 20

// New starts a proxy on 127.0.0.1. With peek, the backend is chosen by route(SNI) and the
// ClientHello is replayed to it; without, route("") is used.
func New(route func(sni string) (string, bool), peek bool) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{ln: ln, route: route, peek: peek}
	go p.accept()
	return p, nil
}

// Addr is the proxy's listening address.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Freeze turns the proxy into a blackhole for existing and new connections.
func (p *Proxy) Freeze() { p.frozen.Store(true) }

// SNIs returns the server names of the ClientHellos the proxy routed.
func (p *Proxy) SNIs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.snis...)
}

// Seen returns the bytes the proxy relayed (both directions, up to 64 MiB).
func (p *Proxy) Seen() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.seen.Bytes()...)
}

// Close stops the listener and closes every relayed connection.
func (p *Proxy) Close() {
	_ = p.ln.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
}

func (p *Proxy) accept() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

// recordingConn records what is read and discards what is written, so crypto/tls can parse the
// ClientHello without sending anything to the client.
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (r *recordingConn) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	r.buf.Write(b[:n])
	return n, err
}

func (r *recordingConn) Write(b []byte) (int, error) { return len(b), nil }

func (p *Proxy) handle(c net.Conn) {
	var sni string
	var hello []byte
	if p.peek {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		rec := &recordingConn{Conn: c}
		_ = tls.Server(rec, &tls.Config{
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				sni = chi.ServerName
				return nil, errPeeked
			},
		}).Handshake()
		_ = c.SetReadDeadline(time.Time{})
		hello = rec.buf.Bytes()
		if sni == "" {
			_ = c.Close()
			return
		}
		p.mu.Lock()
		p.snis = append(p.snis, sni)
		p.mu.Unlock()
	}
	addr, ok := p.route(sni)
	if !ok {
		_ = c.Close()
		return
	}
	up, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		_ = c.Close()
		return
	}
	p.mu.Lock()
	p.conns = append(p.conns, c, up)
	p.mu.Unlock()
	if _, err := up.Write(hello); err != nil {
		_ = c.Close()
		_ = up.Close()
		return
	}
	go p.pipe(up, c)
	go p.pipe(c, up)
}

func (p *Proxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 && !p.frozen.Load() {
			p.mu.Lock()
			if p.seen.Len() < seenLimit {
				p.seen.Write(buf[:n])
			}
			p.mu.Unlock()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				_ = src.Close()
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && !p.frozen.Load() {
				if tc, ok := dst.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
					return
				}
			}
			if !p.frozen.Load() {
				_ = dst.Close()
			}
			return
		}
	}
}
