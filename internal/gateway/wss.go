// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// wssRequestTimeout bounds the request's header before the upgrade on the WSS hostname.
const wssRequestTimeout = 10 * time.Second

// WSSHostname is the gateway's WSS hostname as its snapshot names it; "" offers no WSS.
type WSSHostname struct{ name atomic.Pointer[string] }

// Set sets the name.
func (w *WSSHostname) Set(name string) { w.name.Store(&name) }

// Get returns the name, "" without one.
func (w *WSSHostname) Get() string {
	if w == nil {
		return ""
	}
	if p := w.name.Load(); p != nil {
		return *p
	}
	return ""
}

// ServeWSS serves one connection to the gateway's WSS hostname, its outer TLS ended with the
// hostname's public certificate: an HTTP/1.1 request for tunnel.WSSPath upgrades to a WebSocket,
// inside which serve takes the data session's own TLS with mutual authentication, inner, exactly
// as over TLS and reverse HTTP/2, with its handshake timeout; any other request is 404. Whoever
// ended the outer TLS, such as an intercepting proxy, sees only the inner TLS (ADR-0005; 04,
// "Route edge rules").
func ServeWSS(c *tls.Conn, inner *tls.Config, serve func(*tls.Conn)) {
	done := make(chan struct{})
	conn := &closeNotify{Conn: c, done: done}
	mux := http.NewServeMux()
	mux.HandleFunc(tunnel.WSSPath, func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return // Accept answered the request already
		}
		// The inner session's own PINGs keep it alive; the WebSocket adds none. NetConn lifts the
		// read limit, so the limit is set after it.
		nc := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
		ws.SetReadLimit(tunnel.WSSMessageLimit)
		serve(tls.Server(wssConn{nc}, inner))
	})
	mux.HandleFunc("/", http.NotFound)
	// Only the request's header has a deadline, which net/http clears once it is read, so that the
	// hijacked connection carries the session without one.
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: wssRequestTimeout, Protocols: http1Only(),
		ErrorLog: log.New(io.Discard, "", 0)}
	srv.SetKeepAlivesEnabled(false)
	_ = srv.Serve(&oneConn{conn: conn, done: done})
}

func http1Only() *http.Protocols {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	return p
}

// oneConn is a listener of one connection: Accept returns it once, and then waits until it is
// closed, so that Serve returns only when the connection is done.
type oneConn struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func (l *oneConn) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConn) Close() error   { return nil }
func (l *oneConn) Addr() net.Addr { return l.conn.LocalAddr() }

// closeNotify closes done when the connection is closed, by the HTTP server or after the
// WebSocket that hijacked it ended.
type closeNotify struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeNotify) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

// wssConn is a data session's connection inside a WebSocket: its remote address is the peer's,
// on the network "wss".
type wssConn struct{ net.Conn }

func (c wssConn) RemoteAddr() net.Addr { return wssAddr{c.Conn.RemoteAddr()} }

type wssAddr struct{ net.Addr }

func (wssAddr) Network() string { return "wss" }
