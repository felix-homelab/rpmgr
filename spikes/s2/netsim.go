// SPDX-License-Identifier: Apache-2.0

package s2

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Proxy is a TCP proxy on 127.0.0.1 that adds a one-way delay to each direction and can
// blackhole the connection (forward nothing, close nothing), to test RTT effects and liveness.
// It stands in for netem: the delay is applied per chunk, in order.
type Proxy struct {
	ln        net.Listener
	target    string
	oneWay    time.Duration
	blackhole atomic.Bool
	wg        sync.WaitGroup
	mu        sync.Mutex
	conns     []net.Conn
}

// NewProxy listens on 127.0.0.1:0 and forwards to target with the given one-way delay.
func NewProxy(target string, oneWay time.Duration) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{ln: ln, target: target, oneWay: oneWay}
	go p.accept()
	return p, nil
}

// Addr is the address to dial instead of the target.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Blackhole drops everything in both directions from now on, without closing anything.
func (p *Proxy) Blackhole() { p.blackhole.Store(true) }

// Close closes the listener and all proxied connections.
func (p *Proxy) Close() {
	p.ln.Close()
	p.mu.Lock()
	for _, c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
}

func (p *Proxy) accept() {
	for {
		in, err := p.ln.Accept()
		if err != nil {
			return
		}
		out, err := net.Dial("tcp", p.target)
		if err != nil {
			in.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, in, out)
		p.mu.Unlock()
		go p.pipe(in, out)
		go p.pipe(out, in)
	}
}

type chunk struct {
	at time.Time
	b  []byte
}

func (p *Proxy) pipe(src, dst net.Conn) {
	q := make(chan chunk, 1<<16)
	go func() {
		defer close(q)
		for {
			b := make([]byte, 64<<10)
			n, err := src.Read(b)
			if n > 0 && !p.blackhole.Load() {
				q <- chunk{at: time.Now(), b: b[:n]}
			}
			if err != nil {
				return
			}
		}
	}()
	for c := range q {
		if d := time.Until(c.at.Add(p.oneWay)); d > 0 {
			time.Sleep(d)
		}
		if p.blackhole.Load() {
			continue
		}
		if _, err := dst.Write(c.b); err != nil {
			break
		}
	}
	if tc, ok := dst.(*net.TCPConn); ok && !p.blackhole.Load() {
		tc.CloseWrite()
	}
	io.Copy(io.Discard, src)
}
