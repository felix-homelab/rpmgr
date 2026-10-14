// SPDX-License-Identifier: Apache-2.0

package memnet

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// pipeBuffer is how many bytes one direction of a pipe holds before Write waits for the reader.
const pipeBuffer = 1 << 20

// Pipe returns the two ends of an in-memory connection. Unlike net.Pipe, each direction buffers up
// to 1 MiB, so a write does not wait for the reader: both ends of a TLS connection can send their
// close_notify at once, and a writer keeps going while its reader is busy.
func Pipe() (net.Conn, net.Conn) {
	ab, ba := newHalf(), newHalf()
	return newConn(ba, ab), newConn(ab, ba)
}

// half is one direction of a pipe.
type half struct {
	mu      sync.Mutex
	buf     []byte
	eof     bool          // the writer closed: Read returns io.EOF once buf is empty
	gone    bool          // the reader closed: Write fails
	changed chan struct{} // closed and replaced on every change
}

func newHalf() *half { return &half{changed: make(chan struct{})} }

// notify wakes every goroutine waiting on h. Under h.mu.
func (h *half) notify() {
	close(h.changed)
	h.changed = make(chan struct{})
}

type conn struct {
	in, out *half
	rd, wd  deadline
	once    sync.Once
	closed  chan struct{}
}

func newConn(in, out *half) *conn {
	return &conn{in: in, out: out, rd: newDeadline(), wd: newDeadline(), closed: make(chan struct{})}
}

func (c *conn) Read(b []byte) (int, error) {
	for {
		if err := c.check(&c.rd); err != nil {
			return 0, err
		}
		c.in.mu.Lock()
		switch {
		case len(c.in.buf) > 0:
			n := copy(b, c.in.buf)
			c.in.buf = c.in.buf[n:]
			if len(c.in.buf) == 0 {
				c.in.buf = nil
			}
			c.in.notify()
			c.in.mu.Unlock()
			return n, nil
		case c.in.eof:
			c.in.mu.Unlock()
			return 0, io.EOF
		case len(b) == 0:
			c.in.mu.Unlock()
			return 0, nil
		}
		changed := c.in.changed
		c.in.mu.Unlock()
		if err := c.wait(changed, &c.rd); err != nil {
			return 0, err
		}
	}
}

func (c *conn) Write(b []byte) (int, error) {
	n := 0
	for {
		if err := c.check(&c.wd); err != nil {
			return n, err
		}
		c.out.mu.Lock()
		if c.out.gone {
			c.out.mu.Unlock()
			return n, io.ErrClosedPipe
		}
		if room := pipeBuffer - len(c.out.buf); room > 0 && len(b) > 0 {
			k := min(room, len(b))
			c.out.buf = append(c.out.buf, b[:k]...)
			b, n = b[k:], n+k
			c.out.notify()
		}
		if len(b) == 0 {
			c.out.mu.Unlock()
			return n, nil
		}
		changed := c.out.changed
		c.out.mu.Unlock()
		if err := c.wait(changed, &c.wd); err != nil {
			return n, err
		}
	}
}

// check fails once the conn is closed or the deadline has passed.
func (c *conn) check(d *deadline) error {
	expired, _ := d.channels()
	select {
	case <-c.closed:
		return io.ErrClosedPipe
	case <-expired:
		return os.ErrDeadlineExceeded
	default:
		return nil
	}
}

// wait returns once changed is closed or the deadline is set again, or fails once the conn is
// closed or the deadline passes.
func (c *conn) wait(changed chan struct{}, d *deadline) error {
	expired, reset := d.channels()
	select {
	case <-changed:
	case <-reset:
	case <-c.closed:
		return io.ErrClosedPipe
	case <-expired:
		return os.ErrDeadlineExceeded
	}
	return nil
}

// Close ends both directions: the peer reads what was written, then io.EOF, and its writes fail.
func (c *conn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.out.mu.Lock()
		c.out.eof = true
		c.out.notify()
		c.out.mu.Unlock()
		c.in.mu.Lock()
		c.in.gone, c.in.buf = true, nil
		c.in.notify()
		c.in.mu.Unlock()
	})
	return nil
}

func (c *conn) LocalAddr() net.Addr  { return Addr{} }
func (c *conn) RemoteAddr() net.Addr { return Addr{} }

func (c *conn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.rd.set(t)
	return nil
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	c.wd.set(t)
	return nil
}

// deadline is a read or write deadline: expired is closed once it passes, and reset when it is
// set again, so that a waiting call picks up the new one.
type deadline struct {
	mu      sync.Mutex
	timer   *time.Timer
	expired chan struct{}
	reset   chan struct{}
}

func newDeadline() deadline {
	return deadline{expired: make(chan struct{}), reset: make(chan struct{})}
}

func (d *deadline) channels() (expired, reset chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expired, d.reset
}

// set replaces the deadline; the zero time removes it. Each expired channel is closed by its own
// timer or here, never twice: a stopped timer whose function already ran closed the old one.
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	close(d.reset)
	d.reset = make(chan struct{})
	d.expired = make(chan struct{})
	if t.IsZero() {
		return
	}
	expired := d.expired
	if wait := time.Until(t); wait > 0 {
		d.timer = time.AfterFunc(wait, func() { close(expired) })
		return
	}
	close(expired)
}
