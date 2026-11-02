// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"syscall"
)

// defaultTargetConns is how many connections a connector holds open to one target address for
// streams and health checks together, when the route sets no bound (docs/03-connections.md,
// "Target connection bound").
const defaultTargetConns = 1024

// maxUndecided is how many checks in a row that ran and failed like a target over its limit, with
// streams held, stay undecided before the failure counts: a visitor that keeps one stream open
// must not keep a dead target healthy (docs/03-connections.md, "Target connection bound").
var maxUndecided = 6

// maxTargetConns is the route's bound on connections to one target address; an http route has none,
// as its streams are pooled and its limit counts requests, but its streams are still counted.
func (r Route) maxTargetConns() int {
	if r.HTTP {
		return math.MaxInt
	}
	if r.MaxTargetConns > 0 {
		return r.MaxTargetConns
	}
	return defaultTargetConns
}

// targetConns counts the connections the connector holds to each target address, those of streams
// and those of health checks alike: a target that bounds connections per source sees them all as
// one peer. The bound is the route's, checked on each acquire.
type targetConns struct {
	mu    sync.Mutex
	n     map[string]int      // slots taken, streams and checks
	s     map[string]int      // of them, streams'
	slots map[net.Conn]string // a stream's connection and the address it holds a slot of
}

func newTargetConns() *targetConns {
	return &targetConns{n: map[string]int{}, s: map[string]int{}, slots: map[net.Conn]string{}}
}

// acquire takes a slot of addr unless limit are held; a stream's slot is counted as one.
func (c *targetConns) acquire(addr string, limit int, stream bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n[addr] >= limit {
		return false
	}
	c.n[addr]++
	if stream {
		c.s[addr]++
	}
	return true
}

// release gives back a slot of addr taken as a stream's or a check's.
func (c *targetConns) release(addr string, stream bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dec := func(m map[string]int) {
		if m[addr] <= 1 {
			delete(m, addr)
			return
		}
		m[addr]--
	}
	dec(c.n)
	if stream {
		dec(c.s)
	}
}

// streams returns how many of addr's slots streams hold: other checks' slots say nothing of what
// holds the target's connections.
func (c *targetConns) streams(addr string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s[addr]
}

// held returns how many slots of addr are taken.
func (c *targetConns) held(addr string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[addr]
}

// bind ties a slot of addr to the stream's connection until releaseConn.
func (c *targetConns) bind(conn net.Conn, addr string) {
	c.mu.Lock()
	c.slots[conn] = addr
	c.mu.Unlock()
}

// releaseConn gives back the slot of a stream's connection, once; it does nothing for a connection
// without one.
func (c *targetConns) releaseConn(conn net.Conn) {
	c.mu.Lock()
	addr, ok := c.slots[conn]
	delete(c.slots, conn)
	c.mu.Unlock()
	if ok {
		c.release(addr, true)
	}
}

// errTargetAtBound is what a check reports when the connector already holds its bound of
// connections to the target, so that the check, which would be one more, is not run.
var errTargetAtBound = errors.New("the connector holds its limit of connections to the target")

// checkHeld is a failed check of a target the connector holds streams to. Undecided says the failure
// is one a target at its connections per source gives (a refusal, a reset, a timeout, or no
// check at all), which decides nothing about the target's health; otherwise the failure counts, with
// Held named as the likely cause in the target's status. Ran is false for a check that was not
// dialled for want of a slot, which says nothing either way and is not counted against maxUndecided.
type checkHeld struct {
	err       error
	held      int
	undecided bool
	ran       bool
}

func (e *checkHeld) Error() string { return e.err.Error() }
func (e *checkHeld) Unwrap() error { return e.err }

// note names the likely cause of a failed check: the connections streams hold to the target.
func (e *checkHeld) note() string {
	return fmt.Sprintf("the connector holds %d connections to the target for streams, which may use up the connections it allows per source", e.held)
}

// connFailure reports whether err is what a target gives a peer over its limit: it refuses or resets
// the connection, closes it unanswered, or does not answer in time.
func connFailure(err error) bool {
	var ne net.Error
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &ne) && ne.Timeout() ||
		errors.Is(err, errTargetAtBound)
}
