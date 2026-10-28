// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// quicBindEvery and quicBindFor say how often a process a hand-off started tries to bind the QUIC
// port once the old process exited, and for how long (docs/03-connections.md, "Timeouts").
var (
	quicBindEvery = 100 * time.Millisecond
	quicBindFor   = 5 * time.Second
)

// quicSide is the gateway's QUIC listener for data sessions and the UDP socket under it. After a
// hand-off only the old process reads that socket until it exits, so the new process opens it
// late (docs/03-connections.md, "Restarts with socket hand-off", "UDP and QUIC").
type quicSide struct {
	addr   string
	key    *quic.StatelessResetKey
	tls    *tls.Config
	budget *tunnel.Budget
	reg    prometheus.Registerer
	// serve runs one accepted data session.
	serve func(*tunnel.QUICSession)

	mu     sync.Mutex
	pc     net.PacketConn
	tr     *quic.Transport
	ln     *tunnel.QUICListener
	closed bool
	wg     sync.WaitGroup
}

// open binds the UDP socket, starts the listener and accepts sessions until stopAccepting or
// close. It reports a port that is still held; openWhenFree retries.
func (q *quicSide) open(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return net.ErrClosed
	}
	if q.ln != nil {
		return nil
	}
	pc, err := net.ListenPacket("udp", q.addr)
	if err != nil {
		return err
	}
	tr := &quic.Transport{Conn: pc, StatelessResetKey: q.key}
	if err := tunnel.RegisterHostMetrics(q.reg, pc); err != nil {
		_ = pc.Close()
		return err
	}
	ln, err := tunnel.ListenQUIC(tr, q.tls, q.budget)
	if err != nil {
		_ = tr.Close()
		_ = pc.Close()
		return err
	}
	q.pc, q.tr, q.ln = pc, tr, ln
	q.wg.Go(func() {
		for {
			s, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go q.serve(s)
		}
	})
	return nil
}

// openWhenFree is open, tried again every quicBindEvery for quicBindFor while the port is in
// use: the old process of a hand-off has just exited and its socket may close a moment later.
// Any other error is final. It returns the last error when the time is up or ctx ends.
func (q *quicSide) openWhenFree(ctx context.Context) error {
	deadline := time.Now().Add(quicBindFor)
	for {
		err := q.open(ctx)
		if err == nil || !errors.Is(err, syscall.EADDRINUSE) || !time.Now().Add(quicBindEvery).Before(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(quicBindEvery):
		}
	}
}

// localAddr returns the bound address, "" while the socket is not open.
func (q *quicSide) localAddr() string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pc == nil {
		return ""
	}
	return q.pc.LocalAddr().String()
}

// bound reports whether the listener is open: only a gateway that serves QUIC hands that over.
func (q *quicSide) bound() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.ln != nil
}

// stopAccepting closes the listener, so that no new session starts. Open sessions keep running
// on the transport, which stays up until close; the handshakes of new connectors get no answer,
// so that a connector on auto takes TCP within the head start.
func (q *quicSide) stopAccepting() {
	q.mu.Lock()
	ln := q.ln
	q.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

// close stops the listener, then the transport and the socket, which ends the open sessions. A
// quicSide never opens again after it.
func (q *quicSide) close() {
	q.mu.Lock()
	q.closed = true
	ln, tr, pc := q.ln, q.tr, q.pc
	q.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	q.wg.Wait()
	if tr != nil {
		_ = tr.Close()
	}
	if pc != nil {
		_ = pc.Close() // a Transport does not close a conn it was given
	}
}
