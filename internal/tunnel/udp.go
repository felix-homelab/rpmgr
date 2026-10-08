// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// UDP flows (docs/03-connections.md, "UDP routes"): each flow has a stream for its lifecycle, and
// its payloads travel as QUIC DATAGRAM frames prefixed with the flow stream's full ID as a varint.
// A payload that does not fit into a datagram, and every payload on the TCP transport, travels as
// a frame on the flow's stream instead: varint(length) ‖ payload.

const (
	// datagramQueue is how many datagrams a session queues for sending; more are dropped.
	datagramQueue = 256
	// datagramCeiling is the largest datagram, prefix included, tried before quic-go reports a
	// smaller limit: the packet ceiling after path-MTU discovery, less its overhead.
	datagramCeiling = 1412
	// pendingDatagrams and pendingFor bound what is kept of a flow whose StreamOpen has not
	// arrived yet, and pendingFlows how many such flows a session keeps.
	pendingDatagrams = 8
	pendingFor       = time.Second
	pendingFlows     = 64
	// MaxUDPPayload is the largest UDP payload a frame carries.
	MaxUDPPayload = 65535
)

// ErrFrameTooLarge is returned for a frame longer than MaxUDPPayload.
var ErrFrameTooLarge = errors.New("tunnel: a UDP frame is larger than 65535 bytes")

// WriteFrame writes one UDP payload as a frame on a flow's stream.
func WriteFrame(w io.Writer, p []byte) error {
	if len(p) > MaxUDPPayload {
		return ErrFrameTooLarge
	}
	buf := binary.AppendUvarint(make([]byte, 0, binary.MaxVarintLen64+len(p)), uint64(len(p)))
	_, err := w.Write(append(buf, p...))
	return err
}

// ReadFrame reads one UDP payload frame from a flow's stream; the end of the stream before a
// frame is io.EOF.
func ReadFrame(r io.Reader) ([]byte, error) {
	n, err := binary.ReadUvarint(byteReader{r: r})
	if err != nil {
		return nil, err
	}
	if n > MaxUDPPayload {
		return nil, ErrFrameTooLarge
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return p, nil
}

// StreamID returns the full QUIC stream ID of a stream of a QUIC session, which prefixes its
// flow's datagrams; ok is false on the TCP transport.
func StreamID(st Stream) (id uint64, ok bool) {
	for {
		switch s := st.(type) {
		case *quicStream:
			return uint64(s.st.StreamID()), true //nolint:gosec // G115: stream IDs are non-negative
		case interface{ Unwrap() Stream }:
			st = s.Unwrap()
		default:
			return 0, false
		}
	}
}

// Datagrams carries the UDP payloads of one QUIC session's flows. Sending never blocks: a queue of
// datagramQueue drops what does not fit, as UDP does. Received datagrams go to the flow registered
// for their stream ID; those of a flow not registered yet are kept, up to pendingDatagrams for
// pendingFor, for at most pendingFlows such flows.
type Datagrams struct {
	conn  *quic.Conn
	queue chan []byte
	max   atomic.Int64 // the largest datagram, prefix included, that may fit

	sent, dropped, tooLarge atomic.Uint64

	mu      sync.Mutex
	flows   map[uint64]func([]byte)
	pending map[uint64]*pendingFlow
}

type pendingFlow struct {
	first time.Time
	data  [][]byte
}

// Datagrams returns the session's datagram multiplexer, started on first use.
func (s *QUICSession) Datagrams() *Datagrams {
	s.dgOnce.Do(func() {
		d := &Datagrams{conn: s.conn, queue: make(chan []byte, datagramQueue), flows: map[uint64]func([]byte){},
			pending: map[uint64]*pendingFlow{}}
		d.max.Store(datagramCeiling)
		go d.send()
		go d.receive()
		s.dg = d
	})
	return s.dg
}

// Fits reports whether a payload of n bytes for the flow id may go as a datagram; if not, the
// caller sends it as a frame on the flow's stream.
func (d *Datagrams) Fits(id uint64, n int) bool {
	return int64(n+varintLen(id)) <= d.max.Load()
}

func varintLen(v uint64) int {
	var b [binary.MaxVarintLen64]byte
	return binary.PutUvarint(b[:], v)
}

// Send queues a payload of the flow id as a datagram and reports whether it was queued; a full
// queue drops it. The caller checks Fits first.
func (d *Datagrams) Send(id uint64, p []byte) bool {
	b := binary.AppendUvarint(make([]byte, 0, binary.MaxVarintLen64+len(p)), id)
	b = append(b, p...)
	select {
	case d.queue <- b:
		return true
	default:
		d.dropped.Add(1)
		return false
	}
}

func (d *Datagrams) send() {
	ctx := d.conn.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-d.queue:
			err := d.conn.SendDatagram(b)
			var tooLarge *quic.DatagramTooLargeError
			switch {
			case err == nil:
				d.sent.Add(1)
			case errors.As(err, &tooLarge):
				// The path got smaller: this one is lost, as a UDP datagram would be, and the
				// next ones of this size go as frames.
				d.max.Store(tooLarge.MaxDatagramPayloadSize)
				d.tooLarge.Add(1)
			default:
				d.dropped.Add(1)
			}
		}
	}
}

func (d *Datagrams) receive() {
	ctx := d.conn.Context()
	for {
		b, err := d.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		id, n := binary.Uvarint(b)
		if n <= 0 {
			continue // not a flow datagram: ignored
		}
		d.deliver(id, b[n:])
	}
}

func (d *Datagrams) deliver(id uint64, p []byte) {
	d.mu.Lock()
	f := d.flows[id]
	if f == nil {
		now := time.Now()
		for k, pf := range d.pending {
			if now.Sub(pf.first) > pendingFor {
				delete(d.pending, k)
			}
		}
		pf := d.pending[id]
		if pf == nil {
			if len(d.pending) >= pendingFlows {
				d.dropped.Add(1)
				d.mu.Unlock()
				return
			}
			pf = &pendingFlow{first: now}
			d.pending[id] = pf
		}
		if len(pf.data) < pendingDatagrams {
			pf.data = append(pf.data, p)
		} else {
			d.dropped.Add(1)
		}
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()
	f(p)
}

// Register delivers the datagrams of the flow id, first those kept while it was unknown, to f until
// the returned function unregisters it. f must not block.
func (d *Datagrams) Register(id uint64, f func([]byte)) func() {
	d.mu.Lock()
	d.flows[id] = f
	var kept [][]byte
	if pf := d.pending[id]; pf != nil && time.Since(pf.first) <= pendingFor {
		kept = pf.data
	}
	delete(d.pending, id)
	d.mu.Unlock()
	for _, p := range kept {
		f(p)
	}
	return func() {
		d.mu.Lock()
		delete(d.flows, id)
		d.mu.Unlock()
	}
}

// Stats are a session's datagram counters, for the rpmgr_udp_* metrics.
type Stats struct{ Sent, Dropped, TooLarge uint64 }

// Stats returns the counters so far.
func (d *Datagrams) Stats() Stats {
	return Stats{Sent: d.sent.Load(), Dropped: d.dropped.Load(), TooLarge: d.tooLarge.Load()}
}

// String is for logs.
func (s Stats) String() string {
	return fmt.Sprintf("sent %d, dropped %d, too large %d", s.Sent, s.Dropped, s.TooLarge)
}

// Pending returns how many unknown flows have datagrams kept; for tests.
func (d *Datagrams) Pending() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pending)
}
