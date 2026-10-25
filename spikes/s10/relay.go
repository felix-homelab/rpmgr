// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// relayQueue is the per-socket queue of datagrams passed between the processes (03, "Hand-off
// relay"); beyond it datagrams are dropped and counted.
const relayQueue = 1024

type pkt struct {
	b    []byte
	addr *net.UDPAddr
}

// udpSock is a UDP socket shared by the old and the new process during a hand-off. It reads
// datagrams from the real socket (direct) and/or from the relay of its predecessor (relayIn), and
// passes the datagrams that foreign() claims to its successor (relayOut). It implements only
// net.PacketConn, so quic-go uses ReadFrom/WriteTo and never the socket's batch paths behind it.
type udpSock struct {
	real *net.UDPConn
	in   chan pkt

	mu       sync.Mutex
	out      chan pkt // to the successor, while relaying
	foreign  func(b []byte, addr *net.UDPAddr) bool
	deadline time.Time
	closed   chan struct{}
	once     sync.Once
	direct   atomic.Bool

	Relayed, Dropped, ReadDirect, ReadRelayed atomic.Int64
}

func newUDPSock(real *net.UDPConn) *udpSock {
	return &udpSock{real: real, in: make(chan pkt, 4096), closed: make(chan struct{})}
}

// startDirect starts reading the real socket; only one process reads it at a time.
func (s *udpSock) startDirect() {
	if s.direct.Swap(true) {
		return
	}
	go func() {
		for {
			b := make([]byte, 1500)
			n, addr, err := s.real.ReadFromUDP(b)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			s.ReadDirect.Add(1)
			select {
			case s.in <- pkt{b[:n], addr}:
			case <-s.closed:
				return
			}
		}
	}()
}

// startRelayIn reads datagrams its predecessor passes over f (a unixgram socket).
func (s *udpSock) startRelayIn(f *os.File) {
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return
	}
	go func() {
		defer c.Close()
		buf := make([]byte, 2048)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			p, ok := decodeRelay(buf[:n])
			if !ok {
				continue
			}
			s.ReadRelayed.Add(1)
			select {
			case s.in <- p:
			case <-s.closed:
				return
			}
		}
	}()
}

// startRelayOut passes the datagrams foreign claims to the successor over f.
func (s *udpSock) startRelayOut(f *os.File, foreign func([]byte, *net.UDPAddr) bool) {
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return
	}
	out := make(chan pkt, relayQueue)
	s.mu.Lock()
	s.out, s.foreign = out, foreign
	s.mu.Unlock()
	go func() {
		defer c.Close()
		for p := range out {
			if _, err := c.Write(encodeRelay(p)); err != nil {
				s.Dropped.Add(1)
			}
		}
	}()
}

func (s *udpSock) stopRelayOut() {
	s.mu.Lock()
	if s.out != nil {
		close(s.out)
		s.out = nil
	}
	s.mu.Unlock()
}

func (s *udpSock) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		s.mu.Lock()
		d := s.deadline
		s.mu.Unlock()
		var timer <-chan time.Time
		if !d.IsZero() {
			t := time.NewTimer(time.Until(d))
			defer t.Stop()
			timer = t.C
		}
		select {
		case p := <-s.in:
			s.mu.Lock()
			out, foreign := s.out, s.foreign
			if out != nil && foreign(p.b, p.addr) {
				select {
				case out <- p:
					s.Relayed.Add(1)
				default:
					s.Dropped.Add(1)
				}
				s.mu.Unlock()
				continue
			}
			s.mu.Unlock()
			return copy(b, p.b), p.addr, nil
		case <-timer:
			return 0, nil, os.ErrDeadlineExceeded
		case <-s.closed:
			return 0, nil, net.ErrClosed
		}
	}
}

func (s *udpSock) WriteTo(b []byte, addr net.Addr) (int, error) { return s.real.WriteTo(b, addr) }
func (s *udpSock) LocalAddr() net.Addr                          { return s.real.LocalAddr() }
func (s *udpSock) SetDeadline(t time.Time) error                { return s.SetReadDeadline(t) }
func (s *udpSock) SetWriteDeadline(t time.Time) error           { return s.real.SetWriteDeadline(t) }
func (s *udpSock) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.deadline = t
	s.mu.Unlock()
	return nil
}

// Close stops this process's use of the socket; the descriptor closes too (the other process
// holds its own).
func (s *udpSock) Close() error {
	s.once.Do(func() { close(s.closed); s.stopRelayOut(); _ = s.real.Close() })
	return nil
}

func encodeRelay(p pkt) []byte {
	a := p.addr.AddrPort()
	ab, _ := a.MarshalBinary()
	out := make([]byte, 0, 1+len(ab)+len(p.b))
	out = append(out, byte(len(ab)))
	out = append(out, ab...)
	return append(out, p.b...)
}

func decodeRelay(b []byte) (pkt, bool) {
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return pkt{}, false
	}
	var a net.UDPAddr
	ap := a.AddrPort()
	if err := ap.UnmarshalBinary(b[1 : 1+int(b[0])]); err != nil {
		return pkt{}, false
	}
	body := append([]byte(nil), b[1+int(b[0]):]...)
	return pkt{body, net.UDPAddrFromAddrPort(ap)}, true
}

// quicForeign decides, for the old process during the drain, which QUIC packets belong to the
// new process: every Initial and 0-RTT packet (the old process accepts no new connection), and
// Handshake and short-header packets whose destination connection ID names another generation.
func quicForeign(gen byte, cidLen int) func([]byte, *net.UDPAddr) bool {
	return func(b []byte, _ *net.UDPAddr) bool {
		if len(b) == 0 {
			return false
		}
		if b[0]&0x80 != 0 { // long header
			if len(b) < 7 {
				return false
			}
			typ := (b[0] & 0x30) >> 4 // QUIC v1: 0 Initial, 1 0-RTT, 2 Handshake, 3 Retry
			if typ == 0 || typ == 1 {
				return true
			}
			dl := int(b[5])
			if dl == 0 || len(b) < 6+dl {
				return false
			}
			return b[6] != gen
		}
		if len(b) < 1+cidLen {
			return false
		}
		return b[1] != gen
	}
}

// genCIDs issues connection IDs whose first byte names the process generation (ADR-0022).
type genCIDs struct{ gen byte }

func (g genCIDs) GenerateConnectionID() (quic.ConnectionID, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b[1:]); err != nil {
		return quic.ConnectionID{}, err
	}
	b[0] = g.gen
	return quic.ConnectionIDFromBytes(b), nil
}

func (g genCIDs) ConnectionIDLen() int { return 8 }
