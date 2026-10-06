// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICConfig returns the QUIC parameters of docs/03-connections.md#quic-parameters. The
// connector accepts the gateway's user streams, so it allows 10 000 incoming streams; the
// gateway allows 1 000. The process-wide window budget is not modelled: one benchmark session
// never reaches it.
func QUICConfig(connector bool) *quic.Config {
	incoming := int64(1000)
	if connector {
		incoming = 10000
	}
	return &quic.Config{
		HandshakeIdleTimeout:       5 * time.Second,
		MaxIdleTimeout:             30 * time.Second,
		KeepAlivePeriod:            10 * time.Second,
		InitialStreamReceiveWindow: 512 << 10,
		MaxStreamReceiveWindow:     16 << 20,
		MaxConnectionReceiveWindow: 256 << 20,
		MaxIncomingStreams:         incoming,
		EnableDatagrams:            true,
		Allow0RTT:                  false,
	}
}

// QUICSession is a gateway's view of a connector's QUIC data session.
type QUICSession struct{ Conn *quic.Conn }

// OpenStream opens a stream without blocking; at the stream limit it fails instead of waiting
// (docs/03-connections.md#quic-parameters).
func (s QUICSession) OpenStream() (Stream, error) {
	st, err := s.Conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &QUICStream{Stream: st}, nil
}

// Closed reports whether the session has ended.
func (s QUICSession) Closed() bool { return s.Conn.Context().Err() != nil }

// Close closes the session.
func (s QUICSession) Close() error { return s.Conn.CloseWithError(0, "") }

// QUICStream adapts a quic-go stream. Stream.Close only closes the send direction
// [F quic-go v0.63.0 stream.go:192], so CloseWrite maps to it; Close aborts whatever direction
// has not ended normally.
type QUICStream struct {
	*quic.Stream
	wroteFIN atomic.Bool
	readEOF  atomic.Bool
}

func (s *QUICStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	if errors.Is(err, io.EOF) {
		s.readEOF.Store(true)
	}
	return n, err
}

// CloseWrite sends FIN.
func (s *QUICStream) CloseWrite() error {
	s.wroteFIN.Store(true)
	return s.Stream.Close()
}

// Close resets the directions that did not end normally.
func (s *QUICStream) Close() error {
	if !s.wroteFIN.Load() {
		s.Stream.CancelWrite(1)
	}
	if !s.readEOF.Load() {
		s.Stream.CancelRead(1)
	}
	return nil
}

// DialQUIC opens the connector's data session to a gateway.
func DialQUIC(ctx context.Context, addr string, tlsConf *tls.Config) (*quic.Conn, error) {
	tlsConf = tlsConf.Clone()
	tlsConf.NextProtos = []string{ALPNQUIC}
	return quic.DialAddr(ctx, addr, tlsConf, QUICConfig(true))
}

// ServeQUIC accepts the gateway's streams on a connector session until the session ends.
func ServeQUIC(ctx context.Context, conn *quic.Conn, handle func(Stream)) error {
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go handle(&QUICStream{Stream: st})
	}
}

// ListenQUIC starts the gateway's QUIC listener for data sessions.
func ListenQUIC(addr string, tlsConf *tls.Config) (*quic.Listener, error) {
	tlsConf = tlsConf.Clone()
	tlsConf.NextProtos = []string{ALPNQUIC}
	return quic.ListenAddr(addr, tlsConf, QUICConfig(false))
}

// AcceptQUIC registers every connector session that reaches the gateway's QUIC listener.
func (g *Gateway) AcceptQUIC(ctx context.Context, ln *quic.Listener) error {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return err
		}
		g.AddSession(QUICSession{Conn: conn})
	}
}
