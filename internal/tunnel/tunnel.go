// SPDX-License-Identifier: Apache-2.0

// Package tunnel carries public connections between gateways and connectors over data sessions
// (docs/03-connections.md, "Data session"): the framing of every stream message, the stream
// preamble, the connector's in-band half-close on the TCP transport, and the Session and Stream
// interfaces that the QUIC and the reverse HTTP/2 transport implement, so that gateway and
// connector code never sees which one carries a stream (ADR-0004).
package tunnel

import (
	"context"
	"io"
)

// The ALPN identifiers of the two transports (docs/03-connections.md, "Overview").
const (
	ALPNQUIC = "rpmgr-tunnel/1"
	ALPNH2   = "rpmgr-tunnel-h2/1"
)

// Stream is one bidirectional stream of a data session.
type Stream interface {
	io.Reader
	io.Writer
	// CloseWrite half-closes the sending direction (FIN); reading continues.
	CloseWrite() error
	// Abort resets both directions, as a client's RST does; data not yet delivered is dropped.
	Abort()
	// Close releases the stream after both directions ended; a direction still open is aborted.
	Close() error
}

// Session is a data session between a connector and a gateway.
type Session interface {
	// OpenStream opens a stream without waiting for a round trip. It never blocks on the peer's
	// stream limit: it fails at once instead, so the caller can use another session.
	OpenStream(ctx context.Context) (Stream, error)
	// AcceptStream returns the next stream the peer opened.
	AcceptStream(ctx context.Context) (Stream, error)
	// Close ends the session and every stream on it.
	Close() error
	// Done is closed when the session has ended.
	Done() <-chan struct{}
	// Transport names the transport: "quic" or "h2".
	Transport() string
}
