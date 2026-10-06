// SPDX-License-Identifier: Apache-2.0

// Package tunnel is the minimal tunnel of the S1 benchmark: a gateway that opens one stream per
// public connection on a data session, and a connector that dials the route's target and splices
// bytes, over QUIC or over TLS + reverse HTTP/2 (docs/03-connections.md). It implements only
// what the benchmark measures: the per-connection preamble (StreamOpen, StreamResult), stream
// opening without an extra round trip, half-close and the tuned flow-control parameters. Session
// control streams, OpenRequest, datagrams and the snapshot machinery are out of scope.
package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// ALPN identifiers of the two transports (docs/03-connections.md#versioning-and-capabilities).
const (
	ALPNQUIC = "rpmgr-tunnel/1"
	ALPNH2   = "rpmgr-tunnel-h2/1"
)

// maxPreamble bounds StreamOpen and StreamResult messages (16 KiB on tunnel streams).
const maxPreamble = 16 << 10

// Result codes of StreamResult used by the benchmark.
const (
	ResultOK           byte = 0
	ResultRouteUnknown byte = 1
	ResultRefused      byte = 3
)

// Stream is one bidirectional tunnel stream. CloseWrite half-closes the sending direction;
// Close releases the stream, aborting whatever is still open.
type Stream interface {
	io.Reader
	io.Writer
	CloseWrite() error
	Close() error
}

// Session opens gateway-to-connector streams.
type Session interface {
	OpenStream() (Stream, error)
	Closed() bool
	Close() error
}

// WriteMessage writes varint(len) ‖ payload, the framing of every rpmgr stream message.
func WriteMessage(w io.Writer, payload []byte) error {
	if len(payload) > maxPreamble {
		return fmt.Errorf("tunnel: message of %d bytes exceeds %d", len(payload), maxPreamble)
	}
	buf := binary.AppendUvarint(make([]byte, 0, binary.MaxVarintLen64+len(payload)), uint64(len(payload)))
	_, err := w.Write(append(buf, payload...))
	return err
}

// ReadMessage reads one varint-framed message. It reads byte by byte up to the payload, so no
// bytes after the message are consumed from r.
func ReadMessage(r io.Reader) ([]byte, error) {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = byteReader{r}
	}
	n, err := binary.ReadUvarint(br)
	if err != nil {
		return nil, err
	}
	if n > maxPreamble {
		return nil, fmt.Errorf("tunnel: message of %d bytes exceeds %d", n, maxPreamble)
	}
	payload := make([]byte, n)
	_, err = io.ReadFull(r, payload)
	return payload, err
}

type byteReader struct{ io.Reader }

func (b byteReader) ReadByte() (byte, error) {
	var p [1]byte
	_, err := io.ReadFull(b.Reader, p[:])
	return p[0], err
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}

// Counter counts relayed bytes for the CPU-per-Gbit/s measurement.
var Counter atomic.Int64

// Splice copies a→b and b→a. When one direction ends, it half-closes the other side's sending
// direction and keeps the remaining direction flowing, so a FIN never closes the opposite
// direction early (docs/03-connections.md#one-stream-per-user-connection). It returns when both
// directions have ended and then releases both ends.
func Splice(a, b Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyHalf(b, a) }()
	go func() { defer wg.Done(); copyHalf(a, b) }()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func copyHalf(dst, src Stream) {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	n, err := io.CopyBuffer(writerOnly{dst}, readerOnly{src}, *bp)
	Counter.Add(n)
	if err != nil && !errors.Is(err, io.EOF) {
		// Abort: propagate as a reset in both directions.
		_ = dst.Close()
		_ = src.Close()
		return
	}
	_ = dst.CloseWrite()
}

// readerOnly and writerOnly hide ReaderFrom/WriterTo, so io.CopyBuffer uses the pooled buffer.
type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

// TCPStream adapts a TCP connection to Stream.
type TCPStream struct{ *net.TCPConn }

// Close closes with SO_LINGER=0 only on abort; a normal close after both directions ended is a
// FIN, so it is a plain Close here.
func (s TCPStream) Close() error { return s.TCPConn.Close() }
