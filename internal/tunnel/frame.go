// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
)

// MaxMessage is the largest message on a tunnel stream, and MaxChunk the largest in-band chunk
// (docs/03-connections.md, "Framing").
const (
	MaxMessage = 16 << 10
	MaxChunk   = 16 << 10
)

// ErrTooLarge is returned for a message or chunk above its limit.
var ErrTooLarge = errors.New("tunnel: message too large")

// WriteMessage writes m as varint(length) ‖ protobuf in one Write.
func WriteMessage(w io.Writer, m proto.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > MaxMessage {
		return fmt.Errorf("%w: %d bytes", ErrTooLarge, len(b))
	}
	buf := binary.AppendUvarint(make([]byte, 0, binary.MaxVarintLen64+len(b)), uint64(len(b)))
	_, err = w.Write(append(buf, b...))
	return err
}

// ReadMessage reads one message written by WriteMessage into m. It refuses a length above
// MaxMessage before reading the payload, and it reads nothing after the message, so raw bytes that
// follow stay in r.
func ReadMessage(r io.Reader, m proto.Message) error {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = byteReader{r}
	}
	n, err := binary.ReadUvarint(br)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		return fmt.Errorf("tunnel: message length: %w", err)
	}
	if n > MaxMessage {
		return fmt.Errorf("%w: %d bytes", ErrTooLarge, n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	return proto.Unmarshal(b, m)
}

// byteReader reads one byte at a time, so that ReadMessage never reads past a message.
type byteReader struct{ r io.Reader }

func (b byteReader) ReadByte() (byte, error) {
	var p [1]byte
	_, err := io.ReadFull(b.r, p[:])
	return p[0], err
}

// CheckStreamOpen checks a StreamOpen before anything is dialled and returns the code to answer
// with: RESULT_CODE_PROTOCOL for a kind that Phase 1 does not know, a missing route, a malformed
// address or trace context, or a result on a stream that answers no OpenRequest.
func CheckStreamOpen(o *tunnelv1.StreamOpen) tunnelv1.ResultCode {
	switch o.GetKind() {
	case tunnelv1.StreamKind_STREAM_KIND_TCP, tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW:
		if o.GetRouteId() == "" {
			return tunnelv1.ResultCode_RESULT_CODE_PROTOCOL
		}
	case tunnelv1.StreamKind_STREAM_KIND_CONTROL_PASSTHROUGH, tunnelv1.StreamKind_STREAM_KIND_DIAG:
	default: // unspecified, the relay kinds of Phase 2, and unknown numbers
		return tunnelv1.ResultCode_RESULT_CODE_PROTOCOL
	}
	ipLen := func(b []byte) bool { return len(b) == 0 || len(b) == 4 || len(b) == 16 }
	switch {
	case !ipLen(o.GetSrcIp()), !ipLen(o.GetDstIp()),
		o.GetSrcPort() > 65535, o.GetDstPort() > 65535,
		len(o.GetTraceId()) != 0 && len(o.GetTraceId()) != 16,
		len(o.GetSpanId()) != 0 && len(o.GetSpanId()) != 8,
		o.GetTraceFlags() > 0xff,
		o.GetResult() != nil && o.GetOpenId() == 0:
		return tunnelv1.ResultCode_RESULT_CODE_PROTOCOL
	}
	return tunnelv1.ResultCode_RESULT_CODE_NO_ERROR
}

// ChunkWriter frames the connector-to-gateway bytes of a stream on the TCP transport: each Write
// becomes chunks of varint(length) ‖ bytes, at most MaxChunk each, and CloseWrite writes the
// zero-length chunk, the connector's FIN, which net/http's HTTP/2 server cannot send otherwise
// while it still reads the request (ADR-0005).
type ChunkWriter struct {
	W io.Writer
}

// Write writes p as chunks; an empty p writes nothing.
func (c ChunkWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), MaxChunk)
		buf := binary.AppendUvarint(make([]byte, 0, binary.MaxVarintLen64+n), uint64(n))
		if _, err := c.W.Write(append(buf, p[:n]...)); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite writes the zero-length chunk.
func (c ChunkWriter) CloseWrite() error {
	_, err := c.W.Write([]byte{0})
	return err
}

// ChunkReader decodes what a ChunkWriter wrote. It returns io.EOF after the zero-length chunk and
// io.ErrUnexpectedEOF if the stream ends without it, or in the middle of a chunk.
type ChunkReader struct {
	r      *bufio.Reader
	remain uint64
	fin    bool
}

// NewChunkReader reads chunks from r.
func NewChunkReader(r io.Reader) *ChunkReader {
	return &ChunkReader{r: bufio.NewReaderSize(r, MaxChunk)}
}

// Read returns the bytes of the chunks.
func (c *ChunkReader) Read(p []byte) (int, error) {
	if c.fin {
		return 0, io.EOF
	}
	for c.remain == 0 {
		n, err := binary.ReadUvarint(c.r)
		switch {
		case errors.Is(err, io.EOF):
			return 0, io.ErrUnexpectedEOF // the stream ended without the connector's FIN
		case err != nil:
			return 0, err
		case n == 0:
			c.fin = true
			return 0, io.EOF
		case n > MaxChunk:
			return 0, fmt.Errorf("%w: a chunk of %d bytes", ErrTooLarge, n)
		}
		c.remain = n
	}
	if uint64(len(p)) > c.remain {
		p = p[:c.remain]
	}
	n, err := c.r.Read(p)
	c.remain -= uint64(n) //nolint:gosec // G115: n <= len(p) <= remain
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
