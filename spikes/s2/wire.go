// SPDX-License-Identifier: Apache-2.0

package s2

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxMessage is the largest message on a tunnel stream (docs/03-connections.md, "Framing").
const MaxMessage = 16 << 10

// Messages are varint(length) || payload, as in 03. The spike encodes the payload as JSON
// instead of protobuf to avoid code generation; the framing, not the encoding, is under test.

// StreamOpen is the first message on every gateway-opened stream.
type StreamOpen struct {
	Kind    int           `json:"kind"`
	RouteID string        `json:"route_id,omitempty"`
	OpenID  uint64        `json:"open_id,omitempty"` // answers a connector's OpenRequest
	Result  *StreamResult `json:"result,omitempty"`  // only on open_id streams
}

// StreamResult answers a StreamOpen (03, "Framing").
type StreamResult struct {
	Code int `json:"code"`
}

// Stream kinds and result codes from 03.
const (
	KindTCP       = 1
	KindRelayOut  = 3
	KindRelayIn   = 4
	ResultOK      = 0
	ResultUnknown = 1
	ResultRefused = 3
	ResultProto   = 8
)

// Control is a message on the session control stream. The spike uses one tagged struct.
type Control struct {
	Type       string `json:"type"` // hello, welcome, ping, pong, open_request, open_rejected
	Seq        uint64 `json:"seq,omitempty"`
	Pad        string `json:"pad,omitempty"` // pings are padded to ≥ 64 bytes (03)
	OpenID     uint64 `json:"open_id,omitempty"`
	Kind       int    `json:"kind,omitempty"`
	FirstChunk []byte `json:"first_chunk,omitempty"` // ≤ 16 KiB, forwarded at once (03)
	Code       int    `json:"code,omitempty"`
}

// WriteMsg writes v as varint(length) || JSON.
func WriteMsg(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxMessage+MaxMessage/2 { // JSON base64 of a 16 KiB first chunk
		return fmt.Errorf("message of %d bytes exceeds the limit", len(b))
	}
	var hdr [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(hdr[:], uint64(len(b)))
	buf := make([]byte, 0, n+len(b))
	buf = append(buf, hdr[:n]...)
	buf = append(buf, b...)
	_, err = w.Write(buf)
	return err
}

// ReadMsg reads one message written by WriteMsg into v.
func ReadMsg(r *bufio.Reader, v any) error {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	if n > MaxMessage+MaxMessage/2 {
		return fmt.Errorf("message of %d bytes exceeds the limit", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Framed connector-to-gateway data (the in-band half-close variant): each chunk is
// varint(length) || bytes; a zero-length chunk is the connector's FIN.

// errFramedFIN is returned internally when the zero-length chunk arrives.
var errFramedFIN = errors.New("framed FIN")

// writeChunk writes one framed chunk; len(p) == 0 writes the FIN.
func writeChunk(w io.Writer, p []byte) error {
	var hdr [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(hdr[:], uint64(len(p)))
	if _, err := w.Write(hdr[:n]); err != nil {
		return err
	}
	if len(p) == 0 {
		return nil
	}
	_, err := w.Write(p)
	return err
}

// framedReader decodes chunks written by writeChunk and returns io.EOF after the FIN.
type framedReader struct {
	r      *bufio.Reader
	remain uint64
	fin    bool
}

func (f *framedReader) Read(p []byte) (int, error) {
	if f.fin {
		return 0, io.EOF
	}
	for f.remain == 0 {
		n, err := binary.ReadUvarint(f.r)
		if err != nil {
			if err == io.EOF {
				// END_STREAM without a FIN chunk: the peer ended without half-closing first.
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		if n == 0 {
			f.fin = true
			return 0, io.EOF
		}
		f.remain = n
	}
	if uint64(len(p)) > f.remain {
		p = p[:f.remain]
	}
	n, err := f.r.Read(p)
	f.remain -= uint64(n)
	if err == io.EOF && f.remain > 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
