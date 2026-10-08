// SPDX-License-Identifier: Apache-2.0

// Package tlspeek reads the TLS ClientHello a client sends first, without consuming it, so that a
// listener can choose a handler by SNI and ALPN and then replay the bytes to it
// (docs/03-connections.md, "Port 443 multiplexing"). It reads full TLS records with a bounded size
// and time, parses the ClientHello with cryptobyte, depends on no crypto/tls internals and never
// writes to the client.
package tlspeek

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// The limits of a peek (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	MaxBytes = 16 << 10
	Timeout  = 5 * time.Second
)

const (
	recordTypeHandshake  = 22
	handshakeClientHello = 1
	recordHeaderLen      = 5
	maxRecordPayload     = 1 << 14 // TLSPlaintext.length (RFC 8446, Section 5.1)

	extServerName = 0
	extALPN       = 16
	extKeyShare   = 51
)

// Errors of a peek. A listener closes the connection on each of them without answering.
var (
	ErrNotTLS    = errors.New("tlspeek: not a TLS handshake record")
	ErrTooLarge  = errors.New("tlspeek: ClientHello exceeds the peek limit")
	ErrMalformed = errors.New("tlspeek: malformed ClientHello")
)

// ClientHello is what a listener routes on.
type ClientHello struct {
	ServerName     string   // the SNI host name; empty without SNI
	ALPN           []string // the offered application protocols, in the client's order
	KeyShareGroups []uint16 // the groups of the offered key shares
	Size           int      // the ClientHello handshake message, its 4-byte header included
	Raw            []byte   // every byte read; replay it to the chosen handler
}

// Peek reads full TLS records from c until it holds a complete ClientHello. It reads at most max
// bytes and gives up after timeout. Every byte it read is in Raw, also when the client sent more
// than the ClientHello. The read deadline is cleared on success; on an error the caller closes c.
func Peek(c net.Conn, max int, timeout time.Duration) (*ClientHello, error) {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, min(max, 4096)) // a ClientHello with post-quantum key shares fits
	// fill reads until buf holds at least n bytes.
	fill := func(n int) error {
		if n > max {
			return ErrTooLarge
		}
		for len(buf) < n {
			if cap(buf) < n {
				buf = append(make([]byte, 0, min(max, 2*n)), buf...)
			}
			k, err := c.Read(buf[len(buf):cap(buf)])
			buf = buf[:len(buf)+k]
			if err != nil && len(buf) < n {
				return readErr(err)
			}
		}
		return nil
	}

	var msg []byte // the handshake bytes, reassembled from the records
	size := 0
	for off := 0; size == 0; {
		if err := fill(off + recordHeaderLen); err != nil {
			return nil, err
		}
		hdr := buf[off : off+recordHeaderLen]
		if hdr[0] != recordTypeHandshake || hdr[1] != 3 {
			return nil, ErrNotTLS
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n == 0 || n > maxRecordPayload {
			return nil, fmt.Errorf("%w: record length %d", ErrMalformed, n)
		}
		if err := fill(off + recordHeaderLen + n); err != nil {
			return nil, err
		}
		msg = append(msg, buf[off+recordHeaderLen:off+recordHeaderLen+n]...)
		off += recordHeaderLen + n
		if len(msg) < 4 {
			continue
		}
		if msg[0] != handshakeClientHello {
			return nil, fmt.Errorf("%w: first handshake message of type %d", ErrMalformed, msg[0])
		}
		want := 4 + (int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3]))
		if want+recordHeaderLen > max {
			return nil, ErrTooLarge // known from the length field, before the bytes arrive
		}
		switch {
		case len(msg) > want:
			// A client sends nothing else before the server's answer.
			return nil, fmt.Errorf("%w: handshake data after the ClientHello", ErrMalformed)
		case len(msg) == want:
			size = want
		}
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ch, err := parseClientHello(msg[4:])
	if err != nil {
		return nil, err
	}
	ch.Size, ch.Raw = size, buf
	return ch, nil
}

func readErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: connection closed inside the ClientHello", ErrMalformed)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("tlspeek: no complete ClientHello in time: %w", err)
	}
	return err
}

// parseClientHello parses the body of a ClientHello handshake message (RFC 8446, Section 4.1.2).
// It checks what routing reads strictly and refuses duplicate extensions; crypto/tls checks the
// rest when the chosen handler completes the handshake.
func parseClientHello(body []byte) (*ClientHello, error) {
	s := cryptobyte.String(body)
	var legacyVersion uint16
	var random, sessionID, suites, compression, exts cryptobyte.String
	if !s.ReadUint16(&legacyVersion) || !s.ReadBytes((*[]byte)(&random), 32) ||
		!s.ReadUint8LengthPrefixed(&sessionID) || !s.ReadUint16LengthPrefixed(&suites) ||
		!s.ReadUint8LengthPrefixed(&compression) {
		return nil, fmt.Errorf("%w: fixed fields", ErrMalformed)
	}
	ch := &ClientHello{}
	if s.Empty() {
		return ch, nil // no extensions: legal before TLS 1.3, routed as "no SNI"
	}
	if !s.ReadUint16LengthPrefixed(&exts) || !s.Empty() {
		return nil, fmt.Errorf("%w: extensions block", ErrMalformed)
	}
	seen := map[uint16]bool{}
	for !exts.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&data) {
			return nil, fmt.Errorf("%w: extension header", ErrMalformed)
		}
		if seen[typ] {
			return nil, fmt.Errorf("%w: duplicate extension %d", ErrMalformed, typ)
		}
		seen[typ] = true
		var err error
		switch typ {
		case extServerName:
			err = parseServerName(data, ch)
		case extALPN:
			err = parseALPN(data, ch)
		case extKeyShare:
			err = parseKeyShare(data, ch)
		}
		if err != nil {
			return nil, err
		}
	}
	return ch, nil
}

// parseServerName reads server_name (RFC 6066, Section 3): one host_name at most, not empty.
func parseServerName(data cryptobyte.String, ch *ClientHello) error {
	var list cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() || list.Empty() {
		return fmt.Errorf("%w: server_name", ErrMalformed)
	}
	hostNames := 0
	for !list.Empty() {
		var nameType uint8
		var name cryptobyte.String
		if !list.ReadUint8(&nameType) || !list.ReadUint16LengthPrefixed(&name) || len(name) == 0 {
			return fmt.Errorf("%w: server_name entry", ErrMalformed)
		}
		if nameType == 0 {
			if hostNames++; hostNames > 1 {
				return fmt.Errorf("%w: two host names", ErrMalformed)
			}
			ch.ServerName = string(name)
		}
	}
	return nil
}

// parseALPN reads application_layer_protocol_negotiation (RFC 7301, Section 3.1): a non-empty list
// of non-empty names.
func parseALPN(data cryptobyte.String, ch *ClientHello) error {
	var list cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() || list.Empty() {
		return fmt.Errorf("%w: ALPN", ErrMalformed)
	}
	for !list.Empty() {
		var proto cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&proto) || len(proto) == 0 {
			return fmt.Errorf("%w: ALPN entry", ErrMalformed)
		}
		ch.ALPN = append(ch.ALPN, string(proto))
	}
	return nil
}

// parseKeyShare reads key_share (RFC 8446, Section 4.2.8): entries with a non-empty key.
func parseKeyShare(data cryptobyte.String, ch *ClientHello) error {
	var list cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() {
		return fmt.Errorf("%w: key_share", ErrMalformed)
	}
	for !list.Empty() {
		var group uint16
		var key cryptobyte.String
		if !list.ReadUint16(&group) || !list.ReadUint16LengthPrefixed(&key) || len(key) == 0 {
			return fmt.Errorf("%w: key_share entry", ErrMalformed)
		}
		ch.KeyShareGroups = append(ch.KeyShareGroups, group)
	}
	return nil
}

// NewReplayConn returns c with prefix read again before anything else: the bytes a peek consumed.
// Reading the prefix ignores deadlines; the bytes are already in memory.
func NewReplayConn(c net.Conn, prefix []byte) net.Conn {
	return &replayConn{Conn: c, prefix: prefix}
}

type replayConn struct {
	net.Conn
	mu     sync.Mutex
	prefix []byte
}

func (r *replayConn) Read(p []byte) (int, error) {
	r.mu.Lock()
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		r.mu.Unlock()
		return n, nil
	}
	r.mu.Unlock()
	return r.Conn.Read(p)
}

// CloseWrite half-closes the underlying connection, which TLS passthrough needs to forward a
// client's FIN. It returns errors.ErrUnsupported if the connection cannot half-close.
func (r *replayConn) CloseWrite() error {
	if cw, ok := r.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// SetLinger lets a relay reset the underlying TCP connection.
func (r *replayConn) SetLinger(sec int) error {
	if tc, ok := r.Conn.(*net.TCPConn); ok {
		return tc.SetLinger(sec)
	}
	return nil
}
