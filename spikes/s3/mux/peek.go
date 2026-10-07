// SPDX-License-Identifier: Apache-2.0

// Package mux is the spike S3 prototype of the gateway's port-443 multiplexer
// (docs/03-connections.md, "Port 443 multiplexing").
package mux

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// Limits of the ClientHello peek (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	MaxPeekBytes = 16 << 10
	PeekTimeout  = 5 * time.Second
)

const (
	recordTypeHandshake   = 22
	handshakeClientHello  = 1
	recordHeaderLen       = 5
	maxRecordPayload      = 1 << 14 // TLSPlaintext.length limit (RFC 8446, 5.1)
	extServerName         = 0
	extSupportedGroups    = 10
	extALPN               = 16
	extSupportedVersions  = 43
	extKeyShare           = 51
	extEncryptedClientHel = 0xfe0d
)

// Errors of the peek. The router closes the connection on each of them.
var (
	ErrNotTLS    = errors.New("not a TLS handshake record")
	ErrTooLarge  = errors.New("ClientHello exceeds the peek limit")
	ErrMalformed = errors.New("malformed ClientHello")
)

// ClientHello is what the router needs from the client's first flight, plus measurements.
type ClientHello struct {
	ServerName      string
	ALPN            []string
	SupportedGroups []uint16
	KeyShareGroups  []uint16
	KeyShareBytes   int // sum of the key_exchange lengths
	Versions        []uint16
	ECH             bool   // encrypted_client_hello extension present (outer SNI only)
	Size            int    // ClientHello handshake message incl. its 4-byte header
	Records         int    // TLS records the message spanned
	Reads           int    // conn.Read calls needed (≈ TCP segments as delivered by the kernel)
	Raw             []byte // every byte read; must be replayed to the chosen handler
}

// Peek reads full TLS records from c until a complete ClientHello is available. It reads at most
// max bytes and gives up after timeout; it consumes nothing that is not returned in Raw. The read
// deadline is cleared before it returns successfully.
func Peek(c net.Conn, max int, timeout time.Duration) (*ClientHello, error) {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	ch := &ClientHello{}
	buf := make([]byte, 0, min(max, 4096)) // a typical ClientHello (1.5–2 KB) fits in one buffer
	// fill reads until buf holds at least n bytes.
	fill := func(n int) error {
		if n > max {
			return ErrTooLarge
		}
		for len(buf) < n {
			if cap(buf) < n {
				nb := make([]byte, len(buf), min(max, 2*n))
				copy(nb, buf)
				buf = nb
			}
			k, err := c.Read(buf[len(buf):cap(buf)])
			ch.Reads++
			buf = buf[:len(buf)+k]
			if err != nil {
				if len(buf) >= n {
					break
				}
				return err
			}
		}
		return nil
	}

	var msg []byte // reassembled handshake bytes
	off := 0       // start of the next record in buf
	for {
		if err := fill(off + recordHeaderLen); err != nil {
			return nil, peekErr(err, ch)
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
			return nil, peekErr(err, ch)
		}
		msg = append(msg, buf[off+recordHeaderLen:off+recordHeaderLen+n]...)
		off += recordHeaderLen + n
		ch.Records++
		if len(msg) >= 4 {
			if msg[0] != handshakeClientHello {
				return nil, fmt.Errorf("%w: first handshake message type %d", ErrMalformed, msg[0])
			}
			want := 4 + (int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3]))
			if want+recordHeaderLen > max {
				return nil, ErrTooLarge
			}
			if len(msg) >= want {
				if len(msg) > want {
					// Another handshake message in the same flight: never sent by a client
					// before the server's reply in TLS 1.3, so treat it as malformed.
					return nil, fmt.Errorf("%w: trailing handshake data", ErrMalformed)
				}
				ch.Size = want
				break
			}
		}
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ch.Raw = buf
	if err := parseClientHello(msg[4:], ch); err != nil {
		return nil, err
	}
	return ch, nil
}

func peekErr(err error, ch *ClientHello) error {
	if errors.Is(err, ErrTooLarge) {
		return err
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return fmt.Errorf("peek timeout after %d reads: %w", ch.Reads, err)
	}
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: connection closed inside the ClientHello", ErrMalformed)
	}
	return err
}

// parseClientHello parses the body of a ClientHello handshake message (RFC 8446, 4.1.2).
func parseClientHello(body []byte, ch *ClientHello) error {
	s := cryptobyte.String(body)
	var legacyVersion uint16
	var random, sessionID, suites, compression, exts cryptobyte.String
	if !s.ReadUint16(&legacyVersion) || !s.ReadBytes((*[]byte)(&random), 32) ||
		!s.ReadUint8LengthPrefixed(&sessionID) || !s.ReadUint16LengthPrefixed(&suites) ||
		!s.ReadUint8LengthPrefixed(&compression) {
		return fmt.Errorf("%w: fixed fields", ErrMalformed)
	}
	if s.Empty() {
		return nil // no extensions: legal for TLS 1.2 and below; routed as "no SNI"
	}
	if !s.ReadUint16LengthPrefixed(&exts) || !s.Empty() {
		return fmt.Errorf("%w: extensions block", ErrMalformed)
	}
	seen := map[uint16]bool{}
	for !exts.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&data) {
			return fmt.Errorf("%w: extension header", ErrMalformed)
		}
		if seen[typ] {
			return fmt.Errorf("%w: duplicate extension %d", ErrMalformed, typ)
		}
		seen[typ] = true
		switch typ {
		case extServerName:
			var list cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() {
				return fmt.Errorf("%w: server_name", ErrMalformed)
			}
			for !list.Empty() {
				var nameType uint8
				var name cryptobyte.String
				if !list.ReadUint8(&nameType) || !list.ReadUint16LengthPrefixed(&name) {
					return fmt.Errorf("%w: server_name entry", ErrMalformed)
				}
				if nameType == 0 && ch.ServerName == "" {
					ch.ServerName = string(name)
				}
			}
		case extALPN:
			var list cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() {
				return fmt.Errorf("%w: ALPN", ErrMalformed)
			}
			for !list.Empty() {
				var proto cryptobyte.String
				if !list.ReadUint8LengthPrefixed(&proto) || len(proto) == 0 {
					return fmt.Errorf("%w: ALPN entry", ErrMalformed)
				}
				ch.ALPN = append(ch.ALPN, string(proto))
			}
		case extSupportedGroups:
			var list cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() {
				return fmt.Errorf("%w: supported_groups", ErrMalformed)
			}
			for !list.Empty() {
				var g uint16
				if !list.ReadUint16(&g) {
					return fmt.Errorf("%w: supported_groups entry", ErrMalformed)
				}
				ch.SupportedGroups = append(ch.SupportedGroups, g)
			}
		case extKeyShare:
			var list cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() {
				return fmt.Errorf("%w: key_share", ErrMalformed)
			}
			for !list.Empty() {
				var g uint16
				var kx cryptobyte.String
				if !list.ReadUint16(&g) || !list.ReadUint16LengthPrefixed(&kx) {
					return fmt.Errorf("%w: key_share entry", ErrMalformed)
				}
				ch.KeyShareGroups = append(ch.KeyShareGroups, g)
				ch.KeyShareBytes += len(kx)
			}
		case extSupportedVersions:
			var list cryptobyte.String
			if !data.ReadUint8LengthPrefixed(&list) || !data.Empty() {
				return fmt.Errorf("%w: supported_versions", ErrMalformed)
			}
			for !list.Empty() {
				var v uint16
				if !list.ReadUint16(&v) {
					return fmt.Errorf("%w: supported_versions entry", ErrMalformed)
				}
				ch.Versions = append(ch.Versions, v)
			}
		case extEncryptedClientHel:
			ch.ECH = true
		}
	}
	return nil
}

// errStopHandshake aborts the crypto/tls handshake once the ClientHello was captured.
var errStopHandshake = errors.New("peek: ClientHello captured")

// PeekWithTLS is the alternative peek from docs/03: it runs crypto/tls on a recording connection
// and aborts in GetConfigForClient. Nothing is ever written to the client. It reports what
// tls.ClientHelloInfo exposes (no key-share groups) and the recorded bytes.
func PeekWithTLS(c net.Conn, max int, timeout time.Duration) (*tls.ClientHelloInfo, []byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, err
	}
	rc := &recordingConn{Conn: c, max: max}
	var info *tls.ClientHelloInfo
	srv := tls.Server(rc, &tls.Config{
		MinVersion: tls.VersionTLS12, // see every client; the handshake never completes here
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			cp := *chi
			info = &cp
			return nil, errStopHandshake
		},
	})
	err := srv.Handshake()
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return nil, nil, err
	}
	if info == nil {
		if rc.tooLarge {
			return nil, nil, ErrTooLarge
		}
		return nil, nil, fmt.Errorf("crypto/tls peek: %w", err)
	}
	return info, rc.buf, nil
}

// recordingConn records reads and swallows writes, so the aborted handshake's alert never
// reaches the client.
type recordingConn struct {
	net.Conn
	mu       sync.Mutex
	buf      []byte
	max      int
	tooLarge bool
}

func (r *recordingConn) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) >= r.max {
		r.tooLarge = true
		return 0, ErrTooLarge
	}
	if len(p) > r.max-len(r.buf) {
		p = p[:r.max-len(r.buf)]
	}
	n, err := r.Conn.Read(p)
	r.buf = append(r.buf, p[:n]...)
	return n, err
}

func (r *recordingConn) Write(p []byte) (int, error) { return 0, errors.New("peek: write refused") }

// ReplayConn returns the recorded bytes first, then reads from the connection.
type ReplayConn struct {
	net.Conn
	prefix []byte
}

// NewReplayConn wraps c so that prefix is read again before anything else.
func NewReplayConn(c net.Conn, prefix []byte) *ReplayConn {
	return &ReplayConn{Conn: c, prefix: prefix}
}

func (r *ReplayConn) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	return r.Conn.Read(p)
}

// CloseWrite half-closes the underlying TCP connection, if it supports it.
func (r *ReplayConn) CloseWrite() error {
	if cw, ok := r.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return r.Conn.Close()
}
