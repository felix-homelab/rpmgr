// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// synthHello builds a ClientHello handshake message (type, length, body). If padTo > 0, a padding
// extension (RFC 7685) makes the whole message exactly padTo bytes long.
func synthHello(t testing.TB, sni string, alpn []string, padTo int) []byte {
	t.Helper()
	build := func(pad int) []byte {
		var b cryptobyte.Builder
		b.AddUint8(handshakeClientHello)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x0303)
			rnd := make([]byte, 32)
			_, _ = rand.Read(rnd)
			b.AddBytes(rnd)
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(rnd) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(0x1301)
				b.AddUint16(0x1302)
				b.AddUint16(0x1303)
			})
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				if sni != "" {
					b.AddUint16(extServerName)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddUint8(0)
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(sni)) })
						})
					})
				}
				if len(alpn) > 0 {
					b.AddUint16(extALPN)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							for _, p := range alpn {
								b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(p)) })
							}
						})
					})
				}
				b.AddUint16(extSupportedVersions)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x0304) })
				})
				b.AddUint16(extSupportedGroups)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x001d) })
				})
				b.AddUint16(13) // signature_algorithms
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x0403) })
				})
				b.AddUint16(extKeyShare)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16(0x001d)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							k := make([]byte, 32)
							_, _ = rand.Read(k)
							b.AddBytes(k)
						})
					})
				})
				if pad >= 0 {
					b.AddUint16(21)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, pad)) })
				}
			})
		})
		return b.BytesOrPanic()
	}
	if padTo <= 0 {
		return build(-1)
	}
	base := len(build(0))
	if padTo < base {
		t.Fatalf("padTo %d below minimum %d", padTo, base)
	}
	return build(padTo - base)
}

// records frames a handshake message into TLS records with the given payload sizes; the last
// record takes the rest.
func records(msg []byte, sizes ...int) []byte {
	var out []byte
	for len(msg) > 0 {
		n := len(msg)
		if len(sizes) > 0 {
			n = min(sizes[0], len(msg))
			sizes = sizes[1:]
		}
		out = append(out, recordTypeHandshake, 3, 1, byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

// captureHello returns the first flight a crypto/tls client with cfg sends.
func captureHello(t testing.TB, cfg *tls.Config) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() { _ = tls.Client(c, cfg).Handshake() }()
	defer c.Close()
	defer s.Close()
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(s, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(s, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t testing.TB) (client, server net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- nil
			return
		}
		done <- c
	}()
	client, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-done
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

// writeChunks writes b in chunks of size n with a pause between them, so that the reader sees
// separate reads (as with separate TCP segments).
func writeChunks(c net.Conn, b []byte, n int, pause time.Duration) error {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	for len(b) > 0 {
		k := min(n, len(b))
		if _, err := c.Write(b[:k]); err != nil {
			return err
		}
		b = b[k:]
		if len(b) > 0 && pause > 0 {
			time.Sleep(pause)
		}
	}
	return nil
}
