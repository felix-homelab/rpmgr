// SPDX-License-Identifier: Apache-2.0

package tlspeek_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"github.com/felix-homelab/rpmgr/internal/tlspeek"
)

const host = "peek.example.test"

// TestDefaultsAreDocumented: the limits are the values of docs/03's timeout table, their single
// source of truth.
func TestDefaultsAreDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../docs/03-connections.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\| ClientHello peek \| (\d+) KiB within (\d+) s \|`).FindSubmatch(doc)
	if m == nil {
		t.Fatal("docs/03 has no ClientHello peek row")
	}
	kib, _ := strconv.Atoi(string(m[1]))
	secs, _ := strconv.Atoi(string(m[2]))
	if tlspeek.MaxBytes != kib<<10 || tlspeek.Timeout != time.Duration(secs)*time.Second {
		t.Fatalf("code %d bytes within %v, docs/03 %d KiB within %d s", tlspeek.MaxBytes, tlspeek.Timeout, kib, secs)
	}
}

// TestPeek_GoClient peeks at real ClientHellos of Go's crypto/tls client.
func TestPeek_GoClient(t *testing.T) {
	cases := []struct {
		name, serverName, wantSNI string
		alpn                      []string
	}{
		{"SNI with h2 and http/1.1", host, host, []string{"h2", "http/1.1"}},
		{"tunnel ALPN", host, host, []string{"rpmgr-tunnel-h2/1"}},
		{"no SNI for an IP address", "127.0.0.1", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := captureHello(t, &tls.Config{ServerName: tc.serverName, NextProtos: tc.alpn, MinVersion: tls.VersionTLS13})
			client, server := tcpPair(t)
			go func() { _, _ = client.Write(raw) }()
			ch, err := tlspeek.Peek(server, tlspeek.MaxBytes, tlspeek.Timeout)
			if err != nil {
				t.Fatal(err)
			}
			if ch.ServerName != tc.wantSNI || !slices.Equal(ch.ALPN, tc.alpn) || !bytes.Equal(ch.Raw, raw) {
				t.Fatalf("SNI %q ALPN %v (%d of %d bytes)", ch.ServerName, ch.ALPN, len(ch.Raw), len(raw))
			}
			// Go 1.27 sends an X25519MLKEM768 key share and an X25519 share, about 1.5 KB in all.
			if !slices.Contains(ch.KeyShareGroups, 0x11ec) || !slices.Contains(ch.KeyShareGroups, 0x001d) || ch.Size < 1216 {
				t.Fatalf("key shares %v in a %d-byte ClientHello", ch.KeyShareGroups, ch.Size)
			}
		})
	}
}

// TestPeek_ReplayCompletesHandshake: after the peek, crypto/tls completes the handshake on the
// replayed bytes, and data flows both ways.
func TestPeek_ReplayCompletesHandshake(t *testing.T) {
	cert, pool := selfSigned(t)
	client, server := tcpPair(t)
	errc := make(chan error, 1)
	go func() {
		tc := tls.Client(client, &tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS13})
		if _, err := tc.Write([]byte("ping")); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "pong" {
			errc <- errors.Join(err, errors.New("no pong: "+string(buf)))
			return
		}
		errc <- nil
	}()
	ch, err := tlspeek.Peek(server, tlspeek.MaxBytes, tlspeek.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	ts := tls.Server(tlspeek.NewReplayConn(server, ch.Raw), &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	buf := make([]byte, 4)
	if _, err := io.ReadFull(ts, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("after the replay: %q, %v", buf, err)
	}
	if _, err := ts.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// TestPeek_SpansRecordsAndSegments: a ClientHello split into records and TCP segments of any size
// is reassembled, and every byte read is returned for the replay.
func TestPeek_SpansRecordsAndSegments(t *testing.T) {
	msg := synthHello(t, host, []string{"h2"}, 3000)
	goHello := captureHello(t, &tls.Config{ServerName: host, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS13})
	cases := []struct {
		name  string
		raw   []byte
		chunk int
	}{
		{"one record, one write", records(msg), 1 << 20},
		{"three records", records(msg, 100, 1000), 1 << 20},
		{"MSS-sized segments", records(msg), 1448},
		{"one-byte segments", records(msg, 7, 2000), 1},
		{"Go ClientHello in 64-byte records", records(goHello[5:], repeat(64, 40)...), 1448},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := tcpPair(t)
			// No pause between writes and a generous timeout: about 3000 one-byte writes take
			// seconds on a slow runner with the race detector, and this test is not about time.
			go func() { _ = writeChunks(client, tc.raw, tc.chunk, 0) }()
			ch, err := tlspeek.Peek(server, tlspeek.MaxBytes, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if ch.ServerName != host || !bytes.Equal(ch.Raw, tc.raw) {
				t.Fatalf("SNI %q, %d of %d bytes", ch.ServerName, len(ch.Raw), len(tc.raw))
			}
		})
	}
}

// TestPeek_SizeLimit: the record header and ClientHello of exactly MaxBytes pass, one byte more
// is refused, and a length field announcing 20 000 bytes is refused before they arrive.
func TestPeek_SizeLimit(t *testing.T) {
	for _, tc := range []struct {
		raw  int
		want error
	}{{tlspeek.MaxBytes, nil}, {tlspeek.MaxBytes + 1, tlspeek.ErrTooLarge}} {
		msg := synthHello(t, host, nil, tc.raw-5)
		raw := records(msg, len(msg))
		if len(raw) != tc.raw {
			t.Fatalf("built %d bytes, want %d", len(raw), tc.raw)
		}
		client, server := tcpPair(t)
		go func() { _, _ = client.Write(raw) }()
		ch, err := tlspeek.Peek(server, tlspeek.MaxBytes, tlspeek.Timeout)
		if !errors.Is(err, tc.want) || (tc.want == nil && (err != nil || ch.ServerName != host)) {
			t.Fatalf("%d bytes: %v, want %v", tc.raw, err, tc.want)
		}
	}
	client, server := tcpPair(t)
	go func() { _, _ = client.Write([]byte{22, 3, 1, 0, 4, 1, 0, 0x4e, 0x20}) }() // 20 000 bytes
	start := time.Now()
	if _, err := tlspeek.Peek(server, tlspeek.MaxBytes, tlspeek.Timeout); !errors.Is(err, tlspeek.ErrTooLarge) || time.Since(start) > time.Second {
		t.Fatalf("an announced 20 000 bytes: %v after %v", err, time.Since(start))
	}
}

// TestPeek_Slowloris: a client that dribbles its ClientHello is given up after the timeout.
func TestPeek_Slowloris(t *testing.T) {
	msg := records(synthHello(t, host, nil, 0))
	client, server := tcpPair(t)
	go func() { _ = writeChunks(client, msg[:40], 1, 20*time.Millisecond) }() // then stalls
	start := time.Now()
	_, err := tlspeek.Peek(server, tlspeek.MaxBytes, 300*time.Millisecond)
	if el := time.Since(start); !errors.Is(err, os.ErrDeadlineExceeded) || el < 300*time.Millisecond || el > 2*time.Second {
		t.Fatalf("%v after %v, want the deadline after 300 ms", err, el)
	}
}

// TestPeek_SlowlorisAtTheDefaultTimeout: one byte every 100 ms never completes within Timeout.
func TestPeek_SlowlorisAtTheDefaultTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("takes the full default timeout")
	}
	t.Parallel()
	msg := records(synthHello(t, host, nil, 0))
	client, server := tcpPair(t)
	go func() { _ = writeChunks(client, msg, 1, 100*time.Millisecond) }()
	start := time.Now()
	_, err := tlspeek.Peek(server, tlspeek.MaxBytes, tlspeek.Timeout)
	if el := time.Since(start); !errors.Is(err, os.ErrDeadlineExceeded) || el < tlspeek.Timeout || el > tlspeek.Timeout+time.Second {
		t.Fatalf("%v after %v", err, el)
	}
}

// TestPeek_Refused: everything that is not a well-formed TLS ClientHello is refused with the error
// a listener closes on.
func TestPeek_Refused(t *testing.T) {
	good := synthHello(t, host, nil, 0)
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"HTTP request", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), tlspeek.ErrNotTLS},
		{"HTTP/2 preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), tlspeek.ErrNotTLS},
		{"SSLv2-style hello", []byte{0x80, 0x2e, 0x01, 0x03, 0x01, 0, 0}, tlspeek.ErrNotTLS},
		{"alert record", []byte{21, 3, 1, 0, 2, 2, 40}, tlspeek.ErrNotTLS},
		{"application data record", []byte{23, 3, 3, 0, 1, 0}, tlspeek.ErrNotTLS},
		{"record length zero", []byte{22, 3, 1, 0, 0}, tlspeek.ErrMalformed},
		{"record length above 2^14", []byte{22, 3, 1, 0x40, 0x01}, tlspeek.ErrMalformed},
		{"ServerHello instead of ClientHello", records(append([]byte{2}, good[1:]...)), tlspeek.ErrMalformed},
		{"truncated, then EOF", records(good)[:100], tlspeek.ErrMalformed},
		{"handshake data after the ClientHello", records(append(slices.Clone(good), 20, 0, 0, 0)), tlspeek.ErrMalformed},
		{"extensions longer than the message", records(helloWith(t, rawExts(0xff00, []byte{1}), 10)), tlspeek.ErrMalformed},
		{"duplicate extension", records(helloWith(t, append(sniExt(host), sniExt("b.example.test")...), 0)), tlspeek.ErrMalformed},
		{"two host names", records(helloWith(t, rawExts(0, sniList(host, "b.example.test")), 0)), tlspeek.ErrMalformed},
		{"empty host name", records(helloWith(t, rawExts(0, sniList("")), 0)), tlspeek.ErrMalformed},
		{"empty server_name list", records(helloWith(t, rawExts(0, []byte{0, 0}), 0)), tlspeek.ErrMalformed},
		{"server_name list longer than its extension", records(helloWith(t, rawExts(0, []byte{0, 9, 0}), 0)), tlspeek.ErrMalformed},
		{"empty ALPN list", records(helloWith(t, rawExts(16, []byte{0, 0}), 0)), tlspeek.ErrMalformed},
		{"empty ALPN name", records(helloWith(t, rawExts(16, []byte{0, 1, 0}), 0)), tlspeek.ErrMalformed},
		{"empty key share", records(helloWith(t, rawExts(51, []byte{0, 4, 0, 0x1d, 0, 0}), 0)), tlspeek.ErrMalformed},
		{"fixed fields cut short", records([]byte{1, 0, 0, 3, 3, 3, 0}), tlspeek.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := tcpPair(t)
			go func() {
				_, _ = client.Write(tc.in)
				_ = client.(*net.TCPConn).CloseWrite()
			}()
			if _, err := tlspeek.Peek(server, tlspeek.MaxBytes, time.Second); !errors.Is(err, tc.want) {
				t.Fatalf("%v, want %v", err, tc.want)
			}
		})
	}
}

// TestReplayConn: the replayed bytes come first, also through one-byte reads, then the
// connection's; deadlines and half-close reach the underlying connection.
func TestReplayConn(t *testing.T) {
	client, server := tcpPair(t)
	rc := tlspeek.NewReplayConn(server, []byte("abc"))
	go func() { _, _ = client.Write([]byte("def")) }()
	var got []byte
	one := make([]byte, 1)
	for len(got) < 6 {
		n, err := rc.Read(one)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, one[:n]...)
	}
	if string(got) != "abcdef" {
		t.Fatalf("read %q", got)
	}
	if err := rc.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Read(one); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read after the deadline: %v", err)
	}
	if err := rc.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(one); !errors.Is(err, io.EOF) {
		t.Fatalf("the peer saw %v instead of EOF after the half-close", err)
	}
	if _, err := client.Write([]byte("g")); err != nil {
		t.Fatalf("the other direction closed too: %v", err)
	}
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if err := tlspeek.NewReplayConn(a, nil).(interface{ CloseWrite() error }).CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("half-close of a pipe: %v, want ErrUnsupported", err)
	}
}

func FuzzClientHello(f *testing.F) {
	for _, msg := range [][]byte{synthHello(f, host, []string{"h2", "rpmgr-tunnel/1"}, 0), synthHello(f, "", nil, 600)} {
		f.Add(records(msg))
		f.Add(records(msg, 50, 50))
	}
	f.Add([]byte{22, 3, 1, 0, 6, 1, 0, 0, 2, 3, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4 {
			_, _ = tlspeek.ParseClientHello(data[4:])
		}
		ch, err := tlspeek.Peek(&sliceConn{r: bytes.NewReader(data)}, tlspeek.MaxBytes, time.Second)
		if err == nil && (ch.Size > tlspeek.MaxBytes || len(ch.Raw) > tlspeek.MaxBytes || !bytes.HasPrefix(data, ch.Raw)) {
			t.Fatalf("accepted a ClientHello of %d bytes (%d read)", ch.Size, len(ch.Raw))
		}
	})
}

// sliceConn is a net.Conn that reads from a byte slice.
type sliceConn struct {
	net.Conn
	r *bytes.Reader
}

func (c *sliceConn) Read(p []byte) (int, error)      { return c.r.Read(p) }
func (c *sliceConn) SetReadDeadline(time.Time) error { return nil }
func (c *sliceConn) Write(p []byte) (int, error)     { return len(p), nil }
func (c *sliceConn) Close() error                    { return nil }

// synthHello builds a ClientHello handshake message with SNI, ALPN and an X25519 key share,
// padded with a padding extension to padTo bytes if padTo > 0.
func synthHello(t testing.TB, sni string, alpn []string, padTo int) []byte {
	t.Helper()
	exts := keyShareExt()
	if sni != "" {
		exts = append(sniExt(sni), exts...)
	}
	if len(alpn) > 0 {
		exts = append(exts, alpnExt(alpn...)...)
	}
	if padTo <= 0 {
		return helloWith(t, exts, 0)
	}
	base := len(helloWith(t, append(slices.Clone(exts), rawExts(21, nil)...), 0))
	if padTo < base {
		t.Fatalf("padTo %d is below the minimum %d", padTo, base)
	}
	return helloWith(t, append(exts, rawExts(21, make([]byte, padTo-base))...), 0)
}

// helloWith builds a ClientHello handshake message with the encoded extensions exts; extra makes
// the extensions block announce more bytes than it has.
func helloWith(t testing.TB, exts []byte, extra int) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint8(1)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0x0303)
		b.AddBytes(make([]byte, 32))
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 32)) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x1301) })
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
		b.AddUint16(uint16(len(exts) + extra)) //nolint:gosec // G115: test messages are small
		b.AddBytes(exts)
	})
	msg, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// rawExts encodes one extension.
func rawExts(typ uint16, data []byte) []byte {
	var b cryptobyte.Builder
	b.AddUint16(typ)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(data) })
	return b.BytesOrPanic()
}

func sniList(names ...string) []byte {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, n := range names {
			b.AddUint8(0)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(n)) })
		}
	})
	return b.BytesOrPanic()
}

func sniExt(name string) []byte { return rawExts(0, sniList(name)) }

func alpnExt(protos ...string) []byte {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, p := range protos {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(p)) })
		}
	})
	return rawExts(16, b.BytesOrPanic())
}

func keyShareExt() []byte {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0x001d)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 32)) })
	})
	return rawExts(51, b.BytesOrPanic())
}

// records wraps a handshake message in TLS records of the given payload sizes; the rest goes into
// one more record.
func records(msg []byte, sizes ...int) []byte {
	var out []byte
	for len(msg) > 0 {
		n := len(msg)
		if len(sizes) > 0 {
			n = min(sizes[0], len(msg))
			sizes = sizes[1:]
		}
		out = append(out, 22, 3, 1, byte(n>>8), byte(n)) //nolint:gosec // G115: a record payload is below 2^16
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

func repeat(n, times int) []int {
	s := make([]int, times)
	for i := range s {
		s[i] = n
	}
	return s
}

// captureHello returns the first record a Go TLS client sends: its whole ClientHello.
func captureHello(t testing.TB, cfg *tls.Config) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer func() { _ = c.Close(); _ = s.Close() }()
	go func() { _ = tls.Client(c, cfg).Handshake() }()
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

// selfSigned returns a server certificate for host and a pool that trusts it.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, pool
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t testing.TB) (client, server net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	done := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			c = nil
		}
		done <- c
	}()
	client, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if server = <-done; server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

// writeChunks writes b in chunks of n bytes with a pause between them.
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
