// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"slices"
	"testing"
	"time"
)

func TestPeek_GoClientDefaultsSendHybridPQKeyShare(t *testing.T) {
	certs, err := NewCerts()
	if err != nil {
		t.Fatal(err)
	}
	client, server := tcpPair(t)
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: TestHTTPHost, RootCAs: certs.Public.Pool(),
			NextProtos: []string{"h2", "http/1.1"}}).Handshake()
	}()
	ch, err := Peek(server, MaxPeekBytes, PeekTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if ch.ServerName != TestHTTPHost || !slices.Equal(ch.ALPN, []string{"h2", "http/1.1"}) {
		t.Fatalf("sni %q alpn %v", ch.ServerName, ch.ALPN)
	}
	// Go 1.27 sends an X25519MLKEM768 share plus an X25519 share by default.
	if !slices.Contains(ch.KeyShareGroups, 0x11ec) || !slices.Contains(ch.KeyShareGroups, 0x001d) {
		t.Fatalf("key shares %v, want X25519MLKEM768 and X25519", ch.KeyShareGroups)
	}
	if ch.KeyShareBytes < 1216 {
		t.Fatalf("key share bytes %d; an X25519MLKEM768 share alone is 1216 bytes", ch.KeyShareBytes)
	}
	t.Logf("Go %s ClientHello: %d bytes, %d record(s), %d read(s), key shares %d bytes", "1.27", ch.Size, ch.Records, ch.Reads, ch.KeyShareBytes)
}

func TestPeek_ReplayCompletesHandshake(t *testing.T) {
	certs, _ := NewCerts()
	client, server := tcpPair(t)
	errc := make(chan error, 1)
	go func() {
		tc := tls.Client(client, &tls.Config{ServerName: TestHTTPHost, RootCAs: certs.Public.Pool()})
		if err := tc.Handshake(); err != nil {
			errc <- err
			return
		}
		_, err := tc.Write([]byte("ping"))
		errc <- err
	}()
	ch, err := Peek(server, MaxPeekBytes, PeekTimeout)
	if err != nil {
		t.Fatal(err)
	}
	ts := tls.Server(NewReplayConn(server, ch.Raw), &tls.Config{Certificates: []tls.Certificate{certs.HTTP}})
	buf := make([]byte, 4)
	if _, err := io.ReadFull(ts, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("after replay: %q %v", buf, err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestPeek_SpansRecordsAndSegments(t *testing.T) {
	msg := synthHello(t, "multi.example.test", []string{"h2"}, 3000)
	cases := []struct {
		name    string
		records []int
		chunk   int
	}{
		{"one record, one write", nil, 1 << 20},
		{"three records", []int{100, 1000}, 1 << 20},
		{"MSS-sized segments", nil, 1448},
		{"one-byte segments", []int{7, 2000}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := records(msg, tc.records...)
			client, server := tcpPair(t)
			go func() { _ = writeChunks(client, raw, tc.chunk, 200*time.Microsecond) }()
			ch, err := Peek(server, MaxPeekBytes, PeekTimeout)
			if err != nil {
				t.Fatal(err)
			}
			if ch.ServerName != "multi.example.test" || ch.Size != len(msg) || !bytes.Equal(ch.Raw, raw) {
				t.Fatalf("sni %q size %d raw %d/%d", ch.ServerName, ch.Size, len(ch.Raw), len(raw))
			}
			if want := len(tc.records) + 1; tc.records != nil && ch.Records != want {
				t.Fatalf("records %d, want %d", ch.Records, want)
			}
			t.Logf("%s: %d records, %d reads", tc.name, ch.Records, ch.Reads)
		})
	}
}

func TestPeek_SizeLimitBoundary(t *testing.T) {
	// Raw bytes = 5-byte record header + message. Exactly 16 KiB passes, one byte more fails.
	for _, tc := range []struct {
		raw     int
		wantErr error
	}{{MaxPeekBytes, nil}, {MaxPeekBytes + 1, ErrTooLarge}} {
		msg := synthHello(t, "big.example.test", nil, tc.raw-recordHeaderLen)
		raw := records(msg, len(msg))
		if len(raw) != tc.raw {
			t.Fatalf("built %d bytes, want %d", len(raw), tc.raw)
		}
		client, server := tcpPair(t)
		go func() { _, _ = client.Write(raw) }()
		_, err := Peek(server, MaxPeekBytes, PeekTimeout)
		if !errors.Is(err, tc.wantErr) && !(tc.wantErr == nil && err == nil) {
			t.Fatalf("raw %d: err %v, want %v", tc.raw, err, tc.wantErr)
		}
	}
}

func TestPeek_TooLargeDetectedFromLengthField(t *testing.T) {
	// A ClientHello that announces 20 000 bytes fails at once, without waiting for them.
	client, server := tcpPair(t)
	go func() { _, _ = client.Write([]byte{22, 3, 1, 0, 4, 1, 0, 0x4e, 0x20}) }()
	start := time.Now()
	_, err := Peek(server, MaxPeekBytes, PeekTimeout)
	if !errors.Is(err, ErrTooLarge) || time.Since(start) > time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
}

func TestPeek_SlowlorisTimesOut(t *testing.T) {
	msg := records(synthHello(t, "slow.example.test", nil, 0))
	client, server := tcpPair(t)
	go func() { _ = writeChunks(client, msg[:40], 1, 20*time.Millisecond) }() // then stalls
	start := time.Now()
	_, err := Peek(server, MaxPeekBytes, 300*time.Millisecond)
	el := time.Since(start)
	if err == nil || el < 300*time.Millisecond || el > 2*time.Second {
		t.Fatalf("err %v after %v", err, el)
	}
}

func TestPeek_SlowlorisRealFiveSecondLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("takes 5 s")
	}
	t.Parallel()
	client, server := tcpPair(t)
	// One byte every 100 ms: legitimate-looking but never finishes within 5 s.
	msg := records(synthHello(t, "slow.example.test", nil, 0))
	go func() { _ = writeChunks(client, msg, 1, 100*time.Millisecond) }()
	start := time.Now()
	_, err := Peek(server, MaxPeekBytes, PeekTimeout)
	el := time.Since(start)
	if err == nil || el < PeekTimeout || el > PeekTimeout+time.Second {
		t.Fatalf("err %v after %v", err, el)
	}
}

func TestPeek_RejectsNonTLSAndMalformed(t *testing.T) {
	good := synthHello(t, "x.example.test", nil, 0)
	// The extensions length sits at a fixed offset in synthHello's output: 4 (handshake header)
	// + 2 + 32 (random) + 1 + 32 (session ID) + 2 + 6 (suites) + 1 + 1 (compression) = 81.
	badExt := append([]byte{}, good...)
	badExt[82] += 10 // announces 10 bytes more extensions than there are
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"HTTP request", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), ErrNotTLS},
		{"HTTP/2 preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), ErrNotTLS},
		{"SSLv2-style hello", []byte{0x80, 0x2e, 0x01, 0x03, 0x01, 0, 0}, ErrNotTLS},
		{"alert record", []byte{21, 3, 1, 0, 2, 2, 40}, ErrNotTLS},
		{"record length zero", []byte{22, 3, 1, 0, 0}, ErrMalformed},
		{"record length above 2^14", []byte{22, 3, 1, 0x40, 0x01}, ErrMalformed},
		{"ServerHello instead of ClientHello", records(append([]byte{2}, good[1:]...)), ErrMalformed},
		{"truncated, then EOF", records(good)[:100], ErrMalformed},
		{"extensions length beyond the message", records(badExt), ErrMalformed},
		{"trailing handshake data", records(append(append([]byte{}, good...), 20, 0, 0, 0)), ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := tcpPair(t)
			go func() {
				_, _ = client.Write(tc.in)
				_ = client.(interface{ CloseWrite() error }).CloseWrite()
			}()
			_, err := Peek(server, MaxPeekBytes, time.Second)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPeekWithTLS_AgreesAndWritesNothing(t *testing.T) {
	certs, _ := NewCerts()
	raw := captureHello(t, &tls.Config{ServerName: TunnelName(), RootCAs: certs.Internal.Pool(),
		NextProtos: []string{ALPNTunnelH2}, Certificates: []tls.Certificate{certs.Connector}})
	// Through the cryptobyte peek...
	c1, s1 := tcpPair(t)
	go func() { _, _ = c1.Write(raw) }()
	ch, err := Peek(s1, MaxPeekBytes, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// ...and through crypto/tls aborted in GetConfigForClient.
	c2, s2 := tcpPair(t)
	go func() { _, _ = c2.Write(raw) }()
	info, rec, err := PeekWithTLS(s2, MaxPeekBytes, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if info.ServerName != ch.ServerName || !slices.Equal(info.SupportedProtos, ch.ALPN) || !bytes.Equal(rec, raw) {
		t.Fatalf("crypto/tls %q %v (%d bytes) vs cryptobyte %q %v", info.ServerName, info.SupportedProtos, len(rec), ch.ServerName, ch.ALPN)
	}
	// Nothing (no alert) reached the client.
	_ = c2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := c2.Read(make([]byte, 16)); n != 0 || err == nil {
		t.Fatalf("client received %d bytes (%v)", n, err)
	}
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(synthHello(f, "a.example.test", []string{"h2", ALPNTunnelH2}, 0)[4:])
	f.Add(synthHello(f, "", nil, 600)[4:])
	f.Add([]byte{3, 3})
	f.Fuzz(func(t *testing.T, body []byte) {
		var ch ClientHello
		_ = parseClientHello(body, &ch)
	})
}
