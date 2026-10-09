// SPDX-License-Identifier: Apache-2.0

package tunnel_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

func validOpen() *tunnelv1.StreamOpen {
	return &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_TCP, RouteId: "rt_1",
		SnapshotRev: &agentv1.Revision{DbEpoch: "e", Seq: 3}, SrcIp: []byte{192, 0, 2, 1}, SrcPort: 50000,
		DstIp: []byte{198, 51, 100, 1}, DstPort: 5432, TraceId: make([]byte, 16), SpanId: make([]byte, 8),
		OpenTimeoutMs: 5000}
}

// TestMessage_RoundTripAndLimit: a message round-trips, raw bytes after it stay in the reader, a
// payload of exactly 16 KiB passes and one byte more is refused on both sides.
func TestMessage_RoundTripAndLimit(t *testing.T) {
	var buf bytes.Buffer
	if err := tunnel.WriteMessage(&buf, validOpen()); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("client bytes")
	got := &tunnelv1.StreamOpen{}
	if err := tunnel.ReadMessage(&buf, got); err != nil || !proto.Equal(got, validOpen()) {
		t.Fatalf("round trip: %v %v", got, err)
	}
	if rest, _ := io.ReadAll(&buf); string(rest) != "client bytes" {
		t.Fatalf("ReadMessage read past the message: %q left", rest)
	}

	// A first chunk sized so that the whole OpenRequest is exactly MaxMessage bytes.
	req := &tunnelv1.OpenRequest{OpenId: 1, FirstChunk: make([]byte, tunnel.MaxMessage)}
	for proto.Size(req) > tunnel.MaxMessage {
		req.FirstChunk = req.FirstChunk[:len(req.FirstChunk)-1]
	}
	if n := proto.Size(req); n != tunnel.MaxMessage {
		t.Fatalf("test message of %d bytes", n)
	}
	buf.Reset()
	if err := tunnel.WriteMessage(&buf, req); err != nil {
		t.Fatalf("exactly 16 KiB: %v", err)
	}
	if err := tunnel.ReadMessage(&buf, &tunnelv1.OpenRequest{}); err != nil {
		t.Fatalf("reading exactly 16 KiB: %v", err)
	}
	req.FirstChunk = append(req.FirstChunk, 0)
	if err := tunnel.WriteMessage(&buf, req); !errors.Is(err, tunnel.ErrTooLarge) {
		t.Fatalf("16 KiB + 1 written: %v", err)
	}
	// A length above the limit is refused before the payload is read.
	over := binary.AppendUvarint(nil, tunnel.MaxMessage+1)
	if err := tunnel.ReadMessage(bytes.NewReader(over), &tunnelv1.OpenRequest{}); !errors.Is(err, tunnel.ErrTooLarge) {
		t.Fatalf("16 KiB + 1 read: %v", err)
	}
	huge := binary.AppendUvarint(nil, 1<<62)
	if err := tunnel.ReadMessage(bytes.NewReader(huge), &tunnelv1.OpenRequest{}); !errors.Is(err, tunnel.ErrTooLarge) {
		t.Fatalf("a huge length: %v", err)
	}
}

func TestMessage_Errors(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"empty":            {nil, io.EOF},
		"truncated":        {append(binary.AppendUvarint(nil, 10), 1, 2, 3), io.ErrUnexpectedEOF},
		"bad varint":       {bytes.Repeat([]byte{0xff}, 11), nil},
		"not protobuf":     {append(binary.AppendUvarint(nil, 3), 0xff, 0xff, 0xff), nil},
		"truncated varint": {[]byte{0x80}, nil},
	} {
		err := tunnel.ReadMessage(bytes.NewReader(tc.in), &tunnelv1.StreamOpen{})
		if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

// TestCheckStreamOpen: an unknown or unspecified kind, the Phase 2 relay kinds, a missing route,
// malformed addresses or trace context, and a result without open_id answer PROTOCOL.
func TestCheckStreamOpen(t *testing.T) {
	ok := tunnelv1.ResultCode_RESULT_CODE_NO_ERROR
	bad := tunnelv1.ResultCode_RESULT_CODE_PROTOCOL
	for name, tc := range map[string]struct {
		edit func(*tunnelv1.StreamOpen)
		want tunnelv1.ResultCode
	}{
		"valid":        {func(*tunnelv1.StreamOpen) {}, ok},
		"IPv6":         {func(o *tunnelv1.StreamOpen) { o.SrcIp = make([]byte, 16) }, ok},
		"no addresses": {func(o *tunnelv1.StreamOpen) { o.SrcIp, o.DstIp, o.TraceId, o.SpanId = nil, nil, nil, nil }, ok},
		"control passthrough": {func(o *tunnelv1.StreamOpen) {
			o.Kind, o.RouteId = tunnelv1.StreamKind_STREAM_KIND_CONTROL_PASSTHROUGH, ""
		}, ok},
		"answer with a result":   {func(o *tunnelv1.StreamOpen) { o.OpenId, o.Result = 7, &tunnelv1.StreamResult{} }, ok},
		"unspecified kind":       {func(o *tunnelv1.StreamOpen) { o.Kind = tunnelv1.StreamKind_STREAM_KIND_UNSPECIFIED }, bad},
		"unknown kind":           {func(o *tunnelv1.StreamOpen) { o.Kind = 42 }, bad},
		"relay out":              {func(o *tunnelv1.StreamOpen) { o.Kind = tunnelv1.StreamKind_STREAM_KIND_RELAY_OUT }, bad},
		"relay in":               {func(o *tunnelv1.StreamOpen) { o.Kind = tunnelv1.StreamKind_STREAM_KIND_RELAY_IN }, bad},
		"no route":               {func(o *tunnelv1.StreamOpen) { o.RouteId = "" }, bad},
		"UDP without route":      {func(o *tunnelv1.StreamOpen) { o.Kind, o.RouteId = tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW, "" }, bad},
		"5-byte address":         {func(o *tunnelv1.StreamOpen) { o.SrcIp = make([]byte, 5) }, bad},
		"port 65536":             {func(o *tunnelv1.StreamOpen) { o.DstPort = 65536 }, bad},
		"short trace ID":         {func(o *tunnelv1.StreamOpen) { o.TraceId = make([]byte, 15) }, bad},
		"long span ID":           {func(o *tunnelv1.StreamOpen) { o.SpanId = make([]byte, 9) }, bad},
		"trace flags of 2 bytes": {func(o *tunnelv1.StreamOpen) { o.TraceFlags = 0x101 }, bad},
		"sampled":                {func(o *tunnelv1.StreamOpen) { o.TraceFlags = 1 }, ok},
		"result without ID":      {func(o *tunnelv1.StreamOpen) { o.Result = &tunnelv1.StreamResult{} }, bad},
	} {
		o := validOpen()
		tc.edit(o)
		if got := tunnel.CheckStreamOpen(o); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
}

// TestChunks: bytes cross in chunks of at most 16 KiB; the zero-length chunk is the FIN; a stream
// that ends without it, or inside a chunk, is an unexpected EOF; a chunk above the limit is refused.
func TestChunks(t *testing.T) {
	var buf bytes.Buffer
	w := tunnel.ChunkWriter{W: &buf}
	payload := []byte(strings.Repeat("0123456789abcdef", 3000)) // 48 000 bytes: 3 chunks
	if n, err := w.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write: %d %v", n, err)
	}
	if n, err := w.Write(nil); err != nil || n != 0 {
		t.Fatalf("an empty write: %d %v", n, err)
	}
	if err := w.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	wire := buf.Bytes()
	// Two chunks of 16 384 bytes with a 3-byte length, one of 15 232 with a 2-byte length, the FIN.
	if want := len(payload) + 3 + 3 + 2 + 1; len(wire) != want {
		t.Fatalf("%d bytes on the wire, want %d", len(wire), want)
	}
	got, err := io.ReadAll(tunnel.NewChunkReader(bytes.NewReader(wire)))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read %d bytes: %v", len(got), err)
	}

	noFIN := wire[:len(wire)-1]
	if _, err := io.ReadAll(tunnel.NewChunkReader(bytes.NewReader(noFIN))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("no FIN: %v", err)
	}
	if _, err := io.ReadAll(tunnel.NewChunkReader(bytes.NewReader(wire[:100]))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ends inside a chunk: %v", err)
	}
	big := append(binary.AppendUvarint(nil, tunnel.MaxChunk+1), make([]byte, tunnel.MaxChunk+1)...)
	if _, err := io.ReadAll(tunnel.NewChunkReader(bytes.NewReader(big))); !errors.Is(err, tunnel.ErrTooLarge) {
		t.Fatalf("a chunk of 16 KiB + 1: %v", err)
	}
	exact := append(append(binary.AppendUvarint(nil, tunnel.MaxChunk), make([]byte, tunnel.MaxChunk)...), 0)
	if got, err := io.ReadAll(tunnel.NewChunkReader(bytes.NewReader(exact))); err != nil || len(got) != tunnel.MaxChunk {
		t.Fatalf("a chunk of exactly 16 KiB: %d %v", len(got), err)
	}
	// After the FIN, reading stays at EOF.
	r := tunnel.NewChunkReader(bytes.NewReader([]byte{0}))
	for range 2 {
		if n, err := r.Read(make([]byte, 4)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("after the FIN: %d %v", n, err)
		}
	}
}

// FuzzFrame: no input makes ReadMessage panic or return a message above the limit.
func FuzzFrame(f *testing.F) {
	var buf bytes.Buffer
	_ = tunnel.WriteMessage(&buf, validOpen())
	f.Add(buf.Bytes())
	f.Add([]byte{0})
	f.Add(binary.AppendUvarint(nil, tunnel.MaxMessage+1))
	f.Fuzz(func(t *testing.T, in []byte) {
		m := &tunnelv1.SessionMessage{}
		if err := tunnel.ReadMessage(bytes.NewReader(in), m); err == nil && proto.Size(m) > tunnel.MaxMessage {
			t.Fatalf("a message of %d bytes was accepted", proto.Size(m))
		}
		_, _ = io.ReadAll(tunnel.NewChunkReader(bytes.NewReader(in)))
	})
}

// FuzzStreamOpen: no StreamOpen makes CheckStreamOpen panic, and one it accepts has a Phase 1 kind.
func FuzzStreamOpen(f *testing.F) {
	b, _ := proto.Marshal(validOpen())
	f.Add(b)
	f.Fuzz(func(t *testing.T, in []byte) {
		o := &tunnelv1.StreamOpen{}
		if proto.Unmarshal(in, o) != nil {
			return
		}
		if tunnel.CheckStreamOpen(o) == tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			switch o.GetKind() {
			case tunnelv1.StreamKind_STREAM_KIND_TCP, tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW,
				tunnelv1.StreamKind_STREAM_KIND_CONTROL_PASSTHROUGH, tunnelv1.StreamKind_STREAM_KIND_DIAG:
			default:
				t.Fatalf("kind %v accepted", o.GetKind())
			}
		}
	})
}
