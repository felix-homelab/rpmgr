// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
)

func TestManifest_Validate(t *testing.T) {
	addr := netip.MustParseAddrPort("127.0.0.1:443")
	ok := func() Manifest {
		return Manifest{Version: manifestVersion, Generation: 2, Entries: []Entry{
			{Name: "https", Net: "tcp", Addr: addr, FD: FirstSocketFD},
			{Name: "quic", Net: "udp", Addr: addr, FD: FirstSocketFD + 1},
		}}
	}
	m := ok()
	if err := m.validate(); err != nil {
		t.Fatalf("a good manifest: %v", err)
	}
	empty := Manifest{Version: manifestVersion, Generation: 2}
	if err := empty.validate(); err != nil {
		t.Fatalf("a manifest without sockets: %v", err)
	}
	for name, change := range map[string]func(*Manifest){
		"other version":       func(m *Manifest) { m.Version = 2 },
		"generation 1":        func(m *Manifest) { m.Generation = 1 },
		"descriptor gap":      func(m *Manifest) { m.Entries[1].FD = FirstSocketFD + 2 },
		"descriptors swapped": func(m *Manifest) { m.Entries[0].FD, m.Entries[1].FD = m.Entries[1].FD, m.Entries[0].FD },
		"status descriptor":   func(m *Manifest) { m.Entries[0].FD = StatusFD },
		"unix network":        func(m *Manifest) { m.Entries[0].Net = "unix" },
		"no address":          func(m *Manifest) { m.Entries[0].Addr = netip.AddrPort{} },
		"port 0":              func(m *Manifest) { m.Entries[0].Addr = netip.MustParseAddrPort("127.0.0.1:0") },
		"no name":             func(m *Manifest) { m.Entries[0].Name = "" },
		"long name":           func(m *Manifest) { m.Entries[0].Name = strings.Repeat("n", 65) },
		"too many sockets": func(m *Manifest) {
			m.Entries = make([]Entry, MaxSockets+1)
			for i := range m.Entries {
				m.Entries[i] = Entry{Name: "r", Net: "tcp", Addr: addr, FD: FirstSocketFD + i}
			}
		},
	} {
		m := ok()
		change(&m)
		if err := m.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type rwc struct {
	io.Reader
	io.Writer
}

func (rwc) Close() error { return nil }

func TestPipe_BoundsAndTrims(t *testing.T) {
	var out bytes.Buffer
	p := newPipe(rwc{strings.NewReader(""), &out})
	if err := p.Send(msgFailed, "line one\nforged line\x1b[31m"+strings.Repeat("x", 2*maxReason)); err != nil {
		t.Fatal(err)
	}
	typ, reason, err := newPipe(rwc{&out, io.Discard}).Recv()
	if err != nil || typ != msgFailed {
		t.Fatalf("Recv = %q, %v", typ, err)
	}
	if strings.ContainsAny(reason, "\n\x1b") || len(reason) > maxReason {
		t.Errorf("reason not trimmed: %q (%d bytes)", reason[:40], len(reason))
	}

	// A peer that never ends its line is cut off at MaxMessage, not read into memory forever.
	huge := io.MultiReader(strings.NewReader(`{"type":"`), &endless{})
	if _, _, err := newPipe(rwc{huge, io.Discard}).Recv(); err == nil || !strings.Contains(err.Error(), "over") {
		t.Errorf("an endless line: %v", err)
	}
	if err := p.send(map[string]string{"x": strings.Repeat("y", MaxMessage)}); err == nil {
		t.Error("sent a message over MaxMessage")
	}
	// A line cut short by the peer's exit is no message.
	if _, _, err := newPipe(rwc{strings.NewReader(`{"type":"rea`), io.Discard}).Recv(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a cut line: %v", err)
	}
	if _, _, err := newPipe(rwc{strings.NewReader("not json\n"), io.Discard}).Recv(); err == nil {
		t.Error("accepted a line that is no JSON")
	}
}

type endless struct{ n int }

func (e *endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	e.n += len(p)
	return len(p), nil
}
