// SPDX-License-Identifier: Apache-2.0

// Package handoff restarts a role with socket hand-off: the running process starts the installed
// binary as its child and passes it its listening sockets, a manifest naming each one and a status
// pipe; the child checks every descriptor, reports ready, and only then takes over
// (docs/03-connections.md, "Restarts with socket hand-off"; ADR-0022; docs/04-security.md,
// "Socket hand-off"). The design was tried in spike S10 (branch tmp/s10-socket-handoff, commit
// 22b10c4a, spikes/s10/handoff.go).
//
// The package is the core both sides share. Which sockets a role hands over, when it stops
// accepting and how it drains are the role's.
package handoff

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"
)

// Values of docs/03-connections.md, "Timeouts, keepalive and backoff".
const (
	// ReadinessWindow is how long the new process has from its exec until it reports ready; the
	// old one then kills it and serves on.
	ReadinessWindow = 60 * time.Second
	// MaxMessage bounds one message on the status pipe, the manifest included.
	MaxMessage = 4 << 20
	// MaxSockets bounds the sockets one hand-off passes.
	MaxSockets = 16384
)

// Env names the environment variable that tells a new process it was started by a hand-off. Its
// value is the descriptor of the status pipe, always StatusFD.
const Env = "RPMGR_HANDOFF"

// StatusFD is the status pipe's descriptor in the new process; the sockets follow it in the
// manifest's order, from FirstSocketFD on.
const (
	StatusFD      = 3
	FirstSocketFD = 4
)

// manifestVersion is the version of the manifest this release writes and reads.
const manifestVersion = 1

var (
	// ErrUnsupported is returned where the operating system has no hand-off (Windows, macOS).
	ErrUnsupported = errors.New("handoff: not supported on this system")
	// ErrRefused means the hand-off was refused before a new process got any socket.
	ErrRefused = errors.New("handoff: refused")
	// ErrNotReady means the new process did not report ready within the readiness window, failed
	// or exited first; the old process serves on.
	ErrNotReady = errors.New("handoff: the new process did not become ready")
)

// Entry is one socket of a hand-off as the manifest names it.
type Entry struct {
	// Name says what the socket serves, such as "https" or "route-tcp"; for logs only.
	Name string `json:"name"`
	// Net is "tcp" for a listening stream socket or "udp" for a datagram socket.
	Net string `json:"net"`
	// Addr is the socket's local address.
	Addr netip.AddrPort `json:"addr"`
	// FD is the socket's descriptor in the new process.
	FD int `json:"fd"`
}

// Manifest is the first message the old process writes on the status pipe.
type Manifest struct {
	Version int `json:"version"`
	// Generation counts the processes of a role since its last plain start; the new process's is
	// one more than the old one's. Metrics and logs name it.
	Generation uint64  `json:"generation"`
	Entries    []Entry `json:"entries"`
}

// validate checks what the new process can check without touching a descriptor: the version, the
// count, and that the descriptors follow the status pipe in order without a gap.
func (m *Manifest) validate() error {
	if m.Version != manifestVersion {
		return fmt.Errorf("manifest version %d, this release reads %d", m.Version, manifestVersion)
	}
	if m.Generation < 2 {
		return fmt.Errorf("manifest generation %d; a new process is at least the second", m.Generation)
	}
	if len(m.Entries) > MaxSockets {
		return fmt.Errorf("manifest names %d sockets, at most %d", len(m.Entries), MaxSockets)
	}
	for i, e := range m.Entries {
		if e.FD != FirstSocketFD+i {
			return fmt.Errorf("manifest entry %d (%q) names descriptor %d, expected %d", i, e.Name, e.FD, FirstSocketFD+i)
		}
		if e.Net != "tcp" && e.Net != "udp" {
			return fmt.Errorf("manifest entry %q: network %q", e.Name, e.Net)
		}
		if !e.Addr.IsValid() || e.Addr.Port() == 0 {
			return fmt.Errorf("manifest entry %q: address %v", e.Name, e.Addr)
		}
		if len(e.Name) == 0 || len(e.Name) > 64 {
			return fmt.Errorf("manifest entry %d: a name of %d bytes", i, len(e.Name))
		}
	}
	return nil
}

// Message types on the status pipe after the manifest.
const (
	// msgReady: the new process serves (new → old).
	msgReady = "ready"
	// msgFailed: the new process gives up, with a reason (new → old).
	msgFailed = "failed"
	// msgSwitch: the old process accepted the new one, which now tells systemd it is the main
	// process (old → new).
	msgSwitch = "switch"
)

// message is one line on the status pipe after the manifest. Roles add their own types, such as
// the end of a drain, through Pipe.Send and Pipe.Recv.
type message struct {
	Type   string `json:"type"`
	Reason string `json:"reason,omitempty"`
}

// maxReason bounds a reason the other process sends, as it ends up in logs and the outcome.
const maxReason = 512

// Pipe is one end of the status pipe: JSON messages, one per line, each at most MaxMessage.
type Pipe struct {
	r *bufio.Reader
	w io.Writer
	c io.Closer
}

func newPipe(rwc io.ReadWriteCloser) *Pipe {
	return &Pipe{r: bufio.NewReaderSize(rwc, 64<<10), w: rwc, c: rwc}
}

// send writes v as one line.
func (p *Pipe) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) >= MaxMessage {
		return fmt.Errorf("handoff: a message of %d bytes, at most %d", len(b), MaxMessage)
	}
	_, err = p.w.Write(append(b, '\n'))
	return err
}

// recv reads one line, at most MaxMessage, into v. A line the other process did not end is no
// message.
func (p *Pipe) recv(v any) error {
	var line []byte
	for {
		chunk, err := p.r.ReadSlice('\n')
		if len(line)+len(chunk) > MaxMessage {
			return fmt.Errorf("handoff: a message over %d bytes", MaxMessage)
		}
		line = append(line, chunk...)
		switch {
		case err == nil:
			return json.Unmarshal(line[:len(line)-1], v)
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) > 0:
			return io.ErrUnexpectedEOF
		default:
			return err
		}
	}
}

// Send sends a message of the given type, with an optional reason, to the other process.
func (p *Pipe) Send(typ, reason string) error {
	return p.send(message{Type: typ, Reason: trim(reason)})
}

// Recv returns the type and reason of the next message from the other process.
func (p *Pipe) Recv() (typ, reason string, err error) {
	var m message
	if err := p.recv(&m); err != nil {
		return "", "", err
	}
	return m.Type, trim(m.Reason), nil
}

// Close closes the pipe.
func (p *Pipe) Close() error { return p.c.Close() }

// trim bounds a reason and drops control characters, so that the other process cannot write
// lines of its own into a log or the outcome.
func trim(s string) string {
	if len(s) > maxReason {
		s = s[:maxReason]
	}
	b := []rune{}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b = append(b, r)
	}
	return string(b)
}
