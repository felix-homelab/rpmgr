// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"time"
)

// Handoff is what a new process received from the old one: the manifest's sockets, after checking
// each, and the status pipe.
type Handoff struct {
	// Manifest is the old process's manifest.
	Manifest Manifest
	// Unexpected are the descriptors this process inherited and the manifest does not name; they
	// are closed. A role logs them.
	Unexpected []int

	pipe    *Pipe
	conn    net.Conn
	ppid    int
	sockets map[int]Entry // by descriptor, until taken
	started time.Time
	notify  string // $NOTIFY_SOCKET
}

// Take returns the inherited socket for network ("tcp" or "udp") and addr as a file, and removes it
// from the hand-off; false when the manifest names none. A role takes what its boot file and
// snapshot name and calls Rest for the others.
func (h *Handoff) Take(network string, addr netip.AddrPort) (*os.File, bool) {
	for fd, e := range h.sockets {
		if e.Net == network && e.Addr == addr {
			delete(h.sockets, fd)
			return os.NewFile(uintptr(fd), e.Name), true //nolint:gosec // G115: a descriptor
		}
	}
	return nil, false
}

// Listener takes the inherited listening socket at addr, as Take does.
func (h *Handoff) Listener(addr netip.AddrPort) (net.Listener, bool, error) {
	f, ok := h.Take("tcp", addr)
	if !ok {
		return nil, false, nil
	}
	defer func() { _ = f.Close() }()
	l, err := net.FileListener(f)
	return l, true, err
}

// Rest closes the sockets nobody took, as the configuration does not name them, and returns
// their entries for the log.
func (h *Handoff) Rest() []Entry {
	var rest []Entry
	for fd, e := range h.sockets {
		closeFD(fd)
		rest = append(rest, e)
	}
	clear(h.sockets)
	slices.SortFunc(rest, func(a, b Entry) int { return a.FD - b.FD })
	return rest
}

// Release asks the old process to let go of what only one process may hold, the all-in-one's
// database, and waits, within the readiness window, until it did. The new process opens that
// resource only after Release returned nil. An old process that refuses, or that ends, is an error,
// upon which this process exits; the old one takes its resource up again.
func (h *Handoff) Release() error {
	if err := h.pipe.Send(msgRelease, ""); err != nil {
		return fmt.Errorf("handoff: asking the old process to release: %w", err)
	}
	_ = h.conn.SetReadDeadline(h.started.Add(ReadinessWindow))
	typ, reason, err := h.pipe.Recv()
	_ = h.conn.SetReadDeadline(time.Time{})
	switch {
	case err != nil:
		return fmt.Errorf("handoff: waiting for the old process to release: %w", err)
	case typ == msgFailed:
		return fmt.Errorf("handoff: the old process cannot release: %s", reason)
	case typ != msgReleased:
		return fmt.Errorf("handoff: the old process sent %q instead of released", trim(typ))
	}
	return nil
}

// Ready reports ready to the old process and waits, within the readiness window, until it hands
// over; the new process then tells systemd it is the unit's main process. If the old process
// ended without an answer, its successor takes over all the same. Any other failure returns an
// error, upon which this process exits.
func (h *Handoff) Ready() error {
	if err := h.pipe.Send(msgReady, ""); err != nil {
		return fmt.Errorf("handoff: reporting ready: %w", err)
	}
	_ = h.conn.SetReadDeadline(h.started.Add(ReadinessWindow))
	typ, _, err := h.pipe.Recv()
	_ = h.conn.SetReadDeadline(time.Time{})
	switch {
	case err == nil && typ == msgSwitch:
	case errors.Is(err, io.EOF) && os.Getppid() != h.ppid:
		// The old process is gone: nothing else serves now.
	case err != nil:
		return fmt.Errorf("handoff: waiting for the old process: %w", err)
	default:
		return fmt.Errorf("handoff: the old process sent %q instead of switch", trim(typ))
	}
	return notify(h.notify, fmt.Sprintf("MAINPID=%d\nREADY=1", os.Getpid()))
}

// Fail tells the old process that this one gives up, with the reason, and closes the status pipe
// and every socket nobody took.
func (h *Handoff) Fail(reason string) {
	_ = h.pipe.Send(msgFailed, reason)
	_ = h.pipe.Close()
	h.Rest()
}

// Pipe is the status pipe to the old process, for the role's messages once Ready returned.
func (h *Handoff) Pipe() *Pipe { return h.pipe }
