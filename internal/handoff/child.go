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
	"sync"
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

	settleFor   time.Duration // tests: shorter than SettleMax
	settle      bool          // Ready keeps the unit "reloading" until Settled or SettleMax
	settled     chan struct{} // closed by Settled
	settledOnce sync.Once
}

// SettleAfterSwitch makes Ready tell systemd the unit is reloading after the switch, and ready
// only once Settled is called or SettleMax passed. A role calls it when the old process holds a
// socket that clients use for their own judgement of this process, the admin listener.
func (h *Handoff) SettleAfterSwitch() { h.settle = true }

// SettleMax is how long, after the switch, the unit stays "reloading" for systemd while the old
// process stops answering the admin listener (docs/03-connections.md, "Timeouts, keepalive and
// backoff"). A role that learns the old process stopped calls Settled; else the wait ends here.
const SettleMax = 3 * time.Second

// Settled says the old process no longer takes connections on the shared sockets, so that the unit
// is active again. Calling it more than once, or when no hand-off is waiting for it, is harmless.
func (h *Handoff) Settled() {
	h.settledOnce.Do(func() {
		if h.settled != nil {
			close(h.settled)
		}
	})
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
	// The unit is "reloading" until the old process stopped answering the admin listener, which
	// both processes hold until the old one retires its copy a moment after the switch: an updater
	// that polls /readyz once the unit is active would otherwise land on the old process, whose
	// answer is "not ready", over a connection it then keeps for the whole wait (#1138).
	if !h.settle {
		return notify(h.notify, fmt.Sprintf("MAINPID=%d\nREADY=1", os.Getpid()))
	}
	if h.notify == "" {
		return nil
	}
	if err := notify(h.notify, fmt.Sprintf("MAINPID=%d\nRELOADING=1\nMONOTONIC_USEC=%d", os.Getpid(), monotonicUSec())); err != nil {
		return err
	}
	go func() {
		wait := h.settleFor
		if wait <= 0 {
			wait = SettleMax
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-h.settled:
		case <-t.C:
		}
		_ = notify(h.notify, "READY=1")
	}()
	return nil
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

// Predecessor is the old process's ID: the process that started this one.
func (h *Handoff) Predecessor() int { return h.ppid }

// EndGrace is how long the new process waits, after the old one's hand-off drain should have
// ended, before it signals the old process SIGTERM, and after that before SIGKILL: an old process
// of a release that does not leave its drain when told to stop, or that is stuck, never outlives
// both (docs/03-connections.md, "Timeouts, keepalive and backoff").
const EndGrace = 30 * time.Second
