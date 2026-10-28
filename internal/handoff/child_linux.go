// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// Inherited returns the hand-off this process was started by, or nil after a plain start. Call it
// first, before the process opens a socket of its own: every socket it inherited that the
// manifest does not name is closed. A status pipe that the parent process did not create, a
// manifest it cannot read, or a descriptor that differs from its manifest entry refuses the
// whole hand-off: every inherited socket is closed and an error returned, upon which the new
// process exits and the old one serves on.
func Inherited(getenv func(string) string) (*Handoff, error) {
	v := getenv(Env)
	if v == "" {
		return nil, nil
	}
	_ = os.Unsetenv(Env) // not for this process's own children
	inherited := inheritedSockets()
	refuse := func(err error) (*Handoff, error) {
		for _, fd := range inherited {
			_ = unix.Close(fd)
		}
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if v != strconv.Itoa(StatusFD) {
		return refuse(fmt.Errorf("%s=%q, expected %d", Env, v, StatusFD))
	}
	if err := fromParent(StatusFD); err != nil {
		return refuse(err)
	}
	f := os.NewFile(StatusFD, "handoff-status")
	conn, err := net.FileConn(f) // a duplicate, close-on-exec
	_ = f.Close()
	inherited = slices.DeleteFunc(inherited, func(fd int) bool { return fd == StatusFD })
	if err != nil {
		return refuse(fmt.Errorf("status pipe: %w", err))
	}
	h := &Handoff{pipe: newPipe(conn), conn: conn, ppid: os.Getppid(), sockets: map[int]Entry{},
		started: time.Now(), notify: getenv("NOTIFY_SOCKET")}
	fail := func(err error) (*Handoff, error) {
		_ = h.pipe.Send(msgFailed, err.Error())
		_ = conn.Close()
		return refuse(err)
	}
	_ = conn.SetReadDeadline(h.started.Add(ReadinessWindow))
	if err := h.pipe.recv(&h.Manifest); err != nil {
		return fail(fmt.Errorf("reading the manifest: %w", err))
	}
	if err := h.Manifest.validate(); err != nil {
		return fail(err)
	}
	for _, e := range h.Manifest.Entries {
		if !slices.Contains(inherited, e.FD) {
			return fail(fmt.Errorf("manifest entry %q names descriptor %d, which this process did not inherit as a socket", e.Name, e.FD))
		}
		network, addr, err := inspect(e.FD)
		if err != nil {
			return fail(fmt.Errorf("manifest entry %q: %w", e.Name, err))
		}
		if network != e.Net || addr != e.Addr {
			return fail(fmt.Errorf("manifest entry %q names %s %v, descriptor %d is %s %v", e.Name, e.Net, e.Addr, e.FD, network, addr))
		}
		h.sockets[e.FD] = e
	}
	_ = conn.SetReadDeadline(time.Time{})
	for _, fd := range inherited {
		if _, ok := h.sockets[fd]; !ok {
			_ = unix.Close(fd)
			h.Unexpected = append(h.Unexpected, fd)
		}
	}
	return h, nil
}

// fromParent checks that fd is a unix stream socket whose peer is this process's parent, running
// as the same user, as the status pipe of a hand-off is.
func fromParent(fd int) error {
	if !isSocket(fd) {
		return fmt.Errorf("descriptor %d is no socket", fd)
	}
	if typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || typ != unix.SOCK_STREAM {
		return fmt.Errorf("descriptor %d is no stream socket", fd)
	}
	if sa, err := unix.Getsockname(fd); err != nil {
		return fmt.Errorf("descriptor %d: %w", fd, err)
	} else if _, ok := sa.(*unix.SockaddrUnix); !ok {
		return fmt.Errorf("descriptor %d is no unix socket", fd)
	}
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return fmt.Errorf("descriptor %d: %w", fd, err)
	}
	if int(cred.Pid) != os.Getppid() || int(cred.Uid) != os.Getuid() {
		return fmt.Errorf("the status pipe comes from process %d of user %d, not from the parent process %d of user %d",
			cred.Pid, cred.Uid, os.Getppid(), os.Getuid())
	}
	return nil
}

// inheritedSockets returns the descriptors above standard error that are sockets.
func inheritedSockets() []int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil
	}
	var fds []int
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err == nil && fd > 2 && isSocket(fd) {
			fds = append(fds, fd)
		}
	}
	slices.Sort(fds)
	return fds
}

// Notify tells systemd this process is ready after a plain start ($NOTIFY_SOCKET, Type=notify).
func Notify(getenv func(string) string) error {
	return notify(getenv("NOTIFY_SOCKET"), "READY=1")
}
