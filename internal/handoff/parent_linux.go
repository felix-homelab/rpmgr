// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Start checks the installed binary, starts it with sockets, the manifest and the status pipe, and
// waits until it reports ready, at most the readiness window. It then tells the new process to
// take over and returns it. Any failure leaves this process as it was: a binary that fails the
// check gets nothing (ErrRefused), and a new process that is not ready in time, fails or exits is
// killed (ErrNotReady).
func Start(ctx context.Context, cfg Config, sockets []Socket) (*Child, error) {
	rule, window := rootRule, ReadinessWindow
	if cfg.rule != nil {
		rule = *cfg.rule
	}
	if cfg.window > 0 {
		window = cfg.window
	}
	deadline := time.Now().Add(window)
	if len(sockets) > MaxSockets {
		return nil, fmt.Errorf("%w: %d sockets, at most %d", ErrRefused, len(sockets), MaxSockets)
	}
	m := Manifest{Version: manifestVersion, Generation: cfg.Generation}
	files := make([]*os.File, 0, len(sockets)+1)
	for i, s := range sockets {
		network, addr, err := inspect(int(s.File.Fd()))
		if err != nil {
			return nil, fmt.Errorf("%w: socket %q: %w", ErrRefused, s.Name, err)
		}
		m.Entries = append(m.Entries, Entry{Name: s.Name, Net: network, Addr: addr, FD: FirstSocketFD + i})
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	bin := cfg.bin
	if bin == "" {
		var err error
		if bin, err = os.Executable(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRefused, err)
		}
	}
	path, err := rule.check(bin)
	if err != nil {
		return nil, err
	}

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("handoff: status pipe: %w", err)
	}
	ours, theirs := os.NewFile(uintptr(fds[0]), "handoff-status"), os.NewFile(uintptr(fds[1]), "handoff-status")
	conn, err := net.FileConn(ours)
	_ = ours.Close()
	if err != nil {
		_ = theirs.Close()
		return nil, fmt.Errorf("handoff: status pipe: %w", err)
	}
	files = append(files, theirs)
	for _, s := range sockets {
		files = append(files, s.File)
	}

	args := cfg.Args
	if args == nil {
		args = os.Args[1:]
	}
	env := cfg.Env
	if env == nil {
		env = os.Environ()
	}
	cmd := &exec.Cmd{
		Path:       path,
		Args:       append([]string{bin}, args...),
		Env:        append(without(env, Env), fmt.Sprintf("%s=%d", Env, StatusFD)),
		ExtraFiles: files,
		Stdout:     orDefault(cfg.Stdout, os.Stdout),
		Stderr:     orDefault(cfg.Stderr, os.Stderr),
	}
	err = cmd.Start()
	_ = theirs.Close()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrNotReady, err)
	}
	c := &Child{Pid: cmd.Process.Pid, Generation: m.Generation, Pipe: newPipe(conn), exited: make(chan struct{})}
	go func() { c.err = cmd.Wait(); close(c.exited) }()
	if err := c.await(ctx, conn, m, deadline); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		_ = cmd.Process.Kill()
		<-c.exited
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrNotReady, err)
	}
	return c, nil
}

// await sends the manifest and waits for the new process to report ready before the deadline,
// then sends it the switch.
func (c *Child) await(ctx context.Context, conn net.Conn, m Manifest, deadline time.Time) error {
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if err := c.Pipe.send(m); err != nil {
		return c.why(fmt.Errorf("sending the manifest: %w", err))
	}
	typ, reason, err := c.Pipe.Recv()
	switch {
	case err != nil:
		return c.why(err)
	case typ == msgFailed:
		return fmt.Errorf("the new process failed: %s", reason)
	case typ != msgReady:
		return fmt.Errorf("the new process sent %q instead of ready", trim(typ))
	}
	if err := c.Pipe.Send(msgSwitch, ""); err != nil {
		return c.why(err)
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}

// why explains a failed read or write on the status pipe.
func (c *Child) why(err error) error {
	var wait time.Duration
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		wait = time.Second // the pipe ends just before the process is reaped
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-c.exited:
		if c.err == nil {
			return errors.New("the new process exited before it was ready")
		}
		return fmt.Errorf("the new process exited: %w", c.err)
	case <-t.C:
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return errors.New("not ready within the readiness window")
	}
	return err
}

func without(env []string, name string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	return out
}

func orDefault(w io.Writer, d *os.File) io.Writer {
	if w == nil {
		return d
	}
	return w
}
