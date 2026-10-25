// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// manifestEnv names the environment variable that carries the hand-off manifest to the child.
const manifestEnv = "S10_HANDOFF"

// entry is one inherited descriptor: its name, network, local address and its fd in the child.
type entry struct {
	Name string `json:"name"`
	Net  string `json:"net"` // tcp, udp, unixgram (relay)
	Addr string `json:"addr,omitempty"`
	FD   int    `json:"fd"`
}

// manifest is what the old process tells the new one.
type manifest struct {
	Gen     int     `json:"gen"`
	Status  int     `json:"status"` // fd of the status pipe (child writes READY, reads DONE/CUT)
	Entries []entry `json:"entries"`
}

// checkBinary applies ADR-0022's rule: a regular file owned by root that neither its group nor
// others may write, in directories that follow the same rule.
func checkBinary(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (%v)", path, fi.Mode().Type())
	}
	if err := rootOwnedNotWritable(path, fi); err != nil {
		return err
	}
	for d := filepath.Dir(path); ; d = filepath.Dir(d) {
		di, err := os.Stat(d)
		if err != nil {
			return err
		}
		if err := rootOwnedNotWritable(d, di); err != nil {
			return err
		}
		if d == "/" {
			return nil
		}
	}
}

func rootOwnedNotWritable(p string, fi os.FileInfo) error {
	st := fi.Sys().(*syscall.Stat_t)
	if st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not root", p, st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by its group or others (%v)", p, fi.Mode().Perm())
	}
	return nil
}

func binCheckCmd(args []string) error {
	fs := flag.NewFlagSet("bincheck", flag.ExitOnError)
	_ = fs.Parse(args)
	for _, p := range fs.Args() {
		if err := checkBinary(p); err != nil {
			fmt.Printf("refused %s: %v\n", p, err)
		} else {
			fmt.Printf("accepted %s\n", p)
		}
	}
	return nil
}

// spawn starts bin as a child with the given files, the manifest and a status pipe, and returns
// the child and the parent's end of the status pipe.
func spawn(bin string, args []string, gen int, files []*os.File, entries []entry, extra []string) (*exec.Cmd, *os.File, error) {
	if err := checkBinary(bin); err != nil {
		return nil, nil, fmt.Errorf("hand-off refused: %w", err)
	}
	parentEnd, childEnd, err := socketpairFiles(syscall.SOCK_STREAM, "status")
	if err != nil {
		return nil, nil, err
	}
	m := manifest{Gen: gen, Status: 3 + len(files)}
	for i := range entries {
		entries[i].FD = 3 + i
	}
	m.Entries = entries
	js, _ := json.Marshal(m)
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = append(append([]*os.File{}, files...), childEnd)
	cmd.Env = append(append(os.Environ(), manifestEnv+"="+string(js)), extra...)
	if err := cmd.Start(); err != nil {
		parentEnd.Close()
		childEnd.Close()
		return nil, nil, err
	}
	childEnd.Close()
	return cmd, parentEnd, nil
}

func socketpairFiles(typ int, name string) (*os.File, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, typ|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), name+"-a"), os.NewFile(uintptr(fds[1]), name+"-b"), nil
}

// readManifest reads the manifest the parent passed, if any.
func readManifest() (*manifest, error) {
	s := os.Getenv(manifestEnv)
	if s == "" {
		return nil, nil
	}
	_ = os.Unsetenv(manifestEnv)
	var m manifest
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// adopt checks an inherited descriptor against the manifest entry and the address the
// configuration expects, and returns it as a listener or packet conn; anything else is refused.
func adoptTCP(e entry, want string) (*net.TCPListener, error) {
	f := os.NewFile(uintptr(e.FD), e.Name)
	defer f.Close()
	if err := checkSocket(int(f.Fd()), syscall.SOCK_STREAM, true, want); err != nil {
		return nil, fmt.Errorf("%s: %w", e.Name, err)
	}
	l, err := net.FileListener(f)
	if err != nil {
		return nil, err
	}
	return l.(*net.TCPListener), nil
}

func adoptUDP(e entry, want string) (*net.UDPConn, error) {
	f := os.NewFile(uintptr(e.FD), e.Name)
	defer f.Close()
	if err := checkSocket(int(f.Fd()), syscall.SOCK_DGRAM, false, want); err != nil {
		return nil, fmt.Errorf("%s: %w", e.Name, err)
	}
	c, err := net.FilePacketConn(f)
	if err != nil {
		return nil, err
	}
	u, ok := c.(*net.UDPConn)
	if !ok {
		c.Close()
		return nil, errors.New("not a UDP socket")
	}
	return u, nil
}

// checkSocket verifies the socket type, listening state and local port of fd.
func checkSocket(fd, typ int, listening bool, want string) error {
	got, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return fmt.Errorf("not a socket: %w", err)
	}
	if got != typ {
		return fmt.Errorf("socket type %d, want %d", got, typ)
	}
	if listening {
		acc, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
		if err != nil || acc != 1 {
			return errors.New("not a listening socket")
		}
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return err
	}
	port := 0
	switch a := sa.(type) {
	case *syscall.SockaddrInet4:
		port = a.Port
	case *syscall.SockaddrInet6:
		port = a.Port
	default:
		return errors.New("not an inet socket")
	}
	_, wp, _ := net.SplitHostPort(want)
	if strconv.Itoa(port) != wp {
		return fmt.Errorf("bound to port %d, the configuration names %s", port, wp)
	}
	return nil
}

// closeUnexpected closes inherited descriptors from 3 up to max that the manifest does not name,
// and reports them (ADR-0022: the new process serves only what the manifest names).
func closeUnexpected(m *manifest, max int) []int {
	known := map[int]bool{m.Status: true}
	for _, e := range m.Entries {
		known[e.FD] = true
	}
	var closed []int
	for fd := 3; fd < max; fd++ {
		if known[fd] {
			continue
		}
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) == nil {
			// Go's runtime keeps its own descriptors (epoll, pipes) above the inherited ones only
			// once it has created them; inherited ones come first, so only low fds are candidates.
			if st.Mode&syscall.S_IFMT == syscall.S_IFSOCK {
				_ = syscall.Close(fd)
				closed = append(closed, fd)
			}
		}
	}
	return closed
}

// sdNotify sends state to systemd's notify socket, if there is one.
func sdNotify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(state))
	return err
}

// outcome is what the old process records for `s10 handoff`.
type outcome struct {
	Seq    int    `json:"seq"`
	State  string `json:"state"` // ok, failed, refused
	Reason string `json:"reason,omitempty"`
	OldPID int    `json:"old_pid"`
	NewPID int    `json:"new_pid,omitempty"`
	Gen    int    `json:"gen"`
	Took   string `json:"took"`
}

func writeOutcome(dir string, o outcome) {
	if dir == "" {
		return
	}
	js, _ := json.Marshal(o)
	tmp := filepath.Join(dir, ".handoff.json.tmp")
	if os.WriteFile(tmp, js, 0o644) == nil {
		_ = os.Rename(tmp, filepath.Join(dir, "handoff.json"))
	}
}

func readOutcome(dir string) (outcome, error) {
	var o outcome
	b, err := os.ReadFile(filepath.Join(dir, "handoff.json"))
	if err != nil {
		return o, err
	}
	return o, json.Unmarshal(b, &o)
}

// handoffCmd is `s10 handoff`: signal the running server and wait for the outcome, as
// `rpmgr handoff <role>` will (ExecReload of the unit).
func handoffCmd(args []string) error {
	fs := flag.NewFlagSet("handoff", flag.ExitOnError)
	dir := fs.String("run", "/run/s10", "the server's run directory (pid file and outcome)")
	wait := fs.Duration("wait", 90*time.Second, "how long to wait for the outcome")
	_ = fs.Parse(args)
	b, err := os.ReadFile(filepath.Join(*dir, "pid"))
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	before, _ := readOutcome(*dir)
	if err := syscall.Kill(pid, syscall.SIGUSR2); err != nil {
		return err
	}
	deadline := time.Now().Add(*wait)
	for time.Now().Before(deadline) {
		if o, err := readOutcome(*dir); err == nil && o.Seq != before.Seq && o.OldPID == pid {
			fmt.Printf("hand-off %s: old pid %d, new pid %d, gen %d, took %s %s\n", o.State, o.OldPID, o.NewPID, o.Gen, o.Took, o.Reason)
			if o.State != "ok" {
				return errors.New("hand-off " + o.State)
			}
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("no outcome within the wait")
}

// lineReader reads newline-terminated messages from the status pipe.
func lineReader(f *os.File) <-chan string {
	ch := make(chan string, 4)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			ch <- sc.Text()
		}
	}()
	return ch
}
