// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The test binary is also the new process of every hand-off here: with scenarioEnv set, TestMain
// runs child instead of the tests.
const (
	scenarioEnv = "HANDOFF_TEST_SCENARIO"
	resultEnv   = "HANDOFF_TEST_RESULT"
	addrsEnv    = "HANDOFF_TEST_ADDRS" // the listeners the new process's "boot file" names
)

func TestMain(m *testing.M) {
	if s := os.Getenv(scenarioEnv); s != "" {
		os.Exit(child(s))
	}
	os.Exit(m.Run())
}

// result is what the new process reports to the test.
type result struct {
	Err        string
	Generation uint64
	Unexpected []int
	Took, Rest []string
}

// child is the new process. Scenarios: ready (take the listeners, report ready, answer one
// connection with its generation), never (never report ready), fail (give up with a reason),
// crash (exit before reading anything), check (only Inherited), listen (a helper, not a child:
// listen on a unix socket).
func child(scenario string) int {
	var r result
	write := func() {
		b, _ := json.Marshal(r)
		_ = os.WriteFile(os.Getenv(resultEnv), b, 0o600) //nolint:gosec // G703: the test's own path
	}
	switch scenario {
	case "crash":
		return 3
	case "listen":
		l, err := net.Listen("unix", os.Getenv(addrsEnv))
		if err != nil {
			return 1
		}
		held := make(chan net.Conn, 16) // open until the test kills the helper
		for {
			if c, err := l.Accept(); err == nil {
				select {
				case held <- c:
				default:
					_ = c.Close()
				}
			}
		}
	}
	h, err := Inherited(os.Getenv)
	if err == nil && h == nil {
		err = errors.New("a plain start")
	}
	if err != nil {
		r.Err = err.Error()
		write()
		return 1
	}
	r.Generation, r.Unexpected = h.Manifest.Generation, h.Unexpected
	var ls []net.Listener
	for _, a := range strings.Fields(os.Getenv(addrsEnv)) {
		l, ok, err := h.Listener(netip.MustParseAddrPort(a))
		if ok && err == nil {
			ls = append(ls, l)
			r.Took = append(r.Took, a)
		}
	}
	for _, e := range h.Rest() {
		r.Rest = append(r.Rest, e.Name)
	}
	if strings.HasPrefix(scenario, "release") {
		if err := h.Release(); err != nil {
			r.Err = err.Error()
			write()
			h.Fail(err.Error())
			return 1
		}
		switch scenario {
		case "release-fail":
			h.Fail("the migration failed")
			return 1
		case "release-crash":
			return 3
		}
		scenario = "ready"
	}
	switch scenario {
	case "check":
		write()
		return 0
	case "never":
		write()
		time.Sleep(time.Hour)
	case "fail":
		write()
		h.Fail("cannot start:\nforged line")
		return 1
	}
	if err := h.Ready(); err != nil {
		r.Err = err.Error()
		write()
		return 1
	}
	write()
	for _, l := range ls {
		c, err := l.Accept()
		if err != nil {
			return 1
		}
		_, _ = fmt.Fprintf(c, "gen %d\n", r.Generation)
		_ = c.Close()
	}
	return 0
}

// install copies the test binary to dir/bin/rpmgr, as the binary a hand-off starts.
func install(t *testing.T) (dir, bin string) {
	t.Helper()
	dir = t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self) //nolint:gosec // G304: the test binary
	if err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(dir, "bin", "rpmgr")
	if err := os.Mkdir(filepath.Dir(bin), 0o755); err != nil { //nolint:gosec // G301: like /usr/local/bin
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, b, 0o755); err != nil { //nolint:gosec // G306: an executable
		t.Fatal(err)
	}
	return dir, bin
}

func readResult(t *testing.T, path string) result {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: the test's own file
	if err != nil {
		t.Fatalf("no result from the new process: %v", err)
	}
	var r result
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// listener returns a TCP listener on loopback and a duplicate of it to hand over.
func listener(t *testing.T) (*net.TCPListener, *os.File) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f, err := l.File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return l, f
}

// raw starts bin in scenario "check" as a hostile or broken old process would: with the given
// status descriptor and sockets, and with manifest written on the status pipe if it is one this
// test created. It returns the new process's result and its reply on the pipe.
func raw(t *testing.T, bin string, status *os.File, ours net.Conn, env string, manifest any, sockets ...*os.File) (result, string) {
	t.Helper()
	res := filepath.Join(t.TempDir(), "result.json")
	cmd := exec.Command(bin) //nolint:gosec // G204: the test binary
	cmd.Env = append(os.Environ(), env, scenarioEnv+"=check", resultEnv+"="+res, addrsEnv+"=")
	cmd.ExtraFiles = append([]*os.File{status}, sockets...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var reply string
	if ours != nil {
		p := newPipe(ours)
		_ = ours.SetDeadline(time.Now().Add(10 * time.Second))
		if err := p.send(manifest); err != nil {
			t.Fatal(err)
		}
		typ, reason, err := p.Recv()
		if err == nil {
			reply = typ + ": " + reason
		}
	}
	_ = cmd.Wait()
	return readResult(t, res), reply
}

// statusPipe returns a status pipe as Start creates one: the test's end and the new process's.
func statusPipe(t *testing.T) (net.Conn, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	ours := os.NewFile(uintptr(fds[0]), "ours")
	c, err := net.FileConn(ours)
	_ = ours.Close()
	if err != nil {
		t.Fatal(err)
	}
	theirs := os.NewFile(uintptr(fds[1]), "theirs")
	t.Cleanup(func() { _ = c.Close(); _ = theirs.Close() })
	return c, theirs
}

func entry(name string, l *net.TCPListener, fd int) Entry {
	return Entry{Name: name, Net: "tcp", Addr: l.Addr().(*net.TCPAddr).AddrPort(), FD: fd}
}

// TestHandoff_UnexpectedDescriptorsRefused is the security test of docs/12: the new process
// accepts only the descriptors the manifest names, each as it names it, over a status pipe from
// its parent; it closes any other socket it inherited, and one its boot file does not name.
func TestHandoff_UnexpectedDescriptorsRefused(t *testing.T) {
	_, bin := install(t)
	env := Env + "=3"
	l1, f1 := listener(t)
	l2, f2 := listener(t)
	manifest := func(es ...Entry) Manifest {
		return Manifest{Version: manifestVersion, Generation: 2, Entries: es}
	}

	t.Run("an extra socket is closed", func(t *testing.T) {
		ours, theirs := statusPipe(t)
		r, reply := raw(t, bin, theirs, ours, env, manifest(entry("https", l1, 4)), f1, f2)
		if r.Err != "" || reply != "" || len(r.Unexpected) != 1 || r.Unexpected[0] != 5 || len(r.Rest) != 1 {
			t.Errorf("result %+v, reply %q", r, reply)
		}
	})
	t.Run("a socket the boot file does not name is closed", func(t *testing.T) {
		ours, theirs := statusPipe(t)
		res := filepath.Join(t.TempDir(), "result.json")
		cmd := exec.Command(bin) //nolint:gosec // G204: the test binary
		cmd.Env = append(os.Environ(), env, scenarioEnv+"=check", resultEnv+"="+res, addrsEnv+"="+l1.Addr().String())
		cmd.ExtraFiles = []*os.File{theirs, f1, f2}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if err := newPipe(ours).send(manifest(entry("https", l1, 4), entry("route", l2, 5))); err != nil {
			t.Fatal(err)
		}
		_ = cmd.Wait()
		r := readResult(t, res)
		if r.Err != "" || len(r.Took) != 1 || len(r.Rest) != 1 || r.Rest[0] != "route" {
			t.Errorf("result %+v", r)
		}
	})

	refused := []struct {
		name, want string
		run        func(t *testing.T) (result, string)
	}{
		{"a manifest naming another address", "names tcp", func(t *testing.T) (result, string) {
			ours, theirs := statusPipe(t)
			e := entry("https", l2, 4)
			return raw(t, bin, theirs, ours, env, manifest(e), f1)
		}},
		{"descriptors out of order", "names descriptor 5, expected 4", func(t *testing.T) (result, string) {
			ours, theirs := statusPipe(t)
			return raw(t, bin, theirs, ours, env, manifest(entry("route", l2, 5), entry("https", l1, 4)), f1, f2)
		}},
		{"more entries than sockets", "did not inherit", func(t *testing.T) (result, string) {
			ours, theirs := statusPipe(t)
			return raw(t, bin, theirs, ours, env, manifest(entry("https", l1, 4), entry("route", l2, 5)), f1)
		}},
		{"a connected socket", "no listening socket", func(t *testing.T) (result, string) {
			c, err := net.Dial("tcp", l1.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			cf, _ := c.(*net.TCPConn).File()
			defer func() { _ = cf.Close() }()
			ours, theirs := statusPipe(t)
			e := Entry{Name: "https", Net: "tcp", Addr: c.LocalAddr().(*net.TCPAddr).AddrPort(), FD: 4}
			return raw(t, bin, theirs, ours, env, manifest(e), cf)
		}},
		{"a garbled manifest", "reading the manifest", func(t *testing.T) (result, string) {
			ours, theirs := statusPipe(t)
			return raw(t, bin, theirs, ours, env, "not a manifest", f1)
		}},
		{"another status descriptor", "expected 3", func(t *testing.T) (result, string) {
			ours, theirs := statusPipe(t)
			_ = ours.Close()
			return raw(t, bin, theirs, nil, Env+"=4", nil, f1)
		}},
		{"a pipe as status", "is no socket", func(t *testing.T) (result, string) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close(); _ = w.Close() }()
			return raw(t, bin, r, nil, env, nil, f1)
		}},
		{"a status pipe from another process", "not from the parent process", func(t *testing.T) (result, string) {
			path := filepath.Join(t.TempDir(), "s")
			helper := exec.Command(bin) //nolint:gosec // G204: the test binary
			helper.Env = append(os.Environ(), scenarioEnv+"=listen", addrsEnv+"="+path)
			if err := helper.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = helper.Process.Kill(); _ = helper.Wait() }()
			var c net.Conn
			for i := 0; i < 100; i++ {
				var err error
				if c, err = net.Dial("unix", path); err == nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if c == nil {
				t.Fatal("the helper does not listen")
			}
			defer func() { _ = c.Close() }()
			cf, _ := c.(*net.UnixConn).File()
			defer func() { _ = cf.Close() }()
			return raw(t, bin, cf, nil, env, nil, f1)
		}},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			r, reply := tc.run(t)
			if !strings.Contains(r.Err, ErrRefused.Error()) || !strings.Contains(r.Err, tc.want) {
				t.Errorf("result %+v, want refused with %q", r, tc.want)
			}
			if r.Took != nil || r.Generation != 0 {
				t.Errorf("the new process took sockets: %+v", r)
			}
			if reply != "" && !strings.HasPrefix(reply, msgFailed+": ") {
				t.Errorf("reply %q", reply)
			}
		})
	}
}

func TestInherited_PlainStart(t *testing.T) {
	h, err := Inherited(func(string) string { return "" })
	if h != nil || err != nil {
		t.Errorf("Inherited = %v, %v", h, err)
	}
}

func TestReady_OldProcessGoneWithoutSwitch(t *testing.T) {
	ours, theirs := net.Pipe()
	h := &Handoff{pipe: newPipe(theirs), conn: theirs, ppid: os.Getppid(), started: time.Now()}
	go func() {
		_, _ = io.ReadAll(io.LimitReader(ours, 64)) // the ready line
	}()
	go func() { time.Sleep(100 * time.Millisecond); _ = ours.Close() }()
	if err := h.Ready(); err == nil {
		t.Error("Ready succeeded although the old process, still the parent, never sent the switch")
	}
}

// notifySocket stands in for systemd's notify socket.
func notifySocket(t *testing.T) *net.UnixConn {
	t.Helper()
	ns, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "notify"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ns.Close() })
	return ns
}

// TestHandoff_ReadyAndSwitch: the new process reports ready, tells systemd it is the main process
// only once the old one sent the switch, and then serves the socket it took; anything but the
// switch ends it.
func TestHandoff_ReadyAndSwitch(t *testing.T) {
	_, bin := install(t)
	l, f := listener(t)
	for _, answer := range []string{msgSwitch, "drain"} {
		t.Run(answer, func(t *testing.T) {
			ns := notifySocket(t)
			ours, theirs := statusPipe(t)
			res := filepath.Join(t.TempDir(), "result.json")
			cmd := exec.Command(bin) //nolint:gosec // G204: the test binary
			cmd.Env = append(os.Environ(), Env+"=3", scenarioEnv+"=ready", resultEnv+"="+res, addrsEnv+"="+l.Addr().String(),
				"NOTIFY_SOCKET="+ns.LocalAddr().String())
			cmd.ExtraFiles = []*os.File{theirs, f}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			p := newPipe(ours)
			_ = ours.SetDeadline(time.Now().Add(10 * time.Second))
			if err := p.send(Manifest{Version: manifestVersion, Generation: 2, Entries: []Entry{entry("https", l, 4)}}); err != nil {
				t.Fatal(err)
			}
			if typ, _, err := p.Recv(); err != nil || typ != msgReady {
				t.Fatalf("the new process sent %q, %v", typ, err)
			}
			buf := make([]byte, 256)
			_ = ns.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if n, err := ns.Read(buf); err == nil {
				t.Fatalf("systemd was told %q before the switch", buf[:n])
			}
			if err := p.Send(answer, ""); err != nil {
				t.Fatal(err)
			}
			_ = ns.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := ns.Read(buf)
			if answer != msgSwitch {
				_ = cmd.Wait()
				if r := readResult(t, res); err == nil || !strings.Contains(r.Err, `sent "drain" instead of switch`) {
					t.Errorf("systemd told %q; result %+v", buf[:n], r)
				}
				return
			}
			if want := fmt.Sprintf("MAINPID=%d\nREADY=1", cmd.Process.Pid); err != nil || string(buf[:n]) != want {
				t.Fatalf("systemd was told %q, %v; want %q", buf[:n], err, want)
			}
			c, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			if b, err := io.ReadAll(c); err != nil || string(b) != "gen 2\n" {
				t.Errorf("the new process answered %q, %v", b, err)
			}
		})
	}
}
