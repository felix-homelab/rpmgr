// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// installed is install with a rule that wants the test's user where production wants root, and
// stops at dir.
func installed(t *testing.T) (dir, bin string, rule *binaryRule) {
	t.Helper()
	dir, bin = install(t)
	return dir, bin, &binaryRule{uid: uint32(os.Getuid()), stop: dir} //nolint:gosec // G115: a uid
}

// config returns the configuration of a hand-off to bin in the given scenario, and the path its
// result goes to.
func config(t *testing.T, bin string, rule *binaryRule, scenario string, env ...string) (Config, string) {
	t.Helper()
	res := filepath.Join(t.TempDir(), "result.json")
	return Config{bin: bin, Args: []string{}, Generation: 2, rule: rule, window: 10 * time.Second,
		Env: append(os.Environ(), append(env, scenarioEnv+"="+scenario, resultEnv+"="+res)...)}, res
}

// greeting dials addr and returns the first line it reads.
func greeting(t *testing.T, addr net.Addr) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("no greeting: %v", err)
	}
	return strings.TrimSpace(line)
}

// stillServes checks that the old process's listener still accepts.
func stillServes(t *testing.T, l *net.TCPListener) {
	t.Helper()
	c, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = l.SetDeadline(time.Now().Add(5 * time.Second))
	a, err := l.Accept()
	if err != nil {
		t.Fatalf("the old process's listener: %v", err)
	}
	_ = a.Close()
}

func TestStart_ReadyChildTakesOver(t *testing.T) {
	_, bin, rule := installed(t)
	l, f := listener(t)
	ns := notifySocket(t)
	cfg, res := config(t, bin, rule, "ready", addrsEnv+"="+l.Addr().String(), "NOTIFY_SOCKET="+ns.LocalAddr().String())
	c, err := Start(context.Background(), cfg, []Socket{{Name: "https", File: f}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The old process does not accept: the queued connection goes to the new one.
	if got := greeting(t, l.Addr()); got != "gen 2" {
		t.Errorf("greeting %q", got)
	}
	_ = ns.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, err := ns.Read(buf)
	if want := fmt.Sprintf("MAINPID=%d\nREADY=1", c.Pid); err != nil || string(buf[:n]) != want {
		t.Errorf("systemd was told %q, %v; want %q", buf[:n], err, want)
	}
	if err := c.Err(); err != nil {
		t.Errorf("the new process exited: %v", err)
	}
	r := readResult(t, res)
	if r.Err != "" || r.Generation != 2 || len(r.Took) != 1 || len(r.Unexpected) != 0 || len(r.Rest) != 0 {
		t.Errorf("result %+v", r)
	}
}

func TestStart_TwoInARow(t *testing.T) {
	_, bin, rule := installed(t)
	l, f := listener(t)
	for gen := uint64(2); gen <= 3; gen++ {
		cfg, _ := config(t, bin, rule, "ready", addrsEnv+"="+l.Addr().String())
		cfg.Generation = gen
		c, err := Start(context.Background(), cfg, []Socket{{Name: "https", File: f}})
		if err != nil {
			t.Fatalf("hand-off to generation %d: %v", gen, err)
		}
		if got, want := greeting(t, l.Addr()), fmt.Sprintf("gen %d", gen); got != want {
			t.Errorf("greeting %q, want %q", got, want)
		}
		<-c.Exited()
	}
}

func TestStart_NewProcessNotReady(t *testing.T) {
	_, bin, rule := installed(t)
	for _, tc := range []struct{ scenario, want string }{
		{"never", "not ready within the readiness window"},
		{"crash", "the new process exited: exit status 3"},
		{"fail", "the new process failed: cannot start: forged line"},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			l, f := listener(t)
			cfg, _ := config(t, bin, rule, tc.scenario, addrsEnv+"="+l.Addr().String())
			cfg.window = 2 * time.Second
			start := time.Now()
			c, err := Start(context.Background(), cfg, []Socket{{Name: "https", File: f}})
			if c != nil || !errors.Is(err, ErrNotReady) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Start = %v, %v; want ErrNotReady with %q", c, err, tc.want)
			}
			if tc.scenario == "never" && time.Since(start) < 2*time.Second {
				t.Errorf("gave up after %v, before the readiness window", time.Since(start))
			}
			stillServes(t, l)
		})
	}
}

func TestStart_Canceled(t *testing.T) {
	_, bin, rule := installed(t)
	l, f := listener(t)
	cfg, _ := config(t, bin, rule, "never", addrsEnv+"="+l.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := Start(ctx, cfg, []Socket{{Name: "https", File: f}}); !errors.Is(err, ErrNotReady) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start = %v", err)
	}
	stillServes(t, l)
}

func TestStart_RefusesSocketsItCannotName(t *testing.T) {
	_, bin, rule := installed(t)
	l, _ := listener(t)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	cf, err := c.(*net.TCPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cf.Close() }()
	cfg, res := config(t, bin, rule, "check")
	if _, err := Start(context.Background(), cfg, []Socket{{Name: "conn", File: cf}}); !errors.Is(err, ErrRefused) {
		t.Fatalf("handing over a connected socket: %v", err)
	}
	if _, err := os.Stat(res); err == nil {
		t.Error("a new process started")
	}
}

// TestHandoff_OnlyVerifiedBinaryGetsSockets is the security test of docs/12: only a regular file
// owned by root (here: the test's user) that neither its group nor others may write, in
// directories that follow the same rule, is started and gets the sockets.
func TestHandoff_OnlyVerifiedBinaryGetsSockets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir, bin string, rule *binaryRule) string // returns the binary to start
	}{
		{"group may write the binary", func(t *testing.T, _, bin string, _ *binaryRule) string {
			chmod(t, bin, 0o775)
			return bin
		}},
		{"others may write its directory", func(t *testing.T, _, bin string, _ *binaryRule) string {
			chmod(t, filepath.Dir(bin), 0o757)
			return bin
		}},
		{"others may write a directory above", func(t *testing.T, dir, bin string, _ *binaryRule) string {
			chmod(t, dir, 0o777)
			return bin
		}},
		{"another owner", func(_ *testing.T, _, bin string, rule *binaryRule) string {
			rule.uid++
			return bin
		}},
		{"a link in a writable directory", func(t *testing.T, dir, bin string, _ *binaryRule) string {
			w := mkdir(t, filepath.Join(dir, "writable"), 0o777)
			link := filepath.Join(w, "rpmgr")
			if err := os.Symlink(bin, link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
		{"a link to a binary in a writable directory", func(t *testing.T, dir, bin string, _ *binaryRule) string {
			w := mkdir(t, filepath.Join(dir, "writable"), 0o777)
			other := filepath.Join(w, "rpmgr")
			if err := os.Rename(bin, other); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, bin); err != nil {
				t.Fatal(err)
			}
			return bin
		}},
		{"a link to the verified binary", func(t *testing.T, dir, bin string, _ *binaryRule) string {
			link := filepath.Join(filepath.Dir(bin), "rpmgr-link")
			if err := os.Symlink(bin, link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
		{"a directory link into a writable directory", func(t *testing.T, dir, bin string, _ *binaryRule) string {
			w := mkdir(t, filepath.Join(dir, "writable"), 0o777)
			if err := os.Rename(bin, filepath.Join(w, "rpmgr")); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(filepath.Dir(bin), "lib")
			if err := os.Symlink(w, link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, "rpmgr")
		}},
		{"a relative path", func(_ *testing.T, _, _ string, _ *binaryRule) string { return "bin/rpmgr" }},
		{"a directory", func(_ *testing.T, _, bin string, _ *binaryRule) string { return filepath.Dir(bin) }},
		{"a missing binary", func(_ *testing.T, _, bin string, _ *binaryRule) string { return bin + ".new" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, bin, rule := installed(t)
			l, f := listener(t)
			cfg, res := config(t, tc.setup(t, dir, bin, rule), rule, "ready", addrsEnv+"="+l.Addr().String())
			c, err := Start(context.Background(), cfg, []Socket{{Name: "https", File: f}})
			if c != nil || !errors.Is(err, ErrRefused) {
				t.Fatalf("Start = %v, %v; want ErrRefused", c, err)
			}
			if _, err := os.Stat(res); err == nil {
				t.Error("the binary was started")
			}
			stillServes(t, l)
		})
	}
	t.Run("the verified binary", func(t *testing.T) {
		_, bin, rule := installed(t)
		l, f := listener(t)
		cfg, _ := config(t, bin, rule, "ready", addrsEnv+"="+l.Addr().String())
		c, err := Start(context.Background(), cfg, []Socket{{Name: "https", File: f}})
		if err != nil {
			t.Fatal(err)
		}
		if got := greeting(t, l.Addr()); got != "gen 2" {
			t.Errorf("greeting %q", got)
		}
		<-c.Exited()
	})
}

func chmod(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o755) }) //nolint:gosec // G302: back as installed
}

func mkdir(t *testing.T, p string, mode os.FileMode) string {
	t.Helper()
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	chmod(t, p, mode)
	return p
}

// replaced makes the binary at bin a new file by rename, as the updater and the install script do,
// and returns the path the running image then reads in /proc/self/exe.
func replaced(t *testing.T, bin string) string {
	t.Helper()
	b, err := os.ReadFile(bin) //nolint:gosec // G304: the test's copy
	if err != nil {
		t.Fatal(err)
	}
	next := bin + ".new"
	if err := os.WriteFile(next, b, 0o755); err != nil { //nolint:gosec // G306: an executable
		t.Fatal(err)
	}
	if err := os.Rename(next, bin); err != nil {
		t.Fatal(err)
	}
	return bin + deletedSuffix
}

func TestStart_ReplacedBinaryHandsOffFromTheInstalledPath(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed bool // cfg.Installed names the path; else the suffix is stripped
	}{{"the path without the suffix", false}, {"the installed path", true}} {
		t.Run(tc.name, func(t *testing.T) {
			_, bin, rule := installed(t)
			exe := replaced(t, bin)
			l, f := listener(t)
			cfg, _ := config(t, "", rule, "ready", addrsEnv+"="+l.Addr().String())
			cfg.exe = func() (string, error) { return exe, nil }
			if tc.installed {
				cfg.Installed = bin
				cfg.exe = func() (string, error) { return "/gone/rpmgr" + deletedSuffix, nil }
			}
			c, err := Start(context.Background(), cfg, []Socket{{Name: "https", File: f}})
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			if got := greeting(t, l.Addr()); got != "gen 2" {
				t.Errorf("greeting %q", got)
			}
			<-c.Exited()
		})
	}
}

func TestStart_ReplacedBinaryNotInstalledIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir, bin string, rule *binaryRule) (exe, installed string)
	}{
		{"nothing at the path", func(t *testing.T, _, bin string, _ *binaryRule) (string, string) {
			if err := os.Remove(bin); err != nil {
				t.Fatal(err)
			}
			return bin + deletedSuffix, ""
		}},
		{"an installed path that is missing", func(_ *testing.T, _, bin string, _ *binaryRule) (string, string) {
			return "/gone/rpmgr" + deletedSuffix, bin + ".missing"
		}},
		{"a writable installed binary", func(t *testing.T, _, bin string, _ *binaryRule) (string, string) {
			chmod(t, bin, 0o777)
			return "/gone/rpmgr" + deletedSuffix, bin
		}},
		{"an installed binary of another owner", func(_ *testing.T, _, bin string, rule *binaryRule) (string, string) {
			rule.uid++
			return bin + deletedSuffix, bin
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, bin, rule := installed(t)
			exe, inst := tc.setup(t, dir, bin, rule)
			l, f := listener(t)
			cfg, res := config(t, "", rule, "ready", addrsEnv+"="+l.Addr().String())
			cfg.exe, cfg.Installed = func() (string, error) { return exe, nil }, inst
			c, err := Start(context.Background(), cfg, []Socket{{Name: "https", File: f}})
			if c != nil || !errors.Is(err, ErrRefused) {
				t.Fatalf("Start = %v, %v; want ErrRefused", c, err)
			}
			if _, err := os.Stat(res); err == nil {
				t.Error("a binary was started")
			}
			stillServes(t, l)
		})
	}
}
