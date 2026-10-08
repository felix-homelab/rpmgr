// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/policy"
)

func parse(t *testing.T, s string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func allows(p *policy.Policy, hostport string) bool { return p.Check(hostport) == nil }

// TestPolicy_MetadataAlwaysDenied: cloud metadata and link-local targets, also in their
// IPv4-mapped forms, are denied inside an allowed CIDR and allowed only when listed explicitly.
func TestPolicy_MetadataAlwaysDenied(t *testing.T) {
	broad := parse(t, `version: 1
allow_targets:
  - {cidr: 0.0.0.0/0, ports: ["1-65535"]}
  - {cidr: "::/0", ports: ["1-65535"]}
`)
	for _, target := range []string{"169.254.169.254:80", "[fd00:ec2::254]:80", "100.100.100.200:80", "[fe80::1]:80",
		"169.254.1.1:443", "[::ffff:169.254.169.254]:80", "[::ffff:100.100.100.200]:80"} {
		if allows(broad, target) {
			t.Errorf("%s allowed by a broad CIDR", target)
		}
	}
	for _, target := range []string{"10.0.0.5:5432", "[2001:db8::1]:443", "100.100.100.201:80"} {
		if !allows(broad, target) {
			t.Errorf("%s not allowed by a broad CIDR", target)
		}
	}
	explicit := parse(t, `version: 1
allow_targets:
  - {cidr: 169.254.169.254/32, ports: [80]}
  - {cidr: "fd00:ec2::254/128", ports: [80]}
  - {cidr: 100.100.100.200/32, ports: [80]}
  - {cidr: "fe80::/64", ports: [80]}
`)
	for _, target := range []string{"169.254.169.254:80", "[::ffff:169.254.169.254]:80", "[fd00:ec2::254]:80",
		"100.100.100.200:80", "[fe80::1]:80"} {
		if !allows(explicit, target) {
			t.Errorf("%s not allowed although listed", target)
		}
	}
	if allows(explicit, "169.254.169.254:443") || allows(explicit, "169.254.169.253:80") {
		t.Error("an explicit target allowed another port or address")
	}
	ula := parse(t, "version: 1\nallow_targets: [{cidr: \"fd00::/8\", ports: [80]}]\n")
	if allows(ula, "[fd00:ec2::254]:80") || !allows(ula, "[fd00::1]:80") {
		t.Error("a ULA range must not cover the metadata address")
	}
}

// TestPolicy_AutoUpdateAndChannelDefaults (connector part): without a file the connector allows no
// target and the policy says auto_update auto and update_channel stable; a file without the keys
// says the same; other values are refused. (The updater's part is 11.4 and Phase 2.)
func TestPolicy_AutoUpdateAndChannelDefaults(t *testing.T) {
	p, err := policy.Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if p.AutoUpdate != policy.AutoUpdateAuto || p.UpdateChannel != policy.ChannelStable {
		t.Fatalf("defaults %q %q", p.AutoUpdate, p.UpdateChannel)
	}
	for _, target := range []string{"127.0.0.1:8080", "[::1]:22", "10.0.0.1:443"} {
		if allows(p, target) {
			t.Errorf("%s allowed without a policy file", target)
		}
	}
	if p.AllowsUnix("/run/app.sock") {
		t.Error("a unix socket allowed without a policy file")
	}
	q := parse(t, "version: 1\n")
	if q.AutoUpdate != policy.AutoUpdateAuto || q.UpdateChannel != policy.ChannelStable {
		t.Fatalf("a file without the keys: %q %q", q.AutoUpdate, q.UpdateChannel)
	}
	q = parse(t, "version: 1\nauto_update: off\nupdate_channel: prerelease\n")
	if q.AutoUpdate != policy.AutoUpdateOff || q.UpdateChannel != policy.ChannelPrerelease {
		t.Fatalf("explicit values: %q %q", q.AutoUpdate, q.UpdateChannel)
	}
}

func TestParse_Refused(t *testing.T) {
	for name, src := range map[string]string{
		"no version":        "allow_targets: []\n",
		"version 2":         "version: 2\n",
		"unknown key":       "version: 1\nallow_everything: true\n",
		"bad auto_update":   "version: 1\nauto_update: always\n",
		"bad channel":       "version: 1\nupdate_channel: nightly\n",
		"bad cidr":          "version: 1\nallow_targets: [{cidr: 10.0.0.0/33, ports: [80]}]\n",
		"host bits":         "version: 1\nallow_targets: [{cidr: 10.0.0.1/24, ports: [80]}]\n",
		"no ports":          "version: 1\nallow_targets: [{cidr: 10.0.0.0/24}]\n",
		"port 0":            "version: 1\nallow_targets: [{cidr: 10.0.0.0/24, ports: [0]}]\n",
		"port 65536":        "version: 1\nallow_targets: [{cidr: 10.0.0.0/24, ports: [65536]}]\n",
		"reversed range":    "version: 1\nallow_targets: [{cidr: 10.0.0.0/24, ports: [\"90-80\"]}]\n",
		"range to 65536":    "version: 1\nallow_targets: [{cidr: 10.0.0.0/24, ports: [\"80-65536\"]}]\n",
		"not a port":        "version: 1\nallow_targets: [{cidr: 10.0.0.0/24, ports: [http]}]\n",
		"relative socket":   "version: 1\nallow_targets: [{unix: run/app.sock}]\n",
		"unclean socket":    "version: 1\nallow_targets: [{unix: /run/../etc/app.sock}]\n",
		"socket with ports": "version: 1\nallow_targets: [{unix: /run/app.sock, ports: [80]}]\n",
		"not YAML":          "version: [1\n",
	} {
		if _, err := policy.Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPorts(t *testing.T) {
	p := parse(t, "version: 1\nallow_targets: [{cidr: 192.168.10.0/24, ports: [1, 65535, \"8000-8099\", \"443\"]}]\n")
	for target, want := range map[string]bool{
		"192.168.10.5:1": true, "192.168.10.5:65535": true, "192.168.10.5:8000": true, "192.168.10.5:8099": true,
		"192.168.10.5:443": true, "192.168.10.5:7999": false, "192.168.10.5:8100": false, "192.168.10.5:2": false,
		"192.168.11.5:443": false,
	} {
		if allows(p, target) != want {
			t.Errorf("%s: allowed %v, want %v", target, !want, want)
		}
	}
	unix := parse(t, "version: 1\nallow_targets: [{unix: /run/app/app.sock}]\n")
	if !unix.AllowsUnix("/run/app/app.sock") || unix.AllowsUnix("/run/app/other.sock") {
		t.Error("unix sockets")
	}
	if err := p.Check("not-an-address"); !errors.Is(err, policy.ErrNotIP) {
		t.Errorf("a name instead of an address: %v", err)
	}
}

// TestLoad: a file that does not parse, or that others may write, denies everything and says why.
func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	allowAll := "version: 1\nallow_targets: [{cidr: 10.0.0.0/8, ports: [\"1-65535\"]}]\n"
	good, err := policy.Load(write("good.yaml", allowAll, 0o644))
	if err != nil || !allows(good, "10.1.2.3:80") {
		t.Fatalf("a valid file: %v", err)
	}
	for name, path := range map[string]string{
		"invalid":          write("bad.yaml", "version: 1\nallow_targets: nope\n", 0o644),
		"group writable":   write("group.yaml", allowAll, 0o664),
		"world writable":   write("world.yaml", allowAll, 0o646),
		"is a directory":   dir,
		"unreadable later": write("ok.yaml", allowAll, 0o000),
	} {
		p, err := policy.Load(path)
		if name == "unreadable later" && os.Geteuid() == 0 {
			continue // root reads anything
		}
		if err == nil || p.Invalid == nil || allows(p, "10.1.2.3:80") {
			t.Errorf("%s: err %v, still allows", name, err)
		}
		if p.AutoUpdate != policy.AutoUpdateAuto {
			t.Errorf("%s: auto_update %q", name, p.AutoUpdate)
		}
	}
}

// TestControl checks at dial time on the address actually dialled: a name is checked as what it
// resolves to now, which defeats DNS rebinding, and a refused dial never reaches the target.
func TestControl(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()
	port := netip.MustParseAddrPort(ln.Addr().String()).Port()
	current := parse(t, "version: 1\nallow_targets: [{cidr: 192.0.2.0/24, ports: [\"1-65535\"]}]\n")
	d := net.Dialer{Timeout: time.Second, Control: policy.Control(func() *policy.Policy { return current })}
	ctx := context.Background()
	// The name was allowed when it pointed at 192.0.2.x; it now resolves to loopback.
	_, err = d.DialContext(ctx, "tcp4", net.JoinHostPort("localhost", strconv.Itoa(int(port))))
	var blocked *policy.BlockedError
	if !errors.As(err, &blocked) || blocked.Target != netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String() {
		t.Fatalf("a name that resolves to a forbidden address: %v", err)
	}
	select {
	case <-accepted:
		t.Fatal("a refused dial reached the target")
	case <-time.After(100 * time.Millisecond):
	}
	current = parse(t, "version: 1\nallow_targets: [{cidr: 127.0.0.1/32, ports: [\"1-65535\"]}]\n")
	c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("an allowed dial: %v", err)
	}
	_ = c.Close()
	if _, err := d.DialContext(ctx, "unix", "/run/nothing.sock"); !errors.As(err, &blocked) {
		t.Fatalf("a unix socket not in the policy: %v", err)
	}
}

// FuzzPolicy: no input makes Parse panic, and an accepted policy allows the metadata address only
// if the file names it (dotted, or hexadecimal in an IPv4-mapped IPv6 form).
func FuzzPolicy(f *testing.F) {
	f.Add([]byte("version: 1\nallow_targets: [{cidr: 0.0.0.0/0, ports: [\"1-65535\"]}]\n"))
	f.Add([]byte("version: 1\nallow_targets: [{unix: /run/a.sock}]\nauto_update: off\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		p, err := policy.Parse(in)
		if err != nil {
			return
		}
		lower := strings.ToLower(string(in))
		if p.Allows(netip.MustParseAddr("169.254.169.254"), 80) && !strings.Contains(lower, "169.254") && !strings.Contains(lower, "a9fe") {
			t.Fatalf("metadata allowed by %q", in)
		}
	})
}
