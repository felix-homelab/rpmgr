// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"context"
	"errors"
	"fmt"
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
		"a zone":            "version: 1\nallow_targets: [{cidr: \"fe80::1%eth0\", ports: [80]}]\n",
		"unknown entry key": "version: 1\nallow_targets: [{cidr: 10.0.0.0/24, port: 80}]\n",
		"a list entry":      "version: 1\nallow_targets: [[10.0.0.1]]\n",
		"bad string":        "version: 1\nallow_targets: [\"10.0.0.1:80-\"]\n",
		"IPv6 unbracketed":  "version: 1\nallow_targets: [\"fd00::1:80\"]\n",
		"bad deny cidr":     "version: 1\ndeny_targets: [{cidr: 10.0.0.0/33}]\n",
		"reversed deny":     "version: 1\ndeny_targets: [\"10.0.0.1:500-200\"]\n",
		"relative deny":     "version: 1\ndeny_targets: [{unix: run/app.sock}]\n",
		"deny not a list":   "version: 1\ndeny_targets: 10.0.0.1\n",
		"empty ports":       "version: 1\nallow_targets: [{cidr: 10.0.0.0/8, ports: []}]\n",
		"null ports":        "version: 1\nallow_targets: [{cidr: 10.0.0.0/8, ports: ~}]\n",
		"duplicate cidr":    "version: 1\nallow_targets: [{cidr: 10.0.0.0/8, ports: [80], cidr: 192.168.0.0/16}]\n",
		"duplicate ports":   "version: 1\ndeny_targets: [{cidr: 10.0.0.0/8, ports: [80], ports: [443]}]\n",
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
	<-accepted // the allowed dial above
	current = parse(t, fmt.Sprintf("version: 1\nallow_targets: [127.0.0.1]\ndeny_targets: [\"127.0.0.1:%d\", /run/app.sock]\n", port))
	if _, err := d.DialContext(ctx, "tcp", ln.Addr().String()); !errors.As(err, &blocked) || blocked.Denied == "" {
		t.Fatalf("a denied port: %v", err)
	}
	if _, err := d.DialContext(ctx, "unix", "/run/app.sock"); !errors.As(err, &blocked) || blocked.Denied != "/run/app.sock" {
		t.Fatalf("a denied socket: %v", err)
	}
	select {
	case <-accepted:
		t.Fatal("a denied dial reached the target")
	case <-time.After(100 * time.Millisecond):
	}
}

// FuzzPolicy: no input makes Parse panic, and an accepted policy allows the metadata address only
// if the file names it (dotted, or hexadecimal in an IPv4-mapped IPv6 form).
func FuzzPolicy(f *testing.F) {
	f.Add([]byte("version: 1\nallow_targets: [{cidr: 0.0.0.0/0, ports: [\"1-65535\"]}]\n"))
	f.Add([]byte("version: 1\nallow_targets: [{unix: /run/a.sock}]\nauto_update: off\n"))
	f.Add([]byte("version: 1\nallow_targets: [0.0.0.0/0, \"[::/0]:1-65535\"]\ndeny_targets: [10.0.0.1/8, /run/a.sock]\n"))
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

// TestTargets_Syntax (D84): entries are target strings or mappings; a subnet's host bits are
// cleared, an entry without ports allows all of them, and `rpmgr policy show` says so.
func TestTargets_Syntax(t *testing.T) {
	p := parse(t, `version: 1
allow_targets:
  - 127.0.0.1:200-500
  - 10.0.0.1/16
  - "[fd00::/64]:8000-8099"
  - "[2001:db8::7]"
  - {cidr: 192.168.1.9/24}
  - {cidr: 172.16.0.5, ports: [22]}
  - /run/app.sock
`)
	for target, want := range map[string]bool{
		"127.0.0.1:200": true, "127.0.0.1:500": true, "127.0.0.1:199": false, "127.0.0.1:501": false,
		"10.0.255.255:1": true, "10.0.0.0:65535": true, "10.1.0.0:80": false,
		"[fd00::9]:8050": true, "[fd00::9]:8100": false, "[fd00:0:0:1::9]:8050": false,
		"[2001:db8::7]:1": true, "[2001:db8::8]:1": false,
		"192.168.1.200:9": true, "172.16.0.5:22": true, "172.16.0.5:23": false,
	} {
		if allows(p, target) != want {
			t.Errorf("%s: allowed %v, want %v", target, !want, want)
		}
	}
	if !p.AllowsUnix("/run/app.sock") {
		t.Error("the socket string entry")
	}
	got := p.Describe()
	for _, want := range []string{"127.0.0.1/32 ports 200-500", "10.0.0.0/16 all ports", "fd00::/64 ports 8000-8099",
		"2001:db8::7/128 all ports", "192.168.1.0/24 all ports", "172.16.0.5/32 ports 22", "unix /run/app.sock",
		"denied targets, which win over allowed ones: none"} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe lacks %q:\n%s", want, got)
		}
	}
	// A broad subnet without ports still never lets the protected ranges through.
	broad := parse(t, "version: 1\nallow_targets: [0.0.0.0/0, \"[::/0]\"]\n")
	if allows(broad, "169.254.169.254:80") || allows(broad, "[fd00:ec2::254]:80") || !allows(broad, "203.0.113.9:1") {
		t.Error("an all-ports /0 and the protected ranges")
	}
}

// TestDeny (D84): an entry of deny_targets refuses what it matches, whatever allows it, the
// protected ranges' explicit entries included; a deny without ports denies all of them; the refusal
// names the deny entry; a bad deny entry makes the whole file deny everything.
func TestDeny(t *testing.T) {
	p := parse(t, `version: 1
allow_targets:
  - 127.0.0.1:200-500
  - 10.0.0.0/8
  - 169.254.169.254:80
  - /run/app.sock
  - /run/other.sock
deny_targets:
  - 127.0.0.1:345
  - {cidr: 10.9.0.1/16}
  - {cidr: 10.1.0.0/16, ports: ["8000-8999"]}
  - 169.254.0.0/16
  - {unix: /run/other.sock}
`)
	for target, want := range map[string]bool{
		"127.0.0.1:344": true, "127.0.0.1:345": false, "127.0.0.1:346": true,
		"10.8.0.1:22": true, "10.9.200.1:22": false, "10.9.200.1:65535": false,
		"10.1.0.1:7999": true, "10.1.0.1:8000": false, "10.1.0.1:8999": false, "10.1.0.1:9000": true,
		"169.254.169.254:80": false,
	} {
		if allows(p, target) != want {
			t.Errorf("%s: allowed %v, want %v", target, !want, want)
		}
	}
	if !p.AllowsUnix("/run/app.sock") || p.AllowsUnix("/run/other.sock") || p.DeniedByUnix("/run/other.sock") != "/run/other.sock" {
		t.Error("a denied socket")
	}
	var blocked *policy.BlockedError
	if err := p.Check("127.0.0.1:345"); !errors.As(err, &blocked) || blocked.Denied != "127.0.0.1:345" ||
		blocked.Detail() != "127.0.0.1:345 denied by 127.0.0.1:345" || !strings.Contains(err.Error(), "denies 127.0.0.1:345") {
		t.Fatalf("a denied target: %v", err)
	}
	if err := p.Check("10.9.0.7:22"); !errors.As(err, &blocked) || blocked.Denied != "10.9.0.0/16" {
		t.Fatalf("a target a normalised deny subnet refuses: %v", err)
	}
	if err := p.Check("127.0.0.1:600"); !errors.As(err, &blocked) || blocked.Denied != "" || blocked.Detail() != "127.0.0.1:600" ||
		!strings.Contains(err.Error(), "does not allow") {
		t.Fatalf("a target nothing allows: %v", err)
	}
	if d := p.Describe(); !strings.Contains(d, "denied targets, which win over allowed ones:\n  127.0.0.1/32 ports 345\n  10.9.0.0/16 all ports") {
		t.Errorf("Describe:\n%s", d)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nallow_targets: [10.0.0.0/8]\ndeny_targets: [\"10.0.0.1:0\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if bad, err := policy.Load(path); err == nil || bad.Invalid == nil || bad.Allows(netip.MustParseAddr("10.0.0.2"), 80) {
		t.Fatalf("a bad deny entry: %v", err)
	}
}

// TestDeny_HintsRoundTrip: the deny entry a refusal names is a target string parseTarget reads
// back, IPv6 in brackets and with only the port or range that matched, so that the UI's
// `rpmgr policy remove-deny-target` command takes exactly that out.
func TestDeny_HintsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`version: 1
allow_targets: ["0.0.0.0/0", "[::/0]"]
deny_targets:
  - "[fd00::/64]"
  - {cidr: "2001:db8::1"}
  - {cidr: 10.0.0.0/8, ports: [80, "400-500"]}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{"[fd00::9]:22": "[fd00::/64]", "[2001:db8::1]:443": "[2001:db8::1]",
		"10.1.2.3:80": "10.0.0.0/8:80", "10.1.2.3:450": "10.0.0.0/8:400-500"} {
		var blocked *policy.BlockedError
		if err := load(t, path).Check(target); !errors.As(err, &blocked) || blocked.Denied != want || policy.CheckTarget(blocked.Denied) != nil {
			t.Errorf("%s: %v, want the entry %s", target, err, want)
		}
	}
	changed, err := policy.RemoveDenyTarget(path, "10.0.0.0/8:400-500")
	if err != nil || !changed {
		t.Fatalf("removing the hinted range: %v %v", changed, err)
	}
	if p := load(t, path); p.Check("10.1.2.3:450") != nil || p.Check("10.1.2.3:80") == nil {
		t.Fatalf("after removing the range:\n%s", p.Describe())
	}
	for _, target := range []string{"[fd00::/64]", "[2001:db8::1]"} {
		if changed, err := policy.RemoveDenyTarget(path, target); err != nil || !changed {
			t.Errorf("removing the hinted %s: %v %v", target, changed, err)
		}
	}
	if _, err := policy.RemoveDenyTarget(path, "10.1.0.0/16:80"); !errors.Is(err, policy.ErrInRange) ||
		!strings.Contains(err.Error(), "remove that deny entry") || strings.Contains(err.Error(), "deny-target") {
		t.Errorf("a denial inside a broader deny entry: %v", err)
	}
}

// TestParse_AliasesRefused: anchors, aliases and merge keys make the file invalid, naming the line,
// and no edit command touches such a file: an edit would change every alias of a node with it.
func TestParse_AliasesRefused(t *testing.T) {
	for name, src := range map[string]string{
		"an anchor":       "version: 1\nallow_targets:\n  - &web {cidr: 10.0.0.0/8, ports: [80]}\n",
		"an alias":        "version: 1\nx: &v 1\nallow_targets: [{cidr: 10.0.0.0/8, ports: [*v]}]\n",
		"ports anchor":    "version: 1\nallow_targets: [{cidr: 10.0.0.0/8, ports: &p [22]}]\ndeny_targets: [{cidr: 10.9.0.0/16, ports: *p}]\n",
		"a merge key":     "version: 1\n<<: {deny_targets: [10.0.0.0/8]}\nallow_targets: [10.0.0.0/8]\n",
		"a merged entry":  "version: 1\nallow_targets: [{<<: {ports: [80]}, cidr: 10.0.0.0/8}]\n",
		"an anchored doc": "&d\nversion: 1\n",
	} {
		if _, err := policy.Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "anchors, aliases and merge keys are not allowed") ||
			!strings.Contains(err.Error(), "line ") {
			t.Errorf("%s: %v", name, err)
		}
		path := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		for verb, edit := range map[string]func(string, string) (bool, error){"allow": policy.AllowTarget, "remove": policy.RemoveTarget,
			"deny": policy.DenyTarget, "remove-deny": policy.RemoveDenyTarget} {
			if _, err := edit(path, "10.0.0.1:22"); err == nil || !strings.Contains(err.Error(), "anchors, aliases and merge keys") {
				t.Errorf("%s, %s: %v", name, verb, err)
			}
		}
		if b, _ := os.ReadFile(path); string(b) != src {
			t.Errorf("%s: the file changed:\n%s", name, b)
		}
	}
}
