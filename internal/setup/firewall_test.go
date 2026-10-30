// SPDX-License-Identifier: Apache-2.0

package setup_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/firewall"
	"github.com/felix-homelab/rpmgr/internal/setup"
)

func gatewayWithFirewall() setup.Values {
	return setup.Values{Role: setup.Gateway, ControllerURL: "https://panel.example.com", Pin: "sha256:" + strings.Repeat("A", 43) + "=",
		Firewall: "ufw", FirewallRange: "20000-29999"}
}

// firewallHost is a host with a ufw, whose GiveTo calls are recorded.
func firewallHost(t *testing.T, f *fakeHost, ufw bool, given *[]string) setup.Host {
	t.Helper()
	h := newHost(t, f)
	h.HasUfw = func() bool { return ufw }
	h.GiveTo = func(path string) error { *given = append(*given, path); return nil }
	return h
}

func readBounds(t *testing.T, h setup.Host) firewall.Bounds {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(h.Paths.Etc, "firewall.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b firewall.Bounds
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields() // the helper refuses an unknown field
	if err := dec.Decode(&b); err != nil {
		t.Fatalf("the helper cannot read the bounds %q: %v", raw, err)
	}
	return b
}

func firewallCommands() [][]string {
	return [][]string{{"systemctl", "daemon-reload"}, {"systemctl", "enable", "rpmgr-firewall.service"}, {"systemctl", "enable", "--now", "rpmgr-firewall.path"}}
}

// TestPlan_Firewall (D152): `setup --firewall ufw` on a gateway writes the key into the boot file
// and the bounds the helper reads from the boot file's listeners and the maximum range, makes the
// directory the gateway writes in for the service user, and installs and enables the units.
func TestPlan_Firewall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the firewall helper is Linux's")
	}
	f := &fakeHost{}
	var given []string
	h := firewallHost(t, f, true, &given)
	v := gatewayWithFirewall()
	v.Token = newToken(t)
	v.ListenTCP, v.ListenUDP, v.ListenHTTP = ":8443", ":8444", ":8080"
	p, err := setup.New(v, h)
	if err != nil {
		t.Fatal(err)
	}
	if steps := strings.Join(p.Steps(), "\n"); !strings.Contains(steps, "hand ufw to rpmgr") || !strings.Contains(steps, "rpmgr-firewall.path") {
		t.Errorf("no firewall step in\n%s", steps)
	}
	if sum := p.Summary(); !slices.ContainsFunc(sum, func(kv [2]string) bool { return kv[0] == "firewall" && strings.Contains(kv[1], "20000-29999") }) {
		t.Errorf("summary %v does not show the firewall", sum)
	}
	r, err := p.Run(context.Background(), nil)
	if err != nil {
		t.Fatalf("run: %v (wrote %v)", err, r.Written)
	}
	if r.FirewallNote != "" {
		t.Errorf("a note %q on a host with ufw", r.FirewallNote)
	}
	var cfg config.Gateway
	if err := config.Load(filepath.Join(h.Paths.Etc, "gateway.yaml"), &cfg); err != nil || !cfg.Firewall.On() || cfg.Firewall.MaxRange != "20000-29999" {
		t.Errorf("boot file firewall %+v, %v", cfg.Firewall, err)
	}
	b := readBounds(t, h)
	wantListeners := []firewall.Listener{{Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 8080}, {Protocol: "udp", Port: 8444}}
	if b.Version != 1 || b.Backend != "ufw" || !slices.Equal(b.Listeners, wantListeners) || b.MaxRange == nil || *b.MaxRange != (firewall.PortRange{From: 20000, To: 29999}) {
		t.Errorf("bounds %+v, want the boot file's listeners %v and 20000-29999", b, wantListeners)
	}
	if fi, err := os.Stat(filepath.Join(h.Paths.Etc, "firewall.json")); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("bounds file %v, %v: root's, 0644", fi, err)
	}
	dir := filepath.Join(h.Paths.Lib, "firewall")
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o750 || !slices.Contains(given, dir) {
		t.Errorf("firewall directory %v, %v, given to the service user: %v", fi, err, given)
	}
	for _, u := range []string{"rpmgr-firewall.path", "rpmgr-firewall.service"} {
		if raw, err := os.ReadFile(filepath.Join(h.Paths.Units, u)); err != nil || !strings.Contains(string(raw), "rpmgr-firewall") {
			t.Errorf("unit %s: %q, %v", u, raw, err)
		}
	}
	if svc, _ := os.ReadFile(filepath.Join(h.Paths.Units, "rpmgr-firewall.service")); !strings.Contains(string(svc), "ExecStart="+h.Paths.Bin+" firewall apply") {
		t.Errorf("service %q", svc)
	}
	if !containsRun(f.commands, firewallCommands()) {
		t.Errorf("commands %q lack %q in order", f.commands, firewallCommands())
	}
}

// containsRun reports whether want is a subsequence of got.
func containsRun(got, want [][]string) bool {
	i := 0
	for _, c := range got {
		if i < len(want) && slices.Equal(c, want[i]) {
			i++
		}
	}
	return i == len(want)
}

// A host without ufw is no failure: setup finishes, the bounds are written for the day ufw is
// installed, and the result says the firewall will show as failed until then.
func TestPlan_FirewallWithoutUfw(t *testing.T) {
	f := &fakeHost{}
	var given []string
	h := firewallHost(t, f, false, &given)
	v := gatewayWithFirewall()
	v.Token = newToken(t)
	p, err := setup.New(v, h)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.FirewallNote, "ufw is not installed") {
		t.Errorf("note %q", r.FirewallNote)
	}
	if b := readBounds(t, h); b.Backend != "ufw" {
		t.Errorf("bounds %+v", b)
	}
}

// Running setup again with --force writes the same files and the same commands: nothing piles up.
func TestPlan_FirewallRerunIsIdempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the firewall helper is Linux's")
	}
	f := &fakeHost{}
	var given []string
	h := firewallHost(t, f, true, &given)
	run := func(force bool) {
		v := gatewayWithFirewall()
		v.Token, v.Force = newToken(t), force
		p, err := setup.New(v, h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Run(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	}
	run(false)
	read := func() (string, string, string) {
		b, _ := os.ReadFile(filepath.Join(h.Paths.Etc, "firewall.json"))
		p, _ := os.ReadFile(filepath.Join(h.Paths.Units, "rpmgr-firewall.path"))
		s, _ := os.ReadFile(filepath.Join(h.Paths.Units, "rpmgr-firewall.service"))
		return string(b), string(p), string(s)
	}
	b1, p1, s1 := read()
	n := len(f.commands)
	run(true)
	if b2, p2, s2 := read(); b1 != b2 || p1 != p2 || s1 != s2 {
		t.Error("a second run changed the bounds or the units")
	}
	var again [][]string
	for _, c := range f.commands[n:] {
		if len(c) > 2 && strings.Contains(c[2], "firewall") || len(c) > 3 && strings.Contains(c[3], "firewall") {
			again = append(again, c)
		}
	}
	if len(again) != 2 { // enable and enable --now, as the first run did
		t.Errorf("second run commands for the firewall: %q", again)
	}
	entries, _ := os.ReadDir(h.Paths.Etc)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".firewall.json") {
			t.Errorf("a temporary file %s was left behind", e.Name())
		}
	}
}

// Without --firewall setup writes no bounds, no directory and no unit, runs no command for it,
// and the boot file has no firewall key: the host stays as it was.
func TestPlan_FirewallOptOutDoesNothing(t *testing.T) {
	f := &fakeHost{}
	var given []string
	h := firewallHost(t, f, true, &given)
	p, err := setup.New(setup.Values{Role: setup.Gateway, ControllerURL: "https://panel.example.com", Pin: "sha256:" + strings.Repeat("A", 43) + "=",
		Token: newToken(t)}, h)
	if err != nil {
		t.Fatal(err)
	}
	if steps := strings.Join(p.Steps(), "\n"); strings.Contains(steps, "ufw") || strings.Contains(steps, "firewall") {
		t.Errorf("steps mention the firewall:\n%s", steps)
	}
	if _, err := p.Run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(h.Paths.Etc, "firewall.json"), filepath.Join(h.Paths.Lib, "firewall"),
		filepath.Join(h.Paths.Units, "rpmgr-firewall.path"), filepath.Join(h.Paths.Units, "rpmgr-firewall.service")} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists: %v", path, err)
		}
	}
	if boot, _ := os.ReadFile(filepath.Join(h.Paths.Etc, "gateway.yaml")); strings.Contains(string(boot), "firewall") {
		t.Errorf("boot file %q", boot)
	}
	for _, c := range f.commands {
		if strings.Contains(strings.Join(c, " "), "firewall") {
			t.Errorf("command %q", c)
		}
	}
	if slices.Contains(given, filepath.Join(h.Paths.Lib, "firewall")) {
		t.Errorf("gave the firewall directory to the service user: %v", given)
	}
}

func TestPlan_FirewallWithoutUnit(t *testing.T) {
	f := &fakeHost{}
	var given []string
	h := firewallHost(t, f, true, &given)
	v := gatewayWithFirewall()
	v.Token, v.NoUnit = newToken(t), true
	p, err := setup.New(v, h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if b := readBounds(t, h); b.Backend != "ufw" {
		t.Errorf("bounds %+v", b)
	}
	if _, err := os.Stat(filepath.Join(h.Paths.Units, "rpmgr-firewall.path")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("--no-unit installed the firewall unit: %v", err)
	}
	if len(f.commands) != 0 {
		t.Errorf("--no-unit ran %q", f.commands)
	}
}

// A failed unit step reports the cause and what setup wrote, for cleaning up.
func TestPlan_FirewallFailureIsReported(t *testing.T) {
	f := &fakeHost{}
	var given []string
	h := firewallHost(t, f, true, &given)
	h.GiveTo = func(path string) error {
		if filepath.Base(path) == "firewall" {
			return errors.New("no such user")
		}
		return nil
	}
	v := gatewayWithFirewall()
	v.Token = newToken(t)
	p, err := setup.New(v, h)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Run(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "no such user") || !strings.Contains(err.Error(), "hand ufw to rpmgr") {
		t.Fatalf("run: %v", err)
	}
	if !slices.Contains(r.Written, filepath.Join(h.Paths.Etc, "firewall.json")) {
		t.Errorf("written %v lacks the bounds file", r.Written)
	}
}

func TestNew_FirewallRefuses(t *testing.T) {
	f := &fakeHost{}
	var given []string
	h := firewallHost(t, f, true, &given)
	for name, tc := range map[string]struct {
		change func(v *setup.Values)
		want   string
	}{
		"another firewall":       {func(v *setup.Values) { v.Firewall = "nftables" }, "ufw"},
		"a range without ufw":    {func(v *setup.Values) { v.Firewall = "" }, "needs --firewall ufw"},
		"a reversed range":       {func(v *setup.Values) { v.FirewallRange = "30000-20000" }, "max_range"},
		"a range past 65535":     {func(v *setup.Values) { v.FirewallRange = "20000-70000" }, "max_range"},
		"a range without a dash": {func(v *setup.Values) { v.FirewallRange = "20000" }, "max_range"},
		"a connector":            {func(v *setup.Values) { v.Role = setup.Connector }, "gateway's or an all-in-one's"},
		"a controller":           {func(v *setup.Values) { v.Role = setup.Controller; v.PublicURL = "https://panel.example.com" }, "gateway's or an all-in-one's"},
	} {
		v := gatewayWithFirewall()
		v.Token = newToken(t)
		tc.change(&v)
		if _, err := setup.New(v, h); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

// TestInstallFirewall (D152): what the install script runs once the boot file names the firewall:
// the bounds come from the boot file of a gateway or an all-in-one, a boot file without the key or
// another role is refused, and a missing boot file is an error.
func TestInstallFirewall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the firewall helper is Linux's")
	}
	f := &fakeHost{}
	var given []string
	h := firewallHost(t, f, true, &given)
	ctx := context.Background()
	boot := func(role, body string) {
		write(t, filepath.Join(h.Paths.Etc, role+".yaml"), body)
	}
	if _, err := setup.InstallFirewall(ctx, h, "gateway", false); err == nil {
		t.Error("a host without a boot file was accepted")
	}
	boot("gateway", "version: 1\ncontroller: {endpoints: [https://panel.example.com]}\n")
	if _, err := setup.InstallFirewall(ctx, h, "gateway", false); err == nil || !strings.Contains(err.Error(), "firewall.backend: ufw") {
		t.Errorf("a boot file without the key: %v", err)
	}
	for _, role := range []string{"connector", "controller", "router"} {
		if _, err := setup.InstallFirewall(ctx, h, role, false); err == nil || !strings.Contains(err.Error(), "no firewall to hand") {
			t.Errorf("%s: %v", role, err)
		}
	}
	if _, err := os.Stat(filepath.Join(h.Paths.Etc, "firewall.json")); err == nil {
		t.Fatal("a refused call wrote the bounds")
	}
	boot("gateway", "version: 1\ncontroller: {endpoints: [https://panel.example.com]}\nlisten: {http: \"\", tcp: \":8443\"}\n"+
		"firewall: {backend: ufw, max_range: 20000-20999}\n")
	r, err := setup.InstallFirewall(ctx, h, "gateway", false)
	if err != nil || r.FirewallNote != "" {
		t.Fatalf("gateway: %+v, %v", r, err)
	}
	b := readBounds(t, h)
	if want := []firewall.Listener{{Protocol: "tcp", Port: 8443}, {Protocol: "udp", Port: 443}}; !slices.Equal(b.Listeners, want) || b.MaxRange.To != 20999 {
		t.Errorf("bounds %+v, want listeners %v: no port 80 when listen.http is off", b, want)
	}
	if len(f.commands) != 0 {
		t.Errorf("commands %q: the install script enables the units, not the binary", f.commands)
	}
	if svc, err := os.ReadFile(filepath.Join(h.Paths.Units, "rpmgr-firewall.service")); err != nil || !strings.Contains(string(svc), "firewall apply") {
		t.Errorf("service %q, %v", svc, err)
	}
	boot("all-in-one", "version: 1\npublic_url: https://panel.example.com\nfirewall: {backend: ufw}\n")
	if _, err := setup.InstallFirewall(ctx, h, "all-in-one", true); err != nil {
		t.Fatal(err)
	}
	if b := readBounds(t, h); b.MaxRange != nil || len(b.Listeners) != 3 {
		t.Errorf("all-in-one bounds %+v: three listeners and no range", b)
	}
	h.IsRoot = func() bool { return false }
	if _, err := setup.InstallFirewall(ctx, h, "gateway", false); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("without root: %v", err)
	}
}
