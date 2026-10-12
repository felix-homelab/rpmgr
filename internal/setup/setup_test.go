// SPDX-License-Identifier: Apache-2.0

package setup_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/setup"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// fakeHost is a host in a temporary directory: it records the commands setup runs and enrolls
// nowhere.
type fakeHost struct {
	mu       sync.Mutex
	commands [][]string
	enrolled []agent.EnrollOptions
	ready    []string
	notReady error // what Ready returns
}

func newHost(t *testing.T, f *fakeHost) setup.Host {
	t.Helper()
	d := t.TempDir()
	bin := filepath.Join(d, "rpmgr")
	write(t, bin, "#!/bin/sh\n")
	if err := os.Chmod(bin, 0o755); err != nil { //nolint:gosec // G302: the fake binary must be executable
		t.Fatal(err)
	}
	return setup.Host{
		Paths: setup.Paths{Etc: filepath.Join(d, "etc"), Lib: filepath.Join(d, "lib"), Units: filepath.Join(d, "units"), Bin: bin},
		Run: func(_ context.Context, name string, args ...string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.commands = append(f.commands, append([]string{name}, args...))
			return nil
		},
		UserExists:     func() bool { return true },
		GiveTo:         func(string) error { return nil },
		IsRoot:         func() bool { return true },
		SystemdVersion: func() int { return 255 },
		Enroll: func(_ context.Context, o agent.EnrollOptions) (agent.Identity, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.enrolled = append(f.enrolled, o)
			if err := os.MkdirAll(filepath.Join(o.IdentityDir), 0o700); err != nil {
				return agent.Identity{}, err
			}
			return agent.Identity{AgentID: "con_01TEST", Kind: "connector"}, nil
		},
		Ready: func(_ context.Context, addr string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.ready = append(f.ready, addr)
			return f.notReady
		},
		PortFree: func(string) bool { return true },
	}
}

func newToken(t *testing.T) string {
	t.Helper()
	tok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestChecks: the field checks the form and the flags share refuse what the roles would refuse.
func TestChecks(t *testing.T) {
	for name, err := range map[string]error{
		"http URL":            setup.CheckControllerURL("http://panel.example.com"),
		"URL with a path":     setup.CheckControllerURL("https://panel.example.com/ui"),
		"URL without a host":  setup.CheckControllerURL("https://"),
		"short pin":           setup.CheckPin("sha256:abc"),
		"pin without prefix":  setup.CheckPin("abc"),
		"mistyped token":      setup.CheckToken("rpmgr_enr_0123"),
		"target without port": setup.CheckTarget("10.0.0.5"),
		"relative socket":     setup.CheckTarget("run/app.sock"),
		"address":             setup.CheckAddr("443", false),
		"off where it is not": setup.CheckAddr("off", false),
		"ftp proxy":           setup.CheckProxy("ftp://proxy:21"),
		"proxy without host":  setup.CheckProxy("http://"),
		"role":                setup.CheckRole("router"),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, err := range map[string]error{
		"URL":         setup.CheckControllerURL("https://panel.example.com:8443/"),
		"pin":         setup.CheckPin(pin(t)),
		"IPv6 target": setup.CheckTarget("[fd00::5]:8080"),
		"token":       setup.CheckToken(newToken(t)),
		"target":      setup.CheckTarget("10.0.0.5:8080"),
		"socket":      setup.CheckTarget("/run/app.sock"),
		"http off":    setup.CheckAddr("off", true),
		"socks proxy": setup.CheckProxy("socks5://proxy:1080"),
		"no proxy":    setup.CheckProxy(""),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestNew_Refuses: a plan is refused, with every reason, for wrong values, without root, for a boot
// file or installation setup must not replace, and for what the host cannot do.
func TestNew_Refuses(t *testing.T) {
	f := &fakeHost{}
	gw := setup.Values{Role: setup.Gateway, ControllerURL: "https://panel.example.com", Pin: pin(t), Token: newToken(t)}
	with := func(change func(v *setup.Values)) setup.Values {
		v := gw
		change(&v)
		return v
	}
	cases := map[string]struct {
		v    setup.Values
		host func(h *setup.Host)
		want string
	}{
		"no role":           {setup.Values{}, nil, "role"},
		"agent values":      {setup.Values{Role: setup.Gateway, ControllerURL: "https://panel.example.com", Pin: "x", Token: "y"}, nil, "CA pin"},
		"wrong token":       {with(func(v *setup.Values) { v.Token = "y" }), nil, "token"},
		"gateway targets":   {with(func(v *setup.Values) { v.AllowTargets = []string{"10.0.0.5:80"} }), nil, "connector's"},
		"connector listens": {with(func(v *setup.Values) { v.Role, v.ListenTCP = setup.Connector, ":443" }), nil, "no listen.tcp"},
		"bad target":        {with(func(v *setup.Values) { v.Role, v.AllowTargets = setup.Connector, []string{"10.0.0.5"} }), nil, "allowed target"},
		"bad address":       {with(func(v *setup.Values) { v.ListenAdmin = "7382" }), nil, "listen.admin"},
		"not root":          {gw, func(h *setup.Host) { h.IsRoot = func() bool { return false } }, "as root"},
		"no systemd":        {gw, func(h *setup.Host) { h.SystemdVersion = func() int { return 0 } }, "--no-unit"},
		"no binary":         {gw, func(h *setup.Host) { h.Paths.Bin = filepath.Join(h.Paths.Lib, "rpmgr") }, "install the binary"},
		"admin taken":       {gw, func(h *setup.Host) { h.PortFree = func(string) bool { return false } }, "--listen-admin"},
	}
	for name, c := range cases {
		h := newHost(t, f)
		if c.host != nil {
			c.host(&h)
		}
		if _, err := setup.New(c.v, h); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, c.want)
		}
	}
	h := newHost(t, f)
	h.SystemdVersion = func() int { return 0 }
	h.Paths.Bin = ""
	if _, err := setup.New(with(func(v *setup.Values) { v.NoUnit = true }), h); err != nil {
		t.Errorf("without a unit, systemd and the binary are not needed: %v", err)
	}

	// Existing files: the boot file and the identity only with --force.
	h = newHost(t, f)
	write(t, filepath.Join(h.Paths.Etc, "gateway.yaml"), "version: 1\n")
	if _, err := setup.New(gw, h); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("an existing boot file: %v", err)
	}
	if _, err := setup.New(with(func(v *setup.Values) { v.Force = true }), h); err != nil {
		t.Errorf("an existing boot file with --force: %v", err)
	}
	conn := with(func(v *setup.Values) { v.Role = setup.Connector })
	write(t, filepath.Join(h.Paths.Lib, "identity", agent.ChainFile), "")
	if _, err := setup.New(conn, h); err == nil || !strings.Contains(err.Error(), "enrolled already") {
		t.Errorf("an existing identity: %v", err)
	}
}

// TestPlan_Connector: a connector enrolls through `rpmgr enroll`'s code with the token setup never
// shows, then writes its boot file, its connector-local policy and its proxy drop-in, and installs
// its unit without a credential.
func TestPlan_Connector(t *testing.T) {
	f := &fakeHost{}
	h := newHost(t, f)
	tok := newToken(t)
	p, err := setup.New(setup.Values{Role: setup.Connector, ControllerURL: "https://panel.example.com/", Pin: pin(t), Token: " " + tok + "\n",
		AllowTargets: []string{"10.0.0.5:8080", "/run/app.sock"}, Proxy: "http://proxy.lan:3128"}, h)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range p.Summary() {
		if strings.Contains(kv[1], tok) {
			t.Fatalf("the summary shows the token: %q", kv)
		}
	}
	r, err := p.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.enrolled) != 1 || f.enrolled[0].Token != tok || f.enrolled[0].IdentityDir != filepath.Join(h.Paths.Lib, "identity") ||
		f.enrolled[0].Replace || r.AgentID != "con_01TEST" {
		t.Fatalf("enrolled %+v, result %+v", f.enrolled, r)
	}
	var cfg config.Connector
	if err := config.Load(filepath.Join(h.Paths.Etc, "connector.yaml"), &cfg); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Controller.Endpoints, []string{"https://panel.example.com"}) || cfg.PolicyFile != filepath.Join(h.Paths.Etc, "policy.yaml") {
		t.Errorf("boot file %+v", cfg)
	}
	pol, err := os.ReadFile(cfg.PolicyFile)
	if err != nil || !strings.Contains(string(pol), "10.0.0.5") || !strings.Contains(string(pol), "/run/app.sock") {
		t.Errorf("policy %q %v", pol, err)
	}
	proxy, err := os.ReadFile(filepath.Join(h.Paths.Units, "rpmgr-connector.service.d", "proxy.conf"))
	if err != nil || !strings.Contains(string(proxy), `Environment="HTTPS_PROXY=http://proxy.lan:3128"`) {
		t.Errorf("proxy drop-in %q %v", proxy, err)
	}
	unit, err := os.ReadFile(filepath.Join(h.Paths.Units, "rpmgr-connector.service"))
	if err != nil || !strings.Contains(string(unit), "ExecStart="+h.Paths.Bin+" connector") {
		t.Errorf("unit %q %v", unit, err)
	}
	if !slices.EqualFunc(f.commands, [][]string{{"systemctl", "daemon-reload"}, {"systemctl", "enable", "--now", "rpmgr-connector"}}, slices.Equal) ||
		!slices.Equal(f.ready, []string{"127.0.0.1:7383"}) || r.Unit != "rpmgr-connector" {
		t.Errorf("commands %q, ready %q, unit %q", f.commands, f.ready, r.Unit)
	}
}

// TestPlan_Again: run again with --force, setup keeps the old boot file beside the new one,
// enrolls with Replace, keeps the policy's targets, replaces the proxy, and restarts the running
// role, which holds its admin address itself; it names for cleaning up only what it made this time.
func TestPlan_Again(t *testing.T) {
	f := &fakeHost{}
	h := newHost(t, f)
	v := setup.Values{Role: setup.Connector, ControllerURL: "https://panel.example.com", Pin: pin(t), Token: newToken(t),
		AllowTargets: []string{"10.0.0.5:8080"}, Proxy: "http://proxy.lan:3128"}
	p, err := setup.New(v, h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	boot := filepath.Join(h.Paths.Etc, "connector.yaml")
	first, _ := os.ReadFile(boot)

	h.PortFree = func(string) bool { return false } // the running connector holds it
	f.notReady, f.commands = errors.New("not ready"), nil
	v.Force, v.Token, v.AllowTargets, v.Proxy = true, newToken(t), []string{"/run/app.sock"}, "socks5://proxy.lan:1080"
	v.ListenAdmin = "127.0.0.1:17383"
	if _, err := setup.New(v, h); err == nil || !strings.Contains(err.Error(), "--listen-admin") {
		t.Errorf("a new admin address in use: %v", err)
	}
	v.ListenAdmin = ""
	p, err = setup.New(v, h)
	if err != nil {
		t.Fatal(err)
	}
	if steps := strings.Join(p.Steps(), "\n"); !strings.Contains(steps, "keeping the old one as "+boot+".before-setup") ||
		!strings.Contains(steps, "restart rpmgr-connector") {
		t.Errorf("steps\n%s", steps)
	}
	r, err := p.Run(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("run: %v", err)
	}
	if !slices.Equal(r.Written, []string{boot}) {
		t.Errorf("written %q, want only the new boot file", r.Written)
	}
	if old, err := os.ReadFile(boot + ".before-setup"); err != nil || string(old) != string(first) {
		t.Errorf("the old boot file: %q %v", old, err)
	}
	if len(f.enrolled) != 2 || !f.enrolled[1].Replace {
		t.Errorf("enrolled %+v", f.enrolled)
	}
	if pol, err := os.ReadFile(filepath.Join(h.Paths.Etc, "policy.yaml")); err != nil || !strings.Contains(string(pol), "10.0.0.5") ||
		!strings.Contains(string(pol), "/run/app.sock") {
		t.Errorf("policy %q %v", pol, err)
	}
	if proxy, err := os.ReadFile(filepath.Join(h.Paths.Units, "rpmgr-connector.service.d", "proxy.conf")); err != nil ||
		!strings.Contains(string(proxy), "socks5://proxy.lan:1080") {
		t.Errorf("proxy drop-in %q %v", proxy, err)
	}
	if !slices.ContainsFunc(f.commands, func(c []string) bool { return slices.Equal(c, []string{"systemctl", "restart", "rpmgr-connector"}) }) {
		t.Errorf("commands %q", f.commands)
	}
}

// TestPlan_GatewayFailure: a failed enrollment stops the plan before anything else is written, and
// the result names what setup had created.
func TestPlan_GatewayFailure(t *testing.T) {
	f := &fakeHost{}
	h := newHost(t, f)
	h.Enroll = func(context.Context, agent.EnrollOptions) (agent.Identity, error) {
		return agent.Identity{}, errors.New("token used up")
	}
	p, err := setup.New(setup.Values{Role: setup.Gateway, ControllerURL: "https://panel.example.com", Pin: pin(t), Token: newToken(t),
		ListenHTTP: "off"}, h)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Run(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "token used up") {
		t.Fatalf("run: %v", err)
	}
	if !slices.Equal(r.Written, []string{h.Paths.Etc, h.Paths.Lib}) {
		t.Errorf("written %q", r.Written)
	}
	if _, err := os.Stat(filepath.Join(h.Paths.Etc, "gateway.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the boot file after a failed enrollment: %v", err)
	}
	_, data := p.BootFile()
	var cfg config.Gateway
	if err := config.Parse(data, &cfg); err != nil || *cfg.Listen.HTTP != "" {
		t.Errorf("listen.http off: %q %v", data, err)
	}
}

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// pin is a well-formed CA pin of 32 zero bytes.
func pin(t *testing.T) string {
	t.Helper()
	return "sha256:" + strings.Repeat("A", 43) + "="
}
