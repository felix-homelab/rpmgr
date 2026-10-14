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
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/setup"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
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
		Encrypt: func(_ context.Context, _, path string, b []byte) error {
			return os.WriteFile(path, b, 0o600) // stands in for systemd-creds encrypt
		},
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
		Getenv:   func(string) string { return "" },
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
		"http URL":                setup.CheckControllerURL("http://panel.example.com"),
		"URL with a path":         setup.CheckControllerURL("https://panel.example.com/ui"),
		"URL without a host":      setup.CheckControllerURL("https://"),
		"short pin":               setup.CheckPin("sha256:abc"),
		"pin without prefix":      setup.CheckPin("abc"),
		"mistyped token":          setup.CheckToken("rpmgr_enr_0123"),
		"IPv6 target unbracketed": setup.CheckTarget("fd00::1:80"),
		"reversed port range":     setup.CheckTarget("10.0.0.5:500-200"),
		"relative socket":         setup.CheckTarget("run/app.sock"),
		"address":                 setup.CheckAddr("443", false),
		"off where it is not":     setup.CheckAddr("off", false),
		"ftp proxy":               setup.CheckProxy("ftp://proxy:21"),
		"proxy without host":      setup.CheckProxy("http://"),
		"public URL":              setup.CheckPublicURL("https://panel.example.com/ui"),
		"e-mail":                  setup.CheckEmail("not an address"),
		"named e-mail":            setup.CheckEmail("Ops <ops@example.com>"),
		"role":                    setup.CheckRole("router"),
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
		"subnet":      setup.CheckTarget("10.0.0.1/16"),
		"port range":  setup.CheckTarget("127.0.0.1:200-500"),
		"all ports":   setup.CheckTarget("10.0.0.5"),
		"IPv6 subnet": setup.CheckTarget("[fd00::/64]:8000-8099"),
		"http off":    setup.CheckAddr("off", true),
		"socks proxy": setup.CheckProxy("socks5://proxy:1080"),
		"no proxy":    setup.CheckProxy(""),
		"e-mail":      setup.CheckEmail("ops@example.com"),
		"no e-mail":   setup.CheckEmail(""),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if d, err := setup.Directory("staging"); err != nil || d != setup.StagingDirectory {
		t.Errorf("staging: %q %v", d, err)
	}
	if d, err := setup.Directory("production"); err != nil || d != settings.LetsEncrypt {
		t.Errorf("production: %q %v", d, err)
	}
	if _, err := setup.Directory("http://acme.example.com/dir"); err == nil {
		t.Error("an http directory accepted")
	}
	if host, public := setup.PublicHost("https://rpmgr.internal:8443"); host != "rpmgr.internal" || public {
		t.Errorf("rpmgr.internal: %q %v", host, public)
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
		"gateway denials":   {with(func(v *setup.Values) { v.DenyTargets = []string{"10.0.0.5"} }), nil, "connector's"},
		"connector listens": {with(func(v *setup.Values) { v.Role, v.ListenTCP = setup.Connector, ":443" }), nil, "no listen.tcp"},
		"bad target":        {with(func(v *setup.Values) { v.Role, v.AllowTargets = setup.Connector, []string{"10.0.0.5:0"} }), nil, "allowed target"},
		"bad denial":        {with(func(v *setup.Values) { v.Role, v.DenyTargets = setup.Connector, []string{"fd00::1:80"} }), nil, "denied target"},
		"bad address":       {with(func(v *setup.Values) { v.ListenAdmin = "7382" }), nil, "listen.admin"},
		"not root":          {gw, func(h *setup.Host) { h.IsRoot = func() bool { return false } }, "as root"},
		"no systemd":        {gw, func(h *setup.Host) { h.SystemdVersion = func() int { return 0 } }, "--no-unit"},
		"no binary":         {gw, func(h *setup.Host) { h.Paths.Bin = filepath.Join(h.Paths.Lib, "rpmgr") }, "install the binary"},
		"admin taken":       {gw, func(h *setup.Host) { h.PortFree = func(string) bool { return false } }, "--listen-admin"},
		"gateway with KEK":  {with(func(v *setup.Values) { v.KEKSource = config.KEKFile }), nil, "controller's"},
		"bad public URL":    {setup.Values{Role: setup.Controller, PublicURL: "panel", TLS: setup.TLSSelfSigned}, nil, "public URL"},
		"ACME for an IP":    {setup.Values{Role: setup.AllInOne, PublicURL: "https://192.0.2.10", TLS: setup.TLSACME}, nil, "public CA"},
		"files without":     {setup.Values{Role: setup.AllInOne, PublicURL: "https://panel.example.com", TLS: setup.TLSFiles}, nil, "certificate and the key"},
		"files unreadable":  {setup.Values{Role: setup.AllInOne, PublicURL: "https://panel.example.com", TLS: setup.TLSFiles, CertFile: "/nonexistent.crt", KeyFile: "/nonexistent.key"}, nil, "certificate and key files"},
		"no TLS":            {setup.Values{Role: setup.Controller, PublicURL: "https://panel.example.com"}, nil, "want acme"},
		"KEK source":        {setup.Values{Role: setup.Controller, PublicURL: "https://panel.example.com", TLS: setup.TLSACME, KEKSource: "tpm"}, nil, "KEK source"},
		"listen.https":      {setup.Values{Role: setup.AllInOne, PublicURL: "https://panel.example.com", TLS: setup.TLSACME, ListenHTTPS: ":443"}, nil, "listen.https"},
		"controller tcp":    {setup.Values{Role: setup.Controller, PublicURL: "https://panel.example.com", TLS: setup.TLSACME, ListenTCP: ":443"}, nil, "listen.tcp"},
		"controller pin":    {setup.Values{Role: setup.Controller, PublicURL: "https://panel.example.com", TLS: setup.TLSACME, Pin: pin(t)}, nil, "gateway's"},
		"ACME e-mail":       {setup.Values{Role: setup.Controller, PublicURL: "https://panel.example.com", TLS: setup.TLSACME, ACMEEmail: "ops"}, nil, "e-mail"},
		"old systemd": {setup.Values{Role: setup.AllInOne, PublicURL: "https://panel.example.com", KEKSource: config.KEKSystemdCredential, TLS: setup.TLSSelfSigned},
			func(h *setup.Host) { h.SystemdVersion = func() int { return 249 } }, "systemd 250"},
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
	// An installation: never initialised again, not even with --force.
	aio := setup.Values{Role: setup.AllInOne, PublicURL: "https://panel.example.com", KEKSource: config.KEKFile, TLS: setup.TLSSelfSigned, Force: true}
	write(t, filepath.Join(h.Paths.Lib, "controller.db"), "")
	if _, err := setup.New(aio, h); err == nil || !strings.Contains(err.Error(), "holds an installation") {
		t.Errorf("an existing database: %v", err)
	}
}

// TestPlan_AllInOne: an all-in-one with a KEK file and a self-signed certificate for a public name
// writes its boot file, makes the certificate, initialises through `rpmgr all-in-one init`'s code,
// installs and starts its unit and waits until it is ready.
func TestPlan_AllInOne(t *testing.T) {
	f := &fakeHost{}
	h := newHost(t, f)
	p, err := setup.New(setup.Values{Role: setup.AllInOne, PublicURL: "https://panel.example.com", KEKSource: config.KEKFile,
		TLS: setup.TLSSelfSigned, ListenAdmin: "127.0.0.1:17381"}, h)
	if err != nil {
		t.Fatal(err)
	}
	steps := strings.Join(p.Steps(), "\n")
	for _, want := range []string{"create " + h.Paths.Etc, "self-signed certificate for panel.example.com", "write the boot file",
		"initialise the all-in-one", "enable --now rpmgr-all-in-one", "127.0.0.1:17381/readyz"} {
		if !strings.Contains(steps, want) {
			t.Errorf("no step %q in\n%s", want, steps)
		}
	}
	var progress []string
	r, err := p.Run(context.Background(), func(s string) { progress = append(progress, s) })
	if err != nil {
		t.Fatalf("run: %v (wrote %v)", err, r.Written)
	}
	if len(progress) != len(p.Steps()) || r.TrustDomain == "" || !strings.HasPrefix(r.Pin, "sha256:") ||
		!strings.HasPrefix(r.FirstUserLink, "https://panel.example.com/setup#") || r.GatewayID == "" || r.Unit != "rpmgr-all-in-one" {
		t.Fatalf("result %+v after %v", r, progress)
	}
	var cfg config.AllInOne
	if err := config.Load(filepath.Join(h.Paths.Etc, "all-in-one.yaml"), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.KEK.Source != config.KEKFile || cfg.TLS.CertFile != filepath.Join(h.Paths.Etc, "tls", "panel.example.com.crt") ||
		cfg.Listen.Admin != "127.0.0.1:17381" || cfg.Database.DSN != filepath.Join(h.Paths.Lib, "controller.db") {
		t.Errorf("boot file %+v", cfg)
	}
	unit, err := os.ReadFile(filepath.Join(h.Paths.Units, "rpmgr-all-in-one.service"))
	if err != nil || !strings.Contains(string(unit), "ExecStart="+h.Paths.Bin+" all-in-one") || strings.Contains(string(unit), "LoadCredentialEncrypted") {
		t.Errorf("unit %q %v", unit, err)
	}
	if !slices.EqualFunc(f.commands, [][]string{{"systemctl", "daemon-reload"}, {"systemctl", "enable", "--now", "rpmgr-all-in-one"}}, slices.Equal) ||
		!slices.Equal(f.ready, []string{"127.0.0.1:17381"}) {
		t.Errorf("commands %q, ready %q", f.commands, f.ready)
	}
}

// TestPlan_ControllerACME: a controller with a KEK in a systemd credential and ACME from Let's
// Encrypt staging initialises, sets the instance's ACME directory and e-mail before its first
// start, and loads the credential in its unit; without a unit nothing is started.
func TestPlan_ControllerACME(t *testing.T) {
	f := &fakeHost{}
	h := newHost(t, f)
	p, err := setup.New(setup.Values{Role: setup.Controller, PublicURL: "https://panel.example.com", TLS: setup.TLSACME,
		ACMEDirectory: "staging", ACMEEmail: "ops@example.com", NoUnit: true}, h)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := p.Run(context.Background(), nil); err != nil || r.Unit != "" || r.FirstUserLink == "" {
		t.Fatalf("run: %+v %v", r, err)
	}
	db, err := store.OpenSQLite(context.Background(), filepath.Join(h.Paths.Lib, "controller.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	inst, _, err := settings.Instance(storetest.SystemCtx(t), db.ReadClient())
	if err != nil || inst.GetAcmeDirectoryUrl() != setup.StagingDirectory || inst.GetAcmeEmail() != "ops@example.com" {
		t.Fatalf("instance settings %v %v", inst, err)
	}
	if _, err := os.Stat(filepath.Join(h.Paths.Etc, "credstore", "rpmgr-kek")); err != nil {
		t.Errorf("the KEK credential: %v", err)
	}
	if len(f.commands) != 0 || len(f.ready) != 0 {
		t.Errorf("without a unit: commands %q, ready %q", f.commands, f.ready)
	}
}

// TestPlan_PrivateName: a controller whose name no public CA certifies makes its own self-signed
// certificate, so setup writes no certificate files for it.
func TestPlan_PrivateName(t *testing.T) {
	h := newHost(t, &fakeHost{})
	p, err := setup.New(setup.Values{Role: setup.Controller, PublicURL: "https://rpmgr.home.arpa", KEKSource: config.KEKFile,
		TLS: setup.TLSSelfSigned, ListenHTTP: "off", NoUnit: true}, h)
	if err != nil {
		t.Fatal(err)
	}
	_, data := p.BootFile()
	var cfg config.Controller
	if err := config.Parse(data, &cfg); err != nil || cfg.TLS.CertFile != "" || *cfg.Listen.HTTP != "" {
		t.Errorf("boot file %q: %v", data, err)
	}
	if steps := strings.Join(p.Steps(), "\n"); strings.Contains(steps, "self-signed") {
		t.Errorf("steps\n%s", steps)
	}
}

// TestPlan_KeepsCertificate: a self-signed certificate an earlier run made is used, not made again.
func TestPlan_KeepsCertificate(t *testing.T) {
	h := newHost(t, &fakeHost{})
	dir := filepath.Join(h.Paths.Etc, "tls")
	write(t, filepath.Join(dir, "panel.example.com.crt"), "")
	write(t, filepath.Join(dir, "panel.example.com.key"), "")
	p, err := setup.New(setup.Values{Role: setup.Controller, PublicURL: "https://panel.example.com", KEKSource: config.KEKFile,
		TLS: setup.TLSSelfSigned, NoUnit: true}, h)
	if err != nil {
		t.Fatal(err)
	}
	if steps := strings.Join(p.Steps(), "\n"); strings.Contains(steps, "self-signed") {
		t.Errorf("steps\n%s", steps)
	}
	_, data := p.BootFile()
	if !strings.Contains(string(data), filepath.Join(dir, "panel.example.com.crt")) {
		t.Errorf("boot file %q", data)
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
		AllowTargets: []string{"10.0.0.5:8080", "/run/app.sock", "10.1.0.1/16"}, DenyTargets: []string{"10.1.2.3:22"}, Proxy: "http://proxy.lan:3128"}, h)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Summary(), [2]string{"denied targets", "10.1.2.3:22"}) {
		t.Errorf("the summary does not show the denied target: %q", p.Summary())
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
	if lp, err := policy.Load(cfg.PolicyFile); err != nil || lp.Check("10.1.2.3:22") == nil || lp.Check("10.1.2.3:23") != nil {
		t.Errorf("the policy's deny over its subnet: %v\n%s", err, pol)
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
