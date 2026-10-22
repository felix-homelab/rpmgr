// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"go.yaml.in/yaml/v3"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/units"
	"github.com/felix-homelab/rpmgr/internal/update"
	"github.com/felix-homelab/rpmgr/internal/version"
)

// Plan is what setup does for validated values: its steps, in order. Nothing has happened yet.
type Plan struct {
	v     Values
	h     Host
	boot  string // the boot file
	again bool   // the boot file exists: setup runs again, with --force
	data  []byte // its contents
	booted
	oldAdmin string // the admin listener of the boot file setup replaces
	steps    []step
}

// booted is what setup reads back from a parsed boot file.
type booted struct {
	admin  string        // the admin listener
	policy string        // the connector-local policy file
	unit   units.Options // what the boot file decides of the unit: KEK credential, sink
}

type step struct {
	title string
	run   func(ctx context.Context, r *Result) error
}

// Result is what setup did, and what the operator needs next.
type Result struct {
	// Controller and all-in-one: as `rpmgr <role> init` prints them.
	TrustDomain, Pin, FirstUserLink, KEK, GatewayID, ConnectorID string
	// Gateway and connector: the enrolled identity.
	AgentID, AgentKind string
	Unit               string // the unit setup installed and started; empty without one
	Admin              string // the admin listener
	// NoUpdaterState: the updater is installed, but it has no state, because this development
	// build has no release version; it refuses every release.
	NoUpdaterState bool
	// Written are the files and directories setup created, for cleaning up after a failure.
	Written []string
}

var errRoot = errors.New("setup: run it as root (sudo rpmgr setup)")

// The edits of the connector-local policy, replaced in tests.
var allowTarget, denyTarget = policy.AllowTarget, policy.DenyTarget

// Facts are what a form needs to know about the host before it asks.
type Facts struct {
	Systemd int // systemctl's version; 0 without systemd
}

// Preflight refuses, before anything is asked, what no value can fix: setup runs as root.
func Preflight(h Host) (Facts, error) {
	h.defaults()
	if !h.IsRoot() {
		return Facts{}, errRoot
	}
	return Facts{Systemd: h.SystemdVersion()}, nil
}

// New checks the values against the host and returns the plan, or every problem it found.
func New(v Values, h Host) (*Plan, error) {
	h.defaults()
	// A role this build does not set up is refused before its values are checked.
	if CheckRole(string(v.Role)) == nil && !h.Offers(v.Role) {
		return nil, fmt.Errorf("the role %s: %w", v.Role, cli.ErrNotAvailable)
	}
	if err := v.check(h); err != nil {
		return nil, err
	}
	if !h.IsRoot() {
		return nil, errRoot
	}
	p := &Plan{v: v, h: h, boot: filepath.Join(h.Paths.Etc, string(v.Role)+".yaml")}
	p.again = exists(p.boot)
	if err := p.bootFile(); err != nil {
		return nil, err
	}
	if err := p.hostChecks(); err != nil {
		return nil, err
	}
	p.prepare()
	if v.Role.Initialises() {
		p.initSteps()
	} else {
		p.agentSteps()
	}
	p.updaterSteps()
	if !v.NoUnit {
		p.unitSteps()
	}
	return p, nil
}

// Steps are the titles of the plan's steps, for the summary.
func (p *Plan) Steps() []string {
	out := make([]string, len(p.steps))
	for i, s := range p.steps {
		out[i] = s.title
	}
	return out
}

// BootFile returns the boot file's path and contents as setup will write them.
func (p *Plan) BootFile() (string, []byte) { return p.boot, p.data }

// Run runs the steps in order and stops at the first failure; progress is told each step's title
// before it runs. On a failure, the result's Written lists what setup had created.
func (p *Plan) Run(ctx context.Context, progress func(string)) (Result, error) {
	r := Result{Admin: p.admin}
	for _, s := range p.steps {
		if progress != nil {
			progress(s.title)
		}
		if err := s.run(ctx, &r); err != nil {
			return r, fmt.Errorf("%s: %w", s.title, err)
		}
	}
	return r, nil
}

// bootFile builds the boot file from the values and parses it with the role's config type, which
// fills in the defaults and validates it as the role will.
func (p *Plan) bootFile() error {
	v, paths, defaults := p.v, p.h.Paths, DefaultPaths()
	doc := map[string]any{"version": config.Version}
	listen := map[string]string{}
	set := func(key, val string) {
		switch val {
		case "":
		case "off":
			listen[key] = ""
		default:
			listen[key] = val
		}
	}
	set("https", v.ListenHTTPS)
	set("tcp", v.ListenTCP)
	set("udp", v.ListenUDP)
	set("http", v.ListenHTTP)
	set("admin", v.ListenAdmin)
	if len(listen) > 0 {
		doc["listen"] = listen
	}
	nonDefaultLib := paths.Lib != defaults.Lib
	var parse func([]byte) (booted, error)
	switch v.Role {
	case Controller, AllInOne:
		doc["public_url"] = strings.TrimSuffix(v.PublicURL, "/")
		if nonDefaultLib {
			doc["database"] = map[string]string{"dsn": filepath.Join(paths.Lib, "controller.db")}
		}
		source := v.KEKSource
		if source == "" {
			source = config.KEKSourceFor(p.h.SystemdVersion())
		}
		if source == config.KEKFile {
			path := v.KEKPath
			if path == "" {
				path = filepath.Join(paths.Etc, "kek")
			}
			doc["kek"] = map[string]string{"source": config.KEKFile, "path": path}
		} else {
			doc["kek"] = map[string]string{"source": config.KEKSystemdCredential}
		}
		if cert, key := p.tlsFiles(); cert != "" {
			doc["tls"] = map[string]string{"cert_file": cert, "key_file": key}
		}
		if v.Role == AllInOne {
			if nonDefaultLib {
				doc["state_dir"] = paths.Lib
			}
			if paths.Etc != defaults.Etc {
				doc["policy_file"] = filepath.Join(paths.Etc, "policy.yaml")
			}
			parse = func(b []byte) (booted, error) {
				var c config.AllInOne
				err := config.Parse(b, &c)
				return booted{admin: c.Listen.Admin, policy: c.PolicyFile, unit: units.ForController(c.Controller())}, err
			}
		} else {
			parse = func(b []byte) (booted, error) {
				var c config.Controller
				err := config.Parse(b, &c)
				return booted{admin: c.Listen.Admin, unit: units.ForController(c)}, err
			}
		}
	case Gateway, Connector:
		doc["controller"] = map[string]any{"endpoints": []string{strings.TrimSuffix(v.ControllerURL, "/")}}
		if nonDefaultLib {
			doc["identity_dir"] = filepath.Join(paths.Lib, "identity")
			doc["state_dir"] = paths.Lib
		}
		if v.Role == Gateway {
			parse = func(b []byte) (booted, error) {
				var c config.Gateway
				err := config.Parse(b, &c)
				return booted{admin: c.Listen.Admin}, err
			}
		} else {
			if paths.Etc != defaults.Etc {
				doc["policy_file"] = filepath.Join(paths.Etc, "policy.yaml")
			}
			parse = func(b []byte) (booted, error) {
				var c config.Connector
				err := config.Parse(b, &c)
				return booted{admin: c.Listen.Admin, policy: c.PolicyFile}, err
			}
		}
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if p.booted, err = parse(data); err != nil {
		return fmt.Errorf("setup: the boot file would be invalid: %w", err)
	}
	p.data = data
	if old, err := os.ReadFile(p.boot); err == nil {
		if o, err := parse(old); err == nil {
			p.oldAdmin = o.admin
		}
	}
	return nil
}

// tlsFiles returns the certificate and key files of the boot file: the operator's, or for a
// self-signed certificate of a public name the ones setup makes, which keep the controller from
// ordering one from its ACME CA at the first start. A controller whose name no public CA can
// certify makes its own self-signed certificate, so it needs none.
func (p *Plan) tlsFiles() (string, string) {
	switch p.v.TLS {
	case TLSFiles:
		return p.v.CertFile, p.v.KeyFile
	case TLSSelfSigned:
		if host, public := p.h.PublicHost(p.v.PublicURL); public {
			dir := filepath.Join(p.h.Paths.Etc, "tls")
			return filepath.Join(dir, host+".crt"), filepath.Join(dir, host+".key")
		}
	}
	return "", ""
}

// hostChecks refuses what setup must not overwrite, and what the host cannot do.
func (p *Plan) hostChecks() error {
	v, h := p.v, p.h
	var errs []error
	if p.again && !v.Force {
		errs = append(errs, fmt.Errorf("%s exists; setup replaces it only with --force (keeping the old one beside it)", p.boot))
	}
	if v.Role.Initialises() {
		db := filepath.Join(h.Paths.Lib, "controller.db")
		if exists(db) {
			errs = append(errs, fmt.Errorf("%s exists: this host holds an installation already, which setup never initialises again", db))
		}
		if v.KEKSource == config.KEKSystemdCredential && h.SystemdVersion() < 250 {
			errs = append(errs, errors.New("a KEK in a systemd credential needs systemd 250 or newer; choose the file"))
		}
		if v.TLS == TLSFiles && v.CertFile != "" && v.KeyFile != "" {
			if _, err := tls.LoadX509KeyPair(v.CertFile, v.KeyFile); err != nil {
				errs = append(errs, fmt.Errorf("the certificate and key files: %w", err))
			}
		}
	} else if exists(filepath.Join(h.Paths.Lib, "identity", agent.ChainFile)) && !v.Force {
		errs = append(errs, errors.New("this host is enrolled already; setup enrolls it again only with --force"))
	}
	if !v.NoUnit && h.SystemdVersion() == 0 {
		errs = append(errs, errors.New("no systemd on this host: use --no-unit and start the role yourself"))
	}
	if fi, err := os.Stat(h.Paths.Bin); !v.NoUnit && (err != nil || fi.Mode()&0o111 == 0) {
		errs = append(errs, fmt.Errorf("the unit runs %s, which is no executable: install the binary there first, or use --no-unit", h.Paths.Bin))
	}
	// The role set up before holds its own admin address.
	if p.admin != p.oldAdmin && !h.PortFree(p.admin) {
		errs = append(errs, fmt.Errorf("the admin address %s is in use; choose another with --listen-admin", p.admin))
	}
	return errors.Join(errs...)
}

// prepare adds the steps every role needs first: the service user and the directories.
func (p *Plan) prepare() {
	h := p.h
	if !h.UserExists() {
		p.add("create the system user "+ServiceUser, func(ctx context.Context, _ *Result) error {
			return h.Run(ctx, "useradd", "--system", "--user-group", "--home-dir", h.Paths.Lib, "--shell", "/usr/sbin/nologin", ServiceUser)
		})
	}
	if _, err := os.Stat(h.Paths.Etc); err != nil {
		p.add("create "+h.Paths.Etc, func(_ context.Context, r *Result) error {
			r.Written = append(r.Written, h.Paths.Etc)
			return mkdirMode(h.Paths.Etc, 0o755) // boot files are not secret (docs/10-operations.md)
		})
	}
	if _, err := os.Stat(h.Paths.Lib); err != nil {
		p.add("create "+h.Paths.Lib+", owned by "+ServiceUser, func(_ context.Context, r *Result) error {
			r.Written = append(r.Written, h.Paths.Lib)
			if err := mkdirMode(h.Paths.Lib, 0o750); err != nil {
				return err
			}
			return h.GiveTo(h.Paths.Lib)
		})
	}
}

func (p *Plan) add(title string, run func(ctx context.Context, r *Result) error) {
	p.steps = append(p.steps, step{title, run})
}

// writeBoot writes the boot file; with --force an existing one is kept beside it.
func (p *Plan) writeBoot() {
	title := "write the boot file " + p.boot
	if p.again {
		title = "replace the boot file " + p.boot + ", keeping the old one as " + p.boot + ".before-setup"
	}
	p.add(title, func(_ context.Context, r *Result) error {
		if exists(p.boot) {
			if err := os.Rename(p.boot, p.boot+".before-setup"); err != nil {
				return err
			}
		}
		r.created(p.boot)
		return writeNew(p.boot, p.data, 0o644)
	})
}

// initSteps initialise a controller or all-in-one through `rpmgr <role> init`'s code.
func (p *Plan) initSteps() {
	v, h := p.v, p.h
	// A certificate an earlier run made is kept.
	if cert, key := p.tlsFiles(); cert != "" && v.TLS == TLSSelfSigned && (!exists(cert) || !exists(key)) {
		host, _ := h.PublicHost(v.PublicURL)
		p.add("make a self-signed certificate for "+host+" in "+filepath.Dir(cert), func(_ context.Context, r *Result) error {
			r.created(cert)
			r.created(key)
			return selfSigned(host, cert, key, h)
		})
	}
	p.writeBoot()
	what := "initialise the controller: KEK, database, trust domain and CA"
	if v.Role == AllInOne {
		what = "initialise the all-in-one: KEK, database, trust domain and CA, and enroll its gateway and connector"
	}
	p.add(what, func(ctx context.Context, r *Result) error {
		ir, err := h.Server.Init(ctx, ServerInit{AllInOne: v.Role == AllInOne, ConfigPath: p.boot,
			CredentialsDir: filepath.Join(h.Paths.Etc, "credstore"), Getenv: h.Getenv, Encrypt: h.Encrypt,
			SystemdVersion: h.SystemdVersion, ServiceUser: ServiceUser, Now: h.Now})
		if err != nil {
			return p.initFailed(r, err)
		}
		r.TrustDomain, r.Pin, r.FirstUserLink, r.KEK = ir.TrustDomain, ir.RootPin, ir.FirstUserLink, ir.KEK
		r.GatewayID, r.ConnectorID = ir.GatewayID, ir.ConnectorID
		return nil
	})
	if v.Role == AllInOne {
		p.policySteps()
	}
	// The instance's ACME CA certifies the routes too, whatever certifies the public URL.
	dir, _ := Directory(v.ACMEDirectory)
	if dir != "" || v.ACMEEmail != "" {
		p.add("set the instance's ACME directory and e-mail address", func(ctx context.Context, _ *Result) error {
			return p.h.Server.SetACME(ctx, p.boot, dir, v.ACMEEmail)
		})
	}
}

// initFailed adds what a failed init may have created to the result.
func (p *Plan) initFailed(r *Result, err error) error {
	for _, f := range []string{filepath.Join(p.h.Paths.Lib, "controller.db"), filepath.Join(p.h.Paths.Etc, "kek"),
		filepath.Join(p.h.Paths.Etc, "credstore")} {
		if exists(f) {
			r.Written = append(r.Written, f)
		}
	}
	return err
}

// agentSteps enroll a gateway or connector through `rpmgr enroll`'s code, then write its files.
func (p *Plan) agentSteps() {
	v, h := p.v, p.h
	identity := filepath.Join(h.Paths.Lib, "identity")
	p.add("enroll with "+v.ControllerURL, func(ctx context.Context, r *Result) error {
		fresh := !exists(identity)
		host, _ := os.Hostname()
		o := agent.EnrollOptions{Controller: v.ControllerURL, Pin: v.Pin, Token: strings.TrimSpace(v.Token),
			IdentityDir: identity, Replace: v.Force, Version: version.Version,
			Host: &agentv1.HostFacts{Hostname: host, Os: runtime.GOOS, Arch: runtime.GOARCH}}
		if v.Proxy != "" {
			done, err := throughProxy(&o, v.Proxy)
			if err != nil {
				return err
			}
			defer done()
		}
		id, err := h.Enroll(ctx, o)
		if err != nil {
			return err
		}
		if fresh {
			r.Written = append(r.Written, identity)
		}
		r.AgentID, r.AgentKind = id.AgentID, id.Kind
		return h.GiveTo(identity)
	})
	p.writeBoot()
	if v.Role != Connector {
		return
	}
	p.policySteps()
	if v.Proxy != "" {
		// The URL may hold a password: it goes into a file only root reads, which the drop-in
		// names, never into the drop-in itself, which anyone reads, as `systemctl show` does.
		envFile := filepath.Join(h.Paths.Etc, "connector-proxy.env")
		dropIn := filepath.Join(h.Paths.Units, "rpmgr-connector.service.d", "proxy.conf")
		p.add("set the connector's proxy in "+envFile+", named by "+dropIn, func(_ context.Context, r *Result) error {
			r.created(envFile)
			if err := writeMode(envFile, []byte("HTTPS_PROXY="+v.Proxy+"\n"), 0o600); err != nil {
				return err
			}
			if err := mkdirMode(filepath.Dir(dropIn), 0o755); err != nil { // a unit directory
				return err
			}
			r.created(dropIn)
			return writeMode(dropIn, []byte("[Service]\nEnvironmentFile="+envFile+"\n"), 0o644)
		})
	}
}

// throughProxy makes the enrollment take the proxy the connector's service will take: the
// connector's own dialer (HTTP CONNECT or SOCKS5) for both the trust bundle and the controller. The
// bundle's download keeps the default client's time limit; done closes its idle tunnel.
func throughProxy(o *agent.EnrollOptions, proxyURL string) (done func(), err error) {
	dial, err := connector.ProxyDialer(func(name string) string {
		if name == "HTTPS_PROXY" {
			return proxyURL
		}
		return "" // the service gets no NO_PROXY either
	})
	if err != nil {
		return nil, err
	}
	t := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the standard library's
	t.Proxy = nil
	t.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) { return dial(ctx, addr) }
	o.HTTPClient, o.Dial = &http.Client{Transport: t, Timeout: agent.DownloadTimeout}, dial
	return t.CloseIdleConnections, nil
}

// redactedProxy is the proxy URL with its user name and password, if any, left out.
func redactedProxy(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "(not shown)"
	}
	if u.User != nil {
		u.User = url.User("xxxxx")
	}
	return u.String()
}

// policySteps write the allowed and denied targets into the connector-local policy of a connector
// or all-in-one.
func (p *Plan) policySteps() {
	v := p.v
	if len(v.AllowTargets) > 0 || len(v.DenyTargets) > 0 {
		p.add(fmt.Sprintf("allow %d and deny %d target(s) in the connector-local policy %s", len(v.AllowTargets), len(v.DenyTargets),
			p.policy), func(_ context.Context, r *Result) error {
			r.created(p.policy)
			// Denials first: an allow never stands, not even for a moment, without the denials
			// that narrow it.
			for _, t := range v.DenyTargets {
				if _, err := denyTarget(p.policy, t); err != nil {
					return err
				}
			}
			for _, t := range v.AllowTargets {
				if _, err := allowTarget(p.policy, t); err != nil {
					return err
				}
			}
			return nil
		})
	}
}

// updaterSteps record the installation for the root updater, which every Linux host gets whatever
// its role (docs/10-operations.md, "Who installs the updater"), and install its units. Setup knows
// no release seq: a state an install script wrote stays; a missing one starts at the binary's
// version with seq 0.
func (p *Plan) updaterSteps() {
	h, v := p.h, p.v
	if h.Paths.UpdateState == "" {
		return
	}
	in := update.Installed{Install: update.Install{Method: "setup", Path: h.Paths.Bin, Variant: h.Variant, Roles: []string{string(v.Role)}}}
	title := "record the " + string(v.Role) + " role for the updater in " + h.Paths.UpdateState
	if !v.NoUnit {
		title += ", install its units rpmgr-update.path and rpmgr-update.service: systemctl enable rpmgr-update.service, enable --now rpmgr-update.path"
	}
	p.add(title, func(ctx context.Context, r *Result) error {
		if old, err := update.ReadInstall(h.Paths.UpdateState); err == nil {
			in.Method = old.Method // an install script's record stays its
		}
		r.created(h.Paths.UpdateState)
		in.Floor = version.Version
		_, st, err := update.Record(h.Paths.UpdateState, in)
		if err != nil {
			return err
		}
		r.NoUpdaterState = st.Floor == ""
		if v.NoUnit {
			return nil
		}
		for _, u := range []string{"rpmgr-update.path", "rpmgr-update.service"} {
			r.created(filepath.Join(h.Paths.Units, u))
		}
		if _, err := update.WriteUnits(h.Paths.Units, h.Paths.Bin); err != nil {
			return err
		}
		if err := h.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := h.Run(ctx, "systemctl", "enable", "rpmgr-update.service"); err != nil { // its run at boot
			return err
		}
		return h.Run(ctx, "systemctl", "enable", "--now", "rpmgr-update.path")
	})
}

// unitSteps install the role's unit, start it and wait until it is ready.
func (p *Plan) unitSteps() {
	h, role := p.h, string(p.v.Role)
	name := "rpmgr-" + role
	path := filepath.Join(h.Paths.Units, name+".service")
	title := "install the unit " + path + " and start it: systemctl daemon-reload, enable --now " + name
	if p.again {
		title += ", restart " + name
	}
	p.add(title, func(ctx context.Context, r *Result) error {
		o := p.unit // as `rpmgr systemd-unit` renders it from the boot file
		o.Bin = h.Paths.Bin
		unit, err := units.Render(role, o)
		if err != nil {
			return err
		}
		if err := mkdirMode(h.Paths.Units, 0o755); err != nil { // minimal systems may lack it
			return err
		}
		r.created(path)
		if err := writeMode(path, unit, 0o644); err != nil {
			return err
		}
		if err := h.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		r.Unit = name
		if err := h.Run(ctx, "systemctl", "enable", "--now", name); err != nil || !p.again {
			return err
		}
		return h.Run(ctx, "systemctl", "restart", name) // a running role reads its new boot file
	})
	p.add("wait until "+p.admin+"/readyz reports ready", func(ctx context.Context, _ *Result) error {
		if err := h.Ready(ctx, p.admin); err != nil {
			return fmt.Errorf("%w (journalctl -u %s says why)", err, name)
		}
		return nil
	})
}

// created notes path as written by setup, unless it exists already: setup names only what it made
// for cleaning up after a failure.
func (r *Result) created(path string) {
	if !exists(path) {
		r.Written = append(r.Written, path)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// writeNew writes a file that must not exist, with mode perm whatever the umask: setup may run
// under a strict one, as install.sh's, and the service user must read what setup writes.
func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:gosec // G304: setup's own paths
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// writeMode writes a file, new or not, with mode perm whatever the umask: into a new file in its
// directory, renamed over it, so that the data never sits in a file with an older, wider mode or
// another owner, and a symbolic link in its place is replaced rather than followed.
func writeMode(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // a no-op after the rename
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// mkdirMode creates dir and its missing parents with mode perm whatever the umask (#458): a umask
// such as 027 would keep the service user out of the directories setup creates for it. A directory
// that exists keeps its mode.
func mkdirMode(dir string, perm os.FileMode) error {
	if fi, err := os.Stat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s exists and is no directory", dir)
		}
		return nil
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := mkdirMode(parent, perm); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, perm); err != nil {
		return err
	}
	return os.Chmod(dir, perm)
}

// Summary lists the choices for the confirmation, in order; the token only as given.
func (p *Plan) Summary() [][2]string {
	v := p.v
	out := [][2]string{{"role", string(v.Role)}}
	if v.Role.Initialises() {
		out = append(out, [2]string{"public URL", v.PublicURL}, [2]string{"KEK", p.kekSummary()}, [2]string{"certificate", p.tlsSummary()},
			[2]string{"ACME CA", p.acmeSummary()})
	} else {
		out = append(out, [2]string{"controller", v.ControllerURL}, [2]string{"CA pin", v.Pin}, [2]string{"token", "given (not shown)"})
	}
	if v.Role == Connector || v.Role == AllInOne {
		targets := "none yet (rpmgr policy allow-target adds them)"
		if len(v.AllowTargets) > 0 {
			targets = strings.Join(v.AllowTargets, ", ")
		}
		out = append(out, [2]string{"allowed targets", targets})
		if len(v.DenyTargets) > 0 {
			out = append(out, [2]string{"denied targets", strings.Join(v.DenyTargets, ", ")})
		}
		if v.Proxy != "" {
			out = append(out, [2]string{"proxy", redactedProxy(v.Proxy)})
		}
	}
	out = append(out, [2]string{"admin listener", p.admin})
	unit := "rpmgr-" + string(v.Role) + ", enabled and started"
	if v.NoUnit {
		unit = "none (--no-unit)"
	}
	return append(out, [2]string{"systemd unit", unit})
}

func (p *Plan) kekSummary() string {
	var doc struct {
		KEK struct{ Source, Path string } `yaml:"kek"`
	}
	_ = yaml.Unmarshal(p.data, &doc)
	if doc.KEK.Source == config.KEKFile {
		return "file " + doc.KEK.Path
	}
	return "systemd credential " + filepath.Join(p.h.Paths.Etc, "credstore", "rpmgr-kek")
}

func (p *Plan) tlsSummary() string {
	switch p.v.TLS {
	case TLSFiles:
		return "files " + p.v.CertFile + ", " + p.v.KeyFile
	case TLSACME:
		return "from the instance's ACME CA at the first start"
	}
	return "self-signed, until a certificate replaces it"
}

func (p *Plan) acmeSummary() string {
	dir, _ := Directory(p.v.ACMEDirectory)
	if dir == "" {
		dir = config.LetsEncrypt + " (the default)"
	}
	if p.v.ACMEEmail != "" {
		dir += ", account " + p.v.ACMEEmail
	}
	return dir
}
