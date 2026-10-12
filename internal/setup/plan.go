// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"go.yaml.in/yaml/v3"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/units"
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
	admin  string // the admin listener
	policy string // the connector-local policy file
}

type step struct {
	title string
	run   func(ctx context.Context, r *Result) error
}

// Result is what setup did, and what the operator needs next.
type Result struct {
	// Gateway and connector: the enrolled identity.
	AgentID, AgentKind string
	Unit               string // the unit setup installed and started; empty without one
	Admin              string // the admin listener
	// Written are the files and directories setup created, for cleaning up after a failure.
	Written []string
}

// New checks the values against the host and returns the plan, or every problem it found.
func New(v Values, h Host) (*Plan, error) {
	h.defaults()
	if err := v.check(); err != nil {
		return nil, err
	}
	if !h.IsRoot() {
		return nil, errors.New("setup: run it as root (sudo rpmgr setup)")
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
	p.agentSteps()
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

// hostChecks refuses what setup must not overwrite, and what the host cannot do.
func (p *Plan) hostChecks() error {
	v, h := p.v, p.h
	var errs []error
	if p.again && !v.Force {
		errs = append(errs, fmt.Errorf("%s exists; setup replaces it only with --force (keeping the old one beside it)", p.boot))
	}
	if _, err := os.Lstat(filepath.Join(h.Paths.Lib, "identity", agent.ChainFile)); err == nil && !v.Force {
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
			return os.MkdirAll(h.Paths.Etc, 0o755) //nolint:gosec // G301: boot files are not secret (docs/10-operations.md)
		})
	}
	if _, err := os.Stat(h.Paths.Lib); err != nil {
		p.add("create "+h.Paths.Lib+", owned by "+ServiceUser, func(_ context.Context, r *Result) error {
			r.Written = append(r.Written, h.Paths.Lib)
			if err := os.MkdirAll(h.Paths.Lib, 0o750); err != nil {
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

// agentSteps enroll a gateway or connector through `rpmgr enroll`'s code, then write its files.
func (p *Plan) agentSteps() {
	v, h := p.v, p.h
	identity := filepath.Join(h.Paths.Lib, "identity")
	p.add("enroll with "+v.ControllerURL, func(ctx context.Context, r *Result) error {
		fresh := !exists(identity)
		host, _ := os.Hostname()
		id, err := h.Enroll(ctx, agent.EnrollOptions{Controller: v.ControllerURL, Pin: v.Pin, Token: strings.TrimSpace(v.Token),
			IdentityDir: identity, Replace: v.Force, Version: version.Version,
			Host: &agentv1.HostFacts{Hostname: host, Os: runtime.GOOS, Arch: runtime.GOARCH}})
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
	if len(v.AllowTargets) > 0 {
		p.add(fmt.Sprintf("allow %d target(s) in the connector-local policy %s", len(v.AllowTargets), p.policy),
			func(_ context.Context, r *Result) error {
				r.created(p.policy)
				for _, t := range v.AllowTargets {
					if _, err := policy.AllowTarget(p.policy, t); err != nil {
						return err
					}
				}
				return nil
			})
	}
	if v.Proxy != "" {
		dropIn := filepath.Join(h.Paths.Units, "rpmgr-connector.service.d", "proxy.conf")
		p.add("set the connector's proxy in "+dropIn, func(_ context.Context, r *Result) error {
			if err := os.MkdirAll(filepath.Dir(dropIn), 0o755); err != nil { //nolint:gosec // G301: a unit directory
				return err
			}
			r.created(dropIn)
			unit := fmt.Sprintf("[Service]\nEnvironment=\"HTTPS_PROXY=%s\"\n", v.Proxy)
			return os.WriteFile(dropIn, []byte(unit), 0o644) //nolint:gosec // G306: units are world-readable
		})
	}
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
		unit, err := units.Render(role, units.Options{Bin: h.Paths.Bin})
		if err != nil {
			return err
		}
		if err := os.MkdirAll(h.Paths.Units, 0o755); err != nil { //nolint:gosec // G301: minimal systems may lack it
			return err
		}
		r.created(path)
		if err := os.WriteFile(path, unit, 0o644); err != nil { //nolint:gosec // G306: units are world-readable
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

// writeNew writes a file that must not exist.
func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:gosec // G304: setup's own paths
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Summary lists the choices for the confirmation, in order; the token only as given.
func (p *Plan) Summary() [][2]string {
	v := p.v
	out := [][2]string{{"role", string(v.Role)},
		{"controller", v.ControllerURL}, {"CA pin", v.Pin}, {"token", "given (not shown)"}}
	if v.Role == Connector {
		targets := "none yet (rpmgr policy allow-target adds them)"
		if len(v.AllowTargets) > 0 {
			targets = strings.Join(v.AllowTargets, ", ")
		}
		out = append(out, [2]string{"allowed targets", targets})
		if v.Proxy != "" {
			out = append(out, [2]string{"proxy", v.Proxy})
		}
	}
	out = append(out, [2]string{"admin listener", p.admin})
	unit := "rpmgr-" + string(v.Role) + ", enabled and started"
	if v.NoUnit {
		unit = "none (--no-unit)"
	}
	return append(out, [2]string{"systemd unit", unit})
}
