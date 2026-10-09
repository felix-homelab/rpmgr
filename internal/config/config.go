// SPDX-License-Identifier: Apache-2.0

// Package config reads the boot files of every role (docs/10-operations.md, "Boot files"): strict
// YAML with only what a process needs before its database or its control session is available.
// Everything else is a runtime setting in the database or comes with a snapshot.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// Version is the boot-file format this binary reads.
const Version = 1

// maxSize bounds a boot file; the largest is a few hundred bytes.
const maxSize = 64 << 10

// Path returns the boot file of a role: the --config flag if set, else $RPMGR_CONFIG, else
// /etc/rpmgr/<role>.yaml.
func Path(flag, role string, getenv func(string) string) string {
	if flag != "" {
		return flag
	}
	if p := getenv("RPMGR_CONFIG"); p != "" {
		return p
	}
	return "/etc/rpmgr/" + role + ".yaml"
}

// File is a role's boot file.
type File interface {
	defaults()
	validate() error
}

// Load reads the boot file at path into f; see Parse.
func Load(path string, f File) error {
	fh, err := os.Open(path) //nolint:gosec // G304: the path is the operator's --config or RPMGR_CONFIG
	if err != nil {
		return err
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, maxSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxSize {
		return fmt.Errorf("config: %s is larger than %d bytes", path, maxSize)
	}
	if err := Parse(data, f); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Parse decodes one YAML document into f strictly: an unknown key, a second document or a version
// other than Version is refused. Then unset values get their defaults and f is validated.
func Parse(data []byte, f File) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(f); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("config: the file is empty")
		}
		return fmt.Errorf("config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("config: more than one YAML document")
	}
	f.defaults()
	return f.validate()
}

// Log is the logging section of every role.
type Log = telemetry.LogConfig

// Tracing is the tracing section of every role's boot file (docs/10-operations.md, "Traces").
type Tracing = telemetry.TracingConfig

// Controller is /etc/rpmgr/controller.yaml.
type Controller struct {
	Version   int    `yaml:"version"`
	PublicURL string `yaml:"public_url"`
	Listen    struct {
		HTTPS string  `yaml:"https"`
		HTTP  *string `yaml:"http"` // "" disables
		Admin string  `yaml:"admin"`
	} `yaml:"listen"`
	Database struct {
		Driver string `yaml:"driver"`
		DSN    string `yaml:"dsn"`
	} `yaml:"database"`
	KEK struct {
		Source string `yaml:"source"`
		Name   string `yaml:"name"` // systemd-credential
		Path   string `yaml:"path"` // file
	} `yaml:"kek"`
	// TLS is the certificate of the public URL from files; without it, ACME obtains one.
	TLS struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls"`
	Log           Log           `yaml:"log"`
	Tracing       Tracing       `yaml:"tracing"`
	RevocationLog RevocationLog `yaml:"revocation_log"`
}

// RevocationLog is where the revocation log keeps a copy off the host (docs/10-operations.md,
// "Backup and restore"): a directory, usually a share mounted on every controller host.
type RevocationLog struct {
	Sink string `yaml:"sink"` // empty for none: a single node keeps only its local log
}

func (r RevocationLog) check() error {
	if r.Sink == "" {
		return nil
	}
	return checkAbs("revocation_log.sink", r.Sink)
}

// The KEK sources of Phase 1 (docs/04-security.md, "Secrets at rest and in logs").
const (
	KEKSystemdCredential = "systemd-credential" //nolint:gosec // G101: the name of a source, not a credential
	KEKFile              = "file"
)

func (c *Controller) defaults() {
	setDefault(&c.Listen.HTTPS, ":443")
	setDefaultPtr(&c.Listen.HTTP, ":80")
	setDefault(&c.Listen.Admin, "127.0.0.1:7381")
	setDefault(&c.Database.Driver, "sqlite")
	setDefault(&c.Database.DSN, "/var/lib/rpmgr/controller.db")
	setDefault(&c.KEK.Source, KEKSystemdCredential)
	if c.KEK.Source == KEKSystemdCredential {
		setDefault(&c.KEK.Name, "rpmgr-kek")
	}
}

var credentialNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

var portRe = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)

func (c *Controller) validate() error {
	errs := []error{checkVersion(c.Version), checkURL("public_url", c.PublicURL),
		checkAddr("listen.https", c.Listen.HTTPS, false), checkAddr("listen.http", *c.Listen.HTTP, true),
		checkAdmin(c.Listen.Admin), checkLog(c.Log), c.Tracing.Check(), c.RevocationLog.check()}
	switch c.Database.Driver {
	case "sqlite":
		if !filepath.IsAbs(c.Database.DSN) || strings.ContainsAny(c.Database.DSN, "?#%") {
			errs = append(errs, fmt.Errorf("database.dsn %q: want an absolute path without '?', '#' or '%%'", c.Database.DSN))
		}
	case "postgres":
		errs = append(errs, errors.New("database.driver: postgres comes with Phase 2 (D57); use sqlite"))
	default:
		errs = append(errs, fmt.Errorf("database.driver %q: want sqlite", c.Database.Driver))
	}
	switch {
	case c.TLS.CertFile == "" && c.TLS.KeyFile == "":
	case c.TLS.CertFile == "" || c.TLS.KeyFile == "":
		errs = append(errs, errors.New("tls: cert_file and key_file go together"))
	default:
		errs = append(errs, checkAbs("tls.cert_file", c.TLS.CertFile), checkAbs("tls.key_file", c.TLS.KeyFile))
	}
	switch c.KEK.Source {
	case KEKSystemdCredential:
		if !credentialNameRe.MatchString(c.KEK.Name) || c.KEK.Path != "" {
			errs = append(errs, fmt.Errorf("kek: systemd-credential needs a credential name (letters, digits, '_', '.', '-') and no path"))
		}
	case KEKFile:
		if !filepath.IsAbs(c.KEK.Path) || c.KEK.Name != "" {
			errs = append(errs, fmt.Errorf("kek: file needs an absolute path and no name"))
		}
	case "kms":
		errs = append(errs, errors.New("kek.source: kms comes with Phase 2"))
	default:
		errs = append(errs, fmt.Errorf("kek.source %q: want systemd-credential or file; a KEK is never read from the environment", c.KEK.Source))
	}
	return errors.Join(errs...)
}

// Agent is the part the gateway and connector boot files share.
type Agent struct {
	Version    int `yaml:"version"`
	Controller struct {
		Endpoints []string `yaml:"endpoints"`
		// Passthrough is for gateways only.
		Passthrough Passthrough `yaml:"passthrough"`
	} `yaml:"controller"`
	IdentityDir string  `yaml:"identity_dir"`
	StateDir    string  `yaml:"state_dir"`
	Log         Log     `yaml:"log"`
	Tracing     Tracing `yaml:"tracing"`
}

func (a *Agent) defaults() {
	setDefault(&a.IdentityDir, "/var/lib/rpmgr/identity")
	setDefault(&a.StateDir, "/var/lib/rpmgr")
}

func (a *Agent) validate() error {
	errs := []error{checkVersion(a.Version), checkLog(a.Log), a.Tracing.Check(),
		checkAbs("identity_dir", a.IdentityDir), checkAbs("state_dir", a.StateDir)}
	if len(a.Controller.Endpoints) == 0 {
		errs = append(errs, errors.New("controller.endpoints: at least one controller URL is needed"))
	}
	for i, e := range a.Controller.Endpoints {
		errs = append(errs, checkURL(fmt.Sprintf("controller.endpoints[%d]", i), e))
	}
	return errors.Join(errs...)
}

// Passthrough publishes a private controller through a gateway (docs/03-connections.md, "Reaching
// a private controller"): the gateway forwards the controller's names, still encrypted, to Address.
type Passthrough struct {
	// Address is host:port of the controller's port 443, reached from the gateway directly; ""
	// forwards nothing.
	Address string `yaml:"address"`
	// Hostnames are the controller's UI hostnames; the agent names controller.<td> and
	// reauth.controller.<td> are always forwarded.
	Hostnames []string `yaml:"hostnames"`
}

func (p Passthrough) validate() error {
	if p.Address == "" {
		if len(p.Hostnames) > 0 {
			return errors.New("controller.passthrough.hostnames: they need controller.passthrough.address")
		}
		return nil
	}
	errs := []error{checkHostPort("controller.passthrough.address", p.Address)}
	for i, h := range p.Hostnames {
		errs = append(errs, checkHostname(fmt.Sprintf("controller.passthrough.hostnames[%d]", i), h))
	}
	return errors.Join(errs...)
}

// Gateway is /etc/rpmgr/gateway.yaml.
type Gateway struct {
	Agent  `yaml:",inline"`
	Listen struct {
		TCP       string  `yaml:"tcp"`
		UDP       string  `yaml:"udp"`
		TunnelUDP string  `yaml:"tunnel_udp"` // "": tunnels share listen.udp
		HTTP      *string `yaml:"http"`       // "" disables
		Admin     string  `yaml:"admin"`
	} `yaml:"listen"`
}

func (g *Gateway) defaults() {
	g.Agent.defaults()
	setDefault(&g.Listen.TCP, ":443")
	setDefault(&g.Listen.UDP, ":443")
	setDefaultPtr(&g.Listen.HTTP, ":80")
	setDefault(&g.Listen.Admin, "127.0.0.1:7382")
}

func (g *Gateway) validate() error {
	return errors.Join(g.Agent.validate(), g.Controller.Passthrough.validate(), checkAddr("listen.tcp", g.Listen.TCP, false),
		checkAddr("listen.udp", g.Listen.UDP, false), checkAddr("listen.tunnel_udp", g.Listen.TunnelUDP, true),
		checkAddr("listen.http", *g.Listen.HTTP, true), checkAdmin(g.Listen.Admin))
}

// Connector is /etc/rpmgr/connector.yaml.
type Connector struct {
	Agent      `yaml:",inline"`
	PolicyFile string `yaml:"policy_file"`
	Listen     struct {
		Admin string `yaml:"admin"`
	} `yaml:"listen"`
}

func (c *Connector) defaults() {
	c.Agent.defaults()
	setDefault(&c.PolicyFile, "/etc/rpmgr/policy.yaml")
	setDefault(&c.Listen.Admin, "127.0.0.1:7383")
}

func (c *Connector) validate() error {
	var errs []error
	if p := c.Controller.Passthrough; p.Address != "" || len(p.Hostnames) > 0 {
		errs = append(errs, errors.New("controller.passthrough: only a gateway forwards to a private controller"))
	}
	return errors.Join(append(errs, c.Agent.validate(), checkAbs("policy_file", c.PolicyFile),
		checkAdmin(c.Listen.Admin))...)
}

// AllInOne is /etc/rpmgr/all-in-one.yaml: a controller and a gateway in one process
// (docs/02-architecture.md, "All-in-one"). The controller is reached through the gateway's port
// 443; the gateway's identity and state live under state_dir.
type AllInOne struct {
	Version   int    `yaml:"version"`
	PublicURL string `yaml:"public_url"`
	Listen    struct {
		TCP       string  `yaml:"tcp"`
		UDP       string  `yaml:"udp"`
		TunnelUDP string  `yaml:"tunnel_udp"`
		HTTP      *string `yaml:"http"`
		Admin     string  `yaml:"admin"`
	} `yaml:"listen"`
	Database struct {
		Driver string `yaml:"driver"`
		DSN    string `yaml:"dsn"`
	} `yaml:"database"`
	KEK struct {
		Source string `yaml:"source"`
		Name   string `yaml:"name"`
		Path   string `yaml:"path"`
	} `yaml:"kek"`
	TLS struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls"`
	StateDir      string        `yaml:"state_dir"`
	Log           Log           `yaml:"log"`
	Tracing       Tracing       `yaml:"tracing"`
	RevocationLog RevocationLog `yaml:"revocation_log"`
}

func (a *AllInOne) defaults() {
	setDefault(&a.Listen.TCP, ":443")
	setDefault(&a.Listen.UDP, ":443")
	setDefaultPtr(&a.Listen.HTTP, ":80")
	setDefault(&a.Listen.Admin, "127.0.0.1:7381")
	setDefault(&a.StateDir, "/var/lib/rpmgr")
	setDefault(&a.Database.Driver, "sqlite")
	setDefault(&a.Database.DSN, "/var/lib/rpmgr/controller.db")
	setDefault(&a.KEK.Source, KEKSystemdCredential)
	if a.KEK.Source == KEKSystemdCredential {
		setDefault(&a.KEK.Name, "rpmgr-kek")
	}
}

func (a *AllInOne) validate() error {
	c, g := a.Controller(), a.Gateway()
	return errors.Join(checkAbs("state_dir", a.StateDir), c.validate(), g.validate())
}

// Controller is the controller part of the file; its ports 443 and 80 are the gateway's.
func (a *AllInOne) Controller() Controller {
	var c Controller
	c.Version, c.PublicURL, c.Log, c.Tracing = a.Version, a.PublicURL, a.Log, a.Tracing
	none := ""
	c.Listen.HTTPS, c.Listen.HTTP, c.Listen.Admin = a.Listen.TCP, &none, a.Listen.Admin
	c.Database.Driver, c.Database.DSN = a.Database.Driver, a.Database.DSN
	c.KEK.Source, c.KEK.Name, c.KEK.Path = a.KEK.Source, a.KEK.Name, a.KEK.Path
	c.TLS.CertFile, c.TLS.KeyFile = a.TLS.CertFile, a.TLS.KeyFile
	c.RevocationLog = a.RevocationLog
	return c
}

// Gateway is the gateway part of the file: its identity in <state_dir>/gateway/identity, its
// state in <state_dir>/gateway, the controller at the public URL. Port 80 is the gateway's too: it
// serves the http routes there and redirects every other name as the controller would.
func (a *AllInOne) Gateway() Gateway {
	var g Gateway
	g.Version, g.Log, g.Tracing = a.Version, a.Log, a.Tracing
	g.Controller.Endpoints = []string{a.PublicURL}
	g.StateDir = filepath.Join(a.StateDir, "gateway")
	g.IdentityDir = filepath.Join(g.StateDir, "identity")
	g.Listen.TCP, g.Listen.UDP, g.Listen.TunnelUDP, g.Listen.Admin = a.Listen.TCP, a.Listen.UDP, a.Listen.TunnelUDP, a.Listen.Admin
	g.Listen.HTTP = a.Listen.HTTP
	return g
}

func setDefault(s *string, v string) {
	if *s == "" {
		*s = v
	}
}

func setDefaultPtr(s **string, v string) {
	if *s == nil {
		*s = &v
	}
}

func checkVersion(v int) error {
	if v != Version {
		return fmt.Errorf("version: %d is not supported; this binary reads version %d", v, Version)
	}
	return nil
}

// checkURL accepts an https URL with a host and nothing else: no user, path, query or fragment.
func checkURL(key, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("%s %q: want https://<host>[:<port>]", key, raw)
	}
	return nil
}

// checkAddr accepts host:port with a port from 1 to 65535, and "" only where it disables a listener.
func checkAddr(key, addr string, mayBeEmpty bool) error {
	if addr == "" && mayBeEmpty {
		return nil
	}
	_, port, err := net.SplitHostPort(addr)
	if n, perr := strconv.Atoi(port); err != nil || perr != nil || !portRe.MatchString(port) || n < 1 || n > 65535 {
		return fmt.Errorf("%s %q: want [host]:port", key, addr)
	}
	return nil
}

// checkHostPort accepts host:port with a host and a port from 1 to 65535.
func checkHostPort(key, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" || checkAddr(key, addr, false) != nil {
		return fmt.Errorf("%s %q: want host:port", key, addr)
	}
	return nil
}

// hostnameRe is a DNS name of at least two letter-digit-hyphen labels, in lower case; an
// internationalised name is written in its ASCII (xn--) form.
var hostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// checkHostname accepts a DNS name as hostnameRe has it, up to 253 characters, that is not an IP
// address.
func checkHostname(key, name string) error {
	if len(name) > 253 || !hostnameRe.MatchString(name) || net.ParseIP(name) != nil {
		return fmt.Errorf("%s %q: want a lower-case DNS name such as panel.example.com", key, name)
	}
	return nil
}

// checkAdmin checks the admin listener's address: [host]:port, and never public.
func checkAdmin(addr string) error {
	if err := checkAddr("listen.admin", addr, false); err != nil {
		return err
	}
	if err := telemetry.CheckAdminAddr(addr); err != nil {
		return fmt.Errorf("listen.admin: %w", err)
	}
	return nil
}

func checkAbs(key, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s %q: want an absolute path", key, path)
	}
	return nil
}

func checkLog(l Log) error {
	if _, err := telemetry.NewLogger(io.Discard, l); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	return nil
}
