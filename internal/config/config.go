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
	Log Log `yaml:"log"`
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
		checkAdmin(c.Listen.Admin), checkLog(c.Log)}
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
	} `yaml:"controller"`
	IdentityDir string `yaml:"identity_dir"`
	StateDir    string `yaml:"state_dir"`
	Log         Log    `yaml:"log"`
}

func (a *Agent) defaults() {
	setDefault(&a.IdentityDir, "/var/lib/rpmgr/identity")
	setDefault(&a.StateDir, "/var/lib/rpmgr")
}

func (a *Agent) validate() error {
	errs := []error{checkVersion(a.Version), checkLog(a.Log),
		checkAbs("identity_dir", a.IdentityDir), checkAbs("state_dir", a.StateDir)}
	if len(a.Controller.Endpoints) == 0 {
		errs = append(errs, errors.New("controller.endpoints: at least one controller URL is needed"))
	}
	for i, e := range a.Controller.Endpoints {
		errs = append(errs, checkURL(fmt.Sprintf("controller.endpoints[%d]", i), e))
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
	return errors.Join(g.Agent.validate(), checkAddr("listen.tcp", g.Listen.TCP, false),
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
	return errors.Join(c.Agent.validate(), checkAbs("policy_file", c.PolicyFile),
		checkAdmin(c.Listen.Admin))
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
