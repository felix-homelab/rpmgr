// SPDX-License-Identifier: Apache-2.0

// Package setup is `rpmgr setup` (docs/16-cli.md; docs/10-operations.md, "Install"): the values
// that set up a host's role, their validation, and the plan of actions they give, which runs the
// existing init, enroll, policy and unit code. The form that asks for the values is the command's.
package setup

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// Role is the role a host is set up for.
type Role string

// The roles, as `rpmgr <role>` names them.
const (
	Gateway   Role = "gateway"
	Connector Role = "connector"
)

// Roles are the roles in the order the form offers them, each with one line about it.
var Roles = []struct {
	Role  Role
	About string
}{
	{Gateway, "public listeners for routes, enrolled with a gateway token"},
	{Connector, "reaches the services of its network, enrolled with an enrollment token"},
}

// Values are everything setup asks for. Empty values keep the defaults of docs/10-operations.md.
type Values struct {
	Role Role

	// Listeners (docs/10-operations.md, "Ports"); "off" disables listen.http.
	ListenTCP   string // gateway
	ListenUDP   string // gateway
	ListenHTTP  string // gateway
	ListenAdmin string

	// Gateway and connector.
	ControllerURL string
	Pin           string
	Token         string   // the enrollment or gateway token; never shown, logged or passed as an argument
	AllowTargets  []string // connector: the connector-local policy's targets
	Proxy         string   // connector: HTTPS_PROXY of its service

	NoUnit bool // install no systemd unit and start nothing
	Force  bool // replace an existing boot file, or an agent's identity
}

// CheckRole checks a role's name.
func CheckRole(s string) error {
	for _, r := range Roles {
		if string(r.Role) == s {
			return nil
		}
	}
	return fmt.Errorf("no role %q: gateway or connector", s)
}

// CheckControllerURL checks the controller URL an agent enrolls with: https://<host>[:<port>],
// nothing more.
func CheckControllerURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return fmt.Errorf("%q: want https://<host>[:<port>]", s)
	}
	return nil
}

// CheckPin checks a CA pin as `rpmgr enroll --ca-pin` takes it.
func CheckPin(s string) error {
	if !pki.ValidPin(s) {
		return errors.New("want sha256:<base64>, as `rpmgr controller init` printed it")
	}
	return nil
}

// CheckToken checks the token of an agent's enrollment; it never repeats the token.
func CheckToken(s string) error {
	if k, err := token.Parse(strings.TrimSpace(s)); err != nil || k != token.Enrollment {
		return errors.New("not an enrollment or gateway token (rpmgr_enr_…), or mistyped")
	}
	return nil
}

// CheckTarget checks one connector-local policy target: ip:port, [ipv6]:port or a socket path.
func CheckTarget(s string) error { return policy.CheckTarget(s) }

// CheckAddr checks a listen address host:port; with off, "off" is allowed and disables it.
func CheckAddr(s string, off bool) error {
	if s == "" || (off && s == "off") {
		return nil
	}
	if _, port, err := net.SplitHostPort(s); err != nil || port == "" {
		return fmt.Errorf("%q: want [host]:port", s)
	}
	return nil
}

// CheckProxy checks a proxy URL: http, https or socks5.
func CheckProxy(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
		return fmt.Errorf("%q: want http://, https:// or socks5://<host>:<port>", s)
	}
	return nil
}

// check returns every problem of the values for their role, joined.
func (v *Values) check() error {
	var errs []error
	add := func(what string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", what, err))
		}
	}
	add("role", CheckRole(string(v.Role)))
	add("listen.admin", CheckAddr(v.ListenAdmin, false))
	add("listen.http", CheckAddr(v.ListenHTTP, true))
	add("listen.tcp", CheckAddr(v.ListenTCP, false))
	add("listen.udp", CheckAddr(v.ListenUDP, false))
	if v.Role == Connector && (v.ListenTCP != "" || v.ListenUDP != "" || v.ListenHTTP != "") {
		errs = append(errs, errors.New("a connector has no listen.tcp, listen.udp or listen.http"))
	}
	if v.Role == "" {
		return errors.Join(errs...)
	}
	add("controller URL", CheckControllerURL(v.ControllerURL))
	add("CA pin", CheckPin(v.Pin))
	add("token", CheckToken(v.Token))
	if v.Role == Connector {
		for _, t := range v.AllowTargets {
			add("allowed target", CheckTarget(t))
		}
		add("proxy", CheckProxy(v.Proxy))
	} else if len(v.AllowTargets) > 0 || v.Proxy != "" {
		errs = append(errs, errors.New("allowed targets and a proxy are a connector's"))
	}
	return errors.Join(errs...)
}
