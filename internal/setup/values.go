// SPDX-License-Identifier: Apache-2.0

// Package setup is `rpmgr setup` (docs/16-cli.md; docs/10-operations.md, "Install"): the values
// that set up a host's role, their validation, and the plan of actions they give, which runs the
// existing init, enroll, policy and unit code. The form that asks for the values is the command's.
package setup

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// Role is the role a host is set up for.
type Role string

// The roles, as `rpmgr <role>` names them.
const (
	AllInOne   Role = "all-in-one"
	Controller Role = "controller"
	Gateway    Role = "gateway"
	Connector  Role = "connector"
)

// Roles are the roles in the order the form offers them, each with one line about it.
var Roles = []struct {
	Role  Role
	About string
}{
	{AllInOne, "controller, gateway and connector in one process: the homelab default"},
	{Controller, "web UI, API, CA and configuration, with gateways on other hosts"},
	{Gateway, "public listeners for routes, enrolled with a gateway token"},
	{Connector, "reaches the services of its network, enrolled with an enrollment token"},
}

// The certificate of a controller's public URL.
const (
	TLSACME       = "acme"        // ordered from the instance's ACME CA at the first start
	TLSFiles      = "files"       // the operator's certificate and key files
	TLSSelfSigned = "self-signed" // a certificate no browser trusts, until the operator switches
)

// StagingDirectory is Let's Encrypt's staging ACME directory, whose certificates no browser trusts.
const StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// Values are everything setup asks for. Empty values keep the defaults of docs/10-operations.md.
type Values struct {
	Role Role

	// Controller and all-in-one.
	PublicURL         string
	KEKSource         string // systemd-credential or file; empty picks by the systemd version
	KEKPath           string // with the file source; default <etc>/kek
	TLS               string // acme, files or self-signed
	CertFile, KeyFile string // with files
	ACMEDirectory     string // production, staging or an https URL; empty keeps the instance's
	ACMEEmail         string

	// Listeners (docs/10-operations.md, "Ports"); "off" disables listen.http.
	ListenHTTPS string // controller
	ListenTCP   string // all-in-one and gateway
	ListenUDP   string // all-in-one and gateway
	ListenHTTP  string // controller, all-in-one and gateway
	ListenAdmin string

	// Gateway and connector.
	ControllerURL string
	Pin           string
	Token         string   // the enrollment or gateway token; never shown, logged or passed as an argument
	AllowTargets  []string // connector: the connector-local policy's allow_targets
	DenyTargets   []string // connector: its deny_targets, which win over allow_targets (D84)
	Proxy         string   // connector: HTTPS_PROXY of its service

	NoUnit bool // install no systemd unit and start nothing
	Force  bool // replace an existing boot file, or an agent's identity
}

// Initialises reports whether the role initialises a controller, rather than enrolling an agent.
func (r Role) Initialises() bool { return r == AllInOne || r == Controller }

// CheckRole checks a role's name.
func CheckRole(s string) error {
	for _, r := range Roles {
		if string(r.Role) == s {
			return nil
		}
	}
	return fmt.Errorf("no role %q: all-in-one, controller, gateway or connector", s)
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

// CheckPublicURL checks a controller's public URL, as CheckControllerURL does.
func CheckPublicURL(s string) error { return CheckControllerURL(s) }

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

// CheckTarget checks one connector-local policy target: an address or subnet with an optional port
// or port range, IPv6 in brackets, or a socket path.
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

// CheckProxy checks a proxy URL as the connector reads it (connector.ProxyDialer): an http:// URL
// (HTTP CONNECT) or a socks5:// or socks5h:// URL with a host, with optional credentials. It also
// refuses what the systemd environment file it goes into would read differently. Its errors never
// repeat the URL, which may hold a password.
func CheckProxy(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "socks5" && u.Scheme != "socks5h") {
		return errors.New("the proxy is not an http://, socks5:// or socks5h:// URL with a host")
	}
	if strings.ContainsAny(s, "\"'\\ \t\r\n") {
		return errors.New("the proxy URL holds a quote, a backslash or white space: percent-encode them")
	}
	return nil
}

// CheckEmail checks the ACME account's address; empty is allowed.
func CheckEmail(s string) error {
	if s == "" {
		return nil
	}
	if a, err := mail.ParseAddress(s); err != nil || a.Address != s {
		return fmt.Errorf("%q is not an e-mail address", s)
	}
	return nil
}

// Directory returns the ACME directory URL of a name: production, staging or a URL.
func Directory(s string) (string, error) {
	switch s {
	case "":
		return "", nil
	case "production":
		return settings.LetsEncrypt, nil
	case "staging":
		return StagingDirectory, nil
	}
	if u, err := url.Parse(s); err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("ACME directory %q: want production, staging or an https URL", s)
	}
	return s, nil
}

// PublicHost returns the host of a public URL and whether a public CA can certify it.
func PublicHost(publicURL string) (string, bool) {
	u, err := url.Parse(publicURL)
	if err != nil {
		return "", false
	}
	return u.Hostname(), acme.Eligible(u.Hostname())
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
	add("listen.https", CheckAddr(v.ListenHTTPS, false))
	add("listen.tcp", CheckAddr(v.ListenTCP, false))
	add("listen.udp", CheckAddr(v.ListenUDP, false))
	if v.Role == Connector && (v.ListenTCP != "" || v.ListenUDP != "" || v.ListenHTTP != "") {
		errs = append(errs, errors.New("a connector has no listen.tcp, listen.udp or listen.http"))
	}
	if v.ListenHTTPS != "" && v.Role != Controller {
		errs = append(errs, errors.New("listen.https is a controller's; an all-in-one or gateway has listen.tcp and listen.udp"))
	}
	if v.Role == Controller && (v.ListenTCP != "" || v.ListenUDP != "") {
		errs = append(errs, errors.New("listen.tcp and listen.udp are an all-in-one's or a gateway's; a controller has listen.https"))
	}
	if v.Role.Initialises() {
		v.checkController(add)
		return errors.Join(errs...)
	}
	if v.Role == "" {
		return errors.Join(errs...)
	}
	if v.PublicURL != "" || v.KEKSource != "" || v.KEKPath != "" || v.TLS != "" || v.CertFile != "" || v.KeyFile != "" ||
		v.ACMEDirectory != "" || v.ACMEEmail != "" {
		errs = append(errs, errors.New("a public URL and the KEK, TLS and ACME values are a controller's or an all-in-one's"))
	}
	add("controller URL", CheckControllerURL(v.ControllerURL))
	add("CA pin", CheckPin(v.Pin))
	add("token", CheckToken(v.Token))
	if v.Role == Connector {
		for _, t := range v.AllowTargets {
			add("allowed target", CheckTarget(t))
		}
		for _, t := range v.DenyTargets {
			add("denied target", CheckTarget(t))
		}
		add("proxy", CheckProxy(v.Proxy))
	} else if len(v.AllowTargets) > 0 || len(v.DenyTargets) > 0 || v.Proxy != "" {
		errs = append(errs, errors.New("allowed and denied targets and a proxy are a connector's"))
	}
	return errors.Join(errs...)
}

// checkController checks the values of a controller or all-in-one; an all-in-one's connector takes
// allowed and denied targets too.
func (v *Values) checkController(add func(string, error)) {
	add("public URL", CheckPublicURL(v.PublicURL))
	if v.ControllerURL != "" || v.Pin != "" || v.Token != "" || v.Proxy != "" {
		add("values", errors.New("a controller URL, CA pin, token and a proxy are a gateway's or a connector's"))
	}
	if v.Role == AllInOne {
		for _, t := range v.AllowTargets {
			add("allowed target", CheckTarget(t))
		}
		for _, t := range v.DenyTargets {
			add("denied target", CheckTarget(t))
		}
	} else if len(v.AllowTargets) > 0 || len(v.DenyTargets) > 0 {
		add("values", errors.New("allowed and denied targets are a connector's or an all-in-one's"))
	}
	if v.KEKSource != "" && v.KEKSource != config.KEKFile && v.KEKSource != config.KEKSystemdCredential {
		add("KEK source", fmt.Errorf("%q: want systemd-credential or file", v.KEKSource))
	}
	_, err := Directory(v.ACMEDirectory)
	add("ACME directory", err)
	add("ACME e-mail", CheckEmail(v.ACMEEmail))
	switch host, public := PublicHost(v.PublicURL); v.TLS {
	case TLSACME:
		if !public && v.PublicURL != "" {
			add("TLS", fmt.Errorf("%s cannot have a certificate from a public CA; choose files or self-signed", host))
		}
	case TLSFiles:
		if v.CertFile == "" || v.KeyFile == "" {
			add("TLS", errors.New("files needs the certificate and the key file"))
		}
	case TLSSelfSigned:
	default:
		add("TLS", fmt.Errorf("%q: want acme, files or self-signed", v.TLS))
	}
}
