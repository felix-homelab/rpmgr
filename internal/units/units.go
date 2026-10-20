// SPDX-License-Identifier: Apache-2.0

// Package units writes the hardened systemd units of the four roles (docs/10-operations.md,
// "Hardened systemd units").
package units

import (
	"bytes"
	_ "embed"
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"text/template"

	"github.com/felix-homelab/rpmgr/internal/config"
)

//go:embed rpmgr.service.tmpl
var text string

var unit = template.Must(template.New("unit").Parse(text))

// Options vary a role's unit.
type Options struct {
	// Bin is the binary's absolute path: /usr/local/bin/rpmgr for script installs.
	Bin string
	// Credential, for the controller and all-in-one, names the systemd credential that holds the
	// KEK; empty when the KEK is a file.
	Credential string
	// Writable are directories outside the state directory that the role writes, such as the
	// revocation-log sink of a controller or all-in-one. Each becomes ReadWritePaths= with "-", so
	// that one missing at the start, such as a share not mounted yet, does not keep the role from
	// starting.
	Writable []string
}

// ForController returns the options that a controller's boot file, or an all-in-one's, decides:
// the KEK's systemd credential and the revocation-log sink. The caller sets Bin.
func ForController(c config.Controller) Options {
	var o Options
	if c.KEK.Source == config.KEKSystemdCredential {
		o.Credential = c.KEK.Name
	}
	if c.RevocationLog.Sink != "" {
		o.Writable = []string{c.RevocationLog.Sink}
	}
	return o
}

var (
	credentialRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	binRe        = regexp.MustCompile(`^/[^\s%$\\]+$`)
	// A writable directory holds nothing that systemd splits, unquotes or expands in
	// ReadWritePaths=: whitespace or another control character, %, a backslash or a quote.
	writableRe = regexp.MustCompile(`^/[^\x00-\x20\x7f%\\"']+$`)
)

// Render returns the unit of a role: controller, gateway, connector or all-in-one.
func Render(role string, o Options) ([]byte, error) {
	data := struct {
		Role, Bin, Credential string
		BindLow, Reload       bool
		Writable              []string
	}{Role: role, Bin: o.Bin, Credential: o.Credential}
	switch role {
	case "controller", "gateway":
		data.BindLow = true // ports 443 and 80
	case "all-in-one":
		data.BindLow, data.Reload = true, true // and rpmgr policy reloads its connector
	case "connector":
		data.Reload, data.Credential = true, "" // rpmgr policy reloads it; it binds no low port
	default:
		return nil, fmt.Errorf("units: no role %q", role)
	}
	if role == "gateway" {
		data.Credential = ""
	}
	if !binRe.MatchString(o.Bin) {
		return nil, fmt.Errorf("units: the binary path %q must be absolute, without spaces, %%, $ or \\", o.Bin)
	}
	if data.Credential != "" && !credentialRe.MatchString(data.Credential) {
		return nil, fmt.Errorf("units: credential name %q", data.Credential)
	}
	for _, p := range o.Writable {
		w, err := writable(p)
		if err != nil {
			return nil, err
		}
		data.Writable = append(data.Writable, w)
	}
	var b bytes.Buffer
	if err := unit.Execute(&b, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// writable returns a writable directory as the unit names it, without a trailing or doubled
// slash. It refuses a directory that systemd would read differently, ignore as not normalised
// (with a . or .. part), or that is the root, which would leave nothing read-only.
func writable(p string) (string, error) {
	clean := path.Clean(p)
	if !writableRe.MatchString(p) || clean == "/" || strings.Contains(p+"/", "/./") || strings.Contains(p+"/", "/../") {
		return "", fmt.Errorf("units: the writable directory %q must be absolute and below /, without . or .. parts, "+
			"whitespace, control characters, %%, \\ or quotes", p)
	}
	return clean, nil
}

// SystemdVersion returns the version systemctl reports, or 0 without systemd.
func SystemdVersion() int {
	out, err := exec.Command("systemctl", "--version").Output()
	if err != nil {
		return 0
	}
	var v int
	if _, err := fmt.Sscanf(string(out), "systemd %d", &v); err != nil {
		return 0
	}
	return v
}
