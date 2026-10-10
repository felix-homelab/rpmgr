// SPDX-License-Identifier: Apache-2.0

// Package units writes the hardened systemd units of the four roles (docs/10-operations.md,
// "Hardened systemd units").
package units

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"text/template"
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
}

var (
	credentialRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	binRe        = regexp.MustCompile(`^/[^\s%$\\]+$`)
)

// Render returns the unit of a role: controller, gateway, connector or all-in-one.
func Render(role string, o Options) ([]byte, error) {
	data := struct {
		Role, Bin, Credential string
		BindLow, Reload       bool
	}{Role: role, Bin: o.Bin, Credential: o.Credential}
	switch role {
	case "controller", "all-in-one", "gateway":
		data.BindLow = true // ports 443 and 80
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
	var b bytes.Buffer
	if err := unit.Execute(&b, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
