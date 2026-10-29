// SPDX-License-Identifier: Apache-2.0

// Package units writes the hardened systemd units of the four roles (docs/10-operations.md,
// "Hardened systemd units").
package units

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"text/template"

	"golang.org/x/mod/semver"

	"github.com/felix-homelab/rpmgr/internal/config"
)

//go:embed rpmgr.service.tmpl
var text string

var unit = template.Must(template.New("unit").Parse(text))

//go:embed rpmgr-update.tmpl
var updaterText string

var updater = template.Must(template.New("updater").Parse(updaterText))

// RenderUpdater returns the root-owned updater's pair of units, rpmgr-update.path and
// rpmgr-update.service, each after a comment line that names its file. bin is the installed
// binary, the path install.json records.
func RenderUpdater(bin string) ([]byte, error) {
	if !binRe.MatchString(bin) || path.Clean(bin) != bin {
		return nil, fmt.Errorf("units: the binary path %q must be absolute and clean, without spaces, %%, $ or \\", bin)
	}
	var b bytes.Buffer
	if err := updater.Execute(&b, struct{ Bin, BinDir string }{bin, path.Dir(bin)}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// HandoffSince is the first release whose gateway, all-in-one and connector restart with socket
// hand-off and tell systemd when they are ready (Type=notify).
const HandoffSince = "0.3.0"

// DropIn is the name of the drop-in that makes a role's unit Type=notify; it lives in
// rpmgr-<role>.service.d next to the unit (D155).
const DropIn = "handoff.conf"

// HasHandoff reports whether a release, as `rpmgr version` names it, has the hand-off. A version
// that is no semantic version does not: Type=notify under a binary that never sends READY=1 hangs
// the start, while a plain unit under one that does only loses the early start.
func HasHandoff(version string) bool {
	v := "v" + strings.TrimPrefix(version, "v")
	return semver.IsValid(v) && semver.Compare(v, "v"+HandoffSince+"-0") >= 0
}

// RenderDropIn returns the drop-in of a role that restarts with hand-off, which makes its unit
// Type=notify with NotifyAccess=all, so that the new process of a hand-off can tell systemd it is
// the main one. The unit itself keeps the default type, so that a release without the hand-off
// starts under it; the drop-in goes where the unit does when the installed release has the
// hand-off and away with a rollback to one without. The controller has none.
func RenderDropIn(role string) ([]byte, error) {
	switch role {
	case "gateway", "all-in-one", "connector":
		return []byte("# SPDX-License-Identifier: Apache-2.0\n# rpmgr-" + role + ".service.d/" + DropIn +
			", written with the unit (docs/10-operations.md, \"Hardened systemd units\").\n" +
			"[Service]\nType=notify\nNotifyAccess=all\n"), nil
	case "controller":
		return nil, errors.New("units: the controller restarts without a hand-off and has no drop-in")
	}
	return nil, fmt.Errorf("units: no role %q", role)
}

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
		Role, Bin, Credential                   string
		BindLow, Reload, ReloadHandoff, Handoff bool
		Writable                                []string
	}{Role: role, Bin: o.Bin, Credential: o.Credential, Handoff: role != "controller"}
	switch role {
	case "controller":
		data.BindLow = true // ports 443 and 80
	case "gateway":
		data.BindLow, data.ReloadHandoff = true, true // ports 443 and 80; reload restarts with a hand-off
	case "all-in-one":
		// Reload restarts with a hand-off; rpmgr policy signals its connector with SIGHUP itself.
		data.BindLow, data.ReloadHandoff = true, true
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
