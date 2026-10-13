// SPDX-License-Identifier: Apache-2.0

package installsh

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/felix-homelab/rpmgr/internal/policy"
)

// Command returns the command that installs an agent with the controller's install script and
// enrolls it (docs/04-security.md, "Join command"): controller is the controller's URL and pin the
// pin of its root. The command downloads the script into the current directory and runs it with
// sudo, instead of piping it into sudo: sudo-rs, Ubuntu's sudo since 25.10, does not pass what is
// typed at the terminal on to a command whose standard input is a pipe, so the token typed at the
// prompt of rpmgr enroll would never arrive. Every value is quoted for the shell. A gateway takes
// no targets; a connector's target must be one the connector-local policy reads, without a quote
// or a control character, so that the command runs nothing but the installer.
func Command(controller, pin string, gateway bool, targets []string) (string, error) {
	base := strings.TrimSuffix(controller, "/")
	lines := []string{"curl -fsSLO " + Quote(base+"/install.sh") + " && sudo sh install.sh",
		"  --controller " + Quote(base) + " --ca-pin " + Quote(pin)}
	if gateway {
		if len(targets) > 0 {
			return "", errors.New("installsh: a gateway has no local policy to allow targets in")
		}
		lines = append(lines, "  --role gateway")
	}
	for _, t := range targets {
		if err := policy.CheckTarget(t); err != nil || strings.ContainsFunc(t, func(r rune) bool { return r == '\'' || unicode.IsControl(r) }) {
			return "", fmt.Errorf("installsh: allow target %q: want ip:port, [ipv6]:port or a socket path", t)
		}
		lines = append(lines, "  --allow-target "+Quote(t))
	}
	return strings.Join(lines, " \\\n"), nil
}

// Quote quotes s for a POSIX shell: in single quotes, each single quote closed, escaped and
// reopened.
func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
