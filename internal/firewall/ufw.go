// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ErrNotInstalled is returned when the host has no ufw.
var ErrNotInstalled = errors.New("ufw is not installed")

var errInactive = errors.New("ufw is inactive")

// Runner runs ufw with an argument vector, never through a shell; tests replace it.
type Runner interface {
	Run(ctx context.Context, args ...string) ([]byte, error)
}

type execRunner struct{}

// ufwPaths are where the distributions put ufw; PATH is not trusted.
var ufwPaths = []string{"/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw"}

func (execRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	var bin string
	for _, p := range ufwPaths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, ErrNotInstalled
	}
	ctx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: a fixed binary, arguments built from integers and tcp or udp
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("ufw %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func ufwActive(ctx context.Context, u Runner) error {
	out, err := u.Run(ctx, "status")
	if err != nil {
		return err // ufw failing, without root or modules, is no "inactive"
	}
	switch first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n"); strings.TrimSpace(first) {
	case "Status: active":
		return nil
	case "Status: inactive":
		return errInactive
	default:
		return fmt.Errorf("unexpected output of ufw status: %q", first)
	}
}

// ufwRule is one line of `ufw status numbered`.
type ufwRule struct {
	Number  int
	To      string // the first column without "(v6)": "20000:20999/tcp"
	V6      bool
	Action  string // "ALLOW IN"
	From    string // "Anywhere"
	Comment string
}

// ruleLine reads `[ 2] 20000:20999/tcp (v6)   ALLOW IN    Anywhere (v6)   # rpmgr`. Columns are
// separated by two spaces or more; a comment follows "# " at the end.
var ruleLine = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.*?)\s{2,}(\S+(?: IN| OUT| FWD)?)\s+(.*?)(?:\s+#\s?(.*))?$`)

func parseRules(out []byte) []ufwRule {
	var rules []ufwRule
	for line := range bytes.Lines(out) {
		m := ruleLine.FindStringSubmatch(strings.TrimRight(string(line), "\r\n"))
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		to := m[2]
		v6 := strings.HasSuffix(to, " (v6)")
		rules = append(rules, ufwRule{Number: n, To: strings.TrimSuffix(to, " (v6)"), V6: v6, Action: m[3], From: strings.TrimSuffix(m[4], " (v6)"), Comment: m[5]})
	}
	return rules
}

// owned reports whether a rule carries the marker, which is what makes it the helper's.
func (r ufwRule) owned() bool { return r.Comment == Marker }

// listRules returns the rules `ufw status numbered` shows.
func listRules(ctx context.Context, u Runner) ([]ufwRule, error) {
	out, err := u.Run(ctx, "status", "numbered")
	if err != nil {
		return nil, err
	}
	return parseRules(out), nil
}

// converge makes the rules that carry the marker those of want: it adds what is missing, then
// deletes, highest number first and listing the rules again before each, every marked rule that
// is not wanted or is a repeat. Rules without the marker are never looked at beyond their number.
func converge(ctx context.Context, u Runner, want []Range) error {
	rules, err := listRules(ctx, u)
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, r := range want {
		wanted[r.String()] = true
	}
	have := map[string]bool{}
	for _, r := range rules {
		if r.owned() && !r.V6 && r.Action == "ALLOW IN" && r.From == "Anywhere" {
			have[r.To] = true
		}
	}
	for _, r := range want {
		if have[r.String()] {
			continue
		}
		if _, err := u.Run(ctx, "allow", r.String(), "comment", Marker); err != nil {
			return err
		}
	}
	for range 4 * (len(rules) + len(want) + 1) { // each pass deletes one rule or ends
		rules, err = listRules(ctx, u)
		if err != nil {
			return err
		}
		stale := staleRule(rules, wanted)
		if stale == 0 {
			return nil
		}
		if _, err := u.Run(ctx, "--force", "delete", strconv.Itoa(stale)); err != nil {
			return err
		}
	}
	return errors.New("ufw kept rules of rpmgr after the deletions")
}

// staleRule returns the number of the highest marked rule that is not wanted, or a repeat of one
// that is, or 0.
func staleRule(rules []ufwRule, wanted map[string]bool) int {
	seen := map[string]bool{}
	stale := 0
	for _, r := range rules { // ascending: the first of a kind stays, a later one is a repeat
		if !r.owned() {
			continue
		}
		key := r.To + "|" + strconv.FormatBool(r.V6)
		if !wanted[r.To] || r.Action != "ALLOW IN" || r.From != "Anywhere" || seen[key] {
			stale = max(stale, r.Number)
		}
		seen[key] = true
	}
	return stale
}
