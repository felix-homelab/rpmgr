// SPDX-License-Identifier: Apache-2.0

package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
)

// helpListing parses `rpmgr --help` into the command names under each section title.
func helpListing(t *testing.T) (map[string][]string, []string) {
	t.Helper()
	code, out, errOut := runRpmgr("--help")
	if code != cli.ExitOK {
		t.Fatalf("--help: %d %q", code, errOut)
	}
	sections := map[string][]string{}
	var order []string
	var cur string
	title := regexp.MustCompile(`^([A-Z][A-Za-z ]+):$`)
	for _, l := range strings.Split(out, "\n") {
		if m := title.FindStringSubmatch(l); m != nil {
			cur = m[1]
			order = append(order, cur)
			continue
		}
		if strings.HasPrefix(l, "  ") && cur != "" && cur != "Topics" {
			sections[cur] = append(sections[cur], strings.Fields(l)[0])
		}
	}
	return sections, order
}

// TestRootHelpSections (D151): `rpmgr --help` lists every visible command exactly once, in the
// four sections in their order, and no hidden command.
func TestRootHelpSections(t *testing.T) {
	sections, order := helpListing(t)
	if got, want := strings.Join(order, ","), "Resources,This host,Run a role,Session,Topics"; got != want {
		t.Fatalf("sections %q, want %q", got, want)
	}
	count := map[string]int{}
	for sec, names := range sections {
		for _, n := range names {
			count[n]++
			c := findSub(commands(), n)
			if c == nil {
				t.Errorf("%q is listed but is no command", n)
			} else if c.Section != sec {
				t.Errorf("%q is listed under %q but its section is %q", n, sec, c.Section)
			}
		}
	}
	for _, c := range commands().Sub {
		switch {
		case c.Hidden && count[c.Name] != 0:
			t.Errorf("hidden command %q is listed", c.Name)
		case !c.Hidden && count[c.Name] != 1:
			t.Errorf("command %q is listed %d times", c.Name, count[c.Name])
		}
	}
	for _, n := range []string{"get", "create", "advance"} {
		if !slices.Contains(sections["Resources"], n) {
			t.Errorf("%q is not under Resources", n)
		}
	}
	for sec, want := range map[string][]string{"This host": {"setup", "release", "backup", "diag"},
		"Run a role": {"controller", "gateway", "connector", "all-in-one"}, "Session": {"login", "logout", "version"}} {
		for _, n := range want {
			if !slices.Contains(sections[sec], n) {
				t.Errorf("%q is not under %s", n, sec)
			}
		}
	}
	if _, listed := count["upgrade"]; listed {
		t.Error("the removed upgrade is listed")
	}
	if _, listed := sections["Other commands"]; listed {
		t.Errorf("commands without a section: %v", sections["Other commands"])
	}
}

// TestHiddenUpdater (D151): updater, install and apply are not in the help, and still run: help
// of each works and an invalid use is a usage error of the command, not an unknown one.
func TestHiddenUpdater(t *testing.T) {
	sections, _ := helpListing(t)
	for sec, names := range sections {
		if slices.Contains(names, "updater") {
			t.Errorf("updater is listed under %s", sec)
		}
	}
	for _, args := range [][]string{{"updater"}, {"updater", "apply"}, {"updater", "install"}} {
		if code, out, _ := runRpmgr(append(args, "--help")...); code != cli.ExitOK || !strings.HasPrefix(out, "Usage: rpmgr "+strings.Join(args, " ")) {
			t.Errorf("rpmgr %v --help: %d %q", args, code, out)
		}
	}
	if _, out, _ := runRpmgr("updater", "--help"); strings.Contains(out, "\nCommands:") && (!strings.Contains(out, "apply") || !strings.Contains(out, "install")) {
		t.Errorf("updater help lost its commands: %q", out)
	}
	if code, _, errOut := runRpmgr("updater", "install", "extra"); code != cli.ExitUsage || strings.Contains(errOut, "unknown command") {
		t.Errorf("updater install extra: %d %q", code, errOut)
	}
}

// TestUpgradeRemoved (D151): `rpmgr upgrade` is an unknown command that names its replacement.
func TestUpgradeRemoved(t *testing.T) {
	for _, args := range [][]string{{"upgrade"}, {"upgrade", "connector", "nas"}, {"help", "upgrade"}} {
		code, out, errOut := runRpmgr(args...)
		if code != cli.ExitUsage || out != "" || !strings.Contains(errOut, `unknown command "upgrade"`) ||
			!strings.Contains(errOut, "rpmgr create rollout --easy --release <version> --agent <agent>") {
			t.Errorf("rpmgr %v: %d %q %q", args, code, out, errOut)
		}
	}
}

// TestHelpTopics (D151): every topic is listed in the root help, prints its steps, and names only
// commands of the tree; an unknown topic is an unknown command.
func TestHelpTopics(t *testing.T) {
	root := commands()
	_, rootHelp, _ := runRpmgr("--help")
	if len(root.Topics) < 2 {
		t.Fatalf("%d topics", len(root.Topics))
	}
	for _, topic := range root.Topics {
		if findSub(root, topic.Name) != nil {
			t.Errorf("topic %q is also a command", topic.Name)
		}
		if !strings.Contains(rootHelp, "  "+topic.Name) {
			t.Errorf("topic %q is not in the root help", topic.Name)
		}
		code, out, errOut := runRpmgr("help", topic.Name)
		if code != cli.ExitOK || errOut != "" || !strings.HasPrefix(out, "Usage: rpmgr help "+topic.Name) {
			t.Fatalf("help %s: %d %q %q", topic.Name, code, out, errOut)
		}
		if len(topic.Steps) == 0 {
			t.Errorf("topic %q has no step", topic.Name)
		}
		for _, s := range topic.Steps {
			if !strings.Contains(out, s.Do) {
				t.Errorf("help %s does not print %q", topic.Name, s.Do)
			}
			if !strings.HasPrefix(s.Do, "rpmgr ") {
				continue
			}
			var path []string
			c := root
			for _, w := range strings.Fields(s.Do)[1:] {
				sub := findSub(c, w)
				if sub == nil {
					break
				}
				c, path = sub, append(path, w)
			}
			if len(path) == 0 || c.Run == nil && c.Sub == nil {
				t.Errorf("topic %s: %q names no command of the tree", topic.Name, s.Do)
			}
			if c.Run == nil {
				t.Errorf("topic %s: %q stops at the group %q", topic.Name, s.Do, strings.Join(path, " "))
			}
			if c.Hidden {
				t.Errorf("topic %s: %q names a hidden command", topic.Name, s.Do)
			}
		}
	}
	_, out, _ := runRpmgr("help", "updates")
	if strings.Contains(out, "rpmgr upgrade") {
		t.Errorf("help updates names the removed upgrade: %q", out)
	}
	code, _, errOut := runRpmgr("help", "no-such-topic")
	if code != cli.ExitUsage || !strings.Contains(errOut, `unknown command "no-such-topic"`) {
		t.Errorf("help no-such-topic: %d %q", code, errOut)
	}
}

func findSub(c *cli.Command, name string) *cli.Command {
	for _, s := range c.Sub {
		if s.Name == name {
			return s
		}
	}
	return nil
}
