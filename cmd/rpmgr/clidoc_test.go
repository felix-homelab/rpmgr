// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
)

// updateCLIReference rewrites the user guide's command-line reference from the command tree.
var updateCLIReference = flag.Bool("update", false, "rewrite "+cliReferenceFile+" from the command tree")

// cliReferenceFile is the generated command-line reference, relative to this package.
const cliReferenceFile = "../../docs/guide/reference/cli.md"

// cliReferenceRegenerate is the command that regenerates cliReferenceFile, from the repository
// root.
const cliReferenceRegenerate = "go test ./cmd/rpmgr -run TestCLIReference -update"

// cliReferenceDefaults holds the documented default of each flag, keyed "<command path>
// --<flag>", whose default depends on the machine that renders the reference, such as a home
// directory or a host name. No flag has one at present; renderCLIReference refuses such a default
// until it is added here, so that the page is the same on every machine.
var cliReferenceDefaults = map[string]string{}

// TestCLIReference: the committed command-line reference of the user guide is the command tree
// as renderCLIReference renders it, so that a new command or flag cannot leave it behind.
func TestCLIReference(t *testing.T) {
	got, err := renderCLIReference(commands(), cliReferenceDefaults)
	if err != nil {
		t.Fatal(err)
	}
	if *updateCLIReference {
		if err := os.WriteFile(cliReferenceFile, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(cliReferenceFile)
	if err != nil {
		t.Fatalf("%v; generate it with: %s", err, cliReferenceRegenerate)
	}
	if line, same := firstDifferentLine(string(want), got); !same {
		t.Errorf("%s does not match the command tree (first difference at line %d); regenerate it with: %s",
			cliReferenceFile, line, cliReferenceRegenerate)
	}
}

// TestRenderCLIReference: the renderer's rules on a small tree: the tree's order, groups,
// commands that are not available, zero defaults left out, Markdown escaped, the commands of the
// rpmgrtest build left out, and a machine-specific default refused unless it is documented.
func TestRenderCLIReference(t *testing.T) {
	run := func(context.Context, *cli.Env, []string) error { return nil }
	tree := func(defaultDir string) *cli.Command {
		return &cli.Command{Name: "rpmgr", Summary: "the root", Sub: append([]*cli.Command{
			{Name: "zeta", Summary: "comes first in the tree", Args: "<a> | <b>", Run: run, Flags: func(fs *flag.FlagSet) {
				fs.String("o", "table", "output: table | yaml")
				fs.Bool("all", false, "a switch")
				fs.Duration("wait", 0, "wait up to this long")
				fs.Int("max-uses", 1, "uses of a `count`")
				fs.String("dir", defaultDir, "a directory, <dir>, with *stars*")
			}},
			{Name: "alpha", Summary: "a group", Sub: []*cli.Command{
				{Name: "later", Summary: "not built yet", Run: cli.NotAvailable},
			}},
		}, testCommands...)}
	}

	got, err := renderCLIReference(tree("/var/lib/x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	body := got[len(cliReferenceHeader):]
	for _, want := range []string{
		"\n## rpmgr\n\nThe root.\n\n```text\nrpmgr <command>\n```\n",
		"| [`rpmgr zeta`](#rpmgr-zeta) | Comes first in the tree |\n| [`rpmgr alpha`](#rpmgr-alpha) | A group |\n",
		"```text\nrpmgr zeta [flags] <a> | <b>\n```\n",
		"| `-o string` | `table` | output: table \\| yaml |\n",
		"| `--all` |  | a switch |\n",
		"| `--wait duration` |  | wait up to this long |\n",
		"| `--max-uses count` | `1` | uses of a count |\n",
		"| `--dir string` | `/var/lib/x` | a directory, \\<dir>, with \\*stars\\* |\n",
		"\n## rpmgr alpha\n\nA group.\n\n```text\nrpmgr alpha <command>\n```\n",
		"\n## rpmgr alpha later\n\nNot built yet.\n\n*Not available in this build.*\n\n```text\nrpmgr alpha later\n```\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the reference lacks %q:\n%s", want, body)
		}
	}
	if strings.Index(body, "## rpmgr zeta") > strings.Index(body, "## rpmgr alpha") {
		t.Error("the commands are not in the tree's order")
	}
	if group, _, _ := strings.Cut(body[strings.Index(body, "## rpmgr alpha\n"):], "## rpmgr alpha later"); strings.Contains(group, "[flags]") ||
		strings.Contains(group, "| Flag |") {
		t.Errorf("a group without flags shows flags:\n%s", group)
	}
	for _, c := range testCommands {
		if strings.Contains(body, "rpmgr "+c.Name) {
			t.Errorf("the reference shows the rpmgrtest command %q", c.Name)
		}
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" || home == "/" {
		t.Skip("no home directory to stand for a machine-specific default")
	}
	_, err = renderCLIReference(tree(home+"/.rpmgr"), nil)
	if err == nil || !strings.Contains(err.Error(), "rpmgr zeta --dir") {
		t.Errorf("a default under the home directory was not refused: %v", err)
	}
	got, err = renderCLIReference(tree(home+"/.rpmgr"), map[string]string{"rpmgr zeta --dir": "~/.rpmgr"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "| `--dir string` | `~/.rpmgr` |") || strings.Contains(got, home) {
		t.Errorf("the documented default was not used:\n%s", got)
	}
}

func TestFirstDifferentLine(t *testing.T) {
	for _, c := range []struct {
		a, b string
		line int
		same bool
	}{
		{"x\ny\n", "x\ny\n", 0, true},
		{"", "", 0, true},
		{"x\ny\n", "x\nz\n", 2, false},
		{"x\n", "x\ny\n", 2, false},
		{"x\ny\n", "x\n", 2, false},
		{"", "x", 1, false},
	} {
		if line, same := firstDifferentLine(c.a, c.b); line != c.line || same != c.same {
			t.Errorf("firstDifferentLine(%q, %q) = %d, %t; want %d, %t", c.a, c.b, line, same, c.line, c.same)
		}
	}
}

// firstDifferentLine returns the 1-based number of the first line where a and b differ, and
// whether they are the same.
func firstDifferentLine(a, b string) (int, bool) {
	if a == b {
		return 0, true
	}
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := range min(len(al), len(bl)) {
		if al[i] != bl[i] {
			return i + 1, false
		}
	}
	return min(len(al), len(bl)) + 1, false
}

// cliReferenceHeader is the hand-written start of the command-line reference.
const cliReferenceHeader = `# Command-line reference

This page lists every command of the ` + "`rpmgr`" + ` binary with its synopsis and its flags. It is
for you when you need the exact name of a command or a flag; the task pages of this guide explain
when and why to use them.

<!-- Generated from the command tree in cmd/rpmgr by TestCLIReference. Do not edit by hand. -->

## How to read this page

- Each section below is one command, in the order of the command tree. A command that only
  groups others lists them and has no flags of its own.
- The synopsis shows the command path, ` + "`<command>`" + ` where a sub-command follows,
  ` + "`[flags]`" + ` when the command has flags, and the positional arguments. Flags come before
  the positional arguments, as in ` + "`rpmgr get -o yaml route web`" + `.
- A flag is written ` + "`--name`" + `, or ` + "`-o`" + ` for a one-letter flag, followed by the kind
  of value it takes. A flag without a kind is a switch: ` + "`--all`" + ` turns it on. A flag that
  may be repeated says so in its description.
- The default column is empty where the default is empty, zero or ` + "`false`" + `.
- A command marked *not available in this build* exists in the tree but exits with code 2.
- On a host, ` + "`rpmgr <command> --help`" + ` and ` + "`rpmgr help <command>`" + ` print a
  command's summary, sub-commands and flags as well.

Exit codes, the conventions every command follows and the design notes are in
[16](../../16-cli.md). The task pages show the commands in use, for example
[API tokens and the command line](../accounts/api-tokens-and-cli.md),
[rpmgr setup](../install/setup.md), [Enrolling connectors](../connectors/enroll.md),
[The local policy](../connectors/local-policy.md) and
[Status and diagnostics](../connectors/status-and-diagnostics.md).

## How this page is generated

This page is generated from the command tree in ` + "`cmd/rpmgr`" + `. The test
` + "`TestCLIReference`" + ` fails when the page and the tree differ. After changing a command,
regenerate the page from the repository root and commit it with the change:

` + "```sh\n" + cliReferenceRegenerate + "\n```\n"

// renderCLIReference renders the command tree root as the Markdown command-line reference: the
// header, then one section per command path in the tree's order. The commands of the rpmgrtest
// build are left out, so the page is the same in every build (D60). documented holds the
// documented defaults of machine-specific flags, as cliReferenceDefaults does; any other
// machine-specific default is an error.
func renderCLIReference(root *cli.Command, documented map[string]string) (string, error) {
	var b strings.Builder
	var errs []error
	b.WriteString(cliReferenceHeader)
	notAvailable := reflect.ValueOf(cli.NotAvailable).Pointer()
	var render func(c *cli.Command, path []string)
	render = func(c *cli.Command, path []string) {
		name := strings.Join(path, " ")
		fs := flag.NewFlagSet(name, flag.ContinueOnError)
		if c.Flags != nil {
			c.Flags(fs)
		}
		var flags []*flag.Flag
		fs.VisitAll(func(f *flag.Flag) { flags = append(flags, f) })
		var subs []*cli.Command
		for _, s := range c.Sub {
			if !slices.Contains(testCommands, s) {
				subs = append(subs, s)
			}
		}

		fmt.Fprintf(&b, "\n## %s\n\n%s.\n", name, markdownText(upperFirst(c.Summary)))
		if c.Run != nil && reflect.ValueOf(c.Run).Pointer() == notAvailable {
			b.WriteString("\n*Not available in this build.*\n")
		}
		b.WriteString("\n```text\n")
		if c.Run != nil {
			synopsis := name
			if len(flags) > 0 {
				synopsis += " [flags]"
			}
			if c.Args != "" {
				synopsis += " " + c.Args
			}
			b.WriteString(synopsis + "\n")
		}
		if len(subs) > 0 {
			b.WriteString(name + " <command>\n")
		}
		b.WriteString("```\n")

		if len(subs) > 0 {
			b.WriteString("\n| Command | What it does |\n|---|---|\n")
			for _, s := range subs {
				sub := name + " " + s.Name
				fmt.Fprintf(&b, "| [`%s`](#%s) | %s |\n", sub, markdownAnchor(sub), markdownCell(upperFirst(s.Summary)))
			}
		}
		if len(flags) > 0 {
			b.WriteString("\n| Flag | Default | Description |\n|---|---|---|\n")
			for _, f := range flags {
				kind, usage := flag.UnquoteUsage(f)
				flagName := "--" + f.Name
				if len(f.Name) == 1 {
					flagName = "-" + f.Name
				}
				if kind != "" {
					flagName += " " + kind
				}
				key := name + " --" + f.Name
				def, ok := documented[key]
				if !ok {
					def = f.DefValue
					if machineSpecific(def) {
						errs = append(errs, fmt.Errorf("the default %q of %s depends on this machine; add its documented default to cliReferenceDefaults", def, key))
					}
				}
				switch def { // --help leaves a zero default out too
				case "", "0", "0s", "false", "[]":
					def = ""
				default:
					def = "`" + def + "`"
				}
				fmt.Fprintf(&b, "| `%s` | %s | %s |\n", flagName, def, markdownCell(usage))
			}
		}
		for _, s := range subs {
			render(s, append(append([]string(nil), path...), s.Name))
		}
	}
	render(root, []string{root.Name})
	return b.String(), errors.Join(errs...)
}

// machineSpecific reports whether a flag default holds something of the machine that renders the
// reference: its home, configuration or cache directory, the working directory, the executable,
// the host name, or the platform.
func machineSpecific(def string) bool {
	if def == "" {
		return false
	}
	var dirs []string
	for _, f := range []func() (string, error){os.UserHomeDir, os.UserConfigDir, os.UserCacheDir, os.Getwd, os.Executable} {
		if d, err := f(); err == nil && len(d) > 1 {
			dirs = append(dirs, d)
		}
	}
	for _, d := range dirs {
		if strings.Contains(def, d) {
			return true
		}
	}
	host, err := os.Hostname()
	return (err == nil && host != "" && def == host) || def == runtime.GOOS || def == runtime.GOARCH
}

// markdownAnchor is the anchor GitHub gives the heading s.
func markdownAnchor(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

// markdownText escapes the characters of s that Markdown would read as markup in running text.
func markdownText(s string) string {
	return strings.NewReplacer(`\`, `\\`, "`", "\\`", "*", `\*`, "<", `\<`).Replace(s)
}

// markdownCell is markdownText for a table cell, which also escapes the column separator.
func markdownCell(s string) string {
	return strings.ReplaceAll(markdownText(s), "|", `\|`)
}

// upperFirst is s with its first letter upper-case, as --help prints a summary.
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
