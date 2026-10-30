// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

// listValue is a flag that may be repeated, as the commands' list flags are; its String is the
// values given so far.
type listValue []string

func (l *listValue) String() string     { return strings.Join(*l, ",") }
func (l *listValue) Set(v string) error { *l = append(*l, v); return nil }

// testTree is a small tree with every kind of node: a group, a leaf with flags and arguments,
// a command with both a Run and sub-commands, and commands that fail in each way.
func testTree(got *[]string) *Command {
	record := func(_ context.Context, _ *Env, args []string) error {
		*got = append([]string(nil), args...)
		return nil
	}
	var tags listValue
	return &Command{
		Name:    "rpmgr",
		Summary: "test tree",
		Sub: []*Command{
			{
				Name: "copy", Summary: "copy things", Args: "<src> <dst>",
				Flags: func(fs *flag.FlagSet) { fs.Bool("force", false, "overwrite") },
				Run: func(ctx context.Context, env *Env, args []string) error {
					if len(args) != 2 {
						return Usagef("copy needs <src> and <dst>")
					}
					return record(ctx, env, args)
				},
			},
			{Name: "group", Summary: "a group", Sub: []*Command{
				{Name: "leaf", Summary: "a leaf", Run: record},
			}},
			{Name: "both", Summary: "runs and has a sub-command", Run: record, Sub: []*Command{
				{Name: "sub", Summary: "the sub-command", Run: record},
			}},
			{Name: "later", Summary: "not implemented", Run: NotAvailable},
			{
				Name: "tag", Summary: "refuse the tags given",
				Flags: func(fs *flag.FlagSet) {
					fs.Var(&tags, "tag", "a tag; repeat for more")
					fs.String("mode", "fast", "the mode")
				},
				Run: func(context.Context, *Env, []string) error { return Usagef("the tags %s are refused", tags.String()) },
			},
			{Name: "coded", Summary: "fails with a code of its own", Run: func(context.Context, *Env, []string) error {
				return fmt.Errorf("wrapped: %w", codedErr(3))
			}},
			{Name: "fail", Summary: "always fails", Run: func(context.Context, *Env, []string) error {
				return errors.New("boom")
			}},
		},
	}
}

func run(t *testing.T, args ...string) (code int, stdout, stderr string, got []string) {
	t.Helper()
	var out, errOut bytes.Buffer
	env := &Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}
	code = Main(context.Background(), testTree(&got), args, env)
	return code, out.String(), errOut.String(), got
}

// codedErr is an error that names its exit code (ExitCoder).
type codedErr int

func (e codedErr) Error() string { return fmt.Sprintf("exit %d", int(e)) }
func (e codedErr) ExitCode() int { return int(e) }

func TestMainDispatch(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		code    int
		stdout  string // substring expected on stdout
		stderr  string // substring expected on stderr
		gotArgs []string
		wantRun bool
	}{
		{name: "no arguments", args: nil, code: ExitUsage, stderr: "a command is required"},
		{name: "root help flag", args: []string{"--help"}, code: ExitOK, stdout: "Usage: rpmgr <command>"},
		{name: "root short help", args: []string{"-h"}, code: ExitOK, stdout: "Commands:"},
		{name: "help command", args: []string{"help", "copy"}, code: ExitOK, stdout: "Usage: rpmgr copy [flags] <src> <dst>"},
		{name: "help for unknown command", args: []string{"help", "nope"}, code: ExitUsage, stderr: `unknown command "nope"`},
		{name: "unknown command", args: []string{"nope"}, code: ExitUsage, stderr: `unknown command "nope"`},
		{name: "unknown root flag", args: []string{"--nope"}, code: ExitUsage, stderr: "flag provided but not defined: -nope"},
		{name: "leaf with flags and args", args: []string{"copy", "--force", "a", "b"}, code: ExitOK, gotArgs: []string{"a", "b"}, wantRun: true},
		{name: "usage error from run", args: []string{"copy", "a"}, code: ExitUsage, stderr: "copy needs <src> and <dst>"},
		{name: "unknown flag on leaf", args: []string{"copy", "--nope", "a", "b"}, code: ExitUsage, stderr: "flag provided but not defined"},
		{name: "invalid flag value", args: []string{"copy", "--force=maybe", "a", "b"}, code: ExitUsage, stderr: "invalid boolean value"},
		{name: "leaf help", args: []string{"copy", "--help"}, code: ExitOK, stdout: "-force"},
		{name: "group without command", args: []string{"group"}, code: ExitUsage, stderr: "a command is required"},
		{name: "group with unknown command", args: []string{"group", "nope"}, code: ExitUsage, stderr: `unknown command "nope"`},
		{name: "group leaf", args: []string{"group", "leaf"}, code: ExitOK, gotArgs: []string{}, wantRun: true},
		{name: "unexpected argument", args: []string{"group", "leaf", "extra"}, code: ExitUsage, stderr: `unexpected argument "extra"`},
		{name: "command with sub runs itself", args: []string{"both"}, code: ExitOK, gotArgs: []string{}, wantRun: true},
		{name: "command with sub runs sub", args: []string{"both", "sub"}, code: ExitOK, gotArgs: []string{}, wantRun: true},
		{name: "not available", args: []string{"later"}, code: ExitUsage, stderr: "rpmgr later: not available in this build"},
		{name: "an error with its own exit code", args: []string{"coded"}, code: 3, stderr: "rpmgr coded: wrapped: exit 3"},
		{name: "runtime error", args: []string{"fail"}, code: ExitError, stderr: "rpmgr fail: boom"},
		{name: "flag after the arguments", args: []string{"copy", "a", "b", "--force"}, code: ExitOK, gotArgs: []string{"a", "b"}, wantRun: true},
		{name: "flag between the arguments", args: []string{"copy", "a", "-force", "b"}, code: ExitOK, gotArgs: []string{"a", "b"}, wantRun: true},
		{name: "help after an argument", args: []string{"copy", "a", "--help"}, code: ExitOK, stdout: "Usage: rpmgr copy [flags] <src> <dst>"},
		{name: "help after a sub-command", args: []string{"group", "leaf", "-h"}, code: ExitOK, stdout: "Usage: rpmgr group leaf"},
		{name: "unknown flag after the arguments", args: []string{"copy", "a", "b", "--nope"}, code: ExitUsage, stderr: "flag provided but not defined: -nope"},
		{name: "after -- a flag is an argument", args: []string{"copy", "a", "--", "--help"}, code: ExitOK, gotArgs: []string{"a", "--help"}, wantRun: true},
		{name: "after -- an argument may begin with -", args: []string{"copy", "--force", "--", "-a", "-b"}, code: ExitOK, gotArgs: []string{"-a", "-b"}, wantRun: true},
		{name: "a lone dash is an argument", args: []string{"copy", "-", "b"}, code: ExitOK, gotArgs: []string{"-", "b"}, wantRun: true},
		{name: "a switch takes no value after it", args: []string{"copy", "--force", "false", "a", "b"}, code: ExitUsage, stderr: "copy needs <src> and <dst>"},
		{name: "unexpected argument after --", args: []string{"group", "leaf", "--", "x"}, code: ExitUsage, stderr: `unexpected argument "x"`},
		{name: "unknown command after --", args: []string{"group", "--", "leaf"}, code: ExitUsage, stderr: `unknown command "leaf"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr, got := run(t, tt.args...)
			if code != tt.code {
				t.Errorf("exit code = %d, want %d (stdout %q, stderr %q)", code, tt.code, stdout, stderr)
			}
			if !strings.Contains(stdout, tt.stdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout, tt.stdout)
			}
			if !strings.Contains(stderr, tt.stderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.stderr)
			}
			if tt.wantRun && strings.Join(got, "\x00") != strings.Join(tt.gotArgs, "\x00") {
				t.Errorf("run got args %q, want %q", got, tt.gotArgs)
			}
			if !tt.wantRun && got != nil {
				t.Errorf("run was called with %q, want no call", got)
			}
			if tt.code == ExitUsage && !strings.Contains(stderr, "Usage:") && !strings.Contains(stderr, "not available") {
				t.Errorf("usage error without usage text: %q", stderr)
			}
		})
	}
}

// TestParse: flags stand anywhere among the positional arguments, which keep their order; "--"
// ends the flags; a flag that takes a value takes the next argument, also one that begins with
// "-" or is "--".
func TestParse(t *testing.T) {
	type result struct {
		Pos   []string
		Force bool
		Mode  string
		Tags  listValue
	}
	for _, tc := range []struct {
		name string
		args []string
		want result
		err  string
	}{
		{name: "nothing", args: nil, want: result{Mode: "slow"}},
		{name: "flags before", args: []string{"--force", "--mode", "x", "a", "b"}, want: result{Pos: []string{"a", "b"}, Force: true, Mode: "x"}},
		{name: "flags after", args: []string{"a", "b", "--force", "-mode", "x"}, want: result{Pos: []string{"a", "b"}, Force: true, Mode: "x"}},
		{name: "flags between", args: []string{"a", "--mode=x", "b", "-force"}, want: result{Pos: []string{"a", "b"}, Force: true, Mode: "x"}},
		{name: "a repeated flag", args: []string{"--tag", "x", "a", "--tag=y", "b", "--tag", "z"}, want: result{Pos: []string{"a", "b"}, Mode: "slow", Tags: listValue{"x", "y", "z"}}},
		{name: "a switch set false", args: []string{"a", "--force=false"}, want: result{Pos: []string{"a"}, Mode: "slow"}},
		{name: "a switch takes no next argument", args: []string{"--force", "false"}, want: result{Pos: []string{"false"}, Force: true, Mode: "slow"}},
		{name: "a value that begins with -", args: []string{"a", "--mode", "-x"}, want: result{Pos: []string{"a"}, Mode: "-x"}},
		{name: "-- ends the flags", args: []string{"a", "--", "--force", "-b", "--"}, want: result{Pos: []string{"a", "--force", "-b", "--"}, Mode: "slow"}},
		{name: "-- as a value", args: []string{"--mode", "--", "a", "--force"}, want: result{Pos: []string{"a"}, Force: true, Mode: "--"}},
		{name: "-- alone", args: []string{"--"}, want: result{Mode: "slow"}},
		{name: "a lone dash", args: []string{"-", "--force"}, want: result{Pos: []string{"-"}, Force: true, Mode: "slow"}},
		{name: "an unknown flag after the arguments", args: []string{"a", "--nope"}, err: "flag provided but not defined: -nope"},
		{name: "a value missing at the end", args: []string{"a", "--mode"}, err: "flag needs an argument: -mode"},
		{name: "three dashes", args: []string{"a", "---mode", "x"}, err: "bad flag syntax: ---mode"},
		{name: "an empty name", args: []string{"a", "-=x"}, err: "bad flag syntax: -=x"},
		{name: "a bad switch value", args: []string{"a", "--force=maybe"}, err: "invalid boolean value"},
		{name: "help after the arguments", args: []string{"a", "--help"}, err: flag.ErrHelp.Error()},
		{name: "short help after the arguments", args: []string{"a", "b", "-h"}, err: flag.ErrHelp.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got result
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			fs.BoolVar(&got.Force, "force", false, "")
			fs.StringVar(&got.Mode, "mode", "slow", "")
			fs.Var(&got.Tags, "tag", "")
			pos, err := parse(fs, tc.args)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("parse(%q) = %q, %v; want the error %q", tc.args, pos, err, tc.err)
				}
				return
			}
			got.Pos = pos
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parse(%q) = %+v, %v; want %+v", tc.args, got, err, tc.want)
			}
		})
	}
}

// TestUsageShowsDefaults: after a usage error, and with --help after flags, the usage text shows
// each flag's default, not what the command line gave a repeated flag.
func TestUsageShowsDefaults(t *testing.T) {
	code, _, stderr, _ := run(t, "tag", "--tag", "smtp.server=mail.example.com", "--mode", "slow", "--tag", "other")
	if code != ExitUsage || !strings.Contains(stderr, "the tags smtp.server=mail.example.com,other are refused") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	_, stdout, _, _ := run(t, "tag", "--tag", "smtp.server=mail.example.com", "--mode", "slow", "--help")
	for name, usage := range map[string]string{"after a usage error": stderr[strings.Index(stderr, "Usage:"):], "with --help": stdout} {
		if strings.Contains(usage, "smtp.server") || strings.Contains(usage, "default \"slow\"") {
			t.Errorf("%s, the usage shows the values given:\n%s", name, usage)
		}
		if !strings.Contains(usage, "a tag; repeat for more\n") || !strings.Contains(usage, `the mode (default "fast")`) {
			t.Errorf("%s, the usage lacks the defaults:\n%s", name, usage)
		}
	}
}

func TestHelpListsSubCommandsSorted(t *testing.T) {
	_, stdout, _, _ := run(t, "--help")
	both, copy := strings.Index(stdout, "  both "), strings.Index(stdout, "  copy ")
	if both < 0 || copy < 0 || both > copy {
		t.Errorf("sub-commands not listed in sorted order:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Test tree.") {
		t.Errorf("summary not printed as a sentence:\n%s", stdout)
	}
}

func TestUsageErrorMessage(t *testing.T) {
	err := Usagef("bad %s", "input")
	var ue *UsageError
	if !errors.As(err, &ue) || err.Error() != "bad input" {
		t.Errorf("Usagef = %v, want a *UsageError with message %q", err, "bad input")
	}
}

// TestSectionsHiddenTopicsRemoved (D151): help groups the visible commands by section, in the
// order of Sections, and lists a command without a known section last; a hidden command is not
// listed and runs; topics print their steps; a removed command's error names its replacement.
func TestSectionsHiddenTopicsRemoved(t *testing.T) {
	ran := false
	run := func(context.Context, *Env, []string) error { ran = true; return nil }
	root := &Command{
		Name: "rpmgr", Summary: "test tree", Sections: []string{"B first", "A second"},
		Topics:  []Topic{{Name: "moving", Summary: "move things", Steps: []Step{{Do: "rpmgr zed", Note: "does it"}, {Do: "systemctl reload x"}}}},
		Removed: map[string]string{"old": "use 'rpmgr zed'"},
		Sub: []*Command{
			{Name: "alpha", Summary: "a", Section: "A second", Run: run},
			{Name: "zed", Summary: "z", Section: "B first", Run: run},
			{Name: "plumbing", Summary: "p", Section: "A second", Hidden: true, Run: run},
			{Name: "stray", Summary: "s", Run: run},
			{Name: "elsewhere", Summary: "e", Section: "not named", Run: run},
		},
	}
	main := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := Main(context.Background(), root, args, &Env{Stdout: &out, Stderr: &errOut})
		return code, out.String(), errOut.String()
	}
	code, out, _ := main("--help")
	b, a, o := strings.Index(out, "B first:"), strings.Index(out, "A second:"), strings.Index(out, "Other commands:")
	if code != ExitOK || b < 0 || a < b || o < a || strings.Contains(out, "plumbing") || strings.Contains(out, "\nCommands:") {
		t.Fatalf("sections: %d %q", code, out)
	}
	if !strings.Contains(out[o:], "elsewhere") || !strings.Contains(out[o:], "stray") || !strings.Contains(out[b:a], "zed") ||
		!strings.Contains(out, "Topics:") || !strings.Contains(out, "moving") {
		t.Errorf("sections list the wrong commands: %q", out)
	}
	if code, _, _ := main("plumbing"); code != ExitOK || !ran {
		t.Errorf("a hidden command did not run: %d", code)
	}
	if code, out, _ := main("plumbing", "--help"); code != ExitOK || !strings.HasPrefix(out, "Usage: rpmgr plumbing") {
		t.Errorf("hidden command help: %d %q", code, out)
	}
	code, out, _ = main("help", "moving")
	if code != ExitOK || !strings.Contains(out, "Usage: rpmgr help moving") || !strings.Contains(out, "rpmgr zed\n      does it") ||
		!strings.Contains(out, "systemctl reload x") {
		t.Errorf("topic: %d %q", code, out)
	}
	if code, _, errOut := main("old"); code != ExitUsage || !strings.Contains(errOut, `unknown command "old": it was removed; use 'rpmgr zed'`) {
		t.Errorf("removed: %d %q", code, errOut)
	}
	if code, _, errOut := main("help", "nothing"); code != ExitUsage || !strings.Contains(errOut, `unknown command "nothing"`) ||
		strings.Contains(errOut, "removed") {
		t.Errorf("unknown topic: %d %q", code, errOut)
	}
	// A command shadows a topic of its name.
	root.Topics = append(root.Topics, Topic{Name: "zed", Summary: "x"})
	if _, out, _ := main("help", "zed"); !strings.HasPrefix(out, "Usage: rpmgr zed") {
		t.Errorf("topic shadows a command: %q", out)
	}
}
