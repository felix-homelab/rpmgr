// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"strings"
	"testing"
)

// testTree is a small tree with every kind of node: a group, a leaf with flags and arguments,
// a command with both a Run and sub-commands, and commands that fail in each way.
func testTree(got *[]string) *Command {
	record := func(_ context.Context, _ *Env, args []string) error {
		*got = append([]string(nil), args...)
		return nil
	}
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
		{name: "runtime error", args: []string{"fail"}, code: ExitError, stderr: "rpmgr fail: boom"},
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
