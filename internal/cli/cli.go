// SPDX-License-Identifier: Apache-2.0

// Package cli runs rpmgr's command tree on the standard library's flag package. Every command
// prints its help with -h or --help. Flags may stand before, between or after the positional
// arguments; "--" ends them, so that an argument after it may begin with "-".
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// Exit codes of the rpmgr binary.
const (
	ExitOK    = 0 // the command succeeded, or help was requested
	ExitError = 1 // the command ran and failed
	ExitUsage = 2 // the command line is invalid, or the command is not available in this build
)

// ErrNotAvailable is returned by commands that this build does not implement yet.
var ErrNotAvailable = errors.New("not available in this build")

// Env is what a command may use of its process. Tests replace every field.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
}

// Command is one node of the command tree. A command without Run is a group: it only selects
// one of its sub-commands.
type Command struct {
	Name    string
	Summary string // one line, lower-case start, no trailing period
	Args    string // synopsis of the positional arguments, e.g. "<dir>"; empty for none
	// Flags registers the command's flags on fs; nil if the command has none.
	Flags func(fs *flag.FlagSet)
	// Run executes the command with its positional arguments, in their order, without the flags.
	Run func(ctx context.Context, env *Env, args []string) error
	Sub []*Command
}

// NotAvailable is the Run function of a command that this build does not implement yet.
func NotAvailable(context.Context, *Env, []string) error { return ErrNotAvailable }

// UsageError reports an invalid command line. Main prints it with the usage and exits 2.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// Usagef returns a UsageError with a formatted message.
func Usagef(format string, a ...any) error { return &UsageError{Msg: fmt.Sprintf(format, a...)} }

// Main runs the command line args (without the program name) against root and returns the
// process exit code.
func Main(ctx context.Context, root *Command, args []string, env *Env) int {
	path := []string{root.Name}
	cmd := root
	if len(args) > 0 && args[0] == "help" && root.Sub != nil {
		// "rpmgr help [command ...]" prints the help of that command.
		for _, name := range args[1:] {
			sub := cmd.find(name)
			if sub == nil {
				return usageFail(env, cmd, path, cmd.flagSet(path), Usagef("unknown command %q", name))
			}
			cmd, path = sub, append(path, name)
		}
		cmd.writeHelp(env.Stdout, path, cmd.flagSet(path))
		return ExitOK
	}
	for len(args) > 0 && cmd.Sub != nil && !strings.HasPrefix(args[0], "-") {
		sub := cmd.find(args[0])
		if sub == nil {
			return usageFail(env, cmd, path, cmd.flagSet(path), Usagef("unknown command %q", args[0]))
		}
		cmd, path, args = sub, append(path, args[0]), args[1:]
	}

	// The usage text comes from fs, whose flags were registered before parsing: a flag's default
	// is what its value said then, not what the command line made of it.
	fs := cmd.flagSet(path)
	pos, err := parse(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			cmd.writeHelp(env.Stdout, path, fs)
			return ExitOK
		}
		return usageFail(env, cmd, path, fs, err)
	}
	if cmd.Run == nil {
		if len(pos) > 0 {
			return usageFail(env, cmd, path, fs, Usagef("unknown command %q", pos[0]))
		}
		return usageFail(env, cmd, path, fs, Usagef("a command is required"))
	}
	if cmd.Args == "" && len(pos) > 0 {
		return usageFail(env, cmd, path, fs, Usagef("unexpected argument %q", pos[0]))
	}

	err = cmd.Run(ctx, env, pos)
	var ue *UsageError
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &ue):
		return usageFail(env, cmd, path, fs, err)
	case errors.Is(err, ErrNotAvailable):
		fmt.Fprintf(env.Stderr, "%s: %v\n", strings.Join(path, " "), err)
		return ExitUsage
	default:
		fmt.Fprintf(env.Stderr, "%s: %v\n", strings.Join(path, " "), err)
		return ExitError
	}
}

func usageFail(env *Env, cmd *Command, path []string, fs *flag.FlagSet, err error) int {
	fmt.Fprintf(env.Stderr, "%s: %v\n\n", strings.Join(path, " "), err)
	cmd.writeHelp(env.Stderr, path, fs)
	return ExitUsage
}

// flagSet is a new flag set with the command's flags registered.
func (c *Command) flagSet(path []string) *flag.FlagSet {
	fs := flag.NewFlagSet(strings.Join(path, " "), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if c.Flags != nil {
		c.Flags(fs)
	}
	return fs
}

// parse sets the flags in args, wherever they stand among the positional arguments, and returns
// the positional arguments in their order. "--" ends the flags: every argument after it is
// positional, also one that begins with "-". A lone "-" is positional too.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			return append(pos, args[1:]...), nil
		}
		if len(a) < 2 || a[0] != '-' {
			pos, args = append(pos, a), args[1:]
			continue
		}
		// The flag package parses one flag at a time, with the next argument as its value if the
		// flag takes one and was not given as -name=value.
		n := 1
		if name := strings.TrimPrefix(a[1:], "-"); len(args) > 1 && !strings.Contains(name, "=") {
			if f := fs.Lookup(name); f != nil && !isBoolFlag(f.Value) {
				n = 2
			}
		}
		if err := fs.Parse(args[:n]); err != nil {
			return nil, err
		}
		args = args[n:]
	}
	return pos, nil
}

// isBoolFlag reports whether a flag is a switch, which takes no value after it.
func isBoolFlag(v flag.Value) bool {
	b, ok := v.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

func (c *Command) find(name string) *Command {
	for _, s := range c.Sub {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// writeHelp prints the command's help, with the flags of fs, the command's flag set.
func (c *Command) writeHelp(w io.Writer, path []string, fs *flag.FlagSet) {
	name := strings.Join(path, " ")
	synopsis := name
	if c.Sub != nil {
		synopsis += " <command>"
	}
	hasFlags := false
	fs.VisitAll(func(*flag.Flag) { hasFlags = true })
	if hasFlags {
		synopsis += " [flags]"
	}
	if c.Args != "" {
		synopsis += " " + c.Args
	}
	fmt.Fprintf(w, "Usage: %s\n\n%s.\n", synopsis, upperFirst(c.Summary))
	if c.Sub != nil {
		fmt.Fprintf(w, "\nCommands:\n")
		tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
		subs := append([]*Command(nil), c.Sub...)
		sort.SliceStable(subs, func(i, j int) bool { return subs[i].Name < subs[j].Name })
		for _, s := range subs {
			fmt.Fprintf(tw, "  %s\t%s\n", s.Name, s.Summary)
		}
		if err := tw.Flush(); err != nil {
			return
		}
		fmt.Fprintf(w, "\nRun '%s <command> --help' for the flags of a command.\n", name)
	}
	if hasFlags {
		fmt.Fprintf(w, "\nFlags:\n")
		fs.SetOutput(w)
		fs.PrintDefaults()
	}
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
