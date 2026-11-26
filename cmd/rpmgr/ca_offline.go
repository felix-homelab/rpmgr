// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// The ceremony of the offline root (docs/04-security.md, "Offline root CA"; docs/16-cli.md).

// maxPassphraseFile bounds a passphrase file.
const maxPassphraseFile = 1024

// The terminal of the prompts and how a secret is read from it; a test replaces them.
var (
	openTTY      = func() (*os.File, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }
	readPassword = func(fd int) ([]byte, error) { return term.ReadPassword(fd) }
)

// askSecret writes prompt on the terminal and reads the answer with echo off. A Ctrl-C while it
// waits first puts the terminal back as it was, as ReadPassword would not.
func askSecret(tty *os.File, prompt string) (string, error) {
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", err
	}
	fd := int(tty.Fd()) //nolint:gosec // G115: a file descriptor fits in an int
	if old, err := term.GetState(fd); err == nil {
		sig := make(chan os.Signal, 1)
		done := make(chan struct{})
		signal.Notify(sig, os.Interrupt)
		defer func() { signal.Stop(sig); close(done) }()
		go func() {
			select {
			case <-sig:
				_ = term.Restore(fd, old)
				_, _ = fmt.Fprintln(tty)
				os.Exit(130) // 128 + SIGINT
			case <-done:
			}
		}()
	}
	b, err := readPassword(fd)
	defer clear(b)
	_, _ = fmt.Fprintln(tty)
	return string(b), err
}

// passphrasePrompt asks for the passphrase on the terminal with echo off, twice when it is a new
// one; a test replaces it.
var passphrasePrompt = func(twice bool) (string, error) {
	tty, err := openTTY()
	if err != nil {
		return "", errors.New("no passphrase: use --passphrase-file, or run on a terminal")
	}
	defer func() { _ = tty.Close() }()
	p, err := askSecret(tty, "Passphrase: ")
	if err != nil || !twice {
		return p, err
	}
	again, err := askSecret(tty, "Passphrase again: ")
	if err != nil {
		return "", err
	}
	if again != p {
		return "", errors.New("the two passphrases differ")
	}
	return p, nil
}

// confirmPrompt asks the operator on the terminal whether to go on; a test replaces it.
var confirmPrompt = func(question string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, errors.New("no terminal to confirm on: check the request above and run again with --yes")
	}
	defer func() { _ = tty.Close() }()
	if _, err := fmt.Fprint(tty, question+" [y/N]: "); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes", nil
}

// readPassphraseFile reads a passphrase from a file that only its owner may read; one trailing
// line break is not part of it.
func readPassphraseFile(path string) (string, error) {
	b, err := secret.ReadFile(path, "passphrase file", false, maxPassphraseFile)
	if err != nil {
		return "", err
	}
	defer clear(b)
	return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
}

// offlineRootCommand is `rpmgr ca offline-root`.
func offlineRootCommand() *cli.Command {
	var out, passFile string
	var prompt bool
	c := localCommand("offline-root", "move the root's key into a passphrase file and out of the database", func(fs *flag.FlagSet) {
		fs.StringVar(&out, "out", "", "the file to write, which must not exist; it is created with mode 0600")
		fs.StringVar(&passFile, "passphrase-file", "", "read the passphrase from this file (mode 0600) instead of generating one")
		fs.BoolVar(&prompt, "prompt", false, "ask for the passphrase on the terminal, twice, instead of generating one")
	}, func(ctx context.Context, env *cli.Env, path string) error {
		switch {
		case out == "":
			return cli.Usagef("offline-root needs --out")
		case passFile != "" && prompt:
			return cli.Usagef("give --passphrase-file or --prompt, not both")
		}
		var pass string
		var err error
		switch {
		case passFile != "":
			pass, err = readPassphraseFile(passFile)
		case prompt:
			pass, err = passphrasePrompt(true)
		}
		if err != nil {
			return err
		}
		r, err := controller.OfflineRoot(ctx, controller.OfflineRootOptions{ConfigPath: path, Out: out, Passphrase: pass, Getenv: env.Getenv})
		if err != nil {
			if r.Passphrase != "" {
				// The file was kept and opens only with the generated passphrase, which is nowhere else.
				fmt.Fprintf(env.Stderr, "The file %s was kept. Its generated passphrase, shown once and stored nowhere, is:\n  %s\n"+
					"Write it down: without it the file cannot be opened.\n", out, r.Passphrase)
			}
			return err
		}
		fmt.Fprintf(env.Stdout, "The root's key is in %s (mode 0600). The file was read again, decrypted and compared with the database,\n"+
			"and the key is gone from the database; opening it on the offline host (rpmgr ca sign-intermediate) proves the medium.\nRoot pin:     %s\nFile SHA-256: %s\n", out, r.Pin, r.FileSHA256)
		if r.Passphrase != "" {
			fmt.Fprintf(env.Stdout, "Passphrase:   %s\n\nThis is shown once and stored nowhere. Write it down and keep it apart from the media.\n", r.Passphrase)
		}
		_, err = fmt.Fprintf(env.Stdout, "\nTo do now:\n"+
			"  1. Move the file to offline media and delete every other copy, on this host too; keep a second copy of the media.\n"+
			"  2. Rotate the KEK (%s sealed the key) and destroy the old one: the sealed key survives in free pages, the\n"+
			"     write-ahead log and older backups until then. Then take a new backup (docs/10-operations.md, \"Take the root offline\").\n", r.KEK)
		return err
	})
	c.NoArgEcho = true // a passphrase given as an argument by mistake is not repeated
	return c
}

// signIntermediateCommand is `rpmgr ca sign-intermediate`; it needs no boot file.
func signIntermediateCommand() *cli.Command {
	var rootFile, csr, out, passFile, keyHash, kind string
	var yes bool
	return &cli.Command{
		Name:    "sign-intermediate",
		Summary: "sign a request for an intermediate with the offline root, on the offline host",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&rootFile, "root-file", "", "the root file that `ca offline-root` wrote")
			fs.StringVar(&csr, "csr", "", "the request that `ca rotate-intermediate --csr-out` wrote")
			fs.StringVar(&out, "out", "", "the certificate to write, which must not exist")
			fs.StringVar(&passFile, "passphrase-file", "", "read the passphrase from this file (mode 0600) instead of asking for it")
			fs.StringVar(&keyHash, "key-sha256", "", "the SHA-256 of the key the request must carry, as `ca status` and `ca rotate-intermediate --csr-out` show it; required with --yes")
			fs.BoolVar(&yes, "yes", false, "sign without asking for a confirmation, on a host where nobody is")
			fs.StringVar(&kind, "kind", "intermediate", "intermediate, or cross-root for the request of a new root that ca new-root --csr-out wrote")
		},
		NoArgEcho: true,
		Run: func(_ context.Context, env *cli.Env, _ []string) error {
			if rootFile == "" || csr == "" || out == "" {
				return cli.Usagef("sign-intermediate needs --root-file, --csr and --out")
			}
			if yes && keyHash == "" {
				return cli.Usagef("--yes signs without asking, so it needs --key-sha256, the hash of the key the request must carry")
			}
			var pass string
			var err error
			if passFile != "" {
				pass, err = readPassphraseFile(passFile)
			} else {
				pass, err = passphrasePrompt(false)
			}
			if err != nil {
				return err
			}
			_, err = controller.SignIntermediate(controller.SignOptions{RootFile: rootFile, CSR: csr, Out: out, Passphrase: pass, KeyHash: keyHash,
				Confirm: func(s controller.IntermediateSummary) (bool, error) {
					fmt.Fprintf(env.Stdout, "Request to sign:\n  Subject:     %s (the request's own subject is ignored)\n  Key SHA-256: %s\n"+
						"  Valid:       %s to %s\n  Constraints: %s\n", s.Subject, s.KeyHash, s.NotBefore.UTC().Format(time.RFC3339),
						s.NotAfter.UTC().Format(time.RFC3339), s.Constraints)
					if yes {
						return true, nil
					}
					return confirmPrompt("The key hash must equal the one `ca rotate-intermediate --csr-out` printed. Sign")
				}})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Wrote %s. Carry it to the controller host and run rpmgr ca import-intermediate.\n", out)
			return err
		},
	}
}

// importIntermediateCommand is `rpmgr ca import-intermediate`.
func importIntermediateCommand() *cli.Command {
	var in string
	return localCommand("import-intermediate", "import the intermediate the offline root signed", func(fs *flag.FlagSet) {
		fs.StringVar(&in, "in", "", "the certificate that `ca sign-intermediate` wrote")
	}, func(ctx context.Context, env *cli.Env, path string) error {
		if in == "" {
			return cli.Usagef("import-intermediate needs --in")
		}
		s, err := controller.ImportIntermediate(ctx, path, in, time.Now)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(env.Stdout, "Imported the intermediate for key %s, valid until %s. It stays next until the schedule activates it; running\n"+
			"controllers load it within a minute.\n", s.KeyHash, s.NotAfter.UTC().Format(time.RFC3339))
		return err
	})
}
