// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/update"
)

// Local administration on the controller host (docs/16-cli.md): each command reads the
// controller's or all-in-one's boot file.

const bootFlagHelp = "the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else /etc/rpmgr/all-in-one.yaml)"

// bootDir is where the boot files are; a test replaces it.
var bootDir = "/etc/rpmgr"

// controllerBoot is the boot file of a command on the controller host: the --config flag if set,
// else $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml, else, on an all-in-one host,
// /etc/rpmgr/all-in-one.yaml.
func controllerBoot(flagPath string, getenv func(string) string) string {
	if flagPath != "" || getenv("RPMGR_CONFIG") != "" {
		return config.Path(flagPath, "controller", getenv)
	}
	path := filepath.Join(bootDir, "controller.yaml")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if aio := filepath.Join(bootDir, "all-in-one.yaml"); fileExists(aio) {
			return aio
		}
	}
	return path
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// localCommand is a command of the controller host that takes --config and no arguments.
func localCommand(name, summary string, flags func(fs *flag.FlagSet), run func(ctx context.Context, env *cli.Env, path string) error) *cli.Command {
	var configPath string
	return &cli.Command{
		Name:    name,
		Summary: summary,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&configPath, "config", "", bootFlagHelp)
			if flags != nil {
				flags(fs)
			}
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			return run(ctx, env, controllerBoot(configPath, env.Getenv))
		},
	}
}

// migrateCommand is `rpmgr migrate`.
func migrateCommand() *cli.Command {
	return localCommand("migrate", "apply database migrations", nil, func(ctx context.Context, env *cli.Env, path string) error {
		res, err := controller.Migrate(ctx, path, time.Now)
		if errors.Is(err, store.ErrUnknownMigration) {
			// A distinct code, so that the root updater's rollback tells a schema a newer release
			// migrated from any other failure (docs/10-operations.md, "Backup and restore").
			return unknownMigration{err}
		}
		if err != nil {
			return err
		}
		if len(res.Applied) == 0 {
			_, err = fmt.Fprintln(env.Stdout, "The database is up to date.")
			return err
		}
		_, err = fmt.Fprintf(env.Stdout, "Applied %d migrations: %s.\nThe database before them is %s; delete it once the controller runs.\n",
			len(res.Applied), strings.Join(res.Applied, ", "), res.Copy)
		return err
	})
}

// migrateDBCommand is `rpmgr migrate-db`: a stopped controller's database copied into an empty one,
// between SQLite and PostgreSQL in either direction (docs/16-cli.md). It takes files, never a DSN.
func migrateDBCommand() *cli.Command {
	var from, toFile string
	var noRetire bool
	return &cli.Command{
		Name:    "migrate-db",
		Summary: "copy a stopped controller's database between SQLite and PostgreSQL",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&from, "from", "", "the source: a SQLite database file or a boot file (required)")
			fs.StringVar(&toFile, "to-file", "", "the target: a boot file whose database section names an empty database (required)")
			fs.BoolVar(&noRetire, "no-retire", false, "leave the source usable after the copy, for a test copy")
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			if from == "" || toFile == "" {
				return cli.Usagef("migrate-db needs --from and --to-file")
			}
			tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
			header := true
			r, err := controller.MigrateDB(ctx, controller.MigrateDBOptions{From: from, ToFile: toFile, NoRetire: noRetire, Getenv: env.Getenv,
				Progress: func(table string, rows int64) {
					if header {
						fmt.Fprintln(tw, "TABLE\tROWS")
						header = false
					}
					fmt.Fprintf(tw, "%s\t%d\n", table, rows)
				}})
			if ferr := tw.Flush(); err == nil {
				err = ferr
			}
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "\nCopied %d tables and %d rows from %s to %s; the counts and content hashes agree (%s).\n"+
				"The secrets were copied sealed and the database epoch is kept; no KEK was read.\n", r.Copy.Tables, r.Copy.Rows, r.From, r.To, r.Copy.Hash)
			if err == nil && r.Retired {
				_, err = fmt.Fprintln(env.Stdout, "The source is retired: no controller starts on it. Keep it until the target has run for a while.")
			} else if err == nil {
				_, err = fmt.Fprintln(env.Stdout, "The source is NOT retired (--no-retire): never run a controller on it and on the target at once.")
			}
			return err
		},
	}
}

// caCommand is `rpmgr ca …`.
func caCommand() *cli.Command {
	return group("ca", "administer the internal CA on the controller host",
		localCommand("status", "show the CA keys and their validity", nil, func(ctx context.Context, env *cli.Env, path string) error {
			st, err := controller.CAStatus(ctx, path)
			if err != nil {
				return err
			}
			fmt.Fprintf(env.Stdout, "Trust domain: %s\nRoot pin:     %s\n\n", st.GetTrustDomain(), st.GetRootPin())
			return writeCAKeys(env, st.GetKeys())
		}),
		localCommand("rotate-intermediate", "rotate the issuing intermediate now", nil, func(ctx context.Context, env *cli.Env, path string) error {
			k, err := controller.RotateIntermediate(ctx, path, env.Getenv)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "The new issuing intermediate %s is active, valid until %s; the old one is retired and keeps\n"+
				"verifying the certificates it issued. Running controllers load it within a minute; agents\nreceive the new chain at their next renewal.\n",
				k.GetSubject(), k.GetNotAfter().AsTime().UTC().Format(time.RFC3339))
			return err
		}))
}

var caKinds = map[rpmgrv1.CAKeyKind]string{rpmgrv1.CAKeyKind_CA_KEY_KIND_ROOT: "root", rpmgrv1.CAKeyKind_CA_KEY_KIND_INTERMEDIATE: "intermediate",
	rpmgrv1.CAKeyKind_CA_KEY_KIND_CONFIG_SIGNING: "config-signing", rpmgrv1.CAKeyKind_CA_KEY_KIND_AUDIT_CHECKPOINT: "audit-checkpoint"}

var caStates = map[rpmgrv1.CAKeyState]string{rpmgrv1.CAKeyState_CA_KEY_STATE_ACTIVE: "active", rpmgrv1.CAKeyState_CA_KEY_STATE_NEXT: "next",
	rpmgrv1.CAKeyState_CA_KEY_STATE_RETIRED: "retired"}

func writeCAKeys(env *cli.Env, keys []*rpmgrv1.CAKey) error {
	day := func(t interface{ AsTime() time.Time }) string { return t.AsTime().UTC().Format("2006-01-02") }
	tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tSTATE\tNOT BEFORE\tNOT AFTER\tROTATES\tSUBJECT")
	for _, k := range keys {
		rotates := "-"
		if k.GetRotateTime() != nil {
			rotates = day(k.GetRotateTime())
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", caKinds[k.GetKind()], caStates[k.GetState()], day(k.GetNotBefore()),
			day(k.GetNotAfter()), rotates, k.GetSubject())
	}
	return tw.Flush()
}

// kekCommand is `rpmgr kek …`.
func kekCommand() *cli.Command {
	var previous string
	return group("kek", "administer the key-encryption key on the controller host",
		localCommand("status", "show which KEK version wraps the stored secrets", nil, func(ctx context.Context, env *cli.Env, path string) error {
			st, err := controller.StatusKEK(ctx, path, env.Getenv)
			if err != nil {
				return err
			}
			if st.CurrentErr != nil {
				fmt.Fprintf(env.Stdout, "The boot file's KEK: not loaded (%v)\n\n", st.CurrentErr)
			} else {
				fmt.Fprintf(env.Stdout, "The boot file's KEK: version %s\n\n", st.Current)
			}
			tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "KEK VERSION\tSECRETS")
			for _, v := range slices.Sorted(maps.Keys(st.Versions)) {
				mark := ""
				if v == st.Current {
					mark = " (the boot file's)"
				}
				fmt.Fprintf(tw, "%s%s\t%d\n", v, mark, st.Versions[v])
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if st.Mismatch() {
				fmt.Fprintln(env.Stdout, "\nThe boot file's KEK wraps none of the secrets: it is not the KEK of this database, or a\nrotation is pending (rpmgr kek rotate --previous-file <the old KEK>).")
			}
			if len(st.Old) > 0 && st.CurrentErr == nil {
				fmt.Fprintf(env.Stdout, "\nUnder another KEK than the boot file's (%d):\n", len(st.Old))
				for _, r := range st.Old {
					fmt.Fprintf(env.Stdout, "  %s  (%s)\n", r, r.KEKVersion)
				}
			}
			return nil
		}),
		localCommand("rotate", "re-wrap every stored secret under a new KEK",
			func(fs *flag.FlagSet) {
				fs.StringVar(&previous, "previous-file", "", "the KEK before, in a file of the format of kek.source file, mode 0600 (required)")
			},
			func(ctx context.Context, env *cli.Env, path string) error {
				if previous == "" {
					return cli.Usagef("kek rotate needs --previous-file")
				}
				n, v, err := controller.RotateKEK(ctx, path, previous, env.Getenv)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(env.Stdout, "Re-wrapped %d secrets under KEK version %s; every stored secret is under it now.\n"+
					"Back the new KEK up apart from the database, and retire the old one after a backup and a test restore.\n", n, v)
				return err
			}))
}

// unknownMigration ends `rpmgr migrate` with update.ExitUnknownMigration.
type unknownMigration struct{ error }

func (unknownMigration) ExitCode() int   { return update.ExitUnknownMigration }
func (e unknownMigration) Unwrap() error { return e.error }
