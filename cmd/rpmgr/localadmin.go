// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	var csrOut string
	return group("ca", "administer the internal CA on the controller host",
		localCommand("status", "show the CA keys and their validity", nil, func(ctx context.Context, env *cli.Env, path string) error {
			st, err := controller.CAStatus(ctx, path)
			if err != nil {
				return err
			}
			fmt.Fprintf(env.Stdout, "Trust domain: %s\nRoot pin:     %s\nRoot key:     %s\n", st.GetTrustDomain(), st.GetRootPin(), rootKeyState(st))
			if kek := st.GetRootKeyResidueKek(); kek != "" {
				fmt.Fprintf(env.Stdout, "\nWARNING: the root's sealed key may still be recoverable from free pages, the write-ahead log and older backups,\n"+
					"and KEK %s opens it. Rotate the KEK and destroy that one (docs/10-operations.md, \"Take the root offline\").\n", kek)
			}
			if st.GetRootKekUnknown() {
				fmt.Fprint(env.Stdout, "\nWARNING: cannot tell whether the KEK was rotated since the root went offline: the audit entry of the ceremony is gone.\n"+
					"If it was not, the root's sealed key may still be recoverable from free pages and older backups.\n")
			}
			warnings, err := controller.CAStatusWarnings(ctx, path)
			if err != nil {
				return err
			}
			for _, w := range warnings {
				fmt.Fprintf(env.Stdout, "\nWARNING: %s.\n", w)
			}
			if msg := signingAlertText(st); msg != "" {
				fmt.Fprintf(env.Stdout, "\n%s\n", msg)
			}
			rot, err := controller.CARotationStatus(ctx, path, time.Now)
			if err != nil {
				return err
			}
			if msg := rotationText(rot); msg != "" {
				fmt.Fprintf(env.Stdout, "\n%s\n", msg)
			}
			fmt.Fprintln(env.Stdout)
			return writeCAKeys(env, st.GetKeys())
		}),
		localCommand("rotate-intermediate", "rotate the issuing intermediate now, or with an offline root ask it for a signature", func(fs *flag.FlagSet) {
			fs.StringVar(&csrOut, "csr-out", "", "with an offline root: write the request for its signature to this new file (never overwritten)")
		}, func(ctx context.Context, env *cli.Env, path string) error {
			if csrOut != "" {
				hash, err := controller.RequestIntermediate(ctx, path, csrOut, env.Getenv, time.Now)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(env.Stdout, "Wrote the request to %s. Key SHA-256: %s\nCarry it to the offline host and run rpmgr ca sign-intermediate; it shows the same hash.\n"+
					"Bring the certificate back and run rpmgr ca import-intermediate.\n", csrOut, hash)
				return err
			}
			k, err := controller.RotateIntermediate(ctx, path, env.Getenv)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "The new issuing intermediate %s is active, valid until %s; the old one is retired and keeps\n"+
				"verifying the certificates it issued. Running controllers load it within a minute; agents\nreceive the new chain at their next renewal.\n",
				k.GetSubject(), k.GetNotAfter().AsTime().UTC().Format(time.RFC3339))
			return err
		}),
		offlineRootCommand(), signIntermediateCommand(), importIntermediateCommand(), newRootCommand(), dropRootCommand())
}

// signingAlertText is what `ca status` says of the need for the offline root's signature.
func signingAlertText(st *rpmgrv1.GetPkiStatusResponse) string {
	hash := st.GetNextIntermediateKeyHash()
	switch st.GetSigningAlert() {
	case rpmgrv1.SigningAlert_SIGNING_ALERT_NEEDS_SIGNING:
		return fmt.Sprintf("The intermediate needs the offline root's signature (key SHA-256 %s): sign the request with rpmgr ca sign-intermediate\n"+
			"on the offline host, then run rpmgr ca import-intermediate (rpmgr ca rotate-intermediate --csr-out writes the request again).", hash)
	case rpmgrv1.SigningAlert_SIGNING_ALERT_CRITICAL:
		return fmt.Sprintf("CRITICAL: the intermediate needs the offline root's signature (key SHA-256 %s) and the active one expires soon: sign the\n"+
			"request with rpmgr ca sign-intermediate on the offline host, then run rpmgr ca import-intermediate.", hash)
	case rpmgrv1.SigningAlert_SIGNING_ALERT_NEXT_NOT_VALID:
		return fmt.Sprintf("CRITICAL: the signed intermediate (key SHA-256 %s) is not valid now and is not activated: make a new request with\n"+
			"rpmgr ca rotate-intermediate --csr-out, sign it on the offline host and import it.", hash)
	}
	return ""
}

func rootKeyState(st *rpmgrv1.GetPkiStatusResponse) string {
	if st.GetRootOffline() {
		return "offline (the database holds its certificate and no key)"
	}
	return "online (sealed in the database)"
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
	var previous controller.PreviousKEK
	return group("kek", "administer the key-encryption key on the controller host",
		localCommand("status", "show which KEK version wraps the stored secrets", nil, func(ctx context.Context, env *cli.Env, path string) error {
			st, err := controller.StatusKEK(ctx, path, env.Getenv)
			if err != nil {
				return err
			}
			return st.Write(env.Stdout)
		}),
		localCommand("rotate", "re-wrap every stored secret under a new KEK",
			func(fs *flag.FlagSet) {
				fs.StringVar(&previous.File, "previous-file", "", "the KEK before, in a file of the format of kek.source file, mode 0600")
				fs.StringVar(&previous.Config, "previous-config", "", "the boot file whose kek section names the KEK before, of any source, to move between a file or credential and Transit")
			},
			func(ctx context.Context, env *cli.Env, path string) error {
				if previous.File != "" && previous.Config != "" {
					return cli.Usagef("kek rotate takes --previous-file or --previous-config, not both")
				}
				n, v, err := controller.RotateKEK(ctx, path, previous, env.Getenv)
				if errors.Is(err, controller.ErrPreviousNeeded) {
					return cli.Usagef("kek rotate needs --previous-file or --previous-config, unless kek.source is kms")
				}
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(env.Stdout, "Re-wrapped %d secrets under KEK version %s; every stored secret is under it now.\n", n, v)
				if err != nil {
					return err
				}
				if strings.Contains(v, "@v") {
					_, err = fmt.Fprintln(env.Stdout, "Raise the Transit key's minimum decryption version only after `rpmgr kek status` shows no secret on an older version\nand a fresh backup was taken under the latest one.")
					return err
				}
				_, err = fmt.Fprintln(env.Stdout, "Back the new KEK up apart from the database, and retire the old one after a backup and a test restore.")
				return err
			}))
}

// unknownMigration ends `rpmgr migrate` with update.ExitUnknownMigration.
type unknownMigration struct{ error }

func (unknownMigration) ExitCode() int   { return update.ExitUnknownMigration }
func (e unknownMigration) Unwrap() error { return e.error }
