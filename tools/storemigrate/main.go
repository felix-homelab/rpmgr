// SPDX-License-Identifier: Apache-2.0

// Command storemigrate generates and checks the store's migrations (docs/06-data-model.md,
// "Migrations"); it is a development tool and not part of the rpmgr binary:
//
//	storemigrate diff  -dialect sqlite|postgres [-dev <dsn>] -name <name>   write the next migration
//	storemigrate hash  -dialect sqlite|postgres                             rewrite atlas.sum
//
// SQLite uses an in-memory development database; PostgreSQL needs -dev, an empty database.
// Without changes, diff prints "no changes" and writes nothing.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"ariga.io/atlas/sql/migrate"
	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
	_ "modernc.org/sqlite"             // registers "sqlite"

	"github.com/felix-homelab/rpmgr/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: storemigrate diff|hash -dialect sqlite|postgres [-dev dsn] [-name name] [-dir dir]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dialectName := fs.String("dialect", "sqlite", "sqlite or postgres")
	dev := fs.String("dev", "", "empty development database (PostgreSQL)")
	name := fs.String("name", "", "name of the new migration (diff)")
	root := fs.String("dir", "internal/store/migrations", "directory that holds sqlite/ and postgres/")
	_ = fs.Parse(os.Args[2:])
	if err := run(context.Background(), os.Args[1], *dialectName, *dev, *name, *root); err != nil {
		fmt.Fprintln(os.Stderr, "storemigrate:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd, dialectName, dev, name, root string) error {
	d, driver := map[string]string{"sqlite": store.SQLite, "postgres": store.Postgres}[dialectName], "sqlite"
	if d == "" {
		return fmt.Errorf("unknown dialect %q", dialectName)
	}
	dir, err := migrate.NewLocalDir(filepath.Join(root, dialectName))
	if err != nil {
		return err
	}
	switch cmd {
	case "hash":
		sum, err := dir.Checksum()
		if err != nil {
			return err
		}
		return migrate.WriteSumFile(dir, sum)
	case "diff":
		if name == "" {
			return errors.New("diff needs -name")
		}
		if d == store.SQLite {
			dev = "file:dev?mode=memory&_pragma=foreign_keys(1)"
		} else {
			driver = "pgx"
			if dev == "" {
				return errors.New("diff for postgres needs -dev, an empty database")
			}
		}
		devDB, err := sql.Open(driver, dev)
		if err != nil {
			return err
		}
		defer func() { _ = devDB.Close() }()
		err = store.Diff(ctx, d, devDB, dir, name)
		if errors.Is(err, migrate.ErrNoPlan) {
			fmt.Println("no changes: the migrations match the Ent schema")
			return nil
		}
		return err
	}
	return fmt.Errorf("unknown command %q", cmd)
}
