// SPDX-License-Identifier: Apache-2.0

// Command s5 generates and applies the spike's migrations without the Atlas CLI:
//
//	s5 diff  -dialect sqlite|postgres -dev <dsn> -name <name>   write the next migration file
//	s5 apply -dialect sqlite|postgres -db <dsn> [-n N]          apply pending migrations
//	s5 check -dialect sqlite|postgres -db <dsn>                 compare the live schema with Ent
//	s5 hash  -dialect sqlite|postgres                           rewrite atlas.sum
//
// For SQLite the dev database is in memory unless -dev is given; for PostgreSQL -dev must name an
// empty database. Migration directories: migrations/sqlite and migrations/postgres.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"ariga.io/atlas/sql/migrate"

	"github.com/felix-homelab/rpmgr/spikes/s5/store"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: s5 diff|apply|check [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dialectName := fs.String("dialect", "sqlite", "sqlite or postgres")
	dev := fs.String("dev", "", "dev database DSN (diff)")
	db := fs.String("db", "", "target database DSN (apply, check)")
	name := fs.String("name", "", "migration name (diff)")
	n := fs.Int("n", 0, "apply at most n migrations (0 = all)")
	root := fs.String("dir", "migrations", "root of the migration directories")
	_ = fs.Parse(os.Args[2:])
	if err := run(context.Background(), os.Args[1], *dialectName, *dev, *db, *name, *root, *n); err != nil {
		fmt.Fprintln(os.Stderr, "s5:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd, dialectName, dev, dsn, name, root string, n int) error {
	d := map[string]string{"sqlite": store.SQLite, "postgres": store.Postgres}[dialectName]
	if d == "" {
		return fmt.Errorf("unknown dialect %q", dialectName)
	}
	dir, err := migrate.NewLocalDir(filepath.Join(root, dialectName))
	if err != nil {
		return err
	}
	switch cmd {
	case "diff":
		if name == "" {
			return errors.New("diff needs -name")
		}
		if dev == "" && d == store.SQLite {
			dev = "file:dev?mode=memory&_pragma=foreign_keys(1)"
		}
		devDB, err := store.OpenDB(ctx, d, dev)
		if err != nil {
			return err
		}
		defer devDB.Close()
		err = store.Diff(ctx, d, devDB, dir, name)
		if errors.Is(err, migrate.ErrNoPlan) {
			fmt.Println("no changes: the migration directory matches the Ent schema")
			return nil
		}
		return err
	case "hash":
		sum, err := dir.Checksum()
		if err != nil {
			return err
		}
		return migrate.WriteSumFile(dir, sum)
	case "apply", "check":
		conn, err := store.OpenDB(ctx, d, dsn)
		if err != nil {
			return err
		}
		defer conn.Close()
		if cmd == "apply" {
			return store.Migrate(ctx, d, conn, dir, n)
		}
		return store.Check(ctx, d, conn)
	}
	return fmt.Errorf("unknown command %q", cmd)
}
