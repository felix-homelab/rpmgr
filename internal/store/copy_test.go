// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/schema/field"

	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// seedRows is the number of rows seedAll puts into every table.
const seedRows = 2

// seedAll fills every table of the Ent schema with seedRows rows of synthetic values of every column
// type, parents first so that foreign keys hold, and returns the row counts. Values depend only on
// the table, the column and the row number, and rows of different tables that name an organisation
// name the same ones. The singleton rows carry known values: the database epoch and the
// configuration sequence.
func seedAll(t *testing.T, db *store.DB) map[string]int64 {
	t.Helper()
	if db.Dialect != store.SQLite {
		t.Fatal("seedAll seeds SQLite databases; PostgreSQL ones are made by copying")
	}
	tables, err := store.CopyOrder(db)
	if err != nil {
		t.Fatal(err)
	}
	fks := foreignKeyColumns(t, db)
	ctx := context.Background()
	done := map[string][]map[string]any{}
	counts := map[string]int64{}
	base := time.Date(2026, 11, 24, 10, 20, 30, 123456000, time.UTC)
	for _, tbl := range tables {
		fkCols := fks[tbl.Name] // column -> parent table, parent column
		for i := 1; i <= seedRows; i++ {
			row := map[string]any{}
			cols := make([]string, len(tbl.Columns))
			args := make([]any, len(tbl.Columns))
			marks := make([]string, len(tbl.Columns))
			for j, c := range tbl.Columns {
				var v any
				switch {
				case fkCols[c.Name] != [2]any{}:
					p := fkCols[c.Name]
					v = done[p[0].(string)][i-1][p[1].(string)]
				case c.Nullable && i == 2:
					v = nil
				case c.Name == "org_id" || (tbl.Name == "orgs" && c.Name == "id"):
					v = "org-" + strconv.Itoa(i)
				case tbl.Name == "instance" && c.Name == "db_epoch":
					v = "epoch-" + strconv.Itoa(i)
				case tbl.Name == "config_seq" && c.Name == "seq":
					v = int64(40 + i)
				default:
					switch c.Type {
					case field.TypeBool:
						v = i == 1
					case field.TypeInt, field.TypeInt64:
						v = int64(i*10 + j)
						if c.Increment {
							v = int64(i + 100) // not 1, 2: the sequence must be moved past them
						}
					case field.TypeBytes:
						b := make([]byte, 0, 262)
						for k := 0; k < 256; k++ {
							b = append(b, byte(k))
						}
						v = append(b, byte(i), 0, 0xff, byte(j))
					case field.TypeJSON:
						v = fmt.Sprintf(`{"z": [1, 2.50, {"y": null}], "a": "ünï ✓ %d", "k":%d}`, i, j)
					case field.TypeTime:
						// the second row has nanoseconds, which PostgreSQL cannot keep
						v = base.Add(time.Duration(i)*time.Hour + time.Duration(i-1)*789*time.Nanosecond)
					default:
						v = fmt.Sprintf("%s-%s-%d ünï ✓", tbl.Name, c.Name, i)
					}
				}
				row[c.Name] = v
				cols[j] = `"` + c.Name + `"`
				args[j] = v
				if db.Dialect == store.Postgres {
					marks[j] = "$" + strconv.Itoa(j+1)
				} else {
					marks[j] = "?"
				}
			}
			q := `INSERT INTO "` + tbl.Name + `" (` + strings.Join(cols, ", ") + `) VALUES (` + strings.Join(marks, ", ") + `)` //nolint:gosec // G202: names come from the Ent schema
			if _, err := db.Writer.ExecContext(ctx, q, args...); err != nil {
				t.Fatalf("seed %s row %d: %v", tbl.Name, i, err)
			}
			done[tbl.Name] = append(done[tbl.Name], row)
			counts[tbl.Name]++
		}
	}
	return counts
}

// foreignKeyColumns returns, per table, for each column of a foreign key the parent table and column.
func foreignKeyColumns(t *testing.T, db *store.DB) map[string]map[string][2]any {
	t.Helper()
	rows, err := db.Reader.Query(`SELECT m.name, f."from", f."table", COALESCE(f."to", 'id')
		FROM sqlite_master m, pragma_foreign_key_list(m.name) f WHERE m.type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]map[string][2]any{}
	for rows.Next() {
		var tbl, col, parent, to string
		if err := rows.Scan(&tbl, &col, &parent, &to); err != nil {
			t.Fatal(err)
		}
		if out[tbl] == nil {
			out[tbl] = map[string][2]any{}
		}
		out[tbl][col] = [2]any{parent, to}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func total(m map[string]int64) (n int64) {
	for _, v := range m {
		n += v
	}
	return n
}

// scalar runs a query that returns one value.
func scalar[T any](t *testing.T, db *store.DB, q string) T {
	t.Helper()
	var v T
	if err := db.Reader.QueryRow(q).Scan(&v); err != nil { //nolint:gosec // G701: the tests' own queries
		t.Fatalf("%s: %v", q, err)
	}
	return v
}

// rowCounts returns the number of rows of every table.
func rowCounts(t *testing.T, db *store.DB) map[string]int64 {
	t.Helper()
	tables, err := store.CopyOrder(db)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, tbl := range tables {
		out[tbl.Name] = scalar[int64](t, db, `SELECT count(*) FROM "`+tbl.Name+`"`)
	}
	return out
}

func TestCopyOrder_ParentsFirstNoCycles(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		tables, err := store.CopyOrder(db)
		if err != nil {
			t.Fatal(err)
		}
		pos := map[string]int{}
		for i, tbl := range tables {
			pos[tbl.Name] = i
		}
		rows, err := db.Reader.Query(foreignKeyPairsSQL(db.Dialect))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		n := 0
		for rows.Next() {
			var child, parent string
			if err := rows.Scan(&child, &parent); err != nil {
				t.Fatal(err)
			}
			n++
			if pos[parent] >= pos[child] {
				t.Errorf("%s (%d) comes before its parent %s (%d)", child, pos[child], parent, pos[parent])
			}
		}
		if n < 50 {
			t.Fatalf("only %d foreign keys found", n)
		}
	})
}

func foreignKeyPairsSQL(d string) string {
	if d == store.Postgres {
		return `SELECT cl.relname, rf.relname FROM pg_constraint c
			JOIN pg_class cl ON cl.oid = c.conrelid JOIN pg_class rf ON rf.oid = c.confrelid
			WHERE c.contype = 'f' AND cl.relnamespace = current_schema()::regnamespace`
	}
	return `SELECT m.name, f."table" FROM sqlite_master m, pragma_foreign_key_list(m.name) f WHERE m.type = 'table'`
}

// checkCopy copies src to dst and checks the result against the row counts of the seed.
func checkCopy(t *testing.T, src, dst *store.DB, want map[string]int64) store.CopyResult {
	t.Helper()
	var progress int
	res, err := store.CopyDatabase(context.Background(), src, dst, store.CopyOptions{
		Progress: func(string, int64) { progress++ },
	})
	if err != nil {
		t.Fatalf("%s to %s: %v", src.Dialect, dst.Dialect, err)
	}
	if res.Rows != total(want) || res.Tables != len(want) || progress != len(want) || len(res.Hash) != 64 {
		t.Fatalf("result %+v, progress %d tables; want %d rows in %d tables", res, progress, total(want), len(want))
	}
	got := rowCounts(t, dst)
	for tbl, n := range want {
		if got[tbl] != n {
			t.Errorf("%s: %d rows, want %d", tbl, got[tbl], n)
		}
	}
	// the epoch and the configuration sequence arrive unchanged
	if e := scalar[string](t, dst, `SELECT db_epoch FROM instance WHERE id = 101`); e != "epoch-1" {
		t.Errorf("epoch %q", e)
	}
	if s := scalar[int64](t, dst, `SELECT seq FROM config_seq WHERE id = 101`); s != 41 {
		t.Errorf("config_seq %d, want 41", s)
	}
	// sealed bytes, and every other binary column, arrive byte for byte
	const q = `SELECT value_enc FROM acme_storage WHERE size = (SELECT min(size) FROM acme_storage)`
	sa, sb := scalar[[]byte](t, src, q), scalar[[]byte](t, dst, q)
	if len(sa) < 256 || string(sa) != string(sb) {
		t.Errorf("acme_storage.value_enc differs: %d bytes, then %d", len(sa), len(sb))
	}
	if dst.Dialect == store.Postgres {
		assertSequencesPastIDs(t, dst)
	}
	return res
}

func TestCopyDatabase_SQLiteToSQLite(t *testing.T) {
	a, b := storetest.Migrated(t, store.SQLite), storetest.Migrated(t, store.SQLite)
	checkCopy(t, a, b, seedAll(t, a))
}

// SQLite to PostgreSQL to SQLite to PostgreSQL: every direction, and the digest of the content is
// the same after each step, so it does not depend on the dialect.
func TestCopyDatabase_BothDirections(t *testing.T) {
	a := storetest.Migrated(t, store.SQLite)
	want := seedAll(t, a)
	b := storetest.Migrated(t, store.Postgres)
	first := checkCopy(t, a, b, want)
	c := storetest.Migrated(t, store.SQLite)
	if res := checkCopy(t, b, c, want); res.Hash != first.Hash {
		t.Errorf("PostgreSQL to SQLite: hash %s, want %s", res.Hash, first.Hash)
	}
	d := storetest.Migrated(t, store.Postgres)
	if res := checkCopy(t, c, d, want); res.Hash != first.Hash {
		t.Errorf("SQLite to PostgreSQL again: hash %s, want %s", res.Hash, first.Hash)
	}
	e := storetest.Migrated(t, store.Postgres)
	if res := checkCopy(t, d, e, want); res.Hash != first.Hash {
		t.Errorf("PostgreSQL to PostgreSQL: hash %s, want %s", res.Hash, first.Hash)
	}
}

// assertSequencesPastIDs checks that the next generated id of every identity column is above the
// copied ones.
func assertSequencesPastIDs(t *testing.T, db *store.DB) {
	t.Helper()
	tables, err := store.CopyOrder(db)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, tbl := range tables {
		for _, c := range tbl.Columns {
			if !c.Increment {
				continue
			}
			next := scalar[int64](t, db, `SELECT nextval(pg_get_serial_sequence('"`+tbl.Name+`"', '`+c.Name+`'))`)
			if next <= 102 {
				t.Errorf("%s.%s: next id %d collides with the copied ones", tbl.Name, c.Name, next)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no identity column found")
	}
}

func TestCopyDatabase_EmptySourceCopiesNothing(t *testing.T) {
	src, dst := storetest.Migrated(t, store.SQLite), storetest.Migrated(t, store.SQLite)
	res, err := store.CopyDatabase(context.Background(), src, dst, store.CopyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 0 || res.Tables == 0 {
		t.Fatalf("%+v", res)
	}
}

func TestCopyDatabase_RefusesNonEmptyTarget(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, dst *store.DB) {
		src := storetest.Migrated(t, store.SQLite)
		seedAll(t, src)
		storetest.Init(t, dst) // a database with an instance, as after `controller init`
		before := rowCounts(t, dst)
		_, err := store.CopyDatabase(context.Background(), src, dst, store.CopyOptions{})
		if !errors.Is(err, store.ErrTargetNotEmpty) {
			t.Fatalf("err = %v, want ErrTargetNotEmpty", err)
		}
		for tbl, n := range rowCounts(t, dst) {
			if n != before[tbl] {
				t.Errorf("%s changed: %d rows, was %d", tbl, n, before[tbl])
			}
		}
	})
}

func TestCopyDatabase_RefusesSchemaMismatch(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, dst *store.DB) {
		src := storetest.Migrated(t, store.SQLite)
		seedAll(t, src)
		// the target lacks its newest migration
		if _, err := dst.Writer.Exec(`DELETE FROM ` + store.RevisionTable + ` WHERE version = (SELECT max(version) FROM ` + store.RevisionTable + `)`); err != nil { //nolint:gosec // G202: a constant
			t.Fatal(err)
		}
		_, err := store.CopyDatabase(context.Background(), src, dst, store.CopyOptions{})
		if !errors.Is(err, store.ErrSchemaMismatch) {
			t.Fatalf("err = %v, want ErrSchemaMismatch", err)
		}
		if n := total(rowCounts(t, dst)); n != 0 {
			t.Fatalf("%d rows were copied", n)
		}
	})
}

func TestCopyDatabase_RefusesUnmigratedTarget(t *testing.T) {
	src := storetest.Migrated(t, store.SQLite)
	seedAll(t, src)
	dst, err := store.OpenSQLite(context.Background(), t.TempDir()+"/empty.db", store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dst.Close() })
	if _, err := store.CopyDatabase(context.Background(), src, dst, store.CopyOptions{}); !errors.Is(err, store.ErrSchemaMismatch) {
		t.Fatalf("err = %v, want ErrSchemaMismatch", err)
	}
}

// An interrupted copy changes nothing: the target is as it was, and a new copy succeeds.
func TestCopyDatabase_InterruptedLeavesTargetUntouched(t *testing.T) {
	for _, d := range storetest.Dialects {
		t.Run(d, func(t *testing.T) {
			src, dst := storetest.Migrated(t, store.SQLite), storetest.Migrated(t, d)
			want := seedAll(t, src)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			n := 0
			_, err := store.CopyDatabase(ctx, src, dst, store.CopyOptions{Progress: func(string, int64) {
				if n++; n == 10 {
					cancel()
				}
			}})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
			if got := total(rowCounts(t, dst)); got != 0 {
				t.Fatalf("%d rows remain after the interrupted copy", got)
			}
			res, err := store.CopyDatabase(context.Background(), src, dst, store.CopyOptions{})
			if err != nil {
				t.Fatalf("copy after the interrupted one: %v", err)
			}
			if res.Rows != total(want) {
				t.Fatalf("%d rows, want %d", res.Rows, total(want))
			}
		})
	}
}

// A target that alters what it is given fails the read-back and keeps nothing.
func TestCopyDatabase_VerifyCatchesAlteredRows(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, dst *store.DB) {
		src := storetest.Migrated(t, store.SQLite)
		seedAll(t, src)
		if dst.Dialect == store.Postgres {
			for _, q := range []string{
				`CREATE FUNCTION rpmgr_test_alter() RETURNS trigger AS $$ BEGIN NEW.value_enc = '\x00'; RETURN NEW; END $$ LANGUAGE plpgsql`,
				`CREATE TRIGGER rpmgr_test_alter BEFORE INSERT ON acme_storage FOR EACH ROW EXECUTE FUNCTION rpmgr_test_alter()`,
			} {
				if _, err := dst.Writer.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
		} else if _, err := dst.Writer.Exec(`CREATE TRIGGER rpmgr_test_alter AFTER INSERT ON acme_storage BEGIN UPDATE acme_storage SET value_enc = x'00' WHERE key = NEW.key; END`); err != nil {
			t.Fatal(err)
		}
		_, err := store.CopyDatabase(context.Background(), src, dst, store.CopyOptions{})
		if err == nil || !strings.Contains(err.Error(), "differs from the source") {
			t.Fatalf("err = %v, want a verification failure", err)
		}
		if n := total(rowCounts(t, dst)); n != 0 {
			t.Fatalf("%d rows remain after the failed verification", n)
		}
	})
}
