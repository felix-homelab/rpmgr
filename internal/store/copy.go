// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"

	"github.com/felix-homelab/rpmgr/internal/store/ent/migrate"
)

// ErrTargetNotEmpty is returned by CopyDatabase when the target already holds rows. A copy is
// atomic, so such rows are never the remains of an interrupted copy: they belong to something else.
var ErrTargetNotEmpty = errors.New("store: the target database is not empty")

// ErrSchemaMismatch is returned by CopyDatabase when source and target are not at the same schema
// version.
var ErrSchemaMismatch = errors.New("store: source and target are at different schema versions")

// copyBatch is the number of rows of one INSERT.
const copyBatch = 100

// CopyOptions are the settings of CopyDatabase.
type CopyOptions struct {
	// Source, if set, is a transaction the caller holds on src, which CopyDatabase reads instead of
	// opening a read snapshot of its own (see BeginSource). The caller ends it.
	Source *SourceTx
	// Progress, if set, is called after each table with its name and row count.
	Progress func(table string, rows int64)
}

// CopyResult describes a finished copy.
type CopyResult struct {
	Tables int
	Rows   int64
	// Hash is the hex SHA-256 over every table's name, row count and content digest. It is the same
	// on both sides, whatever their dialect (see tableDigest).
	Hash string
}

// CopyDatabase copies every row of src into the empty, migrated database dst, in an order that
// satisfies the foreign keys, in one transaction on dst: either the whole database arrives or dst
// is unchanged. It works in both directions between SQLite and PostgreSQL. The rows keep their
// values: ids, the configuration sequence and the database epoch, and sealed secrets byte for
// byte, so the KEK of the source opens the copy. Before the commit it reads dst back and compares
// the row count and a content digest of every table with the source's; a difference rolls the copy
// back. A failed or cancelled copy leaves dst as it was.
//
// dst is refused with ErrTargetNotEmpty if any table holds a row, and with ErrSchemaMismatch if
// the migrations applied to the two differ. Instants are compared to the microsecond, the
// precision of PostgreSQL, and JSON documents by value, as PostgreSQL stores them normalised.
// A controller must not run on src while it is copied.
func CopyDatabase(ctx context.Context, src, dst *DB, o CopyOptions) (CopyResult, error) {
	var srcTx querier
	if o.Source != nil {
		srcTx = o.Source
	} else {
		tx, err := beginRead(ctx, src)
		if err != nil {
			return CopyResult{}, err
		}
		defer func() { _ = tx.Rollback() }() // read-only
		srcTx = tx
	}
	dstTx, err := dst.Writer.BeginTx(ctx, nil)
	if err != nil {
		return CopyResult{}, fmt.Errorf("store: copy: %w", err)
	}
	defer func() { _ = dstTx.Rollback() }() // after Commit a no-op

	if err := sameSchema(ctx, srcTx, dstTx); err != nil {
		return CopyResult{}, err
	}
	tables, err := copyOrder(ctx, dstTx, dst.Dialect)
	if err != nil {
		return CopyResult{}, err
	}
	for _, t := range tables {
		if err := checkColumns(ctx, srcTx, t); err != nil {
			return CopyResult{}, fmt.Errorf("%w: source: %w", ErrSchemaMismatch, err)
		}
		if err := checkColumns(ctx, dstTx, t); err != nil {
			return CopyResult{}, fmt.Errorf("%w: target: %w", ErrSchemaMismatch, err)
		}
	}
	for _, t := range tables {
		var one int
		err := dstTx.QueryRowContext(ctx, "SELECT 1 FROM "+quote(t.Name)+" LIMIT 1").Scan(&one)
		if err == nil {
			return CopyResult{}, fmt.Errorf("%w: table %s has rows", ErrTargetNotEmpty, t.Name)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return CopyResult{}, fmt.Errorf("store: copy: %w", err)
		}
	}

	var res CopyResult
	total := sha256.New()
	for _, t := range tables {
		n, digest, err := copyTable(ctx, srcTx, dstTx, dst.Dialect, t)
		if err != nil {
			return CopyResult{}, fmt.Errorf("store: copy table %s: %w", t.Name, err)
		}
		if err := resetSequence(ctx, dstTx, dst.Dialect, t); err != nil {
			return CopyResult{}, fmt.Errorf("store: copy table %s: %w", t.Name, err)
		}
		// What arrived must equal what left: read dst back, still inside the transaction.
		n2, digest2, err := tableDigest(ctx, dstTx, t)
		if err != nil {
			return CopyResult{}, fmt.Errorf("store: verify table %s: %w", t.Name, err)
		}
		if n2 != n || digest2 != digest {
			return CopyResult{}, fmt.Errorf("store: verify table %s: the copy differs from the source (%d rows copied, %d read back)", t.Name, n, n2)
		}
		fmt.Fprintf(total, "%s\x00%d\x00%x\n", t.Name, n, digest)
		res.Tables++
		res.Rows += n
		if o.Progress != nil {
			o.Progress(t.Name, n)
		}
	}
	res.Hash = hex.EncodeToString(total.Sum(nil))
	if err := ctx.Err(); err != nil {
		return CopyResult{}, err
	}
	if err := dstTx.Commit(); err != nil {
		return CopyResult{}, fmt.Errorf("store: copy: %w", err)
	}
	return res, nil
}

// copyOrder returns the tables of the Ent schema, parents before the tables that reference them,
// ties in name order. The foreign keys are read from the database, because most of them are in
// the migrations, not in the Ent schema. A reference cycle, or a table that references itself, is
// an error: rows could then need an order that no table order gives.
func copyOrder(ctx context.Context, q querier, d string) ([]*schema.Table, error) {
	parentsOf, err := foreignKeys(ctx, q, d)
	if err != nil {
		return nil, fmt.Errorf("store: copy: %w", err)
	}
	byName := map[string]*schema.Table{}
	for _, t := range migrate.Tables {
		byName[t.Name] = t
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	slices.Sort(names)
	var out []*schema.Table
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(n string) error
	visit = func(n string) error {
		switch state[n] {
		case 2:
			return nil
		case 1:
			return fmt.Errorf("store: copy: foreign keys form a cycle at table %s", n)
		}
		state[n] = 1
		parents := parentsOf[n]
		slices.Sort(parents)
		for _, p := range parents {
			if _, ok := byName[p]; !ok {
				continue // the revision table, or a table the Ent schema does not know
			}
			if err := visit(p); err != nil {
				return err
			}
		}
		state[n] = 2
		out = append(out, byName[n])
		return nil
	}
	for _, n := range names {
		if err := visit(n); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// foreignKeys returns, for each table, the tables its foreign keys reference.
func foreignKeys(ctx context.Context, q querier, d string) (map[string][]string, error) {
	query := `SELECT m.name, f."table" FROM sqlite_master m, pragma_foreign_key_list(m.name) f WHERE m.type = 'table'`
	if d == Postgres {
		query = `SELECT cl.relname, rf.relname FROM pg_constraint c
  JOIN pg_class cl ON cl.oid = c.conrelid JOIN pg_class rf ON rf.oid = c.confrelid
  JOIN pg_namespace n ON n.oid = cl.relnamespace
  WHERE c.contype = 'f' AND n.nspname = current_schema()`
	}
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]string{}
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			return nil, err
		}
		if !slices.Contains(out[child], parent) {
			out[child] = append(out[child], parent)
		}
	}
	return out, rows.Err()
}

// querier is what *sql.DB and *sql.Tx share.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// SourceTx is a read-write transaction on a database that is copied away and then changed, as
// `rpmgr migrate-db` retires its source. On SQLite it is BEGIN IMMEDIATE on the single writer
// connection, so the file is read as of one moment and no other process, one that does not take
// the controller lock included, can write to it until the transaction ends; on PostgreSQL it is a
// REPEATABLE READ transaction, and the controller lock excludes every controller.
type SourceTx struct {
	querier
	done func(commit bool) error
}

// BeginSource starts the transaction and fails if the database cannot be written, so that a
// read-only file is refused before anything is copied.
func BeginSource(ctx context.Context, db *DB) (*SourceTx, error) {
	t := &SourceTx{}
	if db.Dialect == Postgres {
		// Not tied to ctx: database/sql rolls a transaction back when its context ends, and a
		// command that is interrupted after the target committed must still retire the source.
		tx, err := db.Writer.BeginTx(context.WithoutCancel(ctx), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			return nil, fmt.Errorf("store: begin source: %w", err)
		}
		t.querier = tx
		t.done = func(commit bool) error {
			if commit {
				return tx.Commit()
			}
			return tx.Rollback()
		}
	} else {
		conn, err := db.Writer.Conn(ctx)
		if err != nil {
			return nil, fmt.Errorf("store: begin source: %w", err)
		}
		if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("store: begin source: the database cannot be written: %w", err)
		}
		t.querier = conn
		t.done = func(commit bool) error {
			stmt := "ROLLBACK"
			if commit {
				stmt = "COMMIT"
			}
			_, err := conn.ExecContext(context.WithoutCancel(ctx), stmt)
			return errors.Join(err, conn.Close())
		}
	}
	if db.Dialect == Postgres {
		// First, before any statement takes a snapshot: it waits for the writers that hold a share
		// lock on the instance row (lock-free commands that have checked for a retirement), so what
		// they commit is in the copy, and none starts until the retirement commits.
		if _, err := t.ExecContext(ctx, "LOCK TABLE instance IN EXCLUSIVE MODE"); err != nil {
			_ = t.done(false)
			return nil, fmt.Errorf("store: begin source: %w", err)
		}
	}
	if _, err := t.ExecContext(ctx, "UPDATE instance SET retired_at = retired_at"); err != nil {
		_ = t.done(false)
		return nil, fmt.Errorf("store: begin source: the database cannot be written: %w", err)
	}
	return t, nil
}

// Commit ends the transaction with its changes.
func (t *SourceTx) Commit() error { return t.end(true) }

// Rollback ends the transaction without them; after Commit it does nothing.
func (t *SourceTx) Rollback() error { return t.end(false) }

func (t *SourceTx) end(commit bool) error {
	d := t.done
	t.done = func(bool) error { return nil }
	return d(commit)
}

// beginRead starts a read transaction with one snapshot: PostgreSQL needs REPEATABLE READ for it,
// and a SQLite read transaction in WAL mode has it already.
func beginRead(ctx context.Context, db *DB) (*sql.Tx, error) {
	var opts *sql.TxOptions
	if db.Dialect == Postgres {
		opts = &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	}
	tx, err := db.Reader.BeginTx(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("store: copy: %w", err)
	}
	return tx, nil
}

// sameSchema compares the descriptions of the applied migrations in order; the versions differ
// between the dialects, the descriptions do not.
func sameSchema(ctx context.Context, src, dst querier) error {
	a, err := appliedMigrations(ctx, src)
	if err != nil {
		return fmt.Errorf("%w: source: %w", ErrSchemaMismatch, err)
	}
	b, err := appliedMigrations(ctx, dst)
	if err != nil {
		return fmt.Errorf("%w: target: %w", ErrSchemaMismatch, err)
	}
	if !slices.Equal(a, b) {
		return fmt.Errorf("%w: source has %d migrations, target %d; migrate both to the same release first", ErrSchemaMismatch, len(a), len(b))
	}
	return nil
}

func appliedMigrations(ctx context.Context, q querier) ([]string, error) {
	rows, err := q.QueryContext(ctx, "SELECT description FROM "+RevisionTable+" WHERE error = '' ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// checkColumns selects every column of t without a row, so a table or column the Ent schema names
// but the database lacks is reported before any copying.
func checkColumns(ctx context.Context, q querier, t *schema.Table) error {
	rows, err := q.QueryContext(ctx, "SELECT "+columnList(t)+" FROM "+quote(t.Name)+" LIMIT 0")
	if err != nil {
		return fmt.Errorf("table %s: %w", t.Name, err)
	}
	return rows.Close()
}

func quote(name string) string { return `"` + name + `"` }

func columnList(t *schema.Table) string {
	cols := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		cols[i] = quote(c.Name)
	}
	return strings.Join(cols, ", ")
}

// copyTable copies t from src to dst and returns its row count and content digest, computed from
// the values as read from src.
func copyTable(ctx context.Context, src, dst querier, d string, t *schema.Table) (int64, [32]byte, error) {
	rows, err := src.QueryContext(ctx, "SELECT "+columnList(t)+" FROM "+quote(t.Name))
	if err != nil {
		return 0, [32]byte{}, err
	}
	defer func() { _ = rows.Close() }()
	var (
		n     int64
		sum   digest
		batch [][]any
	)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := insertRows(ctx, dst, d, t, batch)
		batch = batch[:0]
		return err
	}
	for rows.Next() {
		vals, err := scanRow(rows, t)
		if err != nil {
			return 0, [32]byte{}, err
		}
		sum.add(rowHash(t, vals))
		n++
		batch = append(batch, vals)
		if len(batch) == copyBatch {
			if err := flush(); err != nil {
				return 0, [32]byte{}, err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return 0, [32]byte{}, err
	}
	if err := flush(); err != nil {
		return 0, [32]byte{}, err
	}
	return n, sum.v, nil
}

func insertRows(ctx context.Context, dst querier, d string, t *schema.Table, batch [][]any) error {
	var q strings.Builder
	q.WriteString("INSERT INTO " + quote(t.Name) + " (" + columnList(t) + ") VALUES ")
	args := make([]any, 0, len(batch)*len(t.Columns))
	for i, vals := range batch {
		if i > 0 {
			q.WriteString(", ")
		}
		q.WriteByte('(')
		for j, v := range vals {
			if j > 0 {
				q.WriteString(", ")
			}
			if d == Postgres {
				q.WriteString("$" + strconv.Itoa(len(args)+1))
			} else {
				q.WriteByte('?')
			}
			args = append(args, bindValue(v))
		}
		q.WriteByte(')')
	}
	_, err := dst.ExecContext(ctx, q.String(), args...)
	return err
}

// bindValue turns a normalised cell into a query argument.
func bindValue(v any) any {
	switch v := v.(type) {
	case jsonText:
		return string(v)
	case time.Time:
		return v.UTC()
	}
	return v
}

// resetSequence moves the identity sequence of t's auto-increment column on PostgreSQL past the
// copied ids, so the next insert does not collide. SQLite keeps the largest rowid itself.
func resetSequence(ctx context.Context, dst querier, d string, t *schema.Table) error {
	if d != Postgres {
		return nil
	}
	for _, c := range t.Columns {
		if !c.Increment {
			continue
		}
		col := quote(c.Name)
		_, err := dst.ExecContext(ctx, fmt.Sprintf(
			`SELECT setval(pg_get_serial_sequence('%s', '%s'), COALESCE((SELECT max(%s) FROM %s), 1), (SELECT max(%s) IS NOT NULL FROM %s))`,
			quote(t.Name), c.Name, col, quote(t.Name), col, quote(t.Name)))
		if err != nil {
			return err
		}
	}
	return nil
}

// jsonText is a JSON document read from a json or jsonb column.
type jsonText string

// scanRow reads one row and normalises each cell by its Ent type, so both dialects give the same
// Go values: nil, int64, bool, string, []byte, jsonText or time.Time (UTC).
func scanRow(rows *sql.Rows, t *schema.Table) ([]any, error) {
	raw := make([]any, len(t.Columns))
	ptrs := make([]any, len(raw))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, err
	}
	for i, c := range t.Columns {
		v, err := normalise(c, raw[i])
		if err != nil {
			return nil, fmt.Errorf("column %s: %w", c.Name, err)
		}
		raw[i] = v
	}
	return raw, nil
}

func normalise(c *schema.Column, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch c.Type {
	case field.TypeBool:
		switch v := v.(type) {
		case bool:
			return v, nil
		case int64:
			return v != 0, nil
		}
	case field.TypeInt, field.TypeInt64:
		if v, ok := v.(int64); ok {
			return v, nil
		}
	case field.TypeString, field.TypeEnum:
		switch v := v.(type) {
		case string:
			return v, nil
		case []byte:
			return string(v), nil
		}
	case field.TypeBytes:
		if v, ok := v.([]byte); ok {
			return bytes.Clone(v), nil // the driver may reuse its buffer
		}
	case field.TypeJSON:
		switch v := v.(type) {
		case string:
			return jsonText(v), nil
		case []byte:
			return jsonText(v), nil
		}
	case field.TypeTime:
		if v, ok := v.(time.Time); ok {
			return v.UTC(), nil
		}
	default:
		return nil, fmt.Errorf("unsupported type %s", c.Type)
	}
	return nil, fmt.Errorf("unexpected %T for type %s", v, c.Type)
}

// tableDigest reads t and returns its row count and content digest.
func tableDigest(ctx context.Context, q querier, t *schema.Table) (int64, [32]byte, error) {
	rows, err := q.QueryContext(ctx, "SELECT "+columnList(t)+" FROM "+quote(t.Name))
	if err != nil {
		return 0, [32]byte{}, err
	}
	defer func() { _ = rows.Close() }()
	var (
		n   int64
		sum digest
	)
	for rows.Next() {
		vals, err := scanRow(rows, t)
		if err != nil {
			return 0, [32]byte{}, err
		}
		sum.add(rowHash(t, vals))
		n++
	}
	return n, sum.v, rows.Err()
}

// digest is the sum, modulo 2^256, of the hashes of a table's rows. It does not depend on the order
// in which the rows are read, which differs between the dialects (collations), and a changed,
// missing or extra row changes it.
type digest struct{ v [32]byte }

func (d *digest) add(h [32]byte) {
	carry := 0
	for i := 31; i >= 0; i-- {
		s := int(d.v[i]) + int(h[i]) + carry
		d.v[i], carry = byte(s&0xff), s>>8
	}
}

// rowHash hashes a row's cells, each with a type tag and a length, so that no two different rows
// give the same bytes.
func rowHash(t *schema.Table, vals []any) [32]byte {
	h := sha256.New()
	put := func(tag byte, b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		h.Write([]byte{tag})
		h.Write(l[:])
		h.Write(b)
	}
	for _, v := range vals {
		switch v := v.(type) {
		case nil:
			put('n', nil)
		case int64:
			put('i', strconv.AppendInt(nil, v, 10))
		case bool:
			put('b', strconv.AppendBool(nil, v))
		case string:
			put('s', []byte(v))
		case []byte:
			put('x', v)
		case jsonText:
			put('j', canonicalJSON(string(v)))
		case time.Time:
			put('t', []byte(v.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)))
		}
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// canonicalJSON re-encodes a document with sorted keys and compact spacing, numbers kept as
// written, so a document and PostgreSQL's normalised jsonb of it hash alike. Text that is not
// JSON hashes as it is.
func canonicalJSON(s string) []byte {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return []byte(s)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(s)
	}
	return b
}
