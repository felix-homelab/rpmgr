// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// runFacts re-checks, against the pinned PostgreSQL, the LISTEN/NOTIFY behaviour the design rests
// on (D39).
func runFacts([]string) error {
	ctx := context.Background()
	r, err := newReport("facts-postgres")
	if err != nil {
		return err
	}
	defer r.close()
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		return err
	}
	defer pool.Close()
	var version, pages string
	if err := pool.QueryRow(ctx, `SELECT version(), current_setting('max_notify_queue_pages')`).Scan(&version, &pages); err != nil {
		return err
	}
	r.printf("server: %s; max_notify_queue_pages=%s", version, pages)
	listener := func() (*pgx.Conn, error) {
		c, err := pgx.Connect(ctx, dsn())
		if err != nil {
			return nil, err
		}
		_, err = c.Exec(ctx, "LISTEN facts")
		return c, err
	}
	// wait returns the notifications that arrive within d.
	wait := func(c *pgx.Conn, d time.Duration) []string {
		var got []string
		for {
			wctx, cancel := context.WithTimeout(ctx, d)
			n, err := c.WaitForNotification(wctx)
			cancel()
			if err != nil {
				return got
			}
			got = append(got, n.Payload)
		}
	}
	notify := func(payloads ...string) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		for _, p := range payloads {
			if _, err := tx.Exec(ctx, `SELECT pg_notify('facts', $1)`, p); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}

	// 1. Payload limit.
	l, err := listener()
	if err != nil {
		return err
	}
	err7999 := notify(strings.Repeat("x", 7999))
	err8000 := notify(strings.Repeat("x", 8000))
	got := wait(l, 300*time.Millisecond)
	r.verdict(err7999 == nil && err8000 != nil && len(got) == 1 && len(got[0]) == 7999,
		"payload: 7999 bytes accepted (%v), 8000 bytes refused (%v); delivered %d", err7999, err8000, len(got))

	// 2. Duplicates within one transaction are delivered once; distinct payloads each.
	_ = notify("dup", "dup", "a", "b")
	got = wait(l, 300*time.Millisecond)
	r.verdict(len(got) == 3, "duplicates in one transaction collapse: sent dup,dup,a,b; received %v", got)

	// 3. A rolled-back transaction delivers nothing.
	tx, _ := pool.Begin(ctx)
	_, _ = tx.Exec(ctx, `SELECT pg_notify('facts', 'rolled-back')`)
	_ = tx.Rollback(ctx)
	got = wait(l, 300*time.Millisecond)
	r.verdict(len(got) == 0, "a rolled-back NOTIFY is not delivered: received %v", got)

	// 4. A session that LISTENs after a commit does not get it.
	_ = notify("before-listen")
	late, err := listener()
	if err != nil {
		return err
	}
	got = wait(late, 300*time.Millisecond)
	r.verdict(len(got) == 0, "a session that LISTENs after the commit receives nothing of it: %v", got)
	_ = wait(l, 100*time.Millisecond)

	// 5. Notifications committed while a listener is disconnected are lost to it: the new
	// connection does not receive them.
	_ = l.Close(ctx)
	_ = notify("while-disconnected")
	l, err = listener()
	if err != nil {
		return err
	}
	_ = notify("after-reconnect")
	got = wait(l, 300*time.Millisecond)
	r.verdict(len(got) == 1 && got[0] == "after-reconnect",
		"after a reconnect only later notifications arrive: received %v (the one sent while disconnected is lost)", got)

	// 6. A listener inside a transaction receives nothing until that transaction ends.
	ltx, _ := l.Begin(ctx)
	_ = notify("during-listener-tx")
	inTx := wait(l, 300*time.Millisecond)
	_ = ltx.Commit(ctx)
	after := wait(l, 300*time.Millisecond)
	r.verdict(len(inTx) == 0 && len(after) == 1, "a listener in a transaction gets the notification only after it ends: in=%v after=%v", inTx, after)

	// 7. Delivery in commit order: four writers increment one counter, which orders their
	// commits, and notify the value.
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS facts_seq; CREATE TABLE facts_seq (id int PRIMARY KEY, n bigint); INSERT INTO facts_seq VALUES (1, 0)`); err != nil {
		return err
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 250 {
				tx, err := pool.Begin(ctx)
				if err != nil {
					return
				}
				var n int64
				_ = tx.QueryRow(ctx, `UPDATE facts_seq SET n = n + 1 WHERE id = 1 RETURNING n`).Scan(&n)
				_, _ = tx.Exec(ctx, `SELECT pg_notify('facts', $1)`, fmt.Sprint(n))
				_ = tx.Commit(ctx)
			}
		})
	}
	wg.Wait()
	got = wait(l, time.Second)
	ordered := len(got) == 1000
	for i, p := range got {
		if p != fmt.Sprint(i+1) {
			ordered = false
			break
		}
	}
	r.verdict(ordered, "1000 notifications from 4 writers arrive complete and in commit order: %d received", len(got))

	// 8. Transactions that NOTIFY commit one at a time (a lock on "database 0" from the queue
	// insert to the end of the commit): 8 writers on distinct rows, with and without a NOTIFY.
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS facts_rows; CREATE TABLE facts_rows (id int PRIMARY KEY, n bigint);
		INSERT INTO facts_rows SELECT g, 0 FROM generate_series(1, 8) g`); err != nil {
		return err
	}
	rate := func(withNotify bool) float64 {
		var count atomic.Int64
		stop := time.Now().Add(5 * time.Second)
		var wg sync.WaitGroup
		for w := range 8 {
			wg.Go(func() {
				for time.Now().Before(stop) {
					tx, err := pool.Begin(ctx)
					if err != nil {
						return
					}
					_, _ = tx.Exec(ctx, `UPDATE facts_rows SET n = n + 1 WHERE id = $1`, w+1)
					if withNotify {
						_, _ = tx.Exec(ctx, `SELECT pg_notify('facts_other', $1)`, fmt.Sprint(w))
					}
					if tx.Commit(ctx) == nil {
						count.Add(1)
					}
				}
			})
		}
		wg.Wait()
		return float64(count.Load()) / 5
	}
	plain, withN := rate(false), rate(true)
	r.printf("8 writers on distinct rows: %.0f commits/s without NOTIFY, %.0f with (ratio %.2f)", plain, withN, withN/plain)
	var commitMs float64
	start := time.Now()
	for range 50 {
		if _, err := pool.Exec(ctx, `UPDATE facts_rows SET n = n + 1 WHERE id = 1`); err != nil {
			return err
		}
	}
	commitMs = float64(time.Since(start).Microseconds()) / 1000 / 50
	r.printf("one writer: %.2f ms per committed UPDATE (the WAL flush bounds NOTIFY throughput at about %.0f/s)", commitMs, 1000/commitMs)

	// 9. A terminated listener sees an error at once.
	pid := l.PgConn().PID()
	go func() {
		time.Sleep(200 * time.Millisecond)
		_, _ = pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid)
	}()
	t := time.Now()
	_, err = l.WaitForNotification(ctx)
	r.verdict(err != nil, "pg_terminate_backend ends WaitForNotification with an error after %s: %v",
		time.Since(t).Round(time.Millisecond), err)
	return nil
}
