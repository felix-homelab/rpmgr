// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// queued opens n client connections to addr that the server has not accepted yet, and returns
// them once the kernel has established each one (they wait in a listen queue).
func queued(addr string, n int) ([]net.Conn, error) {
	conns := make([]net.Conn, n)
	for i := range conns {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return nil, fmt.Errorf("client %d: %w", i, err)
		}
		conns[i] = c
	}
	return conns, nil
}

// probe writes to each client connection and reads one byte back: served, reset or other.
func probe(conns []net.Conn) (served, reset, other int) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			_, err := c.Write([]byte("x"))
			b := make([]byte, 1)
			if err == nil {
				_, err = io.ReadFull(c, b)
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				served++
			case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
				reset++
			default:
				other++
			}
		}(c)
	}
	wg.Wait()
	return
}

func echoOne(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			b := make([]byte, 1)
			if _, err := io.ReadFull(c, b); err == nil {
				_, _ = c.Write([]byte("y"))
			}
			time.Sleep(100 * time.Millisecond)
			c.Close()
		}()
	}
}

// reuseport checks the fact ADR-0022 rejects SO_REUSEPORT on: two listeners bound with
// SO_REUSEPORT have a queue each, and closing one resets the connections waiting in it.
func reuseport(args []string) error {
	fs := flag.NewFlagSet("reuseport", flag.ExitOnError)
	n := fs.Int("n", 200, "client connections queued before the close")
	_ = fs.Parse(args)
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		_ = rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0xf /* SO_REUSEPORT */, 1) })
		return serr
	}}
	a, err := lc.Listen(nil, "tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	b, err := lc.Listen(nil, "tcp", a.Addr().String())
	if err != nil {
		return err
	}
	conns, err := queued(a.Addr().String(), *n)
	if err != nil {
		return err
	}
	a.Close() // the old process closes its listener
	go echoOne(b)
	served, reset, other := probe(conns)
	fmt.Printf("SO_REUSEPORT, %d connections queued over two listeners, one closed: served %d, reset %d, other %d\n", *n, served, reset, other)
	b.Close()
	return nil
}

// sharedQueue checks the fact the design rests on: two processes holding the same listening
// socket share its queue, so connections waiting in it survive the old process closing its copy.
func sharedQueue(args []string) error {
	if os.Getenv("S10_SQ_CHILD") == "1" {
		l, err := net.FileListener(os.NewFile(3, "inherited"))
		if err != nil {
			return err
		}
		_, _ = os.NewFile(4, "go").Read(make([]byte, 1)) // wait until the parent closed its copy
		echoOne(l)
		return nil
	}
	fs := flag.NewFlagSet("sharedqueue", flag.ExitOnError)
	n := fs.Int("n", 200, "client connections queued before the hand-over")
	_ = fs.Parse(args)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	f, err := l.(*net.TCPListener).File()
	if err != nil {
		return err
	}
	gor, gow, err := os.Pipe()
	if err != nil {
		return err
	}
	self, _ := os.Executable()
	cmd := exec.Command(self, "sharedqueue")
	cmd.ExtraFiles = []*os.File{f, gor}
	cmd.Env = append(os.Environ(), "S10_SQ_CHILD=1")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	f.Close()
	gor.Close()
	conns, err := queued(l.Addr().String(), *n)
	if err != nil {
		return err
	}
	l.Close() // the old process stops accepting and closes its copy
	_, _ = gow.Write([]byte("g"))
	served, reset, other := probe(conns)
	fmt.Printf("shared listening socket, %d connections queued, the old process closed its copy: served %d by the new process, reset %d, other %d\n", *n, served, reset, other)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	return nil
}

// ---- S-6: the all-in-one's database across a hand-off ----------------------------------------

func lockDB(path string, wait time.Duration) (*os.File, error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("database is locked by another process: %w", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sqliteRun(args []string) error {
	fs := flag.NewFlagSet("sqlite", flag.ExitOnError)
	path := fs.String("db", "/tmp/s10.db", "database file")
	migrate := fs.Duration("migrate", 2*time.Second, "time the new process's migration takes")
	failMig := fs.Bool("fail-migration", false, "inject a failing migration")
	child := fs.Bool("child", false, "internal: run as the new process")
	_ = fs.Parse(args)
	if *child {
		return sqliteChild(*path, *migrate, *failMig)
	}
	_ = os.Remove(*path)
	lock, err := lockDB(*path, 0)
	if err != nil {
		return err
	}
	db, err := openDB(*path)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, who TEXT)`); err != nil {
		return err
	}
	// The old process writes, as a controller does.
	stop := make(chan struct{})
	written := make(chan int64)
	go func() {
		var n int64
		for {
			select {
			case <-stop:
				written <- n
				return
			default:
			}
			if _, err := db.Exec(`INSERT INTO t (who) VALUES ('old')`); err == nil {
				n++
			}
			time.Sleep(time.Millisecond)
		}
	}()
	time.Sleep(time.Second)
	// A second writer is refused while the old process holds the database.
	if _, err := lockDB(*path, 0); err == nil {
		return errors.New("a second process took the database lock while the old one held it")
	}
	fmt.Println("second writer while the old process holds the lock: refused")
	self, _ := os.Executable()
	args2 := []string{"sqlite", "-child", "-db", *path, "-migrate", migrate.String()}
	if *failMig {
		args2 = append(args2, "-fail-migration")
	}
	cmd := exec.Command(self, args2...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// Hand-off: stop the controller's writes, close the database, release the lock.
	t0 := time.Now()
	close(stop)
	n := <-written
	if err := db.Close(); err != nil {
		return err
	}
	lock.Close()
	cmd.Env = append(os.Environ(), "S10_OLD_ROWS="+strconv.FormatInt(n, 10), "S10_T0="+strconv.FormatInt(t0.UnixNano(), 10))
	if err := cmd.Run(); err != nil {
		// The new process failed: take the controller work up again.
		t1 := time.Now()
		lock, err2 := lockDB(*path, 10*time.Second)
		if err2 != nil {
			return fmt.Errorf("the old process cannot take the database back: %w", err2)
		}
		defer lock.Close()
		db, err2 := openDB(*path)
		if err2 != nil {
			return err2
		}
		defer db.Close()
		var got int64
		if err := db.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&got); err != nil {
			return err
		}
		_, err3 := db.Exec(`INSERT INTO t (who) VALUES ('old again')`)
		fmt.Printf("new process failed (%v); old process took the database back after %v: %d rows of %d written kept, writes again: %v; window %v\n",
			err, time.Since(t1).Round(time.Millisecond), got, n, err3 == nil, time.Since(t0).Round(time.Millisecond))
		return nil
	}
	return nil
}

func sqliteChild(path string, migrate time.Duration, fail bool) error {
	t0n, _ := strconv.ParseInt(os.Getenv("S10_T0"), 10, 64)
	t0 := time.Unix(0, t0n)
	want, _ := strconv.ParseInt(os.Getenv("S10_OLD_ROWS"), 10, 64)
	lock, err := lockDB(path, 10*time.Second)
	if err != nil {
		return err
	}
	defer lock.Close()
	tLocked := time.Now()
	db, err := openDB(path)
	if err != nil {
		return err
	}
	defer db.Close()
	tm := time.Now()
	time.Sleep(migrate)
	if fail {
		return errors.New("injected migration failure")
	}
	if _, err := db.Exec(`ALTER TABLE t ADD COLUMN gen INTEGER`); err != nil {
		return err
	}
	mig := time.Since(tm)
	var got int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&got); err != nil {
		return err
	}
	if _, err := db.Exec(`INSERT INTO t (who, gen) VALUES ('new', 2)`); err != nil {
		return err
	}
	window := time.Since(t0)
	fmt.Printf("new process: lock after %v, migration %v, controller writing after %v (window without the migration %v); rows kept %d of %d\n",
		tLocked.Sub(t0).Round(time.Microsecond), mig.Round(time.Millisecond), window.Round(time.Millisecond), (window - mig).Round(time.Millisecond), got, want)
	if got != want {
		return fmt.Errorf("lost rows: %d of %d", got, want)
	}
	return nil
}
