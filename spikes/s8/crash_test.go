// SPDX-License-Identifier: Apache-2.0

package s8

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The crash tests run a writer in a child process (this test binary, re-executed) and kill it
// with SIGKILL at a chosen point. Under QEMU user-mode emulation without binfmt_misc the binary
// cannot exec itself, so S8_EXEC_PREFIX names the emulator to run it with, e.g.
// "qemu-aarch64-static".
const (
	envChild  = "S8_CRASH_CHILD" // child mode: "commit" or "checkpoint"
	envDB     = "S8_CRASH_DB"
	envPrefix = "S8_EXEC_PREFIX"
)

// TestCrashChild is the child's body; it does nothing unless started by TestCrashRecovery.
func TestCrashChild(t *testing.T) {
	mode := os.Getenv(envChild)
	if mode == "" {
		t.Skip("child process only")
	}
	ctx := context.Background()
	o := DefaultOptions
	o.CacheSizeKiB = 256 // small cache: uncommitted pages spill into the WAL before COMMIT
	s, err := Open(os.Getenv(envDB), o, 1)
	if err != nil {
		fmt.Println("error", err)
		os.Exit(2)
	}
	out := bufio.NewWriter(os.Stdout)
	payload := strings.Repeat("x", 4096)
	for i := 1; ; i++ {
		tx, err := s.W.BeginTx(ctx, nil)
		if err != nil {
			fmt.Println("error", err)
			os.Exit(2)
		}
		seq, err := NextRevision(ctx, tx, payload)
		if err != nil {
			fmt.Println("error", err)
			os.Exit(2)
		}
		if mode == "commit" && i == 40 {
			// A large uncommitted transaction: ~20 MiB of pages spilled to the WAL, then wait to
			// be killed before COMMIT.
			for j := 0; j < 5000; j++ {
				if _, err := tx.Exec(`INSERT INTO orgs (id, name) VALUES (?, ?)`,
					fmt.Sprintf("org_uncommitted_%d", j), payload); err != nil {
					fmt.Println("error", err)
					os.Exit(2)
				}
			}
			fmt.Fprintln(out, "in-tx")
			out.Flush()
			time.Sleep(time.Hour)
		}
		if err := tx.Commit(); err != nil {
			fmt.Println("error", err)
			os.Exit(2)
		}
		fmt.Fprintf(out, "committed %d\n", seq)
		out.Flush()
		if mode == "checkpoint" && i%5 == 0 {
			// Checkpoints copy WAL pages into the main file; the parent kills at a random moment.
			s.W.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		}
	}
}

// TestCrashRecovery kills a writer mid-transaction and during checkpoints, then reopens the
// database: integrity_check must pass, every reported commit must be present, and nothing of the
// interrupted transaction may be.
func TestCrashRecovery(t *testing.T) {
	if os.Getenv(envChild) != "" {
		t.Skip("parent only")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "checkpoint"} {
		t.Run(mode, func(t *testing.T) {
			_, path := newStore(t, DefaultOptions)
			args := []string{exe, "-test.run=^TestCrashChild$", "-test.v=false"}
			if p := os.Getenv(envPrefix); p != "" {
				args = append(strings.Fields(p), args...)
			}
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Env = append(os.Environ(), envChild+"="+mode, envDB+"="+path)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatalf("start child: %v", err)
			}
			lastCommitted := int64(0)
			killed := false
			sc := bufio.NewScanner(stdout)
			deadline := time.AfterFunc(10*time.Minute, func() { cmd.Process.Kill() })
			defer deadline.Stop()
			for sc.Scan() {
				line := sc.Text()
				switch {
				case strings.HasPrefix(line, "committed "):
					n, _ := strconv.ParseInt(strings.TrimPrefix(line, "committed "), 10, 64)
					lastCommitted = n
					if mode == "checkpoint" && n == 60 {
						// The child starts PRAGMA wal_checkpoint(TRUNCATE) right after reporting
						// commit 60, so the kill lands during the checkpoint or just after it.
						cmd.Process.Signal(syscall.SIGKILL)
						killed = true
					}
				case line == "in-tx":
					cmd.Process.Signal(syscall.SIGKILL)
					killed = true
				case strings.HasPrefix(line, "error"):
					t.Fatalf("child: %s", line)
				}
				if killed {
					break
				}
			}
			cmd.Wait()
			if !killed {
				t.Fatalf("child ended before it was killed (last commit %d)", lastCommitted)
			}

			s, err := Open(path, DefaultOptions, 1)
			if err != nil {
				t.Fatalf("reopen after crash: %v", err)
			}
			defer s.Close()
			var integrity string
			s.R.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
			if integrity != "ok" {
				t.Fatalf("integrity_check after crash: %s", integrity)
			}
			var seq, revs, uncommitted int64
			s.R.QueryRow(`SELECT seq FROM config_seq`).Scan(&seq)
			s.R.QueryRow(`SELECT count(*) FROM config_revisions`).Scan(&revs)
			s.R.QueryRow(`SELECT count(*) FROM orgs WHERE id LIKE 'org_uncommitted_%'`).Scan(&uncommitted)
			// The child may have committed one more transaction after its last report.
			if seq < lastCommitted || seq > lastCommitted+1 || revs != seq {
				t.Fatalf("last reported commit %d, after recovery config_seq=%d revisions=%d",
					lastCommitted, seq, revs)
			}
			if uncommitted != 0 {
				t.Fatalf("%d rows of the interrupted transaction survived", uncommitted)
			}
			// The database is writable again.
			tx, err := s.W.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NextRevision(context.Background(), tx, "after-crash"); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			wal, _ := os.Stat(path + "-wal")
			size := int64(0)
			if wal != nil {
				size = wal.Size()
			}
			t.Logf("%s: killed after commit %d; recovered config_seq=%d; WAL %d bytes at reopen",
				mode, lastCommitted, seq, size)
		})
	}
}
