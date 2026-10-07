// SPDX-License-Identifier: Apache-2.0

package revlog_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/revlog"
)

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func open(t *testing.T, path string) *revlog.Log {
	t.Helper()
	l, err := revlog.Open(path, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func appendN(t *testing.T, l *revlog.Log, n int) {
	t.Helper()
	for i := range n {
		if _, err := l.Append(revlog.Entry{Kind: revlog.CertificateRevoked, Subject: fmt.Sprintf("%x", i+1), Actor: "test"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppendAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocations.log")
	l := open(t, path)
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, %v", st.Mode(), err)
	}
	na := t0.Add(7 * 24 * time.Hour)
	first, err := l.Append(revlog.Entry{Kind: revlog.IdentityRevoked, Org: "org_1", Subject: "spiffe://rpmgr-x/org/org_1/connector/con_1",
		NotAfter: &na, Actor: "usr_1"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq != 1 || first.Prev != "" || len(first.Hash) != 64 || !first.Time.Equal(t0) {
		t.Fatalf("first entry %+v", first)
	}
	at := t0.Add(time.Hour)
	second, err := l.Append(revlog.Entry{Kind: revlog.CertificateSuperseded, Subject: "abc", Time: at})
	if err != nil {
		t.Fatal(err)
	}
	if second.Seq != 2 || second.Prev != first.Hash || !second.Time.Equal(at) {
		t.Fatalf("second entry %+v", second)
	}
	got, err := revlog.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Subject != first.Subject || !got[0].NotAfter.Equal(na) || got[1].Hash != second.Hash {
		t.Fatalf("read %+v", got)
	}
	// Reopening continues the chain.
	l2 := open(t, path)
	third, err := l2.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: "ses_1"})
	if err != nil || third.Seq != 3 || third.Prev != second.Hash {
		t.Fatalf("after reopening: %+v %v", third, err)
	}
}

func TestAppend_Refused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocations.log")
	l := open(t, path)
	for name, e := range map[string]revlog.Entry{
		"unknown kind": {Kind: "certificate_forgiven", Subject: "1"},
		"no subject":   {Kind: revlog.CertificateRevoked},
		"long subject": {Kind: revlog.CertificateRevoked, Subject: strings.Repeat("a", revlog.MaxField+1)},
		"long detail":  {Kind: revlog.RoleDowngraded, Subject: "usr_1", Detail: strings.Repeat("a", revlog.MaxField+1)},
	} {
		if _, err := l.Append(e); err == nil {
			t.Errorf("%s: appended", name)
		}
	}
	if b, _ := os.ReadFile(path); len(b) != 0 {
		t.Fatalf("refused entries were written: %q", b)
	}
	// MaxField itself is fine.
	if _, err := l.Append(revlog.Entry{Kind: revlog.CertificateRevoked, Subject: strings.Repeat("a", revlog.MaxField)}); err != nil {
		t.Fatal(err)
	}
}

// TestRead_DetectsTampering: an altered, removed, reordered or renumbered entry breaks the chain,
// and Open refuses such a log.
func TestRead_DetectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revocations.log")
	appendN(t, open(t, path), 4)
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(orig, []byte("\n"))[:4]
	join := func(ls ...[]byte) []byte { return bytes.Join(ls, nil) }
	altered := bytes.Replace(orig, []byte(`"subject":"2"`), []byte(`"subject":"9"`), 1)
	renumbered := bytes.Replace(orig, []byte(`"seq":4`), []byte(`"seq":5`), 1)
	for name, b := range map[string][]byte{
		"altered":      altered,
		"removed":      join(lines[0], lines[2], lines[3]),
		"reordered":    join(lines[0], lines[2], lines[1], lines[3]),
		"renumbered":   renumbered,
		"first gone":   join(lines[1], lines[2], lines[3]),
		"not json":     join(lines[0], []byte("{oops\n")),
		"duplicated":   join(lines[0], lines[1], lines[1]),
		"unknown kind": bytes.Replace(orig, []byte(`"kind":"certificate_revoked"`), []byte(`"kind":"x"`), 1),
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := revlog.Read(p); !errors.Is(err, revlog.ErrBroken) {
			t.Errorf("%s: %v, want ErrBroken", name, err)
		}
		if _, err := revlog.Open(p, nil); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

// TestAppend_AfterTornWrite: an incomplete last line, as an interrupted append leaves, is ignored
// by Read and replaced by the next Append.
func TestAppend_AfterTornWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocations.log")
	l := open(t, path)
	appendN(t, l, 2)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"seq":3,"time":"2026-10`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if got, err := revlog.Read(path); err != nil || len(got) != 2 {
		t.Fatalf("read with a torn line: %d entries, %v", len(got), err)
	}
	e, err := open(t, path).Append(revlog.Entry{Kind: revlog.CertificateRevoked, Subject: "3"})
	if err != nil || e.Seq != 3 {
		t.Fatalf("append after a torn line: %+v %v", e, err)
	}
	if got, err := revlog.Read(path); err != nil || len(got) != 3 {
		t.Fatalf("read after the append: %d entries, %v", len(got), err)
	}

	// A torn first line.
	path2 := filepath.Join(t.TempDir(), "revocations.log")
	if err := os.WriteFile(path2, []byte(`{"seq":1`), 0o640); err != nil {
		t.Fatal(err)
	}
	if e, err := open(t, path2).Append(revlog.Entry{Kind: revlog.CertificateRevoked, Subject: "1"}); err != nil || e.Seq != 1 {
		t.Fatalf("append after a torn first line: %+v %v", e, err)
	}
}

// TestAppend_Concurrent: appends through several handles, as from several processes, keep one
// gap-free chain.
func TestAppend_Concurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocations.log")
	logs := []*revlog.Log{open(t, path), open(t, path), open(t, path)}
	var wg sync.WaitGroup
	for _, l := range logs {
		for range 2 {
			wg.Go(func() { appendN(t, l, 20) })
		}
	}
	wg.Wait()
	got, err := revlog.Read(path)
	if err != nil || len(got) != 120 {
		t.Fatalf("%d entries, %v", len(got), err)
	}
}

func TestOpen_Errors(t *testing.T) {
	if _, err := revlog.Open(filepath.Join(t.TempDir(), "missing", "revocations.log"), nil); err == nil {
		t.Fatal("opened a log in a missing directory")
	}
	if _, err := revlog.Read(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("read a missing log")
	}
}
