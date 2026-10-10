// SPDX-License-Identifier: Apache-2.0

package revlog_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/revlog"
)

func logWith(t *testing.T, subjects ...string) (string, *revlog.Log) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "revocations.log")
	l, err := revlog.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range subjects {
		if _, err := l.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: s}); err != nil {
			t.Fatal(err)
		}
	}
	return path, l
}

// TestSinkShips: a replica's entries reach the sink as 1..n in order; shipping again ships
// nothing twice; a later entry follows.
func TestSinkShips(t *testing.T) {
	path, l := logWith(t, "ses_1", "ses_2")
	sink := revlog.Sink{Dir: t.TempDir()}
	if left, err := sink.Ship(path, "node-a"); err != nil || len(left) != 0 {
		t.Fatalf("ship: %v %v", left, err)
	}
	if left, err := sink.Ship(path, "node-a"); err != nil || len(left) != 0 {
		t.Fatalf("ship again: %v %v", left, err)
	}
	if _, err := l.Append(revlog.Entry{Kind: revlog.APITokenRevoked, Subject: "tok_1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Ship(path, "node-a"); err != nil {
		t.Fatal(err)
	}
	got, err := sink.Read()
	if err != nil {
		t.Fatal(err)
	}
	var subjects []string
	for i, e := range got {
		if e.Seq != uint64(i)+1 || e.Replica != "node-a" || e.Entry.Seq != uint64(i)+1 {
			t.Errorf("sink entry %d: %+v", i+1, e)
		}
		subjects = append(subjects, e.Entry.Subject)
	}
	if strings.Join(subjects, " ") != "ses_1 ses_2 tok_1" {
		t.Errorf("sink holds %v", subjects)
	}
}

// TestSinkShipsRestoredLog: a restore puts an older log back and appends to it, so new entries
// take numbers the replica shipped before; they are shipped all the same, and the entries the sink
// holds already are not shipped twice.
func TestSinkShipsRestoredLog(t *testing.T) {
	path, _ := logWith(t, "ses_1", "ses_2", "ses_3")
	sink := revlog.Sink{Dir: t.TempDir()}
	if _, err := sink.Ship(path, "node-a"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.SplitAfter(string(b), "\n")[0]
	if err := os.WriteFile(path, []byte(first), 0o600); err != nil { //nolint:gosec // G703: the test's temporary log, now the backup's: ses_1
		t.Fatal(err)
	}
	l, err := revlog.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(revlog.Entry{Kind: revlog.APITokenRevoked, Subject: "tok_after"}); err != nil { // number 2 again
		t.Fatal(err)
	}
	if left, err := sink.Ship(path, "node-a"); err != nil || len(left) != 0 {
		t.Fatalf("ship: %v %v", left, err)
	}
	got, err := sink.Read()
	if err != nil {
		t.Fatal(err)
	}
	var subjects []string
	for _, e := range got {
		subjects = append(subjects, e.Entry.Subject)
	}
	if strings.Join(subjects, " ") != "ses_1 ses_2 ses_3 tok_after" {
		t.Errorf("sink holds %v", subjects)
	}
}

// TestSinkReplicas: two replicas ship into one sink; the numbers stay gapless and each replica's
// entries keep their order.
func TestSinkReplicas(t *testing.T) {
	a, la := logWith(t, "a1")
	b, _ := logWith(t, "b1", "b2")
	sink := revlog.Sink{Dir: t.TempDir()}
	for _, step := range []struct{ path, replica string }{{a, "node-a"}, {b, "node-b"}} {
		if _, err := sink.Ship(step.path, step.replica); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := la.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: "a2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Ship(a, "node-a"); err != nil {
		t.Fatal(err)
	}
	got, err := sink.Read()
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, e := range got {
		order = append(order, e.Replica+":"+e.Entry.Subject)
	}
	if strings.Join(order, " ") != "node-a:a1 node-b:b1 node-b:b2 node-a:a2" {
		t.Errorf("sink order %v", order)
	}
}

// TestSinkDetectsDamage: a missing number, a changed entry and a broken link are refused.
func TestSinkDetectsDamage(t *testing.T) {
	for name, damage := range map[string]func(dir string){
		"a gap":           func(dir string) { _ = os.Remove(filepath.Join(dir, "2")) },
		"a changed entry": func(dir string) { replace(t, filepath.Join(dir, "2"), "ses_2", "ses_X") },
		"a moved entry": func(dir string) {
			b, _ := os.ReadFile(filepath.Join(dir, "3"))
			_ = os.WriteFile(filepath.Join(dir, "2"), b, 0o640) //nolint:gosec // G703: the test's temporary sink
		},
	} {
		path, _ := logWith(t, "ses_1", "ses_2", "ses_3")
		sink := revlog.Sink{Dir: t.TempDir()}
		if _, err := sink.Ship(path, "node-a"); err != nil {
			t.Fatal(err)
		}
		damage(sink.Dir)
		if _, err := sink.Read(); !errors.Is(err, revlog.ErrBroken) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func replace(t *testing.T, path, old, new string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), old, new, 1)), 0o640); err != nil { //nolint:gosec // G703: the test's temporary sink
		t.Fatal(err)
	}
}

// TestSinkUnavailable: with the sink unreachable, shipping reports every entry as unshipped and
// leaves the local log as it was; once the sink is back, it ships them.
func TestSinkUnavailable(t *testing.T) {
	path, _ := logWith(t, "ses_1", "ses_2")
	sink := revlog.Sink{Dir: filepath.Join(t.TempDir(), "share")} // not mounted
	left, err := sink.Ship(path, "node-a")
	if err == nil || len(left) != 2 || left[0].Subject != "ses_1" {
		t.Fatalf("an unreachable sink: %v %v", left, err)
	}
	if err := os.Mkdir(sink.Dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if left, err := sink.Ship(path, "node-a"); err != nil || len(left) != 0 {
		t.Fatalf("the sink back: %v %v", left, err)
	}
}

// TestStatusAlerting: the "not yet off-host" alert fires only with a sink and an entry waiting
// longer than 5 minutes; without a sink it never fires.
func TestStatusAlerting(t *testing.T) {
	logged := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	waiting := []revlog.Entry{{Seq: 1, Time: logged}}
	for _, tc := range []struct {
		name  string
		st    revlog.Status
		after time.Duration
		want  bool
	}{
		{"shipped", revlog.StatusOf(true, nil), time.Hour, false},
		{"waiting 5 min", revlog.StatusOf(true, waiting), 5 * time.Minute, false},
		{"waiting 5 min 1 s", revlog.StatusOf(true, waiting), 5*time.Minute + time.Second, true},
		{"no sink", revlog.StatusOf(false, waiting), time.Hour, false},
	} {
		if got := tc.st.Alerting(logged.Add(tc.after)); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}
