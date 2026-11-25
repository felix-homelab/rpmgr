// SPDX-License-Identifier: Apache-2.0

package revlog_test

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// memBackend is an in-memory Backend that counts calls and fails on demand.
type memBackend struct {
	mu                       sync.Mutex
	objs                     map[string][]byte
	lists, gets, creates     int
	lastAfter                string
	failList, failGet, failC error
	hideKey                  string // an object that exists but is not listed
	beforeCreate             func() // runs once, before the next create: another replica gets in
	failGetAt                int    // the nth get from now fails once (1 = the next); 0 = none
	lostReply                bool   // the next create stores the object and still answers ErrExists
}

func newMem() *memBackend { return &memBackend{objs: map[string][]byte{}} }

func (m *memBackend) List(after string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lists++
	m.lastAfter = after
	if m.failList != nil {
		return nil, m.failList
	}
	var keys []string
	for k := range m.objs {
		if k > after && k != m.hideKey {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (m *memBackend) Get(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	if m.failGetAt > 0 {
		if m.failGetAt--; m.failGetAt == 0 {
			return nil, errors.New("boom once")
		}
	}
	if m.failGet != nil {
		return nil, m.failGet
	}
	b, ok := m.objs[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

func (m *memBackend) CreateIfAbsent(key string, data []byte) error {
	if f := m.beforeCreate; f != nil {
		m.beforeCreate = nil
		f()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creates++
	if m.failC != nil {
		return m.failC
	}
	if _, ok := m.objs[key]; ok {
		return revlog.ErrExists
	}
	m.objs[key] = append([]byte(nil), data...)
	if m.lostReply {
		m.lostReply = false
		return revlog.ErrExists
	}
	return nil
}

func (m *memBackend) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.objs) }

// TestSinkNoFullReread: a tick with nothing new lists the keys after the verified prefix and gets
// no object; an entry of another replica costs one get; the sink's own entries cost none.
func TestSinkNoFullReread(t *testing.T) {
	path, l := logWith(t, "ses_1", "ses_2", "ses_3")
	other, _ := logWith(t, "b1")
	mem := newMem()
	sink := revlog.NewSink(mem)
	if _, err := sink.Ship(path, "node-a"); err != nil {
		t.Fatal(err)
	}
	mem.lists, mem.gets = 0, 0
	if left, err := sink.Ship(path, "node-a"); err != nil || len(left) != 0 {
		t.Fatalf("ship again: %v %v", left, err)
	}
	if mem.lists != 1 || mem.gets != 1 || mem.lastAfter != revlog.Key(2) {
		t.Errorf("an idle tick: %d lists after %q, %d gets; want 1 list after %q and 1 get (the tip)", mem.lists, mem.lastAfter, mem.gets, revlog.Key(2))
	}
	if _, err := l.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: "ses_4"}); err != nil {
		t.Fatal(err)
	}
	mem.lists, mem.gets = 0, 0
	if _, err := sink.Ship(path, "node-a"); err != nil {
		t.Fatal(err)
	}
	if mem.gets != 1 {
		t.Errorf("shipping an own entry read %d objects, want only the tip", mem.gets)
	}
	// Another replica ships through a second Sink value; the first reads exactly that object.
	if _, err := revlog.NewSink(mem).Ship(other, "node-b"); err != nil {
		t.Fatal(err)
	}
	mem.lists, mem.gets = 0, 0
	if _, err := sink.Ship(path, "node-a"); err != nil {
		t.Fatal(err)
	}
	if mem.gets != 2 || mem.lastAfter != revlog.Key(3) {
		t.Errorf("one foreign entry: %d gets after %q, want the tip and the entry after %q", mem.gets, mem.lastAfter, revlog.Key(3))
	}
}

// TestSinkChainBreakMidPrefix: a link that does not fit, or a missing key, in the middle of the
// sink stops shipping: nothing is created, the error is kept until a new Sink is made, and a new
// prefix takes every entry again.
func TestSinkChainBreakMidPrefix(t *testing.T) {
	for name, damage := range map[string]func(m *memBackend){
		"a bad link": func(m *memBackend) { m.objs[revlog.Key(4)] = m.objs[revlog.Key(3)] },
		"a gap":      func(m *memBackend) { delete(m.objs, revlog.Key(4)) },
		"a changed entry": func(m *memBackend) {
			m.objs[revlog.Key(3)] = []byte(strings.Replace(string(m.objs[revlog.Key(3)]), "ses_3", "ses_X", 1))
		},
	} {
		src, _ := logWith(t, "ses_1", "ses_2", "ses_3", "ses_4", "ses_5")
		mem := newMem()
		if _, err := revlog.NewSink(mem).Ship(src, "node-a"); err != nil {
			t.Fatal(err)
		}
		damage(mem)
		n := mem.count()
		fresh := revlog.NewSink(mem) // a restart
		left, err := fresh.Ship(src, "node-a")
		if !errors.Is(err, revlog.ErrBroken) || len(left) != 5 {
			t.Errorf("%s: %d unshipped, %v; want 5 and ErrBroken", name, len(left), err)
		}
		if mem.count() != n {
			t.Errorf("%s: shipping created objects behind a break", name)
		}
		creates := mem.creates
		if _, err := fresh.Ship(src, "node-a"); !errors.Is(err, revlog.ErrBroken) || mem.creates != creates {
			t.Errorf("%s: the break is not kept: %v", name, err)
		}
		next := newMem() // the new prefix
		if left, err := revlog.NewSink(next).Ship(src, "node-a"); err != nil || len(left) != 0 || next.count() != 5 {
			t.Errorf("%s: a new prefix: %v %v, %d objects", name, left, err, next.count())
		}
	}
}

// TestSinkBreakAfterPrefix: a sink that was verified and then gets an object that does not link
// stops shipping too; the verified part stays.
func TestSinkBreakAfterPrefix(t *testing.T) {
	src, l := logWith(t, "ses_1")
	mem := newMem()
	sink := revlog.NewSink(mem)
	if _, err := sink.Ship(src, "node-a"); err != nil {
		t.Fatal(err)
	}
	mem.objs[revlog.Key(2)] = []byte(`{"seq":2,"replica":"x","entry":{},"prev":"00","hash":"00"}` + "\n")
	if _, err := l.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: "ses_2"}); err != nil {
		t.Fatal(err)
	}
	left, err := sink.Ship(src, "node-a")
	if !errors.Is(err, revlog.ErrBroken) || len(left) != 2 {
		t.Fatalf("%d unshipped, %v; want both local entries reported and ErrBroken", len(left), err)
	}
}

// TestSinkRestoredEntriesShippedOnce: after a restore the local numbers start again; the entries
// it appends are created once, and a further tick creates nothing.
func TestSinkRestoredEntriesShippedOnce(t *testing.T) {
	path, _ := logWith(t, "ses_1", "ses_2", "ses_3")
	mem := newMem()
	sink := revlog.NewSink(mem)
	if _, err := sink.Ship(path, "node-a"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.SplitAfter(string(b), "\n")[0]), 0o600); err != nil { //nolint:gosec // G703: the test's temporary log
		t.Fatal(err)
	}
	l, err := revlog.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(revlog.Entry{Kind: revlog.APITokenRevoked, Subject: "tok_after"}); err != nil {
		t.Fatal(err)
	}
	mem.creates = 0
	for range 3 { // also through a restart of the shipper
		if _, err := sink.Ship(path, "node-a"); err != nil {
			t.Fatal(err)
		}
		sink = revlog.NewSink(mem)
	}
	if mem.creates != 1 || mem.count() != 4 {
		t.Errorf("%d creates, %d objects; want 1 and 4", mem.creates, mem.count())
	}
}

// TestSinkBackendErrors: a failing list, get or create leaves the entries unshipped and is no
// break; shipping resumes when the backend works, without a duplicate.
func TestSinkBackendErrors(t *testing.T) {
	boom := errors.New("boom")
	for name, fail := range map[string]func(m *memBackend, on bool){
		"list":   func(m *memBackend, on bool) { m.failList = map[bool]error{true: boom}[on] },
		"get":    func(m *memBackend, on bool) { m.failGet = map[bool]error{true: boom}[on] },
		"create": func(m *memBackend, on bool) { m.failC = map[bool]error{true: boom}[on] },
	} {
		src, _ := logWith(t, "ses_1", "ses_2")
		mem := newMem()
		if name == "get" { // something to get: an entry of another replica
			other, _ := logWith(t, "b1")
			if _, err := revlog.NewSink(mem).Ship(other, "node-b"); err != nil {
				t.Fatal(err)
			}
		}
		fail(mem, true)
		sink := revlog.NewSink(mem)
		left, err := sink.Ship(src, "node-a")
		if !errors.Is(err, boom) || len(left) != 2 || errors.Is(err, revlog.ErrBroken) {
			t.Errorf("%s: %d unshipped, %v", name, len(left), err)
		}
		fail(mem, false)
		if left, err := sink.Ship(src, "node-a"); err != nil || len(left) != 0 {
			t.Errorf("%s: after recovery: %v %v", name, left, err)
		}
		got, err := revlog.NewSink(mem).Read()
		if err != nil {
			t.Fatal(err)
		}
		var subjects []string
		for _, e := range got {
			subjects = append(subjects, e.Entry.Subject)
		}
		want := "ses_1 ses_2"
		if name == "get" {
			want = "b1 ses_1 ses_2"
		}
		if strings.Join(subjects, " ") != want {
			t.Errorf("%s: sink holds %v, want %q", name, subjects, want)
		}
	}
}

// TestSinkLostRace: two replicas that both verified the sink create the same key; the loser gets
// the winner's object and takes the next number. A key that exists but is never listed is a break.
func TestSinkLostRace(t *testing.T) {
	a, _ := logWith(t, "a1")
	b, _ := logWith(t, "b1")
	mem := newMem()
	sa, sb := revlog.NewSink(mem), revlog.NewSink(mem)
	empty, _ := logWith(t)
	for _, s := range []*revlog.Sink{sa, sb} { // both verify the empty sink
		if _, err := s.Ship(empty, "x"); err != nil {
			t.Fatal(err)
		}
	}
	mem.beforeCreate = func() { // a ships between the loser's verification and its create
		if _, err := sa.Ship(a, "node-a"); err != nil {
			t.Error(err)
		}
	}
	mem.creates, mem.gets = 0, 0
	if left, err := sb.Ship(b, "node-b"); err != nil || len(left) != 0 {
		t.Fatalf("the loser: %v %v", left, err)
	}
	if mem.creates != 3 || mem.gets != 1 { // a's create, b's lost create, b's create
		t.Errorf("%d creates and %d gets, want 3 and 1", mem.creates, mem.gets)
	}
	got, err := revlog.NewSink(mem).Read()
	if err != nil || len(got) != 2 || got[0].Replica != "node-a" || got[1].Replica != "node-b" {
		t.Errorf("the sink: %v %v", got, err)
	}

	// An object at the next key that is never listed: the loser cannot make progress.
	mem2 := newMem()
	mem2.objs[revlog.Key(1)] = []byte("{}")
	mem2.hideKey = revlog.Key(1)
	left, err := revlog.NewSink(mem2).Ship(a, "node-a")
	if !errors.Is(err, revlog.ErrBroken) || len(left) != 1 {
		t.Errorf("an unlisted key: %d unshipped, %v", len(left), err)
	}
}

// TestKey: keys are 20 digits, so that a listing sorts numerically at every width.
func TestKey(t *testing.T) {
	for seq, want := range map[uint64]string{
		0:  "00000000000000000000",
		1:  "00000000000000000001",
		9:  "00000000000000000009",
		10: "00000000000000000010",
	} {
		if want != "" && revlog.Key(seq) != want {
			t.Errorf("Key(%d) = %s, want %s", seq, revlog.Key(seq), want)
		}
	}
	if got := revlog.Key(^uint64(0)); got != "18446744073709551615" {
		t.Errorf("Key(max) = %s", got)
	}
	keys := []string{revlog.Key(100), revlog.Key(2), revlog.Key(10), revlog.Key(1), revlog.Key(99), revlog.Key(9)}
	sort.Strings(keys)
	var back []string
	for _, k := range keys {
		back = append(back, strings.TrimLeft(k, "0"))
	}
	if strings.Join(back, " ") != "1 2 9 10 99 100" {
		t.Errorf("order %v", back)
	}
}

// TestDirBackend: listing order and "after", the temporary files, and create-if-absent on an
// existing key with equal and with different content.
func TestDirBackend(t *testing.T) {
	d := revlog.DirBackend{Dir: t.TempDir()}
	for _, n := range []uint64{10, 2, 100, 1, 9, 99} {
		if err := d.CreateIfAbsent(revlog.Key(n), []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d.Dir, ".tmp-x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := d.List("")
	if err != nil || len(keys) != 6 || keys[0] != revlog.Key(1) || keys[5] != revlog.Key(100) || keys[3] != revlog.Key(10) {
		t.Fatalf("list: %v %v", keys, err)
	}
	if keys, _ = d.List(revlog.Key(10)); len(keys) != 2 || keys[0] != revlog.Key(99) {
		t.Errorf("after 10: %v", keys)
	}
	if keys, _ = d.List(revlog.Key(100)); len(keys) != 0 {
		t.Errorf("after the last: %v", keys)
	}
	for name, content := range map[string]string{"equal": "v", "different": "other"} {
		if err := d.CreateIfAbsent(revlog.Key(9), []byte(content)); !errors.Is(err, revlog.ErrExists) {
			t.Errorf("%s content: %v, want ErrExists", name, err)
		}
		if b, _ := d.Get(revlog.Key(9)); string(b) != "v" {
			t.Errorf("%s content overwrote the object: %q", name, b)
		}
	}
	if _, err := d.Get(revlog.Key(3)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("get of a missing key: %v", err)
	}
	if entries, _ := os.ReadDir(d.Dir); len(entries) != 7 { // six objects and the foreign temp file
		t.Errorf("%d files, a temporary file was left behind", len(entries))
	}
	if _, err := (revlog.DirBackend{Dir: filepath.Join(d.Dir, "none")}).List(""); err == nil {
		t.Error("list of a missing directory succeeded")
	}
}

// legacyDir ships three entries and renames the files to the unpadded names the earlier code wrote.
func legacyDir(t *testing.T) (dir, src string, l *revlog.Log) {
	t.Helper()
	dir = t.TempDir()
	src, l = logWith(t, "ses_1", "ses_2", "ses_3")
	if _, err := revlog.NewSink(revlog.DirBackend{Dir: dir}).Ship(src, "node-a"); err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 3; n++ {
		if err := os.Rename(filepath.Join(dir, revlog.Key(uint64(n))), filepath.Join(dir, strconv.Itoa(n))); err != nil {
			t.Fatal(err)
		}
	}
	return dir, src, l
}

// TestSinkLegacyKeys: a directory written by the earlier code (files 1..3) keeps shipping without a
// break and without a duplicate; the new entry is written padded and the old files stay as they
// were. Names that are no keys are ignored.
func TestSinkLegacyKeys(t *testing.T) {
	dir, src, l := legacyDir(t)
	for _, n := range []string{"01", "1.bak", "-1", "x", "18446744073709551616"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sink := revlog.NewSink(revlog.DirBackend{Dir: dir})
	if left, err := sink.Ship(src, "node-a"); err != nil || len(left) != 0 {
		t.Fatalf("ship over a legacy sink: %v %v", left, err)
	}
	if _, err := os.Stat(filepath.Join(dir, revlog.Key(1))); err == nil {
		t.Error("a legacy file was written again padded: a duplicate")
	}
	if _, err := l.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: "ses_4"}); err != nil {
		t.Fatal(err)
	}
	if left, err := sink.Ship(src, "node-a"); err != nil || len(left) != 0 {
		t.Fatalf("a new entry: %v %v", left, err)
	}
	if _, err := os.Stat(filepath.Join(dir, revlog.Key(4))); err != nil {
		t.Errorf("the new entry is not padded: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "4")); err == nil {
		t.Error("the new entry was written unpadded")
	}
	got, err := revlog.NewSink(revlog.DirBackend{Dir: dir}).Read()
	if err != nil || len(got) != 4 || got[3].Entry.Subject != "ses_4" {
		t.Errorf("the sink: %d entries, %v", len(got), err)
	}
	d := revlog.DirBackend{Dir: dir}
	if err := d.CreateIfAbsent(revlog.Key(2), []byte("x")); !errors.Is(err, revlog.ErrExists) {
		t.Errorf("create over a legacy name: %v, want ErrExists", err)
	}
}

// TestSinkLegacyAndPaddedBoth: one sequence number under both names is a duplicate; equal content
// is fine, different content breaks the chain.
func TestSinkLegacyAndPaddedBoth(t *testing.T) {
	for name, content := range map[string]string{"equal": "", "different": "x"} {
		dir, src, _ := legacyDir(t)
		b, err := os.ReadFile(filepath.Join(dir, "2"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, revlog.Key(2)), append(b, content...), 0o600); err != nil { //nolint:gosec // G703: the test's temporary sink
			t.Fatal(err)
		}
		_, err = revlog.NewSink(revlog.DirBackend{Dir: dir}).Ship(src, "node-a")
		if name == "equal" && err != nil {
			t.Errorf("equal duplicate: %v", err)
		}
		if name == "different" && !errors.Is(err, revlog.ErrBroken) {
			t.Errorf("different duplicate: %v, want ErrBroken", err)
		}
	}
}

// TestSinkLosesEntries (finding B1): the verified prefix is checked against the sink at every
// tick. An emptied sink is shipped to again from entry 1; a tip that is gone, rolled back or
// replaced is a break.
func TestSinkLosesEntries(t *testing.T) {
	for name, tc := range map[string]struct {
		damage func(m *memBackend)
		broken bool
	}{
		"a wipe":         {func(m *memBackend) { m.objs = map[string][]byte{} }, false},
		"a rollback":     {func(m *memBackend) { delete(m.objs, revlog.Key(5)); delete(m.objs, revlog.Key(4)) }, true},
		"a lost tip":     {func(m *memBackend) { delete(m.objs, revlog.Key(5)) }, true},
		"a replaced tip": {func(m *memBackend) { m.objs[revlog.Key(5)] = m.objs[revlog.Key(4)] }, true},
		"a changed tip": {func(m *memBackend) {
			m.objs[revlog.Key(5)] = []byte(strings.Replace(string(m.objs[revlog.Key(5)]), "ses_5", "ses_X", 1))
		}, true},
	} {
		src, _ := logWith(t, "ses_1", "ses_2", "ses_3", "ses_4", "ses_5")
		mem := newMem()
		sink := revlog.NewSink(mem)
		if _, err := sink.Ship(src, "node-a"); err != nil {
			t.Fatal(err)
		}
		tc.damage(mem)
		creates := mem.creates
		left, err := sink.Ship(src, "node-a")
		if tc.broken {
			if !errors.Is(err, revlog.ErrBroken) || len(left) != 5 || mem.creates != creates {
				t.Errorf("%s: %d unshipped, %v, %d creates; want 5, ErrBroken and none", name, len(left), err, mem.creates-creates)
			}
			continue
		}
		if err != nil || len(left) != 0 {
			t.Errorf("%s: %v %v", name, left, err)
		}
		got, err := revlog.NewSink(mem).Read()
		if err != nil || len(got) != 5 || got[0].Seq != 1 {
			t.Errorf("%s: the sink after re-shipping: %d entries, %v", name, len(got), err)
		}
	}
}

// TestSinkReverify (finding B1): a key deleted below the tip is found by the full verification
// that runs every ReverifyEvery, and not before.
func TestSinkReverify(t *testing.T) {
	src, _ := logWith(t, "ses_1", "ses_2", "ses_3")
	mem := newMem()
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	sink := revlog.NewSink(mem)
	sink.Now = func() time.Time { return now }
	if _, err := sink.Ship(src, "node-a"); err != nil {
		t.Fatal(err)
	}
	delete(mem.objs, revlog.Key(2))
	now = now.Add(revlog.ReverifyEvery - time.Second)
	if _, err := sink.Ship(src, "node-a"); err != nil {
		t.Fatalf("before the interval the loss below the tip is not looked for: %v", err)
	}
	now = now.Add(time.Second)
	if left, err := sink.Ship(src, "node-a"); !errors.Is(err, revlog.ErrBroken) || len(left) != 3 {
		t.Fatalf("at the interval: %d unshipped, %v; want 3 and ErrBroken", len(left), err)
	}
	if _, err := sink.Ship(src, "node-a"); !errors.Is(err, revlog.ErrBroken) {
		t.Errorf("the break is kept: %v", err)
	}
	// A sink that is intact is verified again without a change of state.
	ok := newMem()
	s2 := revlog.NewSink(ok)
	s2.Now = func() time.Time { return now }
	if _, err := s2.Ship(src, "node-a"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(revlog.ReverifyEvery)
	ok.gets = 0
	if left, err := s2.Ship(src, "node-a"); err != nil || len(left) != 0 || ok.gets != 3 || ok.count() != 3 {
		t.Errorf("an intact sink: %v %v, %d gets, %d objects; want a full read of 3 and no new object", left, err, ok.gets, ok.count())
	}
}

// TestSinkGetFailsOnFirstScan (finding S1): a get that fails once while the sink is first read
// does not make the replica ship its own entries again.
func TestSinkGetFailsOnFirstScan(t *testing.T) {
	src, _ := logWith(t, "ses_1", "ses_2", "ses_3")
	mem := newMem()
	if _, err := revlog.NewSink(mem).Ship(src, "node-a"); err != nil {
		t.Fatal(err)
	}
	for at := 1; at <= 3; at++ {
		mem.failGetAt = at
		sink := revlog.NewSink(mem)
		if left, err := sink.Ship(src, "node-a"); err == nil || len(left) != 3 {
			t.Fatalf("get %d failing: %d unshipped, %v", at, len(left), err)
		}
		if left, err := sink.Ship(src, "node-a"); err != nil || len(left) != 0 {
			t.Fatalf("get %d, the retry: %v %v", at, left, err)
		}
		if mem.count() != 3 {
			t.Fatalf("get %d failing led to %d objects, want 3: entries shipped twice", at, mem.count())
		}
	}
}

// TestSinkCreateReplyLost (finding S2): a create that succeeded but answered "exists" does not
// ship the entry a second time.
func TestSinkCreateReplyLost(t *testing.T) {
	src, _ := logWith(t, "ses_1", "ses_2")
	mem := newMem()
	mem.lostReply = true
	left, err := revlog.NewSink(mem).Ship(src, "node-a")
	if err != nil || len(left) != 0 || mem.count() != 2 {
		t.Fatalf("%v %v, %d objects; want 2 objects, each entry once", left, err, mem.count())
	}
	got, err := revlog.NewSink(mem).Read()
	if err != nil || len(got) != 2 || got[0].Entry.Subject != "ses_1" || got[1].Entry.Subject != "ses_2" {
		t.Errorf("%v %v", got, err)
	}
}

// TestStatusAlertingStalled (finding S3): a round that has not succeeded for longer than the
// alert time alerts although no backlog is known.
func TestStatusAlertingStalled(t *testing.T) {
	last := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	st := revlog.StatusOf(true, nil)
	st.LastOK = last
	if st.Alerting(last.Add(revlog.OffHostAlert)) || !st.Alerting(last.Add(revlog.OffHostAlert+time.Second)) {
		t.Error("a stalled round does not alert at 5 min 1 s, or alerts too early")
	}
	st.Sink = false
	if st.Alerting(last.Add(time.Hour)) {
		t.Error("alert without a sink")
	}
}
