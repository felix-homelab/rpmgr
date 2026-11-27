// SPDX-License-Identifier: Apache-2.0

package revlog_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/objstore"
	"github.com/felix-homelab/rpmgr/internal/objstore/objstoretest"
	"github.com/felix-homelab/rpmgr/internal/revlog"
)

const testPrefix = "revocations/"

func s3Sink(t *testing.T, g objstoretest.Target, timeout time.Duration) *revlog.Sink {
	t.Helper()
	return revlog.NewSink(revlog.NewS3Backend(context.Background(), g.Client(t, timeout), testPrefix))
}

// checkSink verifies the sink from entry 1 and that it holds exactly the entries of each replica's
// log once, with no number missing: Read fails on a gap, a bad link or an overwritten object.
func checkSink(t *testing.T, g objstoretest.Target, want map[string][]string) {
	t.Helper()
	got, err := s3Sink(t, g, 0).Read()
	if err != nil {
		t.Fatalf("the sink does not verify: %v", err)
	}
	have := map[string][]string{}
	for i, e := range got {
		if e.Seq != uint64(i)+1 {
			t.Fatalf("sink entry %d has the number %d", i+1, e.Seq)
		}
		have[e.Replica] = append(have[e.Replica], e.Entry.Subject)
	}
	for replica, subjects := range want {
		if strings.Join(have[replica], " ") != strings.Join(subjects, " ") {
			t.Errorf("%s: the sink holds %v, want %v", replica, have[replica], subjects)
		}
	}
	total := 0
	for _, s := range want {
		total += len(s)
	}
	if len(got) != total {
		t.Errorf("the sink holds %d entries, want %d", len(got), total)
	}
}

// countingProxy puts a proxy in front of g that counts the answers 412, the lost races.
func countingProxy(t *testing.T, g objstoretest.Target) (objstoretest.Target, *atomic.Int32) {
	t.Helper()
	u, err := url.Parse(g.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	var lost atomic.Int32
	rp := httputil.NewSingleHostReverseProxy(u) // keeps the Host header, which the signature covers
	rp.ModifyResponse = func(r *http.Response) error {
		// The probe's own 412 is no lost race.
		if r.StatusCode == http.StatusPreconditionFailed && !strings.Contains(r.Request.URL.Path, "_probe/") {
			lost.Add(1)
		}
		return nil
	}
	srv := httptest.NewServer(rp)
	t.Cleanup(srv.Close)
	g.Endpoint = srv.URL
	return g, &lost
}

func subjectsOf(prefix string, n int) []string {
	var out []string
	for i := 1; i <= n; i++ {
		out = append(out, fmt.Sprintf("%s_%d", prefix, i))
	}
	return out
}

// TestRevlogS3_NoOverwriteNoGap (docs/12-testing-and-quality.md, "Security testing"): two
// shippers racing on an S3-compatible sink leave no gap, no duplicate and no overwritten object, and
// a 412 is the lost race, not an error; a store that does not refuse a second create with
// If-None-Match: * is refused; 503, a timeout and a 403 raise the alert and lose no entry. With the
// build tag objstoreit the race runs against SILO in a container.
func TestRevlogS3_NoOverwriteNoGap(t *testing.T) {
	t.Run("race", func(t *testing.T) {
		g, lost := countingProxy(t, objstoretest.NewTarget(t))
		const n = 40
		pathA, _ := logWith(t, subjectsOf("a", n)...)
		pathB, _ := logWith(t, subjectsOf("b", n)...)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for replica, path := range map[string]string{"node-a": pathA, "node-b": pathB} {
			sink := s3Sink(t, g, 0)
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				// A lost race (412) is not an error: the round ends with nothing left.
				if left, err := sink.Ship(path, replica); err != nil || len(left) != 0 {
					t.Errorf("%s: ship: %d left, %v", replica, len(left), err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if lost.Load() == 0 {
			t.Error("no create answered 412: the shippers did not race")
		}
		checkSink(t, g, map[string][]string{"node-a": subjectsOf("a", n), "node-b": subjectsOf("b", n)})
		// A third round ships nothing and breaks nothing.
		if left, err := s3Sink(t, g, 0).Ship(pathA, "node-a"); err != nil || len(left) != 0 {
			t.Errorf("a later round: %d left, %v", len(left), err)
		}
		checkSink(t, g, map[string][]string{"node-a": subjectsOf("a", n), "node-b": subjectsOf("b", n)})
	})

	t.Run("a taken key is never overwritten", func(t *testing.T) {
		g := objstoretest.NewTarget(t)
		b := revlog.NewS3Backend(context.Background(), g.Client(t, 0), testPrefix)
		key := revlog.Key(1)
		if err := b.CreateIfAbsent(key, []byte("first\n")); err != nil {
			t.Fatal(err)
		}
		if err := b.CreateIfAbsent(key, []byte("second\n")); !errors.Is(err, revlog.ErrExists) {
			t.Fatalf("a second create: %v, want ErrExists", err)
		}
		if got, err := b.Get(key); err != nil || string(got) != "first\n" {
			t.Errorf("the object is %q, %v", got, err)
		}
	})

	t.Run("a store without conditional create is refused", func(t *testing.T) {
		s := objstoretest.New(t)
		s.NoConditional = true
		g := s.Target()
		b := revlog.NewS3Backend(context.Background(), g.Client(t, 0), testPrefix)
		if err := b.Probe(t.Context()); !errors.Is(err, revlog.ErrNoConditionalCreate) {
			t.Fatalf("the probe: %v, want ErrNoConditionalCreate", err)
		}
		// Nothing is shipped to it, and it is not probed again for each tick.
		path, _ := logWith(t, "ses_1")
		sink := revlog.NewSink(b)
		puts := s.Count("PUT")
		left, err := sink.Ship(path, "node-a")
		if !errors.Is(err, revlog.ErrNoConditionalCreate) || len(left) != 1 {
			t.Errorf("ship: %d left, %v", len(left), err)
		}
		if s.Count("PUT") != puts {
			t.Errorf("a refused store was written to again: %d PUTs, had %d", s.Count("PUT"), puts)
		}
		for _, k := range s.Keys() {
			if !strings.Contains(k, "_probe/") {
				t.Errorf("an entry reached the refused store: %s", k)
			}
		}
	})

	for _, c := range []struct {
		name    string
		status  int
		delay   time.Duration
		timeout time.Duration
		isErr   func(error) bool
	}{
		{"503", 503, 0, 0, func(err error) bool { return objstore.Retryable(err) }},
		{"timeout", 0, 3 * time.Second, 200 * time.Millisecond, func(err error) bool { return objstore.Retryable(err) }},
		{"403", 403, 0, 0, func(err error) bool { return objstore.Refused(err) }},
	} {
		t.Run(c.name+" loses no entry", func(t *testing.T) {
			s := objstoretest.New(t)
			g := s.Target()
			path, _ := logWith(t, "ses_1", "ses_2", "ses_3")
			sink := s3Sink(t, g, c.timeout)
			if left, err := sink.Ship(path, "node-a"); err != nil || len(left) != 0 {
				t.Fatalf("first round: %d left, %v", len(left), err)
			}
			var down atomic.Bool
			down.Store(true)
			s.Fault = func(method, key string) (int, time.Duration) {
				if down.Load() && method == "PUT" {
					return c.status, c.delay
				}
				return 0, 0
			}
			// Two more entries cannot be shipped; both stay in the backlog.
			appendEntries(t, path, "ses_4", "ses_5")
			left, err := sink.Ship(path, "node-a")
			if err == nil || !c.isErr(err) || len(left) != 2 {
				t.Fatalf("while the store fails: %d left, %v", len(left), err)
			}
			if st := revlog.StatusOf(true, left); st.Unshipped != 2 || st.Oldest.IsZero() {
				t.Errorf("the backlog is not reported: %+v", st)
			}
			down.Store(false)
			if left, err := sink.Ship(path, "node-a"); err != nil || len(left) != 0 {
				t.Fatalf("after the store recovered: %d left, %v", len(left), err)
			}
			checkSink(t, g, map[string][]string{"node-a": {"ses_1", "ses_2", "ses_3", "ses_4", "ses_5"}})
		})
	}
}

func appendEntries(t *testing.T, path string, subjects ...string) {
	t.Helper()
	l, err := revlog.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range subjects {
		if _, err := l.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: s}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestS3Backend_List: keys come back without the prefix, in order, after the given key, in more
// pages than one; probe objects are not part of the sink.
func TestS3Backend_List(t *testing.T) {
	g := objstoretest.NewTarget(t)
	b := revlog.NewS3Backend(context.Background(), g.Client(t, 0), "sink") // a prefix without its slash gets one
	if err := b.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	const n = 1005 // more than one page of 1 000 keys
	for i := 1; i <= n; i++ {
		if err := b.CreateIfAbsent(revlog.Key(uint64(i)), []byte("x\n")); err != nil {
			t.Fatal(err)
		}
	}
	all, err := b.List("")
	if err != nil || len(all) != n || all[0] != revlog.Key(1) || all[n-1] != revlog.Key(n) {
		t.Fatalf("list: %d keys, %v", len(all), err)
	}
	rest, err := b.List(revlog.Key(1002))
	if err != nil || len(rest) != 3 || rest[0] != revlog.Key(1003) {
		t.Errorf("list after 1002: %v, %v", rest, err)
	}
	if none, err := b.List(revlog.Key(n)); err != nil || len(none) != 0 {
		t.Errorf("list after the last: %v, %v", none, err)
	}
	// A sibling prefix is another sink.
	other := revlog.NewS3Backend(context.Background(), g.Client(t, 0), "sink2")
	if keys, err := other.List(""); err != nil || len(keys) != 0 {
		t.Errorf("another prefix: %v, %v", keys, err)
	}
}

// TestS3Backend_ProbeAnswers: a store that cannot be asked is not a store that failed; one that
// answers 501 to the header failed.
func TestS3Backend_ProbeAnswers(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		final  bool
	}{{"503", 503, false}, {"403", 403, false}, {"501", 501, true}} {
		t.Run(c.name, func(t *testing.T) {
			s := objstoretest.New(t)
			var puts atomic.Int32
			s.Fault = func(method, key string) (int, time.Duration) {
				// The first create passes; the second gets the answer under test.
				if method == "PUT" && puts.Add(1) == 2 {
					return c.status, 0
				}
				return 0, 0
			}
			b := revlog.NewS3Backend(context.Background(), s.Target().Client(t, 0), "")
			err := b.Probe(t.Context())
			if err == nil || errors.Is(err, revlog.ErrNoConditionalCreate) != c.final {
				t.Fatalf("probe: %v, final %v", err, c.final)
			}
			if !c.final {
				if err := b.Probe(t.Context()); err != nil { // asked again, and the store answers
					t.Errorf("a second probe: %v", err)
				}
			}
		})
	}
}

// TestS3Backend_ProbeFirstCreateAnswers (security review S1): a store that rejects the header on the
// first create is refused as well, and so is one with a switch for it; a 412 on the first create
// is proof, since an earlier start made the object.
func TestS3Backend_ProbeFirstCreateAnswers(t *testing.T) {
	for _, status := range []int{400, 501} {
		s := objstoretest.New(t)
		s.Fault = func(method, key string) (int, time.Duration) {
			if method == "PUT" {
				return status, 0
			}
			return 0, 0
		}
		b := revlog.NewS3Backend(context.Background(), s.Target().Client(t, 0), "p")
		if err := b.Probe(t.Context()); !errors.Is(err, revlog.ErrNoConditionalCreate) {
			t.Errorf("a first create answered %d: %v", status, err)
		}
	}
	s := objstoretest.New(t)
	s.RejectConditional = true
	b := revlog.NewS3Backend(context.Background(), s.Target().Client(t, 0), "p")
	if err := b.Probe(t.Context()); !errors.Is(err, revlog.ErrNoConditionalCreate) {
		t.Errorf("a store that rejects the header: %v", err)
	}
	// A second start finds the object: the first create answers 412, and that is enough.
	s = objstoretest.New(t)
	for i := 0; i < 3; i++ {
		if err := revlog.NewS3Backend(context.Background(), s.Target().Client(t, 0), "p").Probe(t.Context()); err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
	}
	if keys := s.Keys(); len(keys) != 1 {
		t.Errorf("three starts left %v", keys)
	}
}

// TestS3Backend_IdleTickAfterStarts (security review S3): probes do not pile up, so a tick with
// nothing to ship costs one request however often the controller started.
func TestS3Backend_IdleTickAfterStarts(t *testing.T) {
	s := objstoretest.New(t)
	var b *revlog.S3Backend
	for i := 0; i < 5; i++ {
		b = revlog.NewS3Backend(context.Background(), s.Target().Client(t, 0), "revocations")
		if err := b.Probe(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.CreateIfAbsent(revlog.Key(1), []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	before := s.Count("GET")
	keys, err := b.List(revlog.Key(1))
	if err != nil || len(keys) != 0 || s.Count("GET")-before != 1 {
		t.Errorf("an idle tick: %v, %v, %d requests", keys, err, s.Count("GET")-before)
	}
}

// TestS3Backend_ListingBounds (security review S2): a listing that never ends, repeats a token or
// runs out of order is an error, and a cancelled context ends the requests.
func TestS3Backend_ListingBounds(t *testing.T) {
	for name, set := range map[string]func(*objstoretest.Server){
		"endless":               func(s *objstoretest.Server) { s.EndlessListing = true },
		"keys that do not rise": func(s *objstoretest.Server) { s.RepeatListing = true },
		"a repeated token":      func(s *objstoretest.Server) { s.RepeatToken = true },
	} {
		t.Run(name, func(t *testing.T) {
			revlog.SetMaxListPages(t, 20)
			s := objstoretest.New(t)
			set(s)
			b := revlog.NewS3Backend(context.Background(), s.Target().Client(t, 0), "p")
			_, err := b.List("")
			if !errors.Is(err, revlog.ErrListing) {
				t.Fatalf("list: %v", err)
			}
			if name == "endless" && !strings.Contains(err.Error(), "20 pages") {
				t.Errorf("the error does not name the cap in effect: %v", err)
			}
			if n := s.Count("GET"); n > 21 {
				t.Errorf("%d requests for a limit of 20 pages", n)
			}
		})
	}
	s := objstoretest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	b := revlog.NewS3Backend(ctx, s.Target().Client(t, 0), "p")
	cancel()
	if _, err := b.List(""); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled context: %v", err)
	}
	if err := b.CreateIfAbsent(revlog.Key(1), []byte("x\n")); !errors.Is(err, context.Canceled) {
		t.Errorf("a create with a cancelled context: %v", err)
	}
}

// TestS3Backend_ObjectLock (security review S6): with LockDays each entry is written locked in
// compliance mode; without it, no lock header is sent.
func TestS3Backend_ObjectLock(t *testing.T) {
	s := objstoretest.New(t)
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	b := revlog.NewS3Backend(context.Background(), s.Target().Client(t, 0), "p")
	if err := b.CreateIfAbsent(revlog.Key(1), []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	if mode, _ := s.Lock("p/" + revlog.Key(1)); mode != "" {
		t.Errorf("a lock without LockDays: %s", mode)
	}
	b.LockDays, b.Now = 90, func() time.Time { return now }
	if err := b.CreateIfAbsent(revlog.Key(2), []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	mode, retain := s.Lock("p/" + revlog.Key(2))
	if mode != "COMPLIANCE" || !strings.HasPrefix(retain, "2027-02-25T12:00:00") {
		t.Errorf("lock %s until %s, want COMPLIANCE until 2027-02-25", mode, retain)
	}
	// A bucket without Object Lock refuses the write; it is no lost race and no break.
	s.NoLock = true
	if err := b.CreateIfAbsent(revlog.Key(3), []byte("x\n")); err == nil || errors.Is(err, revlog.ErrExists) || !objstore.Refused(err) {
		t.Errorf("a bucket without Object Lock: %v", err)
	}
}

// TestS3Backend_ProbeUnreachableFirstCreate: a first create that fails is no verdict either.
func TestS3Backend_ProbeUnreachableFirstCreate(t *testing.T) {
	s := objstoretest.New(t)
	s.Fault = func(method, key string) (int, time.Duration) { return 503, 0 }
	b := revlog.NewS3Backend(context.Background(), s.Target().Client(t, 0), "")
	if err := b.CreateIfAbsent(revlog.Key(1), []byte("x\n")); err == nil || errors.Is(err, revlog.ErrNoConditionalCreate) {
		t.Fatalf("create while the store is down: %v", err)
	}
	if len(s.Keys()) != 0 {
		t.Errorf("a store that was not probed holds %v", s.Keys())
	}
}

// TestS3Backend_ListSequence (review item 3): a key that is not 20 digits is refused before it is
// kept, and a listing stops at the first key out of sequence and the one after it, so the memory
// is that of real entries however many keys follow.
func TestS3Backend_ListSequence(t *testing.T) {
	g := objstoretest.NewTarget(t)
	b := revlog.NewS3Backend(context.Background(), g.Client(t, 0), "sink")
	for _, n := range []uint64{1, 2, 4, 5, 6, 7, 8, 9} {
		if err := b.CreateIfAbsent(revlog.Key(n), []byte("x\n")); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := b.List("")
	if err != nil || len(keys) != 4 || keys[2] != revlog.Key(4) || keys[3] != revlog.Key(5) {
		t.Errorf("a gap at 3: %v, %v; want 1, 2, 4 and the key after the gap", keys, err)
	}
	// Right after the verified prefix, the first key is the one expected.
	if keys, err := b.List(revlog.Key(2)); err != nil || len(keys) != 2 || keys[0] != revlog.Key(4) {
		t.Errorf("after 2: %v, %v", keys, err)
	}
	for _, name := range []string{"notes.txt", "7", "00000000000000000010x"} {
		g := objstoretest.NewTarget(t)
		b := revlog.NewS3Backend(context.Background(), g.Client(t, 0), "sink")
		if err := b.CreateIfAbsent(name, []byte("x\n")); err != nil {
			t.Fatal(err)
		}
		if _, err := b.List(""); !errors.Is(err, revlog.ErrBroken) {
			t.Errorf("the key %q: %v, want ErrBroken", name, err)
		}
	}
}

// TestS3Backend_ProbeCallerErrors (review item 8): a 400 that names the caller's credentials or
// region is no verdict on the store, and the refusal names the store's answer.
func TestS3Backend_ProbeCallerErrors(t *testing.T) {
	for _, code := range []string{"AuthorizationHeaderMalformed", "InvalidAccessKeyId", "SignatureDoesNotMatch"} {
		s := objstoretest.New(t)
		s.PutAnswer = func() (int, string) { return 400, code }
		b := revlog.NewS3Backend(context.Background(), s.Target().Client(t, 0), "p")
		err := b.Probe(t.Context())
		if err == nil || errors.Is(err, revlog.ErrNoConditionalCreate) || !objstore.Refused(err) {
			t.Errorf("%s: %v", code, err)
		}
	}
	s := objstoretest.New(t)
	s.RejectConditional = true
	err := revlog.NewS3Backend(context.Background(), s.Target().Client(t, 0), "p").Probe(t.Context())
	if err == nil || !strings.Contains(err.Error(), "400 InvalidArgument") {
		t.Errorf("the refusal does not name the answer: %v", err)
	}
}
