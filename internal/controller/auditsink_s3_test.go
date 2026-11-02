// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/auditsink"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/objstore/objstoretest"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditsinkcursor"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// The AWS documentation's example secret key, which the repository's secret scan allows.
const awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" //nolint:gosec // G101: the AWS documentation's example

// logBuffer collects the controller's log lines.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// s3Sink makes an object-storage sink for srv.
func (e *sinkEnv) s3Sink(name string, srv *objstoretest.Server, entries bool) *ent.AuditSink {
	e.t.Helper()
	id := ids.New("ask")
	sealed, err := e.sealer.Seal(secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: id}, secret.New(awsSecretKey))
	if err != nil {
		e.t.Fatal(err)
	}
	set := auditsink.S3Settings{Endpoint: srv.URL, Region: objstoretest.Region, Bucket: objstoretest.Bucket, AccessKeyID: objstoretest.AccessKeyID, LockDays: 30}
	return e.db.Client().AuditSink.Create().SetID(id).SetKind("s3").SetName(name).SetSettings(set.Map()).SetSecretEnc(sealed).SetEntries(entries).SaveX(e.sys)
}

// logTo makes the job log to a buffer.
func (e *sinkEnv) logTo() *logBuffer {
	buf := &logBuffer{}
	e.job = controller.AuditSinkJob(controller.AuditSinkOptions{DB: e.db, Leases: e.leases, Sealer: e.sealer, Sender: e.sender,
		Now: func() time.Time { return e.clock }, Logger: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	return buf
}

// cursorSeqs are the checkpoint and entry seqs the sink's cursor holds for a chain.
func (e *sinkEnv) cursorSeqs(s *ent.AuditSink, chain string) (cp, entry int64) {
	e.t.Helper()
	c, err := e.db.Client().AuditSinkCursor.Query().Where(auditsinkcursor.SinkID(s.ID), auditsinkcursor.Chain(chain)).Only(e.sys)
	if ent.IsNotFound(err) {
		return 0, 0
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return c.CheckpointSeq, c.EntrySeq
}

func putKeys(srv *objstoretest.Server) []string {
	var out []string
	for _, r := range srv.Requests() {
		if k, ok := strings.CutPrefix(r, "PUT "); ok {
			out = append(out, k)
		}
	}
	return out
}

// TestAuditSink_S3ShipsAndResumes (#656): an object-storage sink writes every chain's checkpoints
// and entries as objects in seq order; a store that answers 500 fails the batch without moving the
// cursor and is tried again on the sinks' schedule; once it is well the sink ships what is missing,
// the backlog ends at 0, and no text of the sink's status or of the log holds the secret key or the
// store's address.
func TestAuditSink_S3ShipsAndResumes(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newSinkEnv(t, db)
		logs := e.logTo()
		org := storetest.Org(t, db, "org-a")
		srv := objstoretest.New(t)
		s := e.s3Sink("vault", srv, true)
		for range 3 {
			en := e.appendTo(org)
			e.checkpoint(org, en)
		}
		en := e.appendTo("")
		e.checkpoint("", en)

		down := true
		srv.Fault = func(method, _ string) (int, time.Duration) {
			if down && method == http.MethodPut {
				return http.StatusInternalServerError, 0
			}
			return 0, 0
		}
		e.mustRun()
		st := e.status(s)
		if !strings.Contains(st.LastError, "500") || st.LastSuccessAt != nil || len(srv.Keys()) != 0 {
			t.Fatalf("after a 500: error %q, last success %v, %d objects", st.LastError, st.LastSuccessAt, len(srv.Keys()))
		}
		if cp, entry := e.cursorSeqs(s, org); cp != 0 || entry != 0 {
			t.Fatalf("the cursor moved to %d/%d although nothing was acknowledged", cp, entry)
		}
		if b := e.backlog("vault"); b.Items != 3+3+1+1 {
			t.Fatalf("backlog %+v", b)
		}
		// Not tried again before its backoff has passed, and again after it.
		puts := srv.Count("PUT")
		e.mustRun()
		if srv.Count("PUT") != puts {
			t.Fatal("a failing sink was tried before its backoff passed")
		}
		e.clock = e.clock.Add(auditsink.BackoffMin)
		e.mustRun()
		if srv.Count("PUT") == puts {
			t.Fatal("a failing sink was not tried again after its backoff")
		}

		// A failure in the middle of a batch keeps what was acknowledged: the third PUT fails.
		var mu sync.Mutex
		n := 0
		srv.Fault = func(method, _ string) (int, time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			if method == http.MethodPut {
				if n++; n == 3 {
					return http.StatusServiceUnavailable, 0
				}
			}
			return 0, 0
		}
		down = false
		e.clock = e.clock.Add(auditsink.BackoffMax)
		e.mustRun()
		if len(srv.Keys()) == 0 || len(srv.Keys()) >= 8 {
			t.Fatalf("%d objects after a failure in the middle of a batch", len(srv.Keys()))
		}
		if b := e.backlog("vault"); b.Items == 0 || b.Items >= 8 {
			t.Fatalf("backlog %+v after a partial batch", b)
		}

		srv.Fault = nil
		e.clock = e.clock.Add(auditsink.BackoffMax)
		e.mustRun()
		want := []string{
			"audit/" + org + "/checkpoints/00000000000000000001",
			"audit/" + org + "/checkpoints/00000000000000000002",
			"audit/" + org + "/checkpoints/00000000000000000003",
			"audit/" + org + "/entries/00000000000000000001",
			"audit/" + org + "/entries/00000000000000000002",
			"audit/" + org + "/entries/00000000000000000003",
			"audit/instance/checkpoints/00000000000000000001",
			"audit/instance/entries/00000000000000000001",
		}
		slices.Sort(want)
		if got := srv.Keys(); !slices.Equal(got, want) {
			t.Fatalf("objects %v, want %v", got, want)
		}
		if b := e.backlog("vault"); b.Items != 0 || !b.Oldest.IsZero() {
			t.Fatalf("backlog %+v after catching up", b)
		}
		if st := e.status(s); st.LastError != "" || st.LastSuccessAt == nil {
			t.Fatalf("status after catching up: error %q, last success %v", st.LastError, st.LastSuccessAt)
		}

		// Entries of a chain were written in seq order, however many passes it took.
		var seqs []string
		for _, k := range putKeys(srv) {
			if strings.HasPrefix(k, "audit/"+org+"/entries/") {
				seqs = append(seqs, k)
			}
		}
		firsts := map[string]bool{}
		var distinct []string
		for _, k := range seqs {
			if !firsts[k] {
				firsts[k] = true
				distinct = append(distinct, k)
			}
		}
		if !slices.IsSorted(distinct) {
			t.Errorf("entries were first written out of order: %v", distinct)
		}

		for _, text := range []string{logs.String(), e.status(s).LastError} {
			if strings.Contains(text, awsSecretKey) || strings.Contains(text, strings.TrimPrefix(srv.URL, "http://")) {
				t.Fatalf("the secret key or the store's address is in %q", text)
			}
		}
		if !strings.Contains(logs.String(), "audit sink failing") {
			t.Error("a failing sink was not logged")
		}
	})
}

// TestAuditSink_S3RefusalAndResend (#656): a 4xx of the store is a permanent refusal that waits at
// the slowest pace; an object that holds other bytes than the item stops its chain, is never
// overwritten and is named; a cursor that was lost, as by a crash before it moved, makes the sink
// resend, which finds the same bytes and is done, so the store holds each item once.
func TestAuditSink_S3RefusalAndResend(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newSinkEnv(t, db)
		srv := objstoretest.New(t)
		s := e.s3Sink("vault", srv, false)
		en := e.appendTo("")
		e.checkpoint("", en)

		refuse := true
		srv.Fault = func(method, _ string) (int, time.Duration) {
			if refuse && method == http.MethodPut {
				return http.StatusForbidden, 0
			}
			return 0, 0
		}
		e.mustRun()
		if st := e.status(s); !strings.Contains(st.LastError, "403") || !strings.Contains(st.LastError, "ships nothing more of that chain") {
			t.Fatalf("after a 403: %q", st.LastError)
		}
		puts := srv.Count("PUT")
		e.clock = e.clock.Add(auditsink.BackoffMin)
		e.mustRun()
		if srv.Count("PUT") != puts {
			t.Fatal("a permanent refusal was retried at the shortest pace")
		}
		refuse = false
		e.clock = e.clock.Add(auditsink.BackoffMax)
		e.mustRun()
		key := "audit/instance/checkpoints/00000000000000000001"
		body, ok := srv.Get(key)
		if !ok || e.status(s).LastError != "" || e.backlog("vault").Items != 0 {
			t.Fatalf("after the store accepted: object %v, error %q", ok, e.status(s).LastError)
		}

		// The cursor is lost; the resend finds the same bytes.
		db.Client().AuditSinkCursor.Delete().ExecX(e.sys)
		gets := srv.Count("GET")
		e.clock = e.clock.Add(auditsink.Every)
		e.mustRun()
		if srv.Count("GET") == gets || len(srv.Keys()) != 1 || e.status(s).LastError != "" || e.backlog("vault").Items != 0 {
			t.Fatalf("a resend: %d GET, %d objects, error %q", srv.Count("GET")-gets, len(srv.Keys()), e.status(s).LastError)
		}
		if got, _ := srv.Get(key); !bytes.Equal(got, body) {
			t.Fatal("a resend changed the object")
		}

		// Someone wrote other bytes under the key; the chain waits and the object stays.
		srv.Tamper(key, []byte(`{"seq":99}`))
		db.Client().AuditSinkCursor.Delete().ExecX(e.sys)
		e.clock = e.clock.Add(auditsink.BackoffMax)
		e.mustRun()
		st := e.status(s)
		if !strings.Contains(st.LastError, key) || !strings.Contains(st.LastError, "other bytes") || e.backlog("vault").Items == 0 {
			t.Fatalf("other bytes under the key: %q", st.LastError)
		}
		if got, _ := srv.Get(key); string(got) != `{"seq":99}` {
			t.Fatalf("the object was overwritten with %q", got)
		}
	})
}

// TestAuditSink_S3UnusableSink (#656): a sink without a secret key, or one whose key cannot be
// unsealed, fails with a text that says so, and does not stop the other sinks.
func TestAuditSink_S3UnusableSink(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newSinkEnv(t, db)
		srv := objstoretest.New(t)
		good := e.s3Sink("good", srv, false)
		set := auditsink.S3Settings{Endpoint: srv.URL, Region: objstoretest.Region, Bucket: objstoretest.Bucket, AccessKeyID: objstoretest.AccessKeyID}.Map()
		none := db.Client().AuditSink.Create().SetKind("s3").SetName("a-nokey").SetSettings(set).SaveX(e.sys)
		wrong := db.Client().AuditSink.Create().SetKind("s3").SetName("b-wrongkey").SetSettings(set).SetSecretEnc([]byte("not sealed")).SaveX(e.sys)
		badSet := db.Client().AuditSink.Create().SetKind("s3").SetName("c-badsettings").SetSettings(map[string]string{"endpoint": "ftp://x"}).
			SetSecretEnc(*e.s3Sink("tmp", srv, false).SecretEnc).SaveX(e.sys)
		en := e.appendTo("")
		e.checkpoint("", en)
		e.mustRun()
		for _, c := range []struct {
			s    *ent.AuditSink
			want string
		}{{none, "no secret key"}, {wrong, "cannot be opened"}, {badSet, "cannot be opened"}} {
			if st := e.status(c.s); !strings.Contains(st.LastError, c.want) {
				t.Errorf("%s: %q, want %q", c.s.Name, st.LastError, c.want)
			}
		}
		if len(srv.Keys()) != 1 || e.status(good).LastError != "" {
			t.Fatalf("the good sink: %d objects, error %q", len(srv.Keys()), e.status(good).LastError)
		}
	})
}
