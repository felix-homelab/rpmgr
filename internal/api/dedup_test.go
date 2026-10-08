// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestDedupe: a Create with a request_id runs once per caller and method within the window; a
// retry gets the first response, stored sealed; the same ID with another request is
// INVALID_ARGUMENT, and while the first has not answered ABORTED; of two requests at once, one
// runs; a request that failed may run again; without an ID or a caller, or past the window, it
// runs again; the pruning job forgets IDs past the window.
func TestDedupe(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	org := storetest.Org(t, db, "org-a")
	now := time.Now()
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	srv, err := api.New(api.Options{DB: db, Sys: sys, Sealer: testSealer(t), Now: func() time.Time { return time.Unix(0, clock.Load()) },
		Resolver:           func(context.Context, string) (string, error) { return "", api.ErrNotFound },
		OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil }})
	if err != nil {
		t.Fatal(err)
	}
	as := func(user string) context.Context {
		return api.WithCaller(storetest.OrgCtx(t, org), &api.Caller{Principal: authz.Principal{UserID: user}})
	}
	var runs atomic.Int64
	groups := func() int { return db.Client().GatewayGroup.Query().Where(gatewaygroup.OrgID(org)).CountX(sys) }
	// create writes a gateway group and answers with its run number; fail decides what then fails.
	create := func(fail string) func(context.Context) (*rpmgrv1.BasicAuthUser, error) {
		return func(ctx context.Context) (*rpmgrv1.BasicAuthUser, error) {
			n := runs.Add(1)
			if fail == "before" {
				return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
			}
			if _, err := store.ConfigTx(ctx, db, func(tx *ent.Tx) ([]string, error) {
				return []string{org}, tx.GatewayGroup.Create().SetOrgID(org).SetName("group-" + strconv.FormatInt(n, 10)).Exec(ctx)
			}); err != nil {
				return nil, err
			}
			if fail == "after" {
				return nil, connect.NewError(connect.CodeInternal, errors.New("the second step failed"))
			}
			return &rpmgrv1.BasicAuthUser{Name: "run", PasswordHash: strconv.FormatInt(n, 10)}, nil
		}
	}
	req := &rpmgrv1.BasicAuthUser{Name: "alice"}
	call := func(ctx context.Context, id string, req *rpmgrv1.BasicAuthUser, fail string) (*rpmgrv1.BasicAuthUser, error) {
		return api.Dedupe(ctx, srv, id, req, create(fail))
	}

	first, err := call(as("usr_a"), "r1", req, "")
	if err != nil || runs.Load() != 1 || groups() != 1 {
		t.Fatalf("first: %v %v, %d runs", first, err, runs.Load())
	}
	again, err := call(as("usr_a"), "r1", req, "")
	if err != nil || runs.Load() != 1 || groups() != 1 || again.GetPasswordHash() != first.GetPasswordHash() {
		t.Fatalf("a retry: %v %v, %d runs", again, err, runs.Load())
	}
	stored := db.Client().APIRequest.Query().OnlyX(sys)
	if stored.ResponseEnc == nil || bytes.Contains(*stored.ResponseEnc, []byte("run")) {
		t.Fatal("the response is not stored sealed")
	}
	if _, err := call(as("usr_a"), "r1", &rpmgrv1.BasicAuthUser{Name: "bob"}, ""); connect.CodeOf(err) != connect.CodeInvalidArgument || runs.Load() != 1 {
		t.Fatalf("the ID with another request: %v", err)
	}
	for name, run := range map[string]func() (any, error){
		"another caller": func() (any, error) { return call(as("usr_b"), "r1", req, "") },
		"another method": func() (any, error) {
			return api.Dedupe(as("usr_a"), srv, "r1", &rpmgrv1.IPRuleParams{}, create(""))
		},
		"no request_id": func() (any, error) { return call(as("usr_a"), "", req, "") },
		"no caller":     func() (any, error) { return call(storetest.OrgCtx(t, org), "r1", req, "") },
	} {
		before := runs.Load()
		if _, err := run(); err != nil || runs.Load() != before+1 {
			t.Errorf("%s: %v, ran %d times", name, err, runs.Load()-before)
		}
	}

	var before int64
	// A request that fails, before or after writing, may run again.
	for _, fail := range []string{"before", "after"} {
		id := "r-" + fail
		if _, err := call(as("usr_a"), id, req, fail); err == nil {
			t.Fatalf("%s: no error", fail)
		}
		before = runs.Load()
		if _, err := call(as("usr_a"), id, req, ""); err != nil || runs.Load() != before+1 {
			t.Errorf("a retry after a failure %s writing: %v", fail, err)
		}
	}

	// The first request has not answered yet.
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	hash := sha256.Sum256(b)
	db.Client().APIRequest.Create().SetCallerID("usr_a").SetMethod("rpmgr.v1.BasicAuthUser").SetRequestID("r-open").
		SetRequestHash(hash[:]).SetCreatedAt(now).ExecX(sys)
	before = runs.Load()
	if _, err := call(as("usr_a"), "r-open", req, ""); connect.CodeOf(err) != connect.CodeAborted || runs.Load() != before {
		t.Errorf("an ID whose first request has not answered: %v", err)
	}
	if _, err := call(as("usr_a"), "r-open", &rpmgrv1.BasicAuthUser{Name: "bob"}, ""); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("an open ID with another request: %v", err)
	}

	// Two requests at once: one runs, the other is told to retry.
	gate := make(chan struct{})
	slow := func(ctx context.Context) (*rpmgrv1.BasicAuthUser, error) {
		<-gate
		return create("")(ctx)
	}
	beforeGroups := groups()
	before = runs.Load()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Go(func() { _, errs[i] = api.Dedupe(as("usr_c"), srv, "r-race", req, slow) })
	}
	time.Sleep(100 * time.Millisecond)
	close(gate)
	wg.Wait()
	aborted := 0
	for _, err := range errs {
		if connect.CodeOf(err) == connect.CodeAborted {
			aborted++
		} else if err != nil {
			t.Errorf("a request at once: %v", err)
		}
	}
	if aborted != 1 || groups() != beforeGroups+1 || runs.Load() != before+2 {
		t.Errorf("two requests at once: %d aborted, %d groups made", aborted, groups()-beforeGroups)
	}

	// Past the window the ID is free again, and the job forgets it.
	clock.Store(now.Add(api.DedupWindow + time.Minute).UnixNano())
	before = runs.Load()
	if _, err := call(as("usr_a"), "r1", req, ""); err != nil || runs.Load() != before+1 {
		t.Errorf("past the window: %v", err)
	}
	if err := srv.PruneJob(time.Hour).Run(sys, lease.Lease{}); err != nil {
		t.Fatal(err)
	}
	left := db.Client().APIRequest.Query().AllX(sys)
	if len(left) != 1 || left[0].RequestID != "r1" || left[0].CallerID != "usr_a" {
		t.Errorf("after pruning: %d rows", len(left))
	}
}
