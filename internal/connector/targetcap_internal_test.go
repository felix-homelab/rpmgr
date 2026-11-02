// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
)

// TestTargetConns_BoundAndRelease: a slot is taken until the bound, refused over it, given back
// once by release or by the connection's end however often that is called, and counted per address.
func TestTargetConns_BoundAndRelease(t *testing.T) {
	c := newTargetConns()
	var admitted []bool
	for range 3 {
		admitted = append(admitted, c.acquire("a:1", 2))
	}
	if !slices.Equal(admitted, []bool{true, true, false}) {
		t.Fatalf("a bound of 2 admitted %v, want exactly the first two", admitted)
	}
	if !c.acquire("b:1", 2) {
		t.Error("another address shares the bound")
	}
	if c.acquire("a:1", 0) {
		t.Error("a bound of 0 admitted")
	}
	c.release("a:1")
	if c.held("a:1") != 1 || !c.acquire("a:1", 2) {
		t.Errorf("a released slot was not free again, held %d", c.held("a:1"))
	}
	server, client := net.Pipe()
	defer func() { _ = server.Close(); _ = client.Close() }()
	c.bind(server, "a:1")
	c.releaseConn(server)
	c.releaseConn(server) // a second call gives nothing back
	c.releaseConn(client) // a connection without a slot gives nothing back
	if c.held("a:1") != 1 {
		t.Errorf("held %d after the connection's slot was given back twice, want 1", c.held("a:1"))
	}
	c.release("a:1")
	c.release("a:1") // more releases than slots never go below zero
	if c.held("a:1") != 0 || c.acquire("a:1", 1) != true {
		t.Errorf("held %d after the last release", c.held("a:1"))
	}
}

func TestRoute_MaxTargetConns(t *testing.T) {
	if got := (Route{}).maxTargetConns(); got != defaultTargetConns {
		t.Errorf("the default bound is %d, want %d", got, defaultTargetConns)
	}
	if got := (Route{MaxTargetConns: 5}).maxTargetConns(); got != 5 {
		t.Errorf("a route's bound of 5 became %d", got)
	}
}

// TestConnFailure: what a target over its limit gives a peer decides nothing about its health;
// anything else does.
func TestConnFailure(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{syscall.ECONNREFUSED, true},
		{fmt.Errorf("read: %w", syscall.ECONNRESET), true},
		{&net.OpError{Op: "write", Err: syscall.EPIPE}, true},
		{io.EOF, true},
		{fmt.Errorf("read: %w", io.ErrUnexpectedEOF), true},
		{context.DeadlineExceeded, true}, // a check that ran out of time
		{&net.DNSError{IsTimeout: true}, true},
		{errTargetAtBound, true},
		{errors.New("the check's answer is 503, not 200 to 399"), false},
		{errors.New("tls: failed to verify certificate"), false},
		{nil, false},
	} {
		if got := connFailure(tc.err); got != tc.want {
			t.Errorf("connFailure(%v) = %t, want %t", tc.err, got, tc.want)
		}
	}
}

// TestCheck_AtBoundIsNotRun: a check that finds every slot of its target taken dials nothing and
// reports a result that decides nothing; a bound above the streams held lets it run.
func TestCheck_AtBoundIsNotRun(t *testing.T) {
	var dials atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			dials.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	tg := targetOf(t, srv.URL)
	targets := checking(t, loopbackPolicy(t, int(tg.Port)))
	r := Route{ID: "rt_1", MaxTargetConns: 2, Check: &HealthCheck{HTTP: true, Path: "/", StatusMin: 200, StatusMax: 399, Timeout: 2 * time.Second}}
	addr := tg.String()
	targets.conns.acquire(addr, 2)
	targets.conns.acquire(addr, 2)
	err := targets.check(context.Background(), r, tg)
	var held *checkHeld
	if !errors.As(err, &held) || !held.undecided || held.held != 2 || !errors.Is(err, errTargetAtBound) || dials.Load() != 0 {
		t.Fatalf("a check with every slot taken: %v (dials %d), want undecided with 2 held, undialled", err, dials.Load())
	}
	targets.conns.release(addr)
	if err := targets.check(context.Background(), r, tg); err != nil {
		t.Errorf("a check with a slot free: %v", err)
	}
	if got := targets.conns.held(addr); got != 1 {
		t.Errorf("the check kept its slot: held %d, want the 1 stream", got)
	}
}

// TestCheck_FailureWhileStreamsHeld: a refused or reset check with a stream held is undecided; a
// 503 with one held counts and names them; with none held every failure is the plain error.
func TestCheck_FailureWhileStreamsHeld(t *testing.T) {
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	port := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()
	down := Target{ID: "tg_d", Host: "127.0.0.1", Port: uint16(port)} //nolint:gosec // G115: a test port
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	t.Cleanup(bad.Close)
	unavailable := targetOf(t, bad.URL)
	targets := checking(t, loopbackPolicy(t, port, int(unavailable.Port)))
	check := &HealthCheck{HTTP: true, Path: "/", StatusMin: 200, StatusMax: 399, Timeout: 2 * time.Second}
	r := Route{ID: "rt_1", Check: check}

	err := targets.check(context.Background(), r, down)
	var held *checkHeld
	if err == nil || errors.As(err, &held) {
		t.Fatalf("a refused check with no stream held: %v, want the plain error", err)
	}
	targets.conns.acquire(down.String(), 10)
	err = targets.check(context.Background(), r, down)
	if !errors.As(err, &held) || !held.undecided || held.held != 1 || !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("a refused check with a stream held: %v, want undecided", err)
	}
	if want := "the connector holds 1 connections to the target for streams"; len(held.note()) < len(want) || held.note()[:len(want)] != want {
		t.Errorf("the note %q", held.note())
	}

	targets.conns.acquire(unavailable.String(), 10)
	err = targets.check(context.Background(), r, unavailable)
	if !errors.As(err, &held) || held.undecided || held.held != 1 {
		t.Fatalf("a 503 with a stream held: %v, want a failure that counts, naming the stream", err)
	}
}

// TestTargetStatus_NamesHeldStreams: an unknown or unhealthy target's status carries the likely
// cause beside its failure; a healthy one carries nothing.
func TestTargetStatus_NamesHeldStreams(t *testing.T) {
	note := "the connector holds 5 connections to the target for streams"
	if st := targetStatus("tg_1", &targetHealth{unknown: true, note: note}); st.GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_TARGET_UNKNOWN || st.GetDetail() != note {
		t.Errorf("unknown: %v", st)
	}
	if st := targetStatus("tg_1", &targetHealth{unhealthy: true, err: "EOF", note: note}); st.GetDetail() != "EOF; "+note {
		t.Errorf("unhealthy: %v", st)
	}
	if st := targetStatus("tg_1", &targetHealth{unhealthy: true, err: "EOF"}); st.GetDetail() != "EOF" {
		t.Errorf("unhealthy without streams: %v", st)
	}
	if st := targetStatus("tg_1", &targetHealth{note: note}); st.GetDetail() != "" || st.GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_UNSPECIFIED {
		t.Errorf("healthy: %v", st)
	}
}
