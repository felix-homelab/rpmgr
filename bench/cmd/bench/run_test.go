// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRunFlags(t *testing.T) {
	o, err := parseRunFlags(nil)
	if err != nil || !slices.Equal(o.rtts, []float64{1, 80}) || !slices.Equal(o.losses, []float64{0, 1}) || o.reps != 3 ||
		len(o.workloads) != len(allWorkloads) || o.gso != "on" {
		t.Fatalf("defaults: %+v %v", o, err)
	}
	o, err = parseRunFlags([]string{"-rtts", "1, 20,80,200", "-losses", "0,0.5", "-workloads", "throughput,vb18", "-gso", "off"})
	if err != nil || !slices.Equal(o.rtts, []float64{1, 20, 80, 200}) || !o.workloads["vb18"] || o.workloads["idle"] || o.gso != "off" {
		t.Fatalf("%+v %v", o, err)
	}
	for _, bad := range [][]string{
		{"-rtts", "1,fast"}, {"-losses", "-1"}, {"-workloads", "throughput,sideways"}, {"-gso", "maybe"}, {"-reps", "0"},
		{"-idle", "0"}, {"-extra-duration", "1s"}, {"-duration", "0s"},
	} {
		if _, err := parseRunFlags(bad); !errors.Is(err, errUsage) {
			t.Errorf("%v: %v", bad, err)
		}
	}
}

func TestLinkOf(t *testing.T) {
	out := `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
52: eth0    inet 10.232.1.20/24 brd 10.232.1.255 scope global eth0\       valid_lft forever preferred_lft forever
54: eth1    inet 10.232.2.20/24 brd 10.232.2.255 scope global eth1\       valid_lft forever preferred_lft forever
`
	if got := linkOf(out, "10.232.2.20"); got != "eth1" {
		t.Errorf("got %q", got)
	}
	if got := linkOf(out, "10.232.2.2"); got != "" {
		t.Errorf("a prefix of an address matched: %q", got)
	}
}

func TestIdleNames(t *testing.T) {
	if idleName(1) != "idle" || idleName(2) != "idle-2" || idleName(20) != "idle-20" {
		t.Fatal("idle names")
	}
	if c := connectorConfig("/var/lib/rpmgr/c3", 7403); !strings.Contains(c, "127.0.0.1:7403") || !strings.Contains(c, "identity_dir: /var/lib/rpmgr/c3/identity") {
		t.Fatal(c)
	}
}

// TestRoutePorts: no two routes the workloads seed on the one gateway share a port, which the
// controller refuses ("the port is taken"): the fairness routes once took the idle routes' ports.
// The changes workload's ports stay above every fixed one, for any -routes.
func TestRoutePorts(t *testing.T) {
	o, err := parseRunFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	owner := map[int]string{}
	take := func(what string, port int) {
		if port < 1 || port > 65535 {
			t.Errorf("%s: port %d", what, port)
		}
		if other, ok := owner[port]; ok {
			t.Errorf("%s and %s both take port %d", what, other, port)
		}
		owner[port] = what
	}
	fixed := 0
	for tr, r := range routesOf {
		for i, p := range []int{r.sink, r.source, r.echo, r.udp, r.who, r.blockedSink} {
			take(fmt.Sprintf("%s route %d", tr, i), p)
		}
		for i, p := range fairPorts[tr] {
			take(fmt.Sprintf("%s fairness route %d", tr, i), p)
		}
		take(tr+" idle route", idlePorts[tr])
	}
	for p := range owner {
		fixed = max(fixed, p)
	}
	if len(idlePorts) != len(routesOf) || len(fairPorts) != len(routesOf) {
		t.Errorf("a transport without its idle or fairness routes: %v, %v", idlePorts, fairPorts)
	}
	for i := 1; i <= o.routes; i++ {
		take(fmt.Sprintf("change route %d", i), changePort(i))
	}
	if changePort(1) <= fixed {
		t.Errorf("the changes workload starts at %d, below the fixed port %d", changePort(1), fixed)
	}
}

// TestMetricsWait: -above waits for the metric to grow and reports when; it gives up after its
// timeout, and a listener that does not answer 200 is an error.
func TestMetricsWait(t *testing.T) {
	var rev atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprintf(w, "rpmgr_agent_applied_revision %d\n", rev.Load())
	}))
	t.Cleanup(srv.Close)
	go func() { time.Sleep(100 * time.Millisecond); rev.Store(42) }()
	start := time.Now()
	if err := cmdMetrics([]string{"-url", srv.URL + "/metrics", "-names", "rpmgr_agent_applied_revision", "-above", "41", "-timeout", "5s"}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Error("returned before the change")
	}
	if err := cmdMetrics([]string{"-url", srv.URL + "/metrics", "-names", "rpmgr_agent_applied_revision", "-above", "42", "-timeout", "100ms"}); err == nil {
		t.Error("no timeout")
	}
	if err := cmdMetrics([]string{"-url", srv.URL + "/nothing", "-names", "x"}); err == nil {
		t.Error("a 404 was read")
	}
	if err := cmdMetrics([]string{"-url", srv.URL}); !errors.Is(err, errUsage) {
		t.Error("no names accepted")
	}
}

func TestReady(t *testing.T) {
	var up atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(srv.Close)
	if err := cmdReady(context.Background(), []string{"-url", srv.URL, "-duration", "300ms"}); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("not ready: %v", err)
	}
	go func() { time.Sleep(200 * time.Millisecond); up.Store(true) }()
	if err := cmdReady(context.Background(), []string{"-url", srv.URL, "-duration", "5s"}); err != nil {
		t.Error(err)
	}
}
