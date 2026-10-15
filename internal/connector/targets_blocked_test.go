// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"strconv"
	"strings"
	"testing"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/connector"
)

// notReady returns the routes Status reports not ready, by ID, with their detail.
func notReady(e *targetsEnv) map[string]string {
	out := map[string]string{}
	for _, s := range e.Status() {
		out[s.GetResourceId()] = s.GetDetail()
	}
	return out
}

// TestTargets_OneBlockedTargetKeepsRoute (#551): a dial the policy refuses blocks that target only;
// the route stays ready while another of its targets is allowed, for an address and for a name
// refused on its resolved address, over TCP and UDP. A route whose every target is refused is not
// ready, and a later dial of the name that the policy allows makes it ready again.
func TestTargets_OneBlockedTargetKeepsRoute(t *testing.T) {
	svc, blk := startService(t, echoService), startService(t, echoService)
	udpSvc := startUDPService(t)
	e := newTargets(allowLoopback(t, svc.port(), udpSvc.port()))
	at := func(host string, port uint16, priority uint32) connector.Target {
		tg := target(host, port)
		tg.Priority = priority
		return tg
	}
	e.Set([]connector.Route{
		// The refused target comes first, by priority, on every stream.
		{ID: "rt_addr", Targets: []connector.Target{at("127.0.0.1", blk.port(), 0), at("127.0.0.1", svc.port(), 5)}},
		{ID: "rt_name", Targets: []connector.Target{at("localhost", blk.port(), 0), at("127.0.0.1", svc.port(), 5)}},
		{ID: "rt_udp", UDP: true, Targets: []connector.Target{at("localhost", blk.port(), 0), at("127.0.0.1", udpSvc.port(), 5)}},
		{ID: "rt_only", Targets: []connector.Target{at("localhost", blk.port(), 0)}},
	})
	if nr := notReady(e); len(nr) != 0 {
		t.Fatalf("not ready after the snapshot: %v", nr)
	}
	for range 3 {
		for _, route := range []string{"rt_addr", "rt_name"} {
			if code, _ := e.handle(t, tcpOpen(route)); code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
				t.Fatalf("%s: %s", route, code)
			}
		}
		if code, _ := e.handle(t, udpOpen("rt_udp")); code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatalf("rt_udp: %s", code)
		}
	}
	if nr := notReady(e); len(nr) != 0 {
		t.Fatalf("a refused target took its route off: %v", nr)
	}
	if n := blk.conns.Load(); n != 0 {
		t.Fatalf("the refused target got %d connections", n)
	}

	// Every target refused: the route is not ready, with the refusal's detail.
	if code, _ := e.handle(t, tcpOpen("rt_only")); code != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED {
		t.Fatalf("rt_only: %s", code)
	}
	detail, ok := notReady(e)["rt_only"]
	if !ok || !strings.Contains(detail, ":"+strconv.Itoa(int(blk.port()))) {
		t.Fatalf("rt_only after its only target was refused: %v", notReady(e))
	}
	if nr := notReady(e); len(nr) != 1 {
		t.Fatalf("other routes went not ready: %v", nr)
	}

	// The name now dials to an allowed address (here: the policy allows it, without a reload).
	e.cur.Store(allowLoopback(t, svc.port(), udpSvc.port(), blk.port()))
	if code, _ := e.handle(t, tcpOpen("rt_only")); code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatalf("rt_only once allowed: %s", code)
	}
	if nr := notReady(e); len(nr) != 0 {
		t.Fatalf("a name dialled again did not make its route ready: %v", nr)
	}
}

// TestTargets_RefusalBeforeRecheck: a refusal of a dial begun before a Recheck, whose policy or
// snapshot judges the target anew, is not recorded; one of a later dial is.
func TestTargets_RefusalBeforeRecheck(t *testing.T) {
	svc := startService(t, echoService)
	e := newTargets(allowLoopback(t, svc.port()))
	e.Set([]connector.Route{{ID: "rt_name", Targets: []connector.Target{target("localhost", svc.port())}}})
	gen := e.Generation()
	e.Recheck()
	e.Blocked("rt_name", target("localhost", svc.port()).ID, "localhost:1 refused", gen)
	if nr := notReady(e); len(nr) != 0 {
		t.Fatalf("a refusal from before the Recheck counted: %v", nr)
	}
	e.Blocked("rt_name", target("localhost", svc.port()).ID, "localhost:1 refused", e.Generation())
	if nr := notReady(e); nr["rt_name"] != "localhost:1 refused" {
		t.Fatalf("a current refusal: %v", nr)
	}
}
