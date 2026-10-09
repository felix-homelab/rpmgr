// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// sample returns the value of the series of name with labels: a gauge's or counter's value, a
// histogram's count; ok is false if there is none.
func sample(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	metric:
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if want, ok := labels[l.GetName()]; ok && want != l.GetValue() {
					continue metric
				}
			}
			switch mf.GetType() {
			case dto.MetricType_GAUGE:
				return m.GetGauge().GetValue(), true
			case dto.MetricType_HISTOGRAM:
				return float64(m.GetHistogram().GetSampleCount()), true
			default:
				return m.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}

// TestMetrics (docs/10-operations.md, "Metrics"): the gateway reports its sessions per transport,
// and per route its open streams, connections by result, bytes both ways, setup times and HTTP
// requests by status; a route the snapshot drops leaves no series.
func TestMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics, err := gateway.NewMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.NewMetrics(reg); err == nil {
		t.Fatal("the metrics registered twice")
	}
	value := func(name string, labels map[string]string) float64 {
		t.Helper()
		v, _ := sample(t, reg, name, labels)
		return v
	}
	p := planeWith(t, service(t, echoService), "v1", metrics, "rt_1")
	if v, ok := sample(t, reg, "rpmgr_gateway_sessions", map[string]string{"transport": "h2"}); !ok || v != 0 {
		t.Fatalf("h2 sessions before any: %v %v", v, ok)
	}
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port}})
	eventually(t, "no QUIC session", func() bool { return value("rpmgr_gateway_sessions", map[string]string{"transport": "quic"}) == 1 })
	c := dialPort(t, port)
	if err := ping(c, "hello"); err != nil {
		t.Fatal(err)
	}
	route := map[string]string{"route": "rt_1"}
	if v := value("rpmgr_gateway_streams_open", map[string]string{"route": "rt_1", "transport": "quic"}); v != 1 {
		t.Fatalf("open streams: %v", v)
	}
	if v := value("rpmgr_route_connections_total", map[string]string{"route": "rt_1", "result": "no_error"}); v != 1 {
		t.Fatalf("connections: %v", v)
	}
	if v := value("rpmgr_route_connection_setup_seconds", route); v != 1 {
		t.Fatalf("setup observations: %v", v)
	}
	for _, dir := range []string{"in", "out"} {
		if v := value("rpmgr_route_bytes_total", map[string]string{"route": "rt_1", "direction": dir}); v < 5 {
			t.Fatalf("bytes %s: %v", dir, v)
		}
	}
	_ = c.Close()
	eventually(t, "the stream stayed open", func() bool {
		return value("rpmgr_gateway_streams_open", map[string]string{"route": "rt_1", "transport": "quic"}) == 0
	})
	if _, _, err := p.sessions.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "rt_x"}); !errors.Is(err, gateway.ErrNoSession) {
		t.Fatalf("a route no session serves: %v", err)
	}
	if v := value("rpmgr_route_connections_total", map[string]string{"route": "rt_x", "result": "no_session"}); v != 1 {
		t.Fatalf("connections without a session: %v", v)
	}

	// HTTP requests by status.
	up := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), ReadHeaderTimeout: 5 * time.Second}
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = up.Serve(upLn) }()
	t.Cleanup(func() { _ = up.Close() })
	hp := planeWith(t, upLn.Addr().String(), "none", metrics, "rt_web")
	e := newHTTPEnvOn(t, hp.sessions, gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}})
	if r := get(t, e.client(false), "https://app.example.com/", nil); r.status != http.StatusOK {
		t.Fatalf("a request: %d", r.status)
	}
	if r := get(t, e.client(false), "https://app.example.com/", http.Header{"Upgrade": {"websocket"}}); r.status != http.StatusForbidden {
		t.Fatalf("an upgrade the route refuses: %d", r.status)
	}
	if v := value("rpmgr_http_requests_total", map[string]string{"route": "rt_web", "code": "200"}); v != 1 {
		t.Fatalf("requests answered 200: %v", v)
	}
	if v := value("rpmgr_http_requests_total", map[string]string{"route": "rt_web", "code": "403"}); v != 1 {
		t.Fatalf("requests answered 403: %v", v)
	}

	// A snapshot without rt_1 drops its series; rt_web stays.
	a, _ := gateway.NewApplier()
	a.Bind(gateway.Served{Sessions: hp.sessions})
	a.Apply(t.Context(), gatewaySnapshot(1, httpResource("rt_web", "http", "app.example.com")), agent.Changes{})
	if _, ok := sample(t, reg, "rpmgr_route_connections_total", route); ok {
		t.Fatal("a removed route's series stayed")
	}
	if _, ok := sample(t, reg, "rpmgr_http_requests_total", map[string]string{"route": "rt_web"}); !ok {
		t.Fatal("a kept route's series went")
	}
}
