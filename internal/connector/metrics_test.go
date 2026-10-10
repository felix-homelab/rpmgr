// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/policy"
)

// sample returns the value of the series of name with labels, a histogram's count; ok is false
// if there is none.
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

// TestMetrics (docs/10-operations.md, "Metrics"): a dial the local policy refuses is counted and
// not timed, an allowed one is timed; the data sessions report their round-trip time per gateway
// and transport, QUIC's own and h2's from Ping and Pong.
func TestMetrics(t *testing.T) {
	connector.SetPingInterval(t, 50*time.Millisecond)
	reg := prometheus.NewRegistry()
	metrics, err := connector.NewMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connector.NewMetrics(reg); err == nil {
		t.Fatal("the metrics registered twice")
	}

	svc := startService(t, echoService)
	e := newTargetsWith(policy.Defaults(), metrics)
	e.Set([]connector.Route{{ID: "rt_ip", Targets: []connector.Target{target("127.0.0.1", svc.port())}}})
	if code, _ := e.handle(t, tcpOpen("rt_ip")); code != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED {
		t.Fatalf("a blocked target: %s", code)
	}
	route := map[string]string{"route": "rt_ip"}
	if v, _ := sample(t, reg, "rpmgr_connector_policy_denied_total", route); v != 1 {
		t.Fatalf("refused dials: %v", v)
	}
	if _, ok := sample(t, reg, "rpmgr_connector_target_dial_seconds", route); ok {
		t.Fatal("a refused dial was timed")
	}
	e.cur.Store(allowLoopback(t, svc.port()))
	e.Recheck()
	if code, _ := e.handle(t, tcpOpen("rt_ip")); code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatalf("an allowed target: %s", code)
	}
	if v, _ := sample(t, reg, "rpmgr_connector_target_dial_seconds", route); v != 1 {
		t.Fatalf("timed dials: %v", v)
	}

	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	m := newConnectorOptions(t, w, func(o *connector.Options) { o.Metrics = metrics })
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true})
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_2", Ready: true})
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr},
		Routes: map[string]string{"rt_1": connector.TransportQUIC, "rt_2": connector.TransportH2}}})
	for _, tr := range []string{"quic", "h2"} {
		eventually(t, "no round-trip time over "+tr, func() bool {
			v, _ := sample(t, reg, "rpmgr_connector_session_rtt_seconds", map[string]string{"gateway": id.ID, "transport": tr})
			return v > 0 && v < 1
		})
	}
}
