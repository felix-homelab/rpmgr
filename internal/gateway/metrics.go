// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
)

// Metrics are the gateway's metrics (docs/10-operations.md, "Metrics"): its data sessions, and per
// route its open streams, connections, bytes, connection setup times and HTTP requests. A nil
// *Metrics records nothing.
type Metrics struct {
	streams  *prometheus.GaugeVec
	conns    *prometheus.CounterVec
	bytes    *prometheus.CounterVec
	setup    *prometheus.HistogramVec
	requests *prometheus.CounterVec
	count    atomic.Pointer[func() map[string]int] // the sessions per transport
	routes   sync.Map                              // route IDs with series
}

// NewMetrics registers the gateway's metrics with reg.
func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	m := &Metrics{
		streams: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "rpmgr_gateway_streams_open", Help: "Open user streams."},
			[]string{"route", "transport"}),
		conns: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_route_connections_total",
			Help: "User connections by StreamResult code, or no_session, draining, timeout or error without one."}, []string{"route", "result"}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_route_bytes_total",
			Help: "Bytes; direction in is public to service, out the reverse."}, []string{"route", "direction"}),
		setup: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "rpmgr_route_connection_setup_seconds",
			Help: "From asking for a stream to its StreamResult.", Buckets: prometheus.DefBuckets}, []string{"route"}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_http_requests_total", Help: "Requests of http routes by status."},
			[]string{"route", "code"}),
	}
	var errs []error
	for _, c := range []prometheus.Collector{m.streams, m.conns, m.bytes, m.setup, m.requests, sessionsCollector{m}} {
		errs = append(errs, reg.Register(c))
	}
	return m, errors.Join(errs...)
}

var sessionsDesc = prometheus.NewDesc("rpmgr_gateway_sessions", "Data sessions from connectors, by transport.", []string{"transport"}, nil)

// sessionsCollector reports the sessions per transport at each scrape, quic and h2 even at 0.
type sessionsCollector struct{ m *Metrics }

func (c sessionsCollector) Describe(ch chan<- *prometheus.Desc) { ch <- sessionsDesc }

func (c sessionsCollector) Collect(ch chan<- prometheus.Metric) {
	counts := map[string]int{"quic": 0, "h2": 0}
	if f := c.m.count.Load(); f != nil {
		for t, n := range (*f)() {
			counts[t] = n
		}
	}
	for t, n := range counts {
		ch <- prometheus.MustNewConstMetric(sessionsDesc, prometheus.GaugeValue, float64(n), t)
	}
}

// watch makes the sessions gauge report s.
func (m *Metrics) watch(s *Sessions) {
	if m != nil {
		f := s.Count
		m.count.Store(&f)
	}
}

// opened records a stream asked for at start and its outcome.
func (m *Metrics) opened(route string, start time.Time, res *tunnelv1.StreamResult, err error) {
	if m == nil {
		return
	}
	m.routes.Store(route, true)
	result := "error"
	switch {
	case err == nil && res != nil:
		result = strings.ToLower(strings.TrimPrefix(res.GetCode().String(), "RESULT_CODE_"))
		m.setup.WithLabelValues(route).Observe(time.Since(start).Seconds())
	case err == nil, errors.Is(err, ErrNoSession):
		result = "no_session"
	case errors.Is(err, ErrDraining):
		result = "draining"
	case errors.Is(err, ErrResultTimeout):
		result = "timeout"
	}
	m.conns.WithLabelValues(route, result).Inc()
}

// stream returns the counters of a stream of route on transport and counts it open.
func (m *Metrics) stream(route, transport string) (open prometheus.Gauge, in, out prometheus.Counter) {
	if m == nil {
		return nil, nil, nil
	}
	m.routes.Store(route, true)
	open = m.streams.WithLabelValues(route, transport)
	open.Inc()
	return open, m.bytes.WithLabelValues(route, "in"), m.bytes.WithLabelValues(route, "out")
}

// request counts an HTTP request of route answered with code.
func (m *Metrics) request(route string, code int) {
	if m != nil {
		m.routes.Store(route, true)
		m.requests.WithLabelValues(route, strconv.Itoa(code)).Inc()
	}
}

// Counters returns each route's cumulative counters for the controller's traffic rollups
// (docs/03-connections.md, "Configuration reconciliation"): bytes both ways, connections and
// those that failed, and the open ones, by route ID.
func (m *Metrics) Counters() []*agentv1.RouteCounters {
	if m == nil {
		return nil
	}
	by := map[string]*agentv1.RouteCounters{}
	of := func(labels map[string]string) *agentv1.RouteCounters {
		id := labels["route"]
		if by[id] == nil {
			by[id] = &agentv1.RouteCounters{RouteId: id}
		}
		return by[id]
	}
	collect(m.bytes, func(l map[string]string, v float64) {
		if c := of(l); l["direction"] == "in" {
			c.BytesIn += uint64(v)
		} else {
			c.BytesOut += uint64(v)
		}
	})
	collect(m.conns, func(l map[string]string, v float64) {
		c := of(l)
		c.ConnectionsTotal += uint64(v)
		if l["result"] != "no_error" {
			c.ErrorsTotal += uint64(v)
		}
	})
	collect(m.streams, func(l map[string]string, v float64) { of(l).ConnectionsActive += uint64(max(v, 0)) })
	out := make([]*agentv1.RouteCounters, 0, len(by))
	for _, c := range by {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b *agentv1.RouteCounters) int { return strings.Compare(a.GetRouteId(), b.GetRouteId()) })
	return out
}

// collect calls f with the labels and value of each series of a counter or gauge vector.
func collect(c prometheus.Collector, f func(labels map[string]string, v float64)) {
	ch := make(chan prometheus.Metric, 64)
	go func() { c.Collect(ch); close(ch) }()
	for metric := range ch {
		var d dto.Metric
		if metric.Write(&d) != nil {
			continue
		}
		labels := map[string]string{}
		for _, l := range d.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		f(labels, d.GetCounter().GetValue()+d.GetGauge().GetValue())
	}
}

// retain drops the series of routes not in keep, so that a removed route leaves no series behind.
func (m *Metrics) retain(keep map[string]bool) {
	if m == nil {
		return
	}
	m.routes.Range(func(k, _ any) bool {
		if id := k.(string); !keep[id] {
			m.routes.Delete(id)
			for _, v := range []interface {
				DeletePartialMatch(prometheus.Labels) int
			}{m.streams, m.conns, m.bytes, m.setup, m.requests} {
				v.DeletePartialMatch(prometheus.Labels{"route": id})
			}
		}
		return true
	})
}

// statusWriter notes the status code of a response.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

// Unwrap gives http.ResponseController the writer underneath, for flushes and upgrades.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
