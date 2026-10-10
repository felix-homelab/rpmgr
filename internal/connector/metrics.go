// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics are the connector's metrics (docs/10-operations.md, "Metrics"): the round-trip time of
// its data sessions, and per route its target dial times and the dials the local policy refused.
// A nil *Metrics records nothing.
type Metrics struct {
	dials    *prometheus.HistogramVec
	denied   *prometheus.CounterVec
	sessions atomic.Pointer[Sessions]
}

// NewMetrics registers the connector's metrics with reg.
func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	m := &Metrics{
		dials: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "rpmgr_connector_target_dial_seconds",
			Help: "Upstream dial time.", Buckets: prometheus.DefBuckets}, []string{"route"}),
		denied: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_connector_policy_denied_total",
			Help: "Dials refused by the connector-local policy."}, []string{"route"}),
	}
	var errs []error
	for _, c := range []prometheus.Collector{m.dials, m.denied, rttCollector{m}} {
		errs = append(errs, reg.Register(c))
	}
	return m, errors.Join(errs...)
}

var rttDesc = prometheus.NewDesc("rpmgr_connector_session_rtt_seconds", "Smoothed round-trip time of the data sessions, the lowest per gateway and transport.",
	[]string{"gateway", "transport"}, nil)

// rttCollector reports the sessions' round-trip times at each scrape.
type rttCollector struct{ m *Metrics }

func (c rttCollector) Describe(ch chan<- *prometheus.Desc) { ch <- rttDesc }

func (c rttCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.m.sessions.Load()
	if s == nil {
		return
	}
	for k, rtt := range s.RTTs() {
		ch <- prometheus.MustNewConstMetric(rttDesc, prometheus.GaugeValue, rtt.Seconds(), k.Gateway, k.Transport)
	}
}

func (m *Metrics) watch(s *Sessions) {
	if m != nil {
		m.sessions.Store(s)
	}
}

// dial dials addr for route with d, timing the dials the policy did not refuse.
func (m *Metrics) dial(ctx context.Context, d *net.Dialer, route, network, addr string, blocked func(error) bool) (net.Conn, error) {
	start := time.Now()
	conn, err := d.DialContext(ctx, network, addr)
	if m != nil && !blocked(err) {
		m.dials.WithLabelValues(route).Observe(time.Since(start).Seconds())
	}
	return conn, err
}

func (m *Metrics) refused(route string) {
	if m != nil {
		m.denied.WithLabelValues(route).Inc()
	}
}
