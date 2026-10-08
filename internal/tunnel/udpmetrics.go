// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// UDPMetrics are the UDP counters of docs/10-operations.md, "Metrics", which gateways and
// connectors both keep.
type UDPMetrics struct {
	Oversize *prometheus.CounterVec // route
	Dropped  *prometheus.CounterVec // route, reason
}

// NewUDPMetrics registers the UDP counters in reg; a nil reg keeps them unregistered.
func NewUDPMetrics(reg prometheus.Registerer) (*UDPMetrics, error) {
	m := &UDPMetrics{
		Oversize: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_udp_oversize_total",
			Help: "UDP payloads too large for a datagram, sent on the flow stream."}, []string{"route"}),
		Dropped: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_udp_datagrams_dropped_total",
			Help: "UDP payloads dropped."}, []string{"route", "reason"}),
	}
	if reg != nil {
		if err := errors.Join(reg.Register(m.Oversize), reg.Register(m.Dropped)); err != nil {
			return nil, err
		}
	}
	return m, nil
}
