// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
)

// The rate limits whose refusals rpmgr_ratelimit_refused_total counts.
const (
	LimitLogin         = "login"          // logins per address
	LimitAccount       = "account"        // the progressive delay per account, at login and step-up
	LimitPasswordReset = "password_reset" // reset requests per address
	LimitEnrollment    = "enrollment"     // enrollments per address
)

// Metrics are the controller's metrics that read the database at each scrape, and the rate
// limits' refusals (docs/10-operations.md, "Metrics").
type Metrics struct {
	refused *prometheus.CounterVec
}

// NewMetrics registers the controller's metrics with reg: the ACME certificates' expiry, how long
// audit entries have waited for a checkpoint, and the rate limits' refusals, each limit at 0 from
// the start. sys is the system scope.
func NewMetrics(reg prometheus.Registerer, db *store.DB, sys context.Context, now func() time.Time) (*Metrics, error) {
	m := &Metrics{refused: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_ratelimit_refused_total",
		Help: "Requests a rate limit refused; they are not in the audit log."}, []string{"limit"})}
	for _, l := range []string{LimitLogin, LimitAccount, LimitPasswordReset, LimitEnrollment} {
		m.refused.WithLabelValues(l)
	}
	return m, errors.Join(reg.Register(m.refused), reg.Register(dbCollector{db: db, sys: sys, now: now}))
}

// Refused returns the function that counts a refusal of limit.
func (m *Metrics) Refused(limit string) func() {
	c := m.refused.WithLabelValues(limit)
	return c.Inc
}

var (
	acmeExpiryDesc = prometheus.NewDesc("rpmgr_acme_cert_expiry_timestamp_seconds", "When each hostname's ACME certificate expires.",
		[]string{"hostname"}, nil)
	checkpointAgeDesc = prometheus.NewDesc("rpmgr_audit_checkpoint_age_seconds",
		"Age of the oldest audit entry no checkpoint covers yet; 0 when every entry is covered.", nil, nil)
)

// dbCollector reads the certificates and the audit chains at each scrape.
type dbCollector struct {
	db  *store.DB
	sys context.Context
	now func() time.Time
}

func (c dbCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- acmeExpiryDesc
	ch <- checkpointAgeDesc
}

func (c dbCollector) Collect(ch chan<- prometheus.Metric) {
	certs, err := c.db.ReadClient().Certificate.Query().Where(certificate.SourceEQ(certificate.SourceAcme), certificate.NotAfterNotNil()).
		All(c.sys)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(acmeExpiryDesc, err)
	}
	expiry := map[string]time.Time{}
	for _, cert := range certs {
		for _, name := range cert.Sans {
			if at, ok := expiry[name]; !ok || cert.NotAfter.After(at) {
				expiry[name] = *cert.NotAfter
			}
		}
	}
	for name, at := range expiry {
		ch <- prometheus.MustNewConstMetric(acmeExpiryDesc, prometheus.GaugeValue, float64(at.Unix()), name)
	}
	oldest, pending, err := audit.Uncovered(c.sys, c.db)
	switch {
	case err != nil:
		ch <- prometheus.NewInvalidMetric(checkpointAgeDesc, err)
	case pending:
		ch <- prometheus.MustNewConstMetric(checkpointAgeDesc, prometheus.GaugeValue, max(0, c.now().Sub(oldest).Seconds()))
	default:
		ch <- prometheus.MustNewConstMetric(checkpointAgeDesc, prometheus.GaugeValue, 0)
	}
}
