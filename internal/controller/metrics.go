// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/auditsink"
	"github.com/felix-homelab/rpmgr/internal/cfranges"
	"github.com/felix-homelab/rpmgr/internal/dns/budget"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsnamestatus"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
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
	ranges  *prometheus.CounterVec
	syncs   *prometheus.CounterVec
	calls   *prometheus.CounterVec
}

// NewMetrics registers the controller's metrics with reg: the ACME certificates' expiry, how long
// audit entries have waited for a checkpoint, and the rate limits' refusals, each limit at 0 from
// the start. sys is the system scope.
func NewMetrics(reg prometheus.Registerer, db *store.DB, sys context.Context, now func() time.Time) (*Metrics, error) {
	m := &Metrics{refused: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_ratelimit_refused_total",
		Help: "Requests a rate limit refused; they are not in the audit log."}, []string{"limit"})}
	m.ranges = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_dns_cloudflare_ranges_refresh_total",
		Help: "Refresh attempts of the Cloudflare IP ranges by this controller: ok, rejected, failed."}, []string{"result"})
	m.syncs = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_dns_sync_runs_total",
		Help: "DNS passes of each managed zone by this controller: ok, held, failed, rate_limited."}, []string{"zone", "result"})
	m.calls = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_dns_provider_requests_total",
		Help: "Requests this controller sent to DNS providers, by the HTTP status of the answer; error: no answer."}, []string{"provider", "code"})
	for _, r := range []string{RangesOK, RangesRejected, RangesFailed} {
		m.ranges.WithLabelValues(r)
	}
	for _, l := range []string{LimitLogin, LimitAccount, LimitPasswordReset, LimitEnrollment} {
		m.refused.WithLabelValues(l)
	}
	return m, errors.Join(reg.Register(m.refused), reg.Register(m.ranges), reg.Register(m.syncs), reg.Register(m.calls),
		reg.Register(dbCollector{db: db, sys: sys, now: now}))
}

// Refused returns the function that counts a refusal of limit.
func (m *Metrics) Refused(limit string) func() {
	c := m.refused.WithLabelValues(limit)
	return c.Inc
}

// RangesResult returns the function that counts the result of a Cloudflare range refresh.
func (m *Metrics) RangesResult() func(string) {
	return func(result string) { m.ranges.WithLabelValues(result).Inc() }
}

// SyncResult returns the function that counts how a pass of a zone ended (dnsjob.Options.Result).
func (m *Metrics) SyncResult() func(zone, result string) {
	return func(zone, result string) { m.syncs.WithLabelValues(zone, result).Inc() }
}

// ProviderRequest returns the function that counts a request to a DNS provider
// (budget.Budget.Observe).
func (m *Metrics) ProviderRequest() func(provider, code string) {
	return func(provider, code string) { m.calls.WithLabelValues(provider, code).Inc() }
}

var (
	dnsNamesDesc   = prometheus.NewDesc("rpmgr_dns_names", "Names of a managed zone by dns_status.", []string{"zone", "status"}, nil)
	dnsRecordsDesc = prometheus.NewDesc("rpmgr_dns_records", "Records rpmgr owns in a managed zone, by ledger state.", []string{"zone", "state"}, nil)
	dnsExpiryDesc  = prometheus.NewDesc("rpmgr_dns_provider_token_expiry_timestamp_seconds",
		"When the provider's token expires; absent for a token without an expiry.", []string{"provider"}, nil)
	dnsBudgetDesc = prometheus.NewDesc("rpmgr_dns_rate_budget_used",
		"Requests taken from the provider's shared budget in the current window, by the DNS job and DNS-01 together.", []string{"provider"}, nil)
	dnsBlockedDesc = prometheus.NewDesc("rpmgr_dns_rate_blocked_seconds",
		"Seconds left of the provider's retry-after block; 0 when there is none.", []string{"provider"}, nil)
	rangesAgeDesc = prometheus.NewDesc("rpmgr_dns_cloudflare_ranges_age_seconds",
		"Age of the Cloudflare IP ranges in use: since the last accepted refresh, or since the built-in list was retrieved.", nil, nil)
	acmeExpiryDesc = prometheus.NewDesc("rpmgr_acme_cert_expiry_timestamp_seconds", "When each hostname's ACME certificate expires.",
		[]string{"hostname"}, nil)
	checkpointAgeDesc = prometheus.NewDesc("rpmgr_audit_checkpoint_age_seconds",
		"Age of the oldest audit entry no checkpoint covers yet; 0 when every entry is covered.", nil, nil)
	sinkBacklogDesc = prometheus.NewDesc("rpmgr_audit_sink_backlog",
		"Audit entries and checkpoints a sink has not acknowledged.", []string{"sink"}, nil)
	sinkOldestDesc = prometheus.NewDesc("rpmgr_audit_sink_oldest_unshipped_timestamp_seconds",
		"When the oldest item a sink has not acknowledged was appended; 0 when none.", []string{"sink"}, nil)
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
	ch <- sinkBacklogDesc
	ch <- sinkOldestDesc
	ch <- rangesAgeDesc
	ch <- dnsNamesDesc
	ch <- dnsRecordsDesc
	ch <- dnsExpiryDesc
	ch <- dnsBudgetDesc
	ch <- dnsBlockedDesc
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
	if inst, _, err := settings.Instance(c.sys, c.db.ReadClient()); err != nil {
		ch <- prometheus.NewInvalidMetric(rangesAgeDesc, err)
	} else {
		ch <- prometheus.MustNewConstMetric(rangesAgeDesc, prometheus.GaugeValue, cfranges.FromSettings(inst).Age(c.now()).Seconds())
	}
	c.collectDNS(ch)
	oldest, pending, err := audit.Uncovered(c.sys, c.db)
	switch {
	case err != nil:
		ch <- prometheus.NewInvalidMetric(checkpointAgeDesc, err)
	case pending:
		ch <- prometheus.MustNewConstMetric(checkpointAgeDesc, prometheus.GaugeValue, max(0, c.now().Sub(oldest).Seconds()))
	default:
		ch <- prometheus.MustNewConstMetric(checkpointAgeDesc, prometheus.GaugeValue, 0)
	}
	backlogs, err := auditsink.Backlogs(c.sys, c.db)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(sinkBacklogDesc, err)
		return
	}
	for _, b := range backlogs {
		if !b.Enabled {
			continue
		}
		oldest := 0.0
		if !b.Oldest.IsZero() {
			oldest = float64(b.Oldest.Unix())
		}
		ch <- prometheus.MustNewConstMetric(sinkBacklogDesc, prometheus.GaugeValue, float64(b.Items), b.Sink)
		ch <- prometheus.MustNewConstMetric(sinkOldestDesc, prometheus.GaugeValue, oldest, b.Sink)
	}
}

// collectDNS reads the DNS names, the records, the providers' tokens and their request budgets. An
// instance without a provider reports nothing.
func (c dbCollector) collectDNS(ch chan<- prometheus.Metric) {
	rc := c.db.ReadClient()
	zones, err := rc.DNSZone.Query().All(c.sys)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(dnsNamesDesc, err)
		return
	}
	zoneName := map[string]string{}
	for _, z := range zones {
		zoneName[z.ID] = z.Name
	}
	var names []struct {
		Zone   string `json:"dns_zone_id"`
		Status string `json:"status"`
		Count  int    `json:"count"`
	}
	if err := rc.DNSNameStatus.Query().GroupBy(dnsnamestatus.FieldDNSZoneID, dnsnamestatus.FieldStatus).Aggregate(ent.Count()).Scan(c.sys, &names); err != nil {
		ch <- prometheus.NewInvalidMetric(dnsNamesDesc, err)
	}
	// Two orgs may manage a zone of the same name: the series add up.
	byName := map[[2]string]int{}
	for _, n := range names {
		if z, ok := zoneName[n.Zone]; ok {
			byName[[2]string{z, n.Status}] += n.Count
		}
	}
	for k, n := range byName {
		ch <- prometheus.MustNewConstMetric(dnsNamesDesc, prometheus.GaugeValue, float64(n), k[0], k[1])
	}
	var recs []struct {
		Zone  string `json:"dns_zone_id"`
		State string `json:"state"`
		Count int    `json:"count"`
	}
	if err := rc.DNSRecord.Query().GroupBy(dnsrecord.FieldDNSZoneID, dnsrecord.FieldState).Aggregate(ent.Count()).Scan(c.sys, &recs); err != nil {
		ch <- prometheus.NewInvalidMetric(dnsRecordsDesc, err)
	}
	byState := map[[2]string]int{}
	for _, r := range recs {
		if z, ok := zoneName[r.Zone]; ok {
			byState[[2]string{z, r.State}] += r.Count
		}
	}
	for k, n := range byState {
		ch <- prometheus.MustNewConstMetric(dnsRecordsDesc, prometheus.GaugeValue, float64(n), k[0], k[1])
	}
	provs, err := rc.DNSProvider.Query().All(c.sys)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(dnsExpiryDesc, err)
		return
	}
	b := &budget.Budget{DB: c.db, Now: c.now}
	for _, p := range provs {
		if p.TokenExpiresAt != nil {
			ch <- prometheus.MustNewConstMetric(dnsExpiryDesc, prometheus.GaugeValue, float64(p.TokenExpiresAt.Unix()), p.ID)
		}
		st, err := b.Status(c.sys, p.ID)
		if err != nil {
			ch <- prometheus.NewInvalidMetric(dnsBudgetDesc, err)
			continue
		}
		ch <- prometheus.MustNewConstMetric(dnsBudgetDesc, prometheus.GaugeValue, float64(st.Used), p.ID)
		ch <- prometheus.MustNewConstMetric(dnsBlockedDesc, prometheus.GaugeValue, st.Blocked.Seconds(), p.ID)
	}
}
