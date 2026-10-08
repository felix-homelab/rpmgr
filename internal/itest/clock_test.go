// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"net"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

// served reports whether the route answers through the data plane now, without waiting.
func (p *dataPlane) served() bool {
	c, err := net.Dial("tcp", addr(p.publicPort))
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	return ping(c, "served?") == nil
}

// TestTCPRoute_ExpiredCertificate: a connector restarted with a certificate that expired within
// the Reauth grace period gets a new one and carries the route again; one that expired beyond the
// grace period stays out of the data plane, fail-closed (docs/04-security.md, "Leaf certificates").
func TestTCPRoute_ExpiredCertificate(t *testing.T) {
	p := newDataPlane(t)
	p.dial(t)
	id, err := agent.Load(p.conCfg.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}

	p.stopConnector()
	expired := p.c.IssueAt(t, id, time.Now().Add(-8*24*time.Hour)) // expired a day ago
	p.startConnector(t, nil)
	p.dial(t)
	renewed, err := agent.Load(id.Dir)
	if err != nil || pki.SerialHex(renewed.Certificate.Leaf.SerialNumber) == pki.SerialHex(expired.SerialNumber) ||
		!renewed.Certificate.Leaf.NotAfter.After(time.Now()) {
		t.Fatalf("the connector carries the route without a renewed certificate: %v", err)
	}

	p.stopConnector()
	gone := p.c.IssueAt(t, renewed, time.Now().Add(-40*24*time.Hour)) // beyond the 30-day grace period
	p.startConnector(t, nil)
	time.Sleep(3 * time.Second)
	if p.served() {
		t.Fatal("a connector whose certificate expired beyond the grace period carries the route")
	}
	if l, err := agent.Load(id.Dir); err != nil || l.Certificate.Leaf.SerialNumber.Cmp(gone.SerialNumber) != 0 {
		t.Fatalf("the certificate changed beyond the grace period: %v", err)
	}
}

// TestTCPRoute_ClockSkew: a connector whose clock is two minutes ahead or behind still carries the
// route: certificates are backdated, and the skew is only reported (docs/03-connections.md).
func TestTCPRoute_ClockSkew(t *testing.T) {
	p := newDataPlane(t)
	p.dial(t)
	for _, skew := range []time.Duration{2 * time.Minute, -2 * time.Minute} {
		p.stopConnector()
		waitFor(t, "the route still answers without the connector", func() bool { return !p.served() })
		p.startConnector(t, func() time.Time { return time.Now().Add(skew) })
		waitFor(t, "no route with a skewed connector clock", p.served)
	}
}
