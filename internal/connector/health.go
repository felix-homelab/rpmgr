// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/upstreamtls"
)

// The defaults of a health check, and the most of its body it reads (docs/03-connections.md,
// "Timeouts, keepalive and backoff").
const (
	checkInterval  = 10 * time.Second
	checkTimeout   = 5 * time.Second
	checkUnhealthy = 3
	checkHealthy   = 2
	checkBody      = 64 << 10
)

// HealthCheck is a route's active health check (docs/03-connections.md, "Target health"), with
// its defaults filled in.
type HealthCheck struct {
	// HTTP checks with a GET of Path, with the Host header Host, that answers StatusMin to
	// StatusMax; otherwise the dial alone. HTTPS speaks TLS, verified by each target's TLS.
	HTTP, HTTPS          bool
	Path, Host           string
	StatusMin, StatusMax int
	// Port is checked instead of the target's port; 0 is the target's.
	Port              uint16
	Interval, Timeout time.Duration
	// Unhealthy failed checks in a row make a target unhealthy, Healthy passed ones healthy again.
	Unhealthy, Healthy int
}

// healthCheckOf is a snapshot's health check with its defaults, or nil without one.
func healthCheckOf(c *agentv1.HealthCheck) *HealthCheck {
	if c == nil {
		return nil
	}
	ms := func(v uint32, def time.Duration) time.Duration {
		if v == 0 {
			return def
		}
		return time.Duration(v) * time.Millisecond
	}
	n := func(v uint32, def int) int {
		if v == 0 {
			return def
		}
		return int(v)
	}
	out := &HealthCheck{HTTP: c.GetType() == "http", HTTPS: c.GetHttps(), Path: c.GetPath(), Host: c.GetHost(),
		Port:     uint16(c.GetPort()), //nolint:gosec // G115: Validate bounds the port
		Interval: ms(c.GetIntervalMs(), checkInterval), Timeout: ms(c.GetTimeoutMs(), checkTimeout),
		Unhealthy: n(c.GetUnhealthyThreshold(), checkUnhealthy), Healthy: n(c.GetHealthyThreshold(), checkHealthy),
		StatusMin: n(c.GetStatusMin(), 200), StatusMax: n(c.GetStatusMax(), 399)}
	if out.Path == "" {
		out.Path = "/"
	}
	return out
}

// targetHealth is what the checks found of one target: healthy until Unhealthy checks in a row
// fail, then unhealthy until Healthy checks in a row pass, so that one odd result moves nothing.
type targetHealth struct {
	unhealthy bool
	streak    int // passes in a row if positive, failures in a row if negative
}

// observe records one check of the target and reports whether its health changed.
func (h *targetHealth) observe(pass bool, c *HealthCheck) bool {
	if pass {
		h.streak = max(h.streak, 0) + 1
		if h.unhealthy && h.streak >= c.Healthy {
			h.unhealthy = false
			return true
		}
		return false
	}
	h.streak = min(h.streak, 0) - 1
	if !h.unhealthy && -h.streak >= c.Unhealthy {
		h.unhealthy = true
		return true
	}
	return false
}

// checker runs one route's health check until it is stopped.
type checker struct {
	stop context.CancelFunc
	done chan struct{}
	r    Route // the route it checks, as Set gave it
}

// startChecks runs r's health check in the background, a round at once and then every interval,
// each target of a round at the same time. Under t.mu.
func (t *Targets) startChecks(r Route) {
	ctx, cancel := context.WithCancel(t.ctx)
	c := &checker{stop: cancel, done: make(chan struct{}), r: r}
	t.checkers[r.ID] = c
	t.targetHealth[r.ID] = map[string]*targetHealth{}
	go func() {
		defer close(c.done)
		tick := time.NewTicker(r.Check.Interval)
		defer tick.Stop()
		for {
			t.checkRound(ctx, c)
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
}

// stopChecks stops a route's checks and forgets what they found. Under t.mu.
func (t *Targets) stopChecks(id string) {
	if c := t.checkers[id]; c != nil {
		c.stop()
		delete(t.checkers, id)
	}
	delete(t.targetHealth, id)
}

// checkRound checks every target of c's route once and reports the route's readiness if a
// target's health changed, unless c was stopped meanwhile.
func (t *Targets) checkRound(ctx context.Context, c *checker) {
	r := c.r
	results := make([]bool, len(r.Targets))
	var wg sync.WaitGroup
	for i, tg := range r.Targets {
		wg.Go(func() { results[i] = t.check(ctx, r, tg) == nil })
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	p := t.o.Policy()
	t.mu.Lock()
	var h *tunnelv1.RouteHealth
	if hs := t.targetHealth[r.ID]; hs != nil && t.checkers[r.ID] == c {
		changed := false
		for i, tg := range r.Targets {
			if hs[tg.ID] == nil {
				hs[tg.ID] = &targetHealth{}
			}
			changed = hs[tg.ID].observe(results[i], r.Check) || changed
		}
		if cur, ok := t.routes[r.ID]; ok && changed {
			h = t.updateHealthLocked(r.ID, readiness(cur, p, t.refused[r.ID], t.unhealthyLocked(r.ID)))
		}
	}
	t.mu.Unlock()
	t.reportRoute(h)
}

// unhealthyLocked returns the route's targets its checks found unhealthy. Under t.mu.
func (t *Targets) unhealthyLocked(route string) map[string]bool {
	out := map[string]bool{}
	for id, h := range t.targetHealth[route] {
		if h.unhealthy {
			out[id] = true
		}
	}
	return out
}

// errCheckBlocked is a check of a target the local policy does not allow: it fails, undialled.
var errCheckBlocked = errors.New("the local policy does not allow the target")

// check runs r's health check against one target: it dials as traffic does, under the local
// policy, which a target it blocks fails without being dialled; for an http check it then sends a
// GET, over TLS verified by the target's settings if the check is https, follows no redirect and
// reads at most checkBody of the answer's body.
func (t *Targets) check(ctx context.Context, r Route, tg Target) error {
	c := r.Check
	if !tg.allowed(t.o.Policy()) {
		return errCheckBlocked
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	network, addr := "tcp", tg.String()
	if tg.UnixPath != "" {
		network = "unix"
	} else if c.Port != 0 {
		addr = net.JoinHostPort(tg.Host, strconv.Itoa(int(c.Port)))
	}
	d := &net.Dialer{Control: policy.Control(t.o.Policy)}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		var b *policy.BlockedError
		if errors.As(err, &b) {
			return errCheckBlocked
		}
		return err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if h := proxyHeader(tg, &tunnelv1.StreamOpen{}); h != nil && c.Port == 0 {
		if _, err := h.WriteTo(conn); err != nil {
			return err
		}
	}
	if !c.HTTP {
		return nil
	}
	if c.HTTPS {
		if tg.TLS == nil {
			return errors.New("an https check of a target without TLS settings")
		}
		cfg, err := tg.TLS.Config()
		if err != nil {
			return err
		}
		cfg.NextProtos = []string{"http/1.1"}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return err
		}
		conn = tc
	}
	host := c.Host
	if host == "" {
		host = tg.String()
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: rpmgr-health-check\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		c.Path, host); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, checkBody))
	_ = resp.Body.Close()
	if resp.StatusCode < c.StatusMin || resp.StatusCode > c.StatusMax {
		return fmt.Errorf("the check's answer is %d, not %d to %d", resp.StatusCode, c.StatusMin, c.StatusMax)
	}
	return nil
}

// tlsOf is a snapshot target's TLS settings for an https check, or nil.
func tlsOf(u *agentv1.UpstreamTLS) *upstreamtls.Settings {
	if u == nil {
		return nil
	}
	s := &upstreamtls.Settings{ServerName: u.GetServerName(), CAPEM: u.GetCaPem(), SPKISHA256: u.GetSpkiSha256()}
	switch u.GetVerification() {
	case agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_UNVERIFIED:
		s.Verify = upstreamtls.Nothing
	case agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_PINNED_KEY:
		s.Verify = upstreamtls.PinnedKey
	}
	return s
}
