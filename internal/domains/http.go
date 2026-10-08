// SPDX-License-Identifier: Apache-2.0

package domains

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
)

// The HTTP proof check (docs/15-dns.md, "Timers and limits").
const (
	HTTPTimeout  = 10 * time.Second
	maxTokenBody = 256
)

// ErrHTTPToken is returned when the token does not hold the challenge value.
var ErrHTTPToken = errors.New("domains: the HTTP token does not hold the challenge value")

// ChallengePath is where a gateway serves a claim's HTTP token (R17).
func ChallengePath(id string) string { return "/.well-known/rpmgr-challenge/" + id }

// ChallengeURL is the URL of a claim's HTTP token.
func ChallengeURL(fqdn, id string) string { return "http://" + fqdn + ChallengePath(id) }

// HTTPVerifier fetches a claim's HTTP token, which the org's own gateways serve for its pending
// claims, so pointing the name at them is the proof (R17). It follows no redirect, reads at most
// 256 bytes, and goes through the proxy the environment names, as all controller egress does
// (R44).
type HTTPVerifier struct {
	// Transport, if set, replaces the proxy-aware default (tests).
	Transport http.RoundTripper
}

// Verify reports nil if the token holds the challenge value.
func (v *HTTPVerifier) Verify(ctx context.Context, c Challenge) error {
	url := ChallengeURL(c.FQDN, c.ID)
	ctx, cancel := context.WithTimeout(ctx, HTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	tr := v.Transport
	if tr == nil {
		tr = &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: HTTPTimeout}).DialContext}
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("domains: %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered %s", ErrHTTPToken, url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBody+1))
	if err != nil {
		return fmt.Errorf("domains: %s: %w", url, err)
	}
	if len(body) > maxTokenBody {
		return fmt.Errorf("%w: %s answered more than %d bytes", ErrHTTPToken, url, maxTokenBody)
	}
	if strings.TrimSpace(string(body)) != c.Value {
		return fmt.Errorf("%w: %s", ErrHTTPToken, url)
	}
	return nil
}

// GatewayChallenges compiles a gateway's HTTP tokens: those of the pending HTTP claims of its org,
// while it serves. A gateway of another org never gets them, so only the org's own gateways prove
// its claims.
func GatewayChallenges(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	if a.Identity.Kind != pki.KindGateway {
		return nil, nil
	}
	gw, err := tx.Gateway.Get(ctx, a.Identity.ID)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil || !gw.Enabled || gw.DecommissionedAt != nil {
		return nil, err
	}
	claims, err := tx.Domain.Query().Where(domain.OrgID(gw.OrgID), domain.StatusEQ(domain.StatusPending), domain.MethodEQ(domain.MethodHTTP)).
		Order(ent.Asc(domain.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*agentv1.Resource, 0, len(claims))
	for _, d := range claims {
		out = append(out, &agentv1.Resource{Id: d.ID, Kind: &agentv1.Resource_GatewayDomainChallenge{
			GatewayDomainChallenge: &agentv1.GatewayDomainChallenge{Fqdn: d.Fqdn, Value: d.ChallengeValue}}})
	}
	return out, nil
}
