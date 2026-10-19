// SPDX-License-Identifier: Apache-2.0

package domains

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/proxyenv"
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

// ErrHTTPUnreachable is returned when the token could not be fetched. Its message names the kind of
// failure only, never an address or a resolver's, as members of the org read it (issue #815).
var ErrHTTPUnreachable = errors.New("domains: the HTTP token could not be fetched")

// ChallengePath is where a gateway serves a claim's HTTP token (R17).
func ChallengePath(id string) string { return "/.well-known/rpmgr-challenge/" + id }

// ChallengeURL is the URL of a claim's HTTP token.
func ChallengeURL(fqdn, id string) string { return "http://" + fqdn + ChallengePath(id) }

// HTTPVerifier fetches a claim's HTTP token, which the org's own gateways serve for its pending
// claims, so pointing the name at them is the proof (R17). It follows no redirect, reads at most
// 256 bytes, and goes through the proxy the environment names, as all controller egress does
// (R44, D93). Without a proxy it connects only to public addresses (internal/egress), checked for
// the address it dials, so a claim cannot make the controller reach an internal one; through a
// proxy, the proxy decides where it connects (docs/04-security.md, "Route and hostname
// ownership").
type HTTPVerifier struct {
	// Proxy chooses the proxy of the request; nil is proxyenv.FromEnvironment (HTTP_PROXY, else
	// ALL_PROXY; NO_PROXY).
	Proxy func(*http.Request) (*url.URL, error)
	// Resolver, if set, resolves the name for a direct connection (tests).
	Resolver *net.Resolver
	// Transport, if set, replaces the proxy-aware, guarded default (tests).
	Transport http.RoundTripper
}

// Verify reports nil if the token holds the challenge value.
func (v *HTTPVerifier) Verify(ctx context.Context, c Challenge) error {
	url := ChallengeURL(c.FQDN, c.ID)
	ctx, cancel := context.WithTimeout(ctx, HTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("%w: %s: not a valid URL", ErrHTTPUnreachable, url)
	}
	tr := v.Transport
	if tr == nil {
		proxy := v.Proxy
		if proxy == nil {
			proxy = proxyenv.FromEnvironment
		}
		via, err := proxy(req)
		if err != nil {
			return fmt.Errorf("%w: %s: the proxy setting is not valid", ErrHTTPUnreachable, url)
		}
		if via != nil {
			tr = &http.Transport{Proxy: http.ProxyURL(via), DialContext: (&net.Dialer{Timeout: HTTPTimeout}).DialContext,
				DisableKeepAlives: true}
		} else {
			tr = &http.Transport{DialContext: egress.Dialer(HTTPTimeout, v.Resolver).DialContext, DisableKeepAlives: true}
		}
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s: %s", ErrHTTPUnreachable, url, failure(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// The status code only: a reason phrase is the server's own text.
		return fmt.Errorf("%w: %s answered HTTP %d", ErrHTTPToken, url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBody+1))
	if err != nil {
		return fmt.Errorf("%w: %s: the answer broke off", ErrHTTPUnreachable, url)
	}
	if len(body) > maxTokenBody {
		return fmt.Errorf("%w: %s answered more than %d bytes", ErrHTTPToken, url, maxTokenBody)
	}
	if strings.TrimSpace(string(body)) != c.Value {
		return fmt.Errorf("%w: %s", ErrHTTPToken, url)
	}
	return nil
}

// failure is the kind of a failed request, without the addresses its error names.
func failure(err error) string {
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, egress.ErrRefused):
		return "the name resolves to an address that is not public; prove the domain with a TXT record, " +
			"or have the Instance Admin mark it trusted"
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return "the name does not resolve"
	case errors.As(err, &dnsErr) && dnsErr.IsTimeout:
		return "resolving the name timed out"
	case errors.As(err, &dnsErr):
		return "the name could not be resolved"
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		return "no answer in time"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "the connection was refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "the connection was reset"
	case errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH):
		return "the address is not reachable"
	default:
		return "the request failed"
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
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
