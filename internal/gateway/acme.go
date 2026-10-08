// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/domains"
)

// maxChallenges bounds the challenges a gateway keeps at once; the controller removes each after
// its authorization.
const maxChallenges = 1000

// Challenges are the ACME challenges the controller pushed to this gateway (docs/03-connections.md,
// "Service sketch"): it answers HTTP-01 on port 80 and TLS-ALPN-01 on port 443 from them, keeps
// them in memory only, and never reads the controller's storage.
type Challenges struct {
	mu   sync.Mutex
	http map[string]string           // "<host>\x00<token>" → key authorization
	alpn map[string]*tls.Certificate // host → the acme-tls/1 certificate
}

// NewChallenges returns an empty set.
func NewChallenges() *Challenges {
	return &Challenges{http: map[string]string{}, alpn: map[string]*tls.Certificate{}}
}

// Apply adds or removes a challenge; it is agent.ControlOptions.OnAcmeChallenge.
func (c *Challenges) Apply(ch *agentv1.AcmeChallenge) error {
	host, err := domains.Normalize(ch.GetIdentifier(), false)
	if err != nil {
		return fmt.Errorf("challenge identifier: %w", err)
	}
	add := ch.GetAction() == agentv1.AcmeAction_ACME_ACTION_ADD
	if !add && ch.GetAction() != agentv1.AcmeAction_ACME_ACTION_REMOVE {
		return errors.New("an ACME challenge without an action")
	}
	if add && ch.GetKeyAuthorization() == "" {
		return errors.New("an ACME challenge without a key authorization")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch ch.GetType() {
	case agentv1.AcmeChallengeType_ACME_CHALLENGE_TYPE_HTTP_01:
		token := ch.GetToken()
		if token == "" || strings.ContainsAny(token, "/?#") {
			return fmt.Errorf("challenge token %q", token)
		}
		key := host + "\x00" + token
		if !add {
			delete(c.http, key)
			return nil
		}
		if _, ok := c.http[key]; !ok && len(c.http)+len(c.alpn) >= maxChallenges {
			return errors.New("too many ACME challenges at once")
		}
		c.http[key] = ch.GetKeyAuthorization()
	case agentv1.AcmeChallengeType_ACME_CHALLENGE_TYPE_TLS_ALPN_01:
		if !add {
			delete(c.alpn, host)
			return nil
		}
		if _, ok := c.alpn[host]; !ok && len(c.http)+len(c.alpn) >= maxChallenges {
			return errors.New("too many ACME challenges at once")
		}
		cert, err := acmez.TLSALPN01ChallengeCert(acme.Challenge{Identifier: acme.Identifier{Type: "dns", Value: host},
			KeyAuthorization: ch.GetKeyAuthorization()})
		if err != nil {
			return err
		}
		c.alpn[host] = cert
	default:
		return fmt.Errorf("a %s challenge is not answered by gateways", ch.GetType())
	}
	return nil
}

// HTTP01 returns the key authorization for a host's HTTP-01 token; it is
// HTTPOptions.Challenges.
func (c *Challenges) HTTP01(host, token string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ka, ok := c.http[strings.ToLower(host)+"\x00"+token]
	return ka, ok
}

// ALPN returns the acme-tls/1 certificate of a host's TLS-ALPN-01 challenge, or nil; it is
// Router.ACME.
func (c *Challenges) ALPN(host string) *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.alpn[strings.ToLower(strings.TrimSuffix(host, "."))]
}

// Len returns how many challenges are kept.
func (c *Challenges) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.http) + len(c.alpn)
}
