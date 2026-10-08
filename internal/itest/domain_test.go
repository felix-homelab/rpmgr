// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestDomainHTTPProof (R17): the gateway serves the HTTP token of its org's pending HTTP claim on
// port 80, for the claimed name only, and the controller's HTTP verifier finds it there; another
// org's claim is not served by it, so pointing a name at this gateway proves nothing for that org.
func TestDomainHTTPProof(t *testing.T) {
	p := newDataPlane(t)
	c := p.c
	http80 := addr(freeTCPUDPPort(t))
	p.stopGateway()
	p.gwCfg.Listen.HTTP = &http80
	p.startGateway(t)
	orgB := storetest.Org(t, c.DB, "org-b")
	claim := func(org, fqdn string) *ent.Domain {
		var d *ent.Domain
		if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
			var err error
			if d, err = domains.Claim(c.Sys, tx, org, fqdn, false); err != nil {
				return nil, err
			}
			d, err = tx.Domain.UpdateOne(d).SetMethod(domain.MethodHTTP).Save(c.Sys)
			return []string{d.ID}, err
		}); err != nil {
			t.Fatal(err)
		}
		return d
	}
	ours, theirs := claim(c.Org, "app.example.com"), claim(orgB, "other.example.com")

	// Every name resolves to this gateway, as DNS pointing at it would.
	v := &domains.HTTPVerifier{Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, http80)
	}}}
	ctx := context.Background()
	waitFor(t, "the gateway never served the org's token", func() bool {
		return v.Verify(ctx, domains.ChallengeOf(ours)) == nil
	})
	if err := v.Verify(ctx, domains.ChallengeOf(theirs)); !errors.Is(err, domains.ErrHTTPToken) {
		t.Fatalf("another org's claim through this gateway: %v", err)
	}
	// The token is answered for the claimed name only.
	wrongHost := domains.ChallengeOf(ours)
	wrongHost.FQDN = "elsewhere.example.com"
	if err := v.Verify(ctx, wrongHost); !errors.Is(err, domains.ErrHTTPToken) {
		t.Fatalf("the token under another name: %v", err)
	}
}
