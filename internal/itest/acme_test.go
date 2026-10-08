// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
)

// TestACMEChallenge_ReachesGateway: an HTTP-01 challenge certmagic stores on the controller is
// pushed over the control session to the gateway of the name, which answers it on port 80 once
// it acknowledged; deleting it removes it from the gateway.
func TestACMEChallenge_ReachesGateway(t *testing.T) {
	p := newDataPlane(t)
	c := p.c
	port80 := freeTCPUDPPort(t)
	http80 := addr(port80)
	p.stopGateway()
	p.gwCfg.Listen.HTTP = &http80
	p.startGateway(t)
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		tcp, err := tx.Route.Get(c.Sys, p.routeID)
		if err != nil {
			return nil, err
		}
		d, err := domains.Claim(c.Sys, tx, c.Org, "example.com", true)
		if err != nil {
			return nil, err
		}
		if err := tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Exec(c.Sys); err != nil {
			return nil, err
		}
		r, err := tx.Route.Create().SetOrgID(c.Org).SetName("web").SetType("http").SetGatewayGroupID(tcp.GatewayGroupID).Save(c.Sys)
		if err != nil {
			return nil, err
		}
		_, err = routes.AddHostname(c.Sys, tx, r.ID, "app.example.com", "")
		return []string{r.ID}, err
	}); err != nil {
		t.Fatal(err)
	}
	storage := acme.NewChallengeStorage(acme.NewStorage(c.DB, c.Sys, c.Sealer(), lease.New(c.DB, "ctn_test", nil), nil),
		c.Sessions, acme.GatewaysServing(c.DB, c.Sys))
	t.Cleanup(storage.Close)
	key := "acme/ca/challenge_tokens/app.example.com.json"
	value := []byte(`{"type":"http-01","token":"tok123","keyAuthorization":"tok123.thumb","identifier":{"type":"dns","value":"app.example.com"}}`)
	waitFor(t, "the gateway did not acknowledge the challenge", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return storage.Store(ctx, key, value) == nil
	})
	get := func() (int, string) {
		req, _ := http.NewRequest(http.MethodGet, "http://"+http80+"/.well-known/acme-challenge/tok123", nil)
		req.Host = "app.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get(); code != http.StatusOK || body != "tok123.thumb" {
		t.Fatalf("the gateway's answer: %d %q", code, body)
	}
	if err := storage.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(); code != http.StatusNotFound {
		t.Fatalf("a removed challenge: %d", code)
	}
	if err := storage.Store(context.Background(), "acme/ca/challenge_tokens/other.example.com.json",
		[]byte(`{"type":"http-01","token":"t","keyAuthorization":"k","identifier":{"type":"dns","value":"other.example.com"}}`)); err == nil {
		t.Fatal("a challenge for a name no gateway serves was stored")
	}
}
