// SPDX-License-Identifier: Apache-2.0

package domains_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestHTTPVerifier: the token is fetched from http://<fqdn>/.well-known/rpmgr-challenge/<id> and
// must hold the value, trailing white space aside; a wrong value, another status, a redirect,
// which is not followed, an over-long body and an unreachable name are no proof.
func TestHTTPVerifier(t *testing.T) {
	var redirected atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "app.example.com" {
			http.Error(w, "wrong host "+r.Host, http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/.well-known/rpmgr-challenge/dom_ok":
			_, _ = w.Write([]byte(value + "\n"))
		case "/.well-known/rpmgr-challenge/dom_wrong":
			_, _ = w.Write([]byte("something else"))
		case "/.well-known/rpmgr-challenge/dom_long":
			_, _ = w.Write([]byte(value + strings.Repeat(" ", 300) + "x"))
		case "/.well-known/rpmgr-challenge/dom_moved":
			http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently)
		case "/elsewhere":
			redirected.Add(1)
			_, _ = w.Write([]byte(value))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	to := func(addr string) *domains.HTTPVerifier {
		return &domains.HTTPVerifier{Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}}
	}
	v := to(srv.Listener.Addr().String())
	ctx := context.Background()
	check := func(id string) error {
		return v.Verify(ctx, domains.Challenge{ID: id, FQDN: "app.example.com", Value: value})
	}
	if err := check("dom_ok"); err != nil {
		t.Fatalf("the token: %v", err)
	}
	for _, id := range []string{"dom_wrong", "dom_missing", "dom_moved", "dom_long"} {
		if err := check(id); !errors.Is(err, domains.ErrHTTPToken) {
			t.Errorf("%s: %v", id, err)
		}
	}
	if redirected.Load() != 0 {
		t.Fatal("a redirect was followed")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()
	if err := to(dead).Verify(ctx, domains.Challenge{ID: "dom_ok", FQDN: "app.example.com", Value: value}); err == nil || errors.Is(err, domains.ErrHTTPToken) {
		t.Fatalf("an unreachable name: %v", err)
	}
}

// TestGatewayChallenges: a gateway gets the tokens of the pending HTTP claims of its own org, and
// nothing while it is disabled; a connector gets none.
func TestGatewayChallenges(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		orgA, orgB := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		c := db.Client()
		group := c.GatewayGroup.Create().SetOrgID(orgA).SetName("eu").SaveX(sys)
		gw := c.Gateway.Create().SetOrgID(orgA).SetGatewayGroupID(group.ID).SetName("gw1").SetTunnelEndpoints([]string{"gw1.example.com:443"}).SaveX(sys)
		add := func(org, fqdn string, method domain.Method, status domain.Status) string {
			return c.Domain.Create().SetOrgID(org).SetFqdn(fqdn).SetChallengeValue("v" + strings.ReplaceAll(fqdn, ".", "")).SetMethod(method).
				SetStatus(status).SaveX(sys).ID
		}
		want := add(orgA, "a.example", domain.MethodHTTP, domain.StatusPending)
		add(orgA, "b.example", domain.MethodDNSTxt, domain.StatusPending)
		add(orgA, "c.example", domain.MethodHTTP, domain.StatusVerified)
		add(orgB, "d.example", domain.MethodHTTP, domain.StatusPending)
		compile := func(kind pki.Kind, id string) []string {
			t.Helper()
			var ids []string
			if err := store.ReadTx(sys, db, func(tx *ent.Tx, _ store.Revision) error {
				rs, err := domains.GatewayChallenges(sys, tx, snapshot.Agent{Identity: pki.Identity{Kind: kind, Org: orgA, ID: id}})
				for _, r := range rs {
					if r.GetGatewayDomainChallenge().GetFqdn() == "a.example" && r.GetGatewayDomainChallenge().GetValue() != "vaexample" {
						t.Errorf("the token's value: %v", r)
					}
					ids = append(ids, r.GetId())
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return ids
		}
		if got := compile(pki.KindGateway, gw.ID); len(got) != 1 || got[0] != want {
			t.Fatalf("the gateway's tokens: %v, want [%s]", got, want)
		}
		if got := compile(pki.KindConnector, "con_x"); len(got) != 0 {
			t.Fatalf("a connector's: %v", got)
		}
		c.Gateway.UpdateOneID(gw.ID).SetEnabled(false).ExecX(sys)
		if got := compile(pki.KindGateway, gw.ID); len(got) != 0 {
			t.Fatalf("a disabled gateway's: %v", got)
		}
	})
}
