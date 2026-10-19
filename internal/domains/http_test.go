// SPDX-License-Identifier: Apache-2.0

package domains_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

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

// fakeDNS answers every A query with the address of answers[name], NXDOMAIN for a name it does not
// know, and nothing for AAAA; resolver is a Go resolver that asks it.
func fakeDNS(t *testing.T, answers map[string]string) (*net.Resolver, string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		name := strings.TrimSuffix(q.Question[0].Name, ".")
		ip, ok := answers[name]
		switch {
		case !ok:
			m.Rcode = dns.RcodeNameError
		case q.Question[0].Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	addr := pc.LocalAddr().String()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", addr)
	}}, addr
}

// TestDomainProof_EgressGuard: without a proxy, an HTTP proof never connects to an address that is
// not public, whatever the name resolves to, and the error it leaves names the kind of failure,
// not an address or the resolver's; a proxy, also one on loopback, is still used as before, and a
// server's reason phrase is not kept (issue #815).
func TestDomainProof_EgressGuard(t *testing.T) {
	ctx := context.Background()
	noProxy := func(*http.Request) (*url.URL, error) { return nil, nil }
	resolver, dnsAddr := fakeDNS(t, map[string]string{
		"loop.example.com": "127.0.0.1", "lan.example.com": "192.168.1.10", "meta.example.com": "169.254.169.254",
		"cgnat.example.com": "100.100.100.200", "zero.example.com": "0.0.0.0",
	})
	v := &domains.HTTPVerifier{Proxy: noProxy, Resolver: resolver}
	for _, name := range []string{"loop.example.com", "lan.example.com", "meta.example.com", "cgnat.example.com", "zero.example.com"} {
		err := v.Verify(ctx, domains.Challenge{ID: "dom_x", FQDN: name, Value: value})
		if !errors.Is(err, domains.ErrHTTPUnreachable) || !strings.Contains(err.Error(), "not public") {
			t.Errorf("%s: %v, want refused as not public", name, err)
		}
		for _, leak := range []string{"127.0.0.1", "192.168.", "169.254.", "100.100.", "0.0.0.0", dnsAddr} {
			if err != nil && strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the error names %s: %v", name, leak, err)
			}
		}
	}
	err := v.Verify(ctx, domains.Challenge{ID: "dom_x", FQDN: "missing.example.com", Value: value})
	if !errors.Is(err, domains.ErrHTTPUnreachable) || !strings.Contains(err.Error(), "does not resolve") ||
		strings.Contains(err.Error(), dnsAddr) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("a name that does not resolve: %v", err)
	}
	// The system resolver: localhost is loopback.
	if err := (&domains.HTTPVerifier{Proxy: noProxy}).Verify(ctx, domains.Challenge{ID: "dom_x", FQDN: "localhost", Value: value}); !errors.Is(err, domains.ErrHTTPUnreachable) || !strings.Contains(err.Error(), "not public") {
		t.Errorf("localhost: %v", err)
	}

	// Through a proxy, here on loopback, the request goes to the proxy unchanged.
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "http://loop.example.com/.well-known/rpmgr-challenge/dom_x" {
			http.Error(w, "unexpected "+r.URL.String(), http.StatusBadRequest)
			return
		}
		proxied.Add(1)
		_, _ = w.Write([]byte(value))
	}))
	t.Cleanup(proxy.Close)
	pu, _ := url.Parse(proxy.URL)
	viaProxy := &domains.HTTPVerifier{Proxy: http.ProxyURL(pu), Resolver: resolver}
	if err := viaProxy.Verify(ctx, domains.Challenge{ID: "dom_x", FQDN: "loop.example.com", Value: value}); err != nil || proxied.Load() != 1 {
		t.Errorf("through the proxy: %v (%d requests)", err, proxied.Load())
	}

	// A reason phrase is the server's own text and is not kept.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("HTTP/1.1 404 db01.internal 10.9.8.7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			_ = c.Close()
		}
	}()
	raw := &domains.HTTPVerifier{Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}}}
	err = raw.Verify(ctx, domains.Challenge{ID: "dom_x", FQDN: "app.example.com", Value: value})
	if !errors.Is(err, domains.ErrHTTPToken) || !strings.Contains(err.Error(), "HTTP 404") || strings.Contains(err.Error(), "db01") ||
		strings.Contains(err.Error(), "10.9.8.7") {
		t.Errorf("a reason phrase: %v", err)
	}
}
