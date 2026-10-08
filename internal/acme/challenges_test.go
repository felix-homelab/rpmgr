// SPDX-License-Identifier: Apache-2.0

package acme_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/acme/acmetest"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// fleetOps routes the challenge operations to two gateways: gw_a answers the CA, gw_b only
// acknowledges, or misbehaves as the test says.
type fleetOps struct {
	a, b  *gateway.Challenges
	bMode atomic.Value // "ack", "error", "silent", "offline"
	sent  atomic.Int64
}

func (f *fleetOps) Op(ctx context.Context, id string, msg func(string) *agentv1.ControllerMessage) error {
	f.sent.Add(1)
	ch := msg("op_1").GetAcmeChallenge()
	switch id {
	case "gw_a":
		return f.a.Apply(ch)
	case "gw_b":
		switch f.bMode.Load() {
		case "error":
			return errors.New("the gateway refused it")
		case "silent":
			<-ctx.Done()
			return ctx.Err()
		case "offline":
			return errors.New("no control session")
		}
		return f.b.Apply(ch)
	}
	return errors.New("unknown gateway")
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestACME_ValidationWaitsForEveryGateway: for HTTP-01 and TLS-ALPN-01 the CA is asked to validate
// only after every gateway serving the name acknowledged its challenge: a gateway that refuses,
// does not answer within the deadline or has no control session fails the order without a
// validation request; once validated, the challenges are removed from every gateway, which keep
// them in memory only.
func TestACME_ValidationWaitsForEveryGateway(t *testing.T) {
	acme.SetPushTimeout(t, time.Second)
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	dns, err := acmetest.StartDNS([]string{"example.test"}, func(string) []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dns.Close)

	// gw_a: port 80 answers HTTP-01 and port 443 TLS-ALPN-01 from its challenges, as a gateway
	// does; the CA connects to it.
	ops := &fleetOps{a: gateway.NewChallenges(), b: gateway.NewChallenges()}
	ops.bMode.Store("ack")
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Challenges: ops.a.HTTP01})
	t.Cleanup(h.Close)
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = h.Serve80(plain) }()
	t.Cleanup(func() { _ = plain.Close() })
	def, err := gateway.DefaultTLS()
	if err != nil {
		t.Fatal(err)
	}
	tlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	router := &gateway.Router{TrustDomain: "rpmgr-acmetest", GatewayID: "gw_a", DefaultTLS: def, ACME: ops.a.ALPN}
	go func() { _ = router.Serve(tlsLn) }()
	t.Cleanup(func() { _ = tlsLn.Close() })

	pebble, err := acmetest.Start(acmetest.Options{HTTPPort: plain.Addr().(*net.TCPAddr).Port,
		TLSPort: tlsLn.Addr().(*net.TCPAddr).Port, Resolver: dns.Addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pebble.Close)

	s := sealer(t)
	storage := acme.NewChallengeStorage(acme.NewStorage(db, sys, s, lease.New(db, "ctn_a", nil), nil), ops,
		func(context.Context, string) ([]string, error) { return []string{"gw_a", "gw_b"}, nil })
	t.Cleanup(storage.Close)
	obtain := func(name string, http bool) error {
		cache := certmagic.NewCache(certmagic.CacheOptions{Logger: zap.NewNop(),
			GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return nil, errors.New("no renewals here") }})
		defer cache.Stop()
		cfg := certmagic.New(cache, certmagic.Config{Storage: storage, Logger: zap.NewNop()})
		cfg.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
			CA: pebble.DirectoryURL, TrustedRoots: pebble.ServerRoots, Agreed: true, Email: "ops@example.test", Logger: zap.NewNop(),
			DisableHTTPChallenge: !http, DisableTLSALPNChallenge: http,
			// certmagic still starts its own challenge listeners; they go where no CA connects.
			ListenHost: "127.0.0.1", AltHTTPPort: freePort(t), AltTLSALPNPort: freePort(t),
		})}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		return cfg.ObtainCertSync(ctx, name)
	}

	for _, tc := range []struct {
		name, mode string
		http       bool
	}{
		{"http.example.test", "ack", true},
		{"alpn.example.test", "ack", false},
	} {
		ops.bMode.Store(tc.mode)
		before := pebble.ChallengePosts.Load()
		if err := obtain(tc.name, tc.http); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if pebble.ChallengePosts.Load() == before {
			t.Fatalf("%s: issued without a validation request", tc.name)
		}
		if ops.a.Len() != 0 || ops.b.Len() != 0 {
			t.Fatalf("%s: challenges left on the gateways: %d and %d", tc.name, ops.a.Len(), ops.b.Len())
		}
	}

	for _, mode := range []string{"error", "silent", "offline"} {
		for _, http := range []bool{true, false} {
			ops.bMode.Store(mode)
			name := mode + strconv.FormatBool(http) + ".example.test"
			before, sent := pebble.ChallengePosts.Load(), ops.sent.Load()
			if err := obtain(name, http); err == nil {
				t.Fatalf("%s: issued although gw_b did not acknowledge (%s)", name, mode)
			}
			if pebble.ChallengePosts.Load() != before {
				t.Fatalf("%s: the CA was asked to validate although gw_b did not acknowledge (%s)", name, mode)
			}
			if ops.sent.Load() == sent {
				t.Fatalf("%s: no challenge was pushed", name)
			}
		}
	}
}

// TestChallengeStorage: only certmagic's challenge keys are pushed; a name no gateway serves fails;
// DNS-01 challenges stay in the controller; a removal that fails does not keep the key.
func TestChallengeStorage(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	ops := &fleetOps{a: gateway.NewChallenges(), b: gateway.NewChallenges()}
	ops.bMode.Store("ack")
	var served []string
	storage := acme.NewChallengeStorage(acme.NewStorage(db, sys, sealer(t), lease.New(db, "ctn_a", nil), nil), ops,
		func(context.Context, string) ([]string, error) { return served, nil })
	t.Cleanup(storage.Close)
	ctx := context.Background()
	key := "acme/pebble/challenge_tokens/app.example.test.json"
	http01 := []byte(`{"type":"http-01","token":"tok","keyAuthorization":"tok.thumb","identifier":{"type":"dns","value":"app.example.test"}}`)
	if err := storage.Store(ctx, key, http01); err == nil || storage.Exists(ctx, key) {
		t.Fatalf("a name no gateway serves: %v", err)
	}
	served = []string{"gw_a", "gw_b"}
	if err := storage.Store(ctx, "certificates/x/x.crt", []byte("x")); err != nil || ops.sent.Load() != 0 {
		t.Fatalf("an ordinary key: %v, %d pushes", err, ops.sent.Load())
	}
	if err := storage.Store(ctx, key, http01); err != nil || !storage.Exists(ctx, key) {
		t.Fatal(err)
	}
	if ka, ok := ops.a.HTTP01("app.example.test", "tok"); !ok || ka != "tok.thumb" {
		t.Fatalf("gw_a: %q %v", ka, ok)
	}
	if err := storage.Store(ctx, key, []byte("not json")); err == nil {
		t.Fatal("a challenge that does not parse was stored")
	}
	ops.bMode.Store("error")
	if err := storage.Delete(ctx, key); err != nil || storage.Exists(ctx, key) {
		t.Fatalf("a removal that gw_b refused: %v", err)
	}
	if _, ok := ops.a.HTTP01("app.example.test", "tok"); ok {
		t.Fatal("gw_a still answers a removed challenge")
	}
	dns01 := []byte(`{"type":"dns-01","token":"t","keyAuthorization":"k","identifier":{"type":"dns","value":"app.example.test"}}`)
	sent := ops.sent.Load()
	if err := storage.Store(ctx, "acme/pebble/challenge_tokens/dns.example.test.json", dns01); err != nil || ops.sent.Load() != sent {
		t.Fatalf("a DNS-01 challenge: %v, %d pushes", err, ops.sent.Load()-sent)
	}
	if !acme.IsChallengeKey(key) || acme.IsChallengeKey("acme/pebble/users/x.json") || acme.IsChallengeKey("challenge_tokens/x.txt") {
		t.Fatal("IsChallengeKey")
	}
}
