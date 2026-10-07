// SPDX-License-Identifier: Apache-2.0

// End-to-end tests of spike S6 against Pebble: a controller running certmagic on a database
// storage, gateways answering HTTP-01 and TLS-ALPN-01, and DNS-01 through the libdns adapter
// over a fake Cloudflare API. Run with: go test -race -count=1 -v ./...
package s6

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/felix-homelab/rpmgr/spikes/s6/internal/cfclient"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/controller"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/controlplane"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/dbstore"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/dnsadapter"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/dnsserver"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/fakecf"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/gateway"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/pebblehost"
)

const (
	managedZone = "managed.test" // a zone at the fake Cloudflare account: DNS-01
	otherZone   = "other.test"   // served by the test DNS server only: HTTP-01 / TLS-ALPN-01
	cfToken     = "spike-token"
	marker      = "rpmgr rpmgr-s6spike0 acme"
)

type env struct {
	t        *testing.T
	pebble   *pebblehost.Pebble
	dns      *dnsserver.Server
	cf       *fakecf.Server
	cfURL    string
	gws      []*gateway.Gateway
	gwTLS    []string // TLS listener address per gateway
	sessions []*controlplane.LocalSession
	dbPath   string
}

type envOptions struct {
	validity time.Duration
	gateways int // gateways on 127.0.0.1, 127.0.0.2, … with the same ports
}

func newEnv(t *testing.T, o envOptions) *env {
	t.Helper()
	if o.gateways == 0 {
		o.gateways = 1
	}
	e := &env{t: t, dbPath: filepath.Join(t.TempDir(), "controller.db")}
	e.cf = fakecf.New(cfToken, managedZone)
	cfSrv := httptest.NewServer(e.cf.Handler())
	t.Cleanup(cfSrv.Close)
	e.cfURL = cfSrv.URL + "/client/v4"

	var err error
	e.dns, err = dnsserver.Start([]string{managedZone, otherZone}, e.cf.TXT)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.dns.Close)

	var httpPort, tlsPort int
	for i := range o.gateways {
		ip := fmt.Sprintf("127.0.0.%d", i+1)
		hl, err := net.Listen("tcp", net.JoinHostPort(ip, fmt.Sprint(httpPort)))
		if err != nil {
			t.Fatal(err)
		}
		tl, err := net.Listen("tcp", net.JoinHostPort(ip, fmt.Sprint(tlsPort)))
		if err != nil {
			t.Fatal(err)
		}
		httpPort, tlsPort = hl.Addr().(*net.TCPAddr).Port, tl.Addr().(*net.TCPAddr).Port
		gw := gateway.New(fmt.Sprintf("gw%d", i+1), hl, tl)
		t.Cleanup(gw.Close)
		e.gws = append(e.gws, gw)
		e.gwTLS = append(e.gwTLS, tl.Addr().String())
		e.sessions = append(e.sessions, &controlplane.LocalSession{GW: gw, Latency: 20 * time.Millisecond})
	}

	var pebbleLog io.Writer
	if os.Getenv("S6_PEBBLE_LOG") != "" {
		pebbleLog = os.Stderr
	}
	e.pebble, err = pebblehost.Start(pebblehost.Options{HTTPPort: httpPort, TLSPort: tlsPort,
		Resolver: e.dns.Addr, Validity: o.validity, Log: pebbleLog})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.pebble.Close)
	return e
}

type ctlOptions struct {
	noPush                          bool // negative control: no SyncStorage
	disableHTTP01, disableTLSALPN01 bool
	token                           string
	renewalRatio                    float64
	renewCheck                      time.Duration
	onObtained                      func(string, bool)
	pushTimeout                     time.Duration
}

type ctl struct {
	*controller.Controller
	store *dbstore.Storage
	sync  *controlplane.SyncStorage
}

func (e *env) controller(o ctlOptions) *ctl {
	e.t.Helper()
	st, err := dbstore.Open(e.dbPath)
	if err != nil {
		e.t.Fatal(err)
	}
	st.LeaseTTL = 10 * time.Second
	c := &ctl{store: st}
	var storage certmagic.Storage = st
	if !o.noPush {
		c.sync = &controlplane.SyncStorage{Storage: st, PushTimeout: o.pushTimeout,
			Route: func(string) []controlplane.Session {
				out := make([]controlplane.Session, len(e.sessions))
				for i, s := range e.sessions {
					out[i] = s
				}
				return out
			}}
		storage = c.sync
	}
	token := o.token
	if token == "" {
		token = cfToken
	}
	logger := zap.NewNop()
	if os.Getenv("S6_CERTMAGIC_LOG") != "" {
		logger, _ = zap.NewDevelopment()
	}
	c.Controller, err = controller.New(controller.Options{
		Storage: storage, DirectoryURL: e.pebble.DirectoryURL, ACMETrust: e.pebble.ServerRoots,
		Email: "spike@rpmgr.test", ManagedZones: []string{managedZone},
		DNSProvider:           &dnsadapter.Provider{Client: cfclient.New(e.cfURL, token, nil), Marker: marker},
		Resolvers:             []string{e.dns.Addr},
		DNSPropagationTimeout: -1, // the fake publishes synchronously; no nameserver on port 53
		DisableHTTP01:         o.disableHTTP01, DisableTLSALPN01: o.disableTLSALPN01,
		RenewalWindowRatio: o.renewalRatio,
		CacheOptions:       certmagic.CacheOptions{RenewCheckInterval: o.renewCheck},
		PushCertificate: func(cert *tls.Certificate) error {
			for _, gw := range e.gws {
				if err := gw.ApplyCertificate(cert); err != nil {
					return err
				}
			}
			return nil
		},
		OnObtained: o.onObtained,
		Logger:     logger,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.Stop(); _ = st.Close() })
	return c
}

func (e *env) gatewayAnswers() (http, alpn, pushes int64) {
	for _, g := range e.gws {
		http += g.HTTPAnswered.Load()
		alpn += g.ALPNAnswered.Load()
		pushes += g.Pushes.Load()
	}
	return
}

// verifyChain checks that cert is valid for name and chains to Pebble's issuance root.
func (e *env) verifyChain(cert *tls.Certificate, name string) {
	e.t.Helper()
	roots, err := e.pebble.IssuanceRoots(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	inter := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			e.t.Fatal(err)
		}
		inter.AddCert(c)
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{DNSName: strings.Replace(name, "*", "x", 1),
		Roots: roots, Intermediates: inter}); err != nil {
		e.t.Fatalf("certificate for %s does not verify against Pebble's root: %v", name, err)
	}
}

func TestHTTP01AnsweredByGateway(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.controller(ctlOptions{disableTLSALPN01: true})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	name := "app." + otherZone
	if err := c.Manage(ctx, []string{name}); err != nil {
		t.Fatal(err)
	}
	cert, err := c.Load(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	e.verifyChain(cert, name)
	http, alpn, pushes := e.gatewayAnswers()
	if http < 1 || alpn != 0 || pushes < 2 || c.sync.Pushed.Load() < 1 {
		t.Fatalf("gateway answered http=%d alpn=%d, pushes=%d, controller pushed %d", http, alpn, pushes, c.sync.Pushed.Load())
	}
	if e.gws[0].HasChallenge(name) {
		t.Fatal("challenge still installed on the gateway after issuance")
	}
	// The issued certificate was pushed to the gateway, which now serves it.
	conn, err := tls.Dial("tcp", e.gwTLS[0], &tls.Config{ServerName: name, RootCAs: mustRoots(t, e)})
	if err != nil {
		t.Fatalf("gateway does not serve the pushed certificate: %v", err)
	}
	conn.Close()
	t.Logf("HTTP-01: gateway answered %d validation request(s); %d challenge update(s) pushed", http, pushes)
}

func mustRoots(t *testing.T, e *env) *x509.CertPool {
	t.Helper()
	r, err := e.pebble.IssuanceRoots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTLSALPN01AnsweredByGateway(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.controller(ctlOptions{disableHTTP01: true})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	name := "alpn." + otherZone
	if err := c.Manage(ctx, []string{name}); err != nil {
		t.Fatal(err)
	}
	cert, err := c.Load(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	e.verifyChain(cert, name)
	http, alpn, _ := e.gatewayAnswers()
	if alpn < 1 || http != 0 {
		t.Fatalf("gateway answered http=%d alpn=%d; want TLS-ALPN-01 only", http, alpn)
	}
	t.Logf("TLS-ALPN-01: gateway answered %d validation handshake(s)", alpn)
}

// Negative control: without the push, the CA validates against the gateway, which knows nothing,
// and issuance fails. This shows that the gateway, not certmagic's own listener, answers.
func TestWithoutPushValidationFails(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.controller(ctlOptions{noPush: true, disableTLSALPN01: true})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := c.Obtain(ctx, "nopush."+otherZone)
	if err == nil {
		t.Fatal("issuance succeeded although no gateway knew the challenge")
	}
	if e.pebble.ChallengePosts.Load() == 0 {
		t.Fatal("the CA was never asked to validate; the negative control did not run")
	}
	http, _, _ := e.gatewayAnswers()
	if http != 0 {
		t.Fatalf("gateway answered %d requests without a pushed challenge", http)
	}
	t.Logf("without push: issuance failed as expected (%v)", firstLine(err))
}

// A gateway that does not acknowledge the push fails Present, so the CA is never asked to
// validate a challenge no gateway can answer.
func TestUnacknowledgedPushFailsBeforeValidation(t *testing.T) {
	e := newEnv(t, envOptions{gateways: 2})
	e.sessions[1].Drop.Store(true)
	c := e.controller(ctlOptions{pushTimeout: 2 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.Obtain(ctx, "lost."+otherZone); err == nil {
		t.Fatal("issuance succeeded although a gateway never acknowledged the challenge")
	}
	if n := e.pebble.ChallengePosts.Load(); n != 0 {
		t.Fatalf("the CA was asked to validate %d time(s) without every gateway's acknowledgement", n)
	}
	if c.sync.Failed.Load() == 0 {
		t.Fatal("no failed push recorded")
	}
}

// With two gateways, every gateway of the group gets the challenge before validation, so it does
// not matter which one the CA reaches.
func TestChallengeReachesEveryGatewayOfTheGroup(t *testing.T) {
	e := newEnv(t, envOptions{gateways: 2})
	e.dns.SetA("second."+otherZone, net.IPv4(127, 0, 0, 2))
	c := e.controller(ctlOptions{disableTLSALPN01: true})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.Manage(ctx, []string{"first." + otherZone, "second." + otherZone}); err != nil {
		t.Fatal(err)
	}
	if e.gws[0].HTTPAnswered.Load() < 1 || e.gws[1].HTTPAnswered.Load() < 1 {
		t.Fatalf("answers per gateway: gw1=%d gw2=%d; both must have answered", e.gws[0].HTTPAnswered.Load(), e.gws[1].HTTPAnswered.Load())
	}
}

func TestDNS01WildcardViaFakeCloudflare(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.controller(ctlOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	names := []string{"apps." + managedZone, "*.apps." + managedZone}
	if err := c.Manage(ctx, names); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		cert, err := c.Load(ctx, n)
		if err != nil {
			t.Fatal(err)
		}
		e.verifyChain(cert, n)
	}
	if got := e.cf.Creates.Load(); got < 2 {
		t.Fatalf("TXT records created at the provider = %d, want ≥ 2", got)
	}
	if left := e.cf.Records(); len(left) != 0 {
		t.Fatalf("challenge TXT records left at the provider: %+v", left)
	}
	if e.cf.Deletes.Load() != e.cf.Creates.Load() {
		t.Fatalf("created %d, deleted %d", e.cf.Creates.Load(), e.cf.Deletes.Load())
	}
	if _, _, pushes := e.gatewayAnswers(); pushes != 0 {
		t.Fatalf("DNS-01 names pushed %d challenges to gateways", pushes)
	}
	t.Logf("DNS-01: %d TXT record(s) created and removed at the fake provider", e.cf.Creates.Load())
}

func TestDNS01WithRejectedTokenFails(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.controller(ctlOptions{token: "wrong-token"})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.Obtain(ctx, "denied."+managedZone); err == nil {
		t.Fatal("issuance succeeded with a token the provider rejects")
	}
	if e.cf.AuthFailures.Load() == 0 || len(e.cf.Records()) != 0 {
		t.Fatalf("auth failures %d, records %d", e.cf.AuthFailures.Load(), len(e.cf.Records()))
	}
}

func TestWildcardOutsideManagedZoneRefused(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.controller(ctlOptions{})
	err := c.Manage(context.Background(), []string{"*." + otherZone})
	if !errors.Is(err, controller.ErrWildcardNeedsManagedZone) {
		t.Fatalf("Manage(wildcard outside managed zones) = %v", err)
	}
	if e.pebble.NewOrders.Load() != 0 {
		t.Fatal("an order was placed for a wildcard that cannot be validated")
	}
}

// Two certmagic configurations on one storage, chosen per name.
func TestConfigurationChosenPerName(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.controller(ctlOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dnsNames := []string{"a." + managedZone, "*.w." + managedZone}
	httpNames := []string{"b." + otherZone, "c." + otherZone}
	if err := c.Manage(ctx, append(append([]string{}, dnsNames...), httpNames...)); err != nil {
		t.Fatal(err)
	}
	for _, n := range append(dnsNames, httpNames...) {
		if _, err := c.Load(ctx, n); err != nil {
			t.Fatalf("%s not in the shared storage: %v", n, err)
		}
	}
	_, _, pushes := e.gatewayAnswers()
	for _, n := range dnsNames {
		if e.gws[0].HasChallenge(n) {
			t.Fatalf("DNS-01 name %s was pushed to a gateway", n)
		}
	}
	if pushes < int64(2*len(httpNames)) || e.cf.Creates.Load() < int64(len(dnsNames)) {
		t.Fatalf("pushes=%d (want ≥ %d), TXT creates=%d (want ≥ %d)", pushes, 2*len(httpNames),
			e.cf.Creates.Load(), len(dnsNames))
	}
	for _, r := range e.cf.Records() {
		t.Fatalf("TXT left behind: %+v", r)
	}
}

// Renewal of both kinds of names, with short-lived certificates.
func TestRenewalOfBothKinds(t *testing.T) {
	e := newEnv(t, envOptions{validity: 40 * time.Second})
	var mu sync.Mutex
	renewed := map[string]int{}
	c := e.controller(ctlOptions{renewalRatio: 0.5, renewCheck: time.Second,
		onObtained: func(name string, renewal bool) {
			if renewal {
				mu.Lock()
				renewed[name]++
				mu.Unlock()
			}
		}})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	names := []string{"renew." + managedZone, "*.renew." + managedZone, "renew." + otherZone}
	if err := c.Manage(ctx, names); err != nil {
		t.Fatal(err)
	}
	first := map[string]string{}
	for _, n := range names {
		cert, err := c.Load(ctx, n)
		if err != nil {
			t.Fatal(err)
		}
		first[n] = cert.Leaf.SerialNumber.String()
	}
	creates0 := e.cf.Creates.Load()
	_, _, pushes0 := e.gatewayAnswers()
	for {
		mu.Lock()
		done := true
		for _, n := range names {
			done = done && renewed[n] > 0
		}
		mu.Unlock()
		if done {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("not all names renewed in time: %v", renewed)
		case <-time.After(500 * time.Millisecond):
		}
	}
	for _, n := range names {
		cert, err := c.Load(ctx, n)
		if err != nil {
			t.Fatal(err)
		}
		if cert.Leaf.SerialNumber.String() == first[n] {
			t.Fatalf("%s: renewal kept the old certificate", n)
		}
		e.verifyChain(cert, n)
	}
	_, _, pushes1 := e.gatewayAnswers()
	if e.cf.Creates.Load() <= creates0 || pushes1 <= pushes0 {
		t.Fatalf("renewal did not validate again: TXT creates %d→%d, pushes %d→%d",
			creates0, e.cf.Creates.Load(), pushes0, pushes1)
	}
	t.Logf("renewed: %v", renewed)
}

func firstLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
