// SPDX-License-Identifier: Apache-2.0

// Command s6run runs the parts of spike S6 as separate processes, for the maintainer's external
// run against Let's Encrypt staging and a real Cloudflare zone (D37), and for rehearsing that run
// locally against Pebble and the fake Cloudflare API. See ../../README.md, "External run".
//
//	s6run testbed    --state-dir DIR --cf-token-file F [--zones managed.test,other.test]
//	s6run gateway    --http :80 --tls :443 --control 127.0.0.1:9180 --control-token-file F
//	s6run controller --id a --db FILE --directory URL [--acme-ca-file F] --email E
//	                 --cf-token-file F [--cf-base-url URL] --dns01-zone ZONE [--resolver ADDR]
//	                 [--dns-propagation-timeout D] --gateway-control URL --control-token-file F
//	                 --names n1,n2,… [--force-renew] [--disable-ari] [--manage-for D]
//	                 [--disable-http01 | --disable-tlsalpn01]
//
// Secrets (the Cloudflare token, the control token) are read from files that must be private
// (mode 0600); they never appear on the command line.
package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: s6run testbed|gateway|controller [flags]")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "testbed":
		err = testbed(ctx, os.Args[2:])
	case "gateway":
		err = runGateway(ctx, os.Args[2:])
	case "controller":
		err = runController(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "s6run:", err)
		os.Exit(1)
	}
}

func readSecret(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s is readable by group or others (mode %v); use chmod 600", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	s := strings.TrimSpace(string(b))
	if err == nil && s == "" {
		err = fmt.Errorf("%s is empty", path)
	}
	return s, err
}

func emit(v map[string]any) {
	v["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}

// testbedState is written by "testbed" and read by the rehearsal script.
type testbedState struct {
	Directory  string `json:"directory"`
	ACMECAFile string `json:"acme_ca_file"`
	CFBaseURL  string `json:"cf_base_url"`
	Resolver   string `json:"resolver"`
	HTTPPort   int    `json:"http_port"`
	TLSPort    int    `json:"tls_port"`
}

func testbed(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("testbed", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "directory for testbed.json and the ACME server's CA file")
	tokenFile := fs.String("cf-token-file", "", "token the fake Cloudflare API accepts")
	zones := fs.String("zones", "managed.test,other.test", "zones of the test DNS server; the first is at the fake Cloudflare account")
	validity := fs.Duration("validity", 0, "certificate lifetime (0: Pebble's default)")
	_ = fs.Parse(args)
	token, err := readSecret(*tokenFile)
	if err != nil {
		return err
	}
	zl := strings.Split(*zones, ",")
	cf := fakecf.New(token, zl[0])
	cfLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	go func() { _ = http.Serve(cfLn, cf.Handler()) }()
	dns, err := dnsserver.Start(zl, cf.TXT)
	if err != nil {
		return err
	}
	defer dns.Close()
	httpPort, tlsPort := freePort(), freePort()
	p, err := pebblehost.Start(pebblehost.Options{HTTPPort: httpPort, TLSPort: tlsPort,
		Resolver: dns.Addr, Validity: *validity, Log: os.Stderr})
	if err != nil {
		return err
	}
	defer p.Close()
	caFile := filepath.Join(*stateDir, "acme-server-ca.pem")
	if err := os.WriteFile(caFile, p.ServerCertPEM(), 0o600); err != nil {
		return err
	}
	st := testbedState{Directory: p.DirectoryURL, ACMECAFile: caFile,
		CFBaseURL: "http://" + cfLn.Addr().String() + "/client/v4", Resolver: dns.Addr,
		HTTPPort: httpPort, TLSPort: tlsPort}
	b, _ := json.MarshalIndent(st, "", "  ")
	if err := os.WriteFile(filepath.Join(*stateDir, "testbed.json"), b, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "testbed ready: %s\n", b)
	<-ctx.Done()
	emit(map[string]any{"event": "testbed_orders", "new_orders": p.NewOrders.Load(),
		"challenge_posts": p.ChallengePosts.Load(), "txt_creates": cf.Creates.Load(),
		"txt_deletes": cf.Deletes.Load(), "txt_left": len(cf.Records())})
	return nil
}

func runGateway(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	httpAddr := fs.String("http", ":80", "HTTP listener (ACME HTTP-01)")
	tlsAddr := fs.String("tls", ":443", "TLS listener (ACME TLS-ALPN-01, issued certificates)")
	control := fs.String("control", "127.0.0.1:9180", "control endpoint; keep it on loopback")
	tokenFile := fs.String("control-token-file", "", "bearer token of the control endpoint")
	_ = fs.Parse(args)
	token, err := readSecret(*tokenFile)
	if err != nil {
		return err
	}
	hl, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		return err
	}
	tl, err := net.Listen("tcp", *tlsAddr)
	if err != nil {
		return err
	}
	cl, err := net.Listen("tcp", *control)
	if err != nil {
		return err
	}
	g := gateway.New("gw1", hl, tl)
	defer g.Close()
	srv := &http.Server{Handler: gateway.ControlHandler(g, token), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(cl) }()
	defer srv.Close()
	emit(map[string]any{"event": "gateway_ready", "http": hl.Addr().String(), "tls": tl.Addr().String()})
	<-ctx.Done()
	emit(map[string]any{"event": "gateway_stats", "http01_answered": g.HTTPAnswered.Load(),
		"tlsalpn01_answered": g.ALPNAnswered.Load(), "challenge_updates": g.Pushes.Load()})
	return nil
}

func runController(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("controller", flag.ExitOnError)
	id := fs.String("id", "a", "replica name, for the output")
	db := fs.String("db", "", "SQLite file shared by the replicas")
	directory := fs.String("directory", "https://acme-staging-v02.api.letsencrypt.org/directory", "ACME directory")
	acmeCA := fs.String("acme-ca-file", "", "extra CA for the ACME server's TLS (Pebble only)")
	email := fs.String("email", "", "ACME account e-mail")
	cfTokenFile := fs.String("cf-token-file", "", "Cloudflare API token (Zone Read, DNS Write)")
	cfBase := fs.String("cf-base-url", cfclient.DefaultBaseURL, "Cloudflare API base URL (spike only; the product compiles it in)")
	dnsZones := fs.String("dns01-zone", "", "comma-separated managed zones: names below them use DNS-01")
	resolver := fs.String("resolver", "", "DNS server for finding a name's zone (default: system)")
	propagation := fs.Duration("dns-propagation-timeout", 0, "TXT propagation check (0: 2 min default, -1ns: off)")
	gwControl := fs.String("gateway-control", "http://127.0.0.1:9180", "gateway control endpoint")
	ctlTokenFile := fs.String("control-token-file", "", "bearer token of the gateway control endpoint")
	names := fs.String("names", "", "comma-separated names to obtain")
	forceRenew := fs.Bool("force-renew", false, "renew every name once after obtaining it")
	disableARI := fs.Bool("disable-ari", false, "renew by the lifetime ratio only")
	noHTTP01 := fs.Bool("disable-http01", false, "do not use HTTP-01 (TLS-ALPN-01 only for non-managed names)")
	noTLSALPN01 := fs.Bool("disable-tlsalpn01", false, "do not use TLS-ALPN-01")
	manageFor := fs.Duration("manage-for", 0, "keep managing (renewing) the names for this long")
	_ = fs.Parse(args)

	cfToken, err := readSecret(*cfTokenFile)
	if err != nil {
		return err
	}
	ctlToken, err := readSecret(*ctlTokenFile)
	if err != nil {
		return err
	}
	var trust *x509.CertPool
	if *acmeCA != "" {
		pemBytes, err := os.ReadFile(*acmeCA)
		if err != nil {
			return err
		}
		trust = x509.NewCertPool()
		if !trust.AppendCertsFromPEM(pemBytes) {
			return errors.New("no certificate in --acme-ca-file")
		}
	}
	st, err := dbstore.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	sess := &controlplane.HTTPSession{ID: "gw1", URL: *gwControl, Token: ctlToken}
	storage := &controlplane.SyncStorage{Storage: st, Route: func(string) []controlplane.Session {
		return []controlplane.Session{sess}
	}}
	var resolvers []string
	if *resolver != "" {
		resolvers = []string{*resolver}
	}
	logger, _ := zap.NewProduction()
	logger = logger.With(zap.String("replica", *id))
	marker := "rpmgr s6-spike " + randHex(4)
	ctl, err := controller.New(controller.Options{
		Storage: storage, DirectoryURL: *directory, ACMETrust: trust, Email: *email,
		ManagedZones:          splitList(*dnsZones),
		DNSProvider:           &dnsadapter.Provider{Client: cfclient.New(*cfBase, cfToken, nil), Marker: marker},
		Resolvers:             resolvers,
		DNSPropagationTimeout: *propagation,
		DisableARI:            *disableARI,
		DisableHTTP01:         *noHTTP01,
		DisableTLSALPN01:      *noTLSALPN01,
		CacheOptions:          certmagic.CacheOptions{RenewCheckInterval: 10 * time.Second},
		OnObtained: func(name string, renewal bool) {
			emit(map[string]any{"event": "obtained", "replica": *id, "name": name, "renewal": renewal})
		},
		Logger: logger,
	})
	if err != nil {
		return err
	}
	defer ctl.Stop()

	list := splitList(*names)
	if len(list) == 0 {
		return errors.New("--names is empty")
	}
	var wg sync.WaitGroup
	errs := make([]error, len(list))
	for i, n := range list {
		wg.Go(func() { errs[i] = ctl.Obtain(ctx, n) })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return err
	}
	report := func(stage string) error {
		for _, n := range list {
			c, err := ctl.Load(ctx, n)
			if err != nil {
				return err
			}
			emit(map[string]any{"event": stage, "replica": *id, "name": n,
				"serial": c.Leaf.SerialNumber.String(), "issuer": c.Leaf.Issuer.CommonName,
				"sans": c.Leaf.DNSNames, "not_before": c.Leaf.NotBefore, "not_after": c.Leaf.NotAfter,
				"dns01": ctl.IsManaged(n)})
		}
		return nil
	}
	if err := report("certificate"); err != nil {
		return err
	}
	if *forceRenew {
		for i, n := range list {
			wg.Go(func() { errs[i] = ctl.Renew(ctx, n, true) })
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			return err
		}
		if err := report("renewed_certificate"); err != nil {
			return err
		}
	}
	if *manageFor > 0 {
		if err := ctl.Manage(ctx, list); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
		case <-time.After(*manageFor):
		}
	}
	emit(map[string]any{"event": "lock_waits", "replica": *id, "n": st.Waits.Load()})
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func freePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
