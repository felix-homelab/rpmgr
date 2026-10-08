// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/enroll"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// drainWait is how long a stopping controller waits after Drain for its agents to move
// (docs/03-connections.md, "Timeouts, keepalive and backoff"); a variable for tests.
var drainWait = 5 * time.Second

// RunOptions configure Run.
type RunOptions struct {
	Config  config.Controller
	Version string
	// Sources compile the agents' snapshots.
	Sources []snapshot.Source
	Getenv  func(string) string // os.Getenv
	Now     func() time.Time    // time.Now
	Logger  *slog.Logger
	// Listening, if set, is called once every listener is up.
	Listening func()
	// Listener, if set, takes the place of listen.https: all-in-one hands it the connections its
	// gateway routes to the controller, and its own control session.
	Listener net.Listener
	// Registry, if set, receives the controller's metrics and Run serves no admin listener;
	// Readiness then gets the controller's readiness check.
	Registry  *prometheus.Registry
	Readiness func(check func(context.Context) error)
}

// ErrNotInitialised is returned by Run for a database without an installation.
var ErrNotInitialised = errors.New("controller: the database holds no installation; run `rpmgr controller init` first")

// Run runs a controller from its boot file until ctx ends (docs/02-architecture.md,
// docs/10-operations.md): the database with its lifetime lock and migrations, the CA, the agent
// endpoint and the web server on port 443 split by name, the redirect on port 80, the singleton
// jobs, and the admin listener. On the way out it drains its control sessions.
func Run(ctx context.Context, o RunOptions) error {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	cfg := o.Config
	public, err := url.Parse(cfg.PublicURL)
	if err != nil {
		return err
	}
	kek, err := loadKEK(cfg, o.Getenv)
	if err != nil {
		return err
	}
	sealer, err := secret.NewSealer(kek)
	if err != nil {
		return err
	}
	db, err := store.OpenSQLite(ctx, cfg.Database.DSN, store.SQLiteOptions{Lock: true})
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	dir, err := migrations.Dir(db.Dialect)
	if err != nil {
		return err
	}
	if n, err := store.Migrate(ctx, db, dir); err != nil {
		return err
	} else if n > 0 {
		o.Logger.Info("applied database migrations", "files", n)
	}
	sys, err := authz.System(ctx, "controller", "rpmgr controller", audit.SystemScopes(db))
	if err != nil {
		return err
	}
	if ok, err := db.ReadClient().Instance.Query().Exist(sys); err != nil {
		return err
	} else if !ok {
		return ErrNotInitialised
	}
	ca, err := pki.LoadCA(sys, db, sealer, o.Now)
	if err != nil {
		return err
	}
	td := ca.TrustDomain()
	stateDir := filepath.Dir(cfg.Database.DSN)
	rl, err := revlog.Open(filepath.Join(stateDir, "revocations.log"), o.Now)
	if err != nil {
		return err
	}
	nodeID, err := nodeIdentity(filepath.Join(stateDir, "controller-node.id"))
	if err != nil {
		return err
	}
	node, err := ca.NodeCertificate(sys, db, nodeID)
	if err != nil {
		return err
	}
	holder := pki.NewHolder(node)
	endpoints := []string{cfg.PublicURL}

	sessions := NewSessions(SessionsOptions{DB: db, CA: ca, Node: nodeID, Version: o.Version, Sys: sys, Now: o.Now, RevLog: rl, Sealer: sealer,
		Logger:   o.Logger,
		Compiler: &snapshot.Compiler{Sources: o.Sources, Endpoints: func() []string { return endpoints }}})
	reg := o.Registry
	if reg == nil {
		reg = telemetry.NewRegistry()
	}
	if err := sessions.Register(reg); err != nil {
		return err
	}
	ready := NewReadiness(db, dir, sys)

	roots := x509.NewCertPool()
	roots.AddCert(ca.Root())
	agentTLS := pki.AgentEndpointConfig(holder, roots, pki.Expect{TrustDomain: td,
		Kinds: []pki.Kind{pki.KindConnector, pki.KindGateway}, Denied: sessions.Denied}, o.Now, ReauthChecks(db, sys))
	agents := NewAgentServer(agentTLS, td)
	agentv1.RegisterControlServer(agents, sessions)
	agentv1.RegisterReauthServer(agents, NewReauthService(sessions))
	agentv1.RegisterEnrollmentServer(agents, enroll.NewService(db, ca, endpoints, o.Now))

	cert, err := newWebCert(cfg.TLS.CertFile, cfg.TLS.KeyFile, public.Hostname(), o.Logger)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/.well-known/rpmgr/trust-bundle", enroll.TrustBundleHandler(ca.Root()))
	web := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
		ErrorLog: slog.NewLogLogger(o.Logger.Handler(), slog.LevelDebug)}

	ln := o.Listener
	if ln == nil {
		if ln, err = net.Listen("tcp", cfg.Listen.HTTPS); err != nil {
			return err
		}
	}
	var redirect *http.Server
	var httpLn net.Listener
	if *cfg.Listen.HTTP != "" {
		if httpLn, err = net.Listen("tcp", *cfg.Listen.HTTP); err != nil {
			_ = ln.Close()
			return err
		}
		redirect = &http.Server{Handler: redirectHandler(public), ReadHeaderTimeout: 10 * time.Second}
	}
	split := NewSplitter(td, ln.Addr())

	run, stop := context.WithCancel(ctx)
	defer stop()
	errs := make(chan error, 8)
	serve := func(name string, f func() error) {
		go func() {
			if err := f(); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				errs <- fmt.Errorf("controller: %s: %w", name, err)
			}
		}()
	}
	sessionsDone := make(chan struct{})
	go func() { sessions.Run(run); close(sessionsDone) }()
	leases := lease.New(db, nodeID, o.Now)
	caOpts := CAOptions{DB: db, CA: ca, Sealer: sealer, Leases: leases, Now: o.Now, Logger: o.Logger}
	go leases.Run(sys, CARotation(caOpts), func(err error) { o.Logger.Warn("CA rotation job", "error", err) })
	go ReloadCA(sys, caOpts)
	go RenewNodeCertificate(sys, NodeCertOptions{CA: ca, DB: db, Sys: sys, NodeID: nodeID, Holder: holder, Now: o.Now, Logger: o.Logger})
	serve("agent endpoint", func() error { return agents.Serve(split.Agents()) })
	serve("web server", func() error {
		return web.Serve(tls.NewListener(split.Web(), &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: cert.GetCertificate}))
	})
	serve("port 443", func() error { return split.Serve(ln) })
	if redirect != nil {
		serve("port 80", func() error { return redirect.Serve(httpLn) })
	}
	if o.Registry == nil {
		serve("admin listener", func() error { return telemetry.ServeAdmin(run, cfg.Listen.Admin, reg, ready.Ready) })
	} else if o.Readiness != nil {
		o.Readiness(ready.Ready)
	}
	o.Logger.Info("controller running", "trust_domain", td, "node", nodeID, "https", ln.Addr().String(), "public_url", cfg.PublicURL)
	if o.Listening != nil {
		o.Listening()
	}

	var result error
	select {
	case <-ctx.Done():
	case result = <-errs:
	}
	// Drain: agents move to another endpoint, then the servers stop.
	sessions.Drain(time.Now().Add(drainWait))
	waitUntil := time.Now().Add(drainWait)
	for time.Now().Before(waitUntil) && len(sessions.Connected()) > 0 {
		time.Sleep(100 * time.Millisecond)
	}
	_ = ln.Close()
	if httpLn != nil {
		_ = redirect.Close()
	}
	stopped := make(chan struct{})
	go func() { agents.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(drainWait):
		agents.Stop()
	}
	shut, cancel := context.WithTimeout(context.Background(), drainWait)
	defer cancel()
	_ = web.Shutdown(shut)
	stop()
	<-sessionsDone
	return result
}

// loadKEK loads the KEK the boot file names; Run never creates one.
func loadKEK(cfg config.Controller, getenv func(string) string) (secret.KEK, error) {
	switch cfg.KEK.Source {
	case config.KEKFile:
		return secret.LoadKEKFile(cfg.KEK.Path)
	case config.KEKSystemdCredential:
		return secret.LoadSystemdCredential(cfg.KEK.Name, getenv)
	}
	return secret.KEK{}, fmt.Errorf("controller: kek.source %q", cfg.KEK.Source)
}

// nodeIdentity returns this replica's node ID, kept in path so that a restart presents the same
// identity; the first start creates it.
func nodeIdentity(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: in the configured state directory
	if err == nil {
		id := strings.TrimSpace(string(b))
		if !ids.Valid("ctn", id) {
			return "", fmt.Errorf("controller: %s does not hold a node ID", path)
		}
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	id := ids.New("ctn")
	if err := writeNew(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

// redirectHandler sends every plain-HTTP request to the same path on the public URL.
func redirectHandler(public *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := *public
		target.Path, target.RawQuery = r.URL.Path, r.URL.RawQuery
		http.Redirect(w, r, target.String(), http.StatusMovedPermanently)
	})
}
