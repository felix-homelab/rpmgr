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
	"sync"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/enroll"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/installsh"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/proxyenv"
	"github.com/felix-homelab/rpmgr/internal/ratelimit"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/websession"
	"github.com/felix-homelab/rpmgr/internal/webui"
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
	// ACMERoots, if set, trusts the ACME CA's TLS certificate instead of the system roots (tests).
	ACMERoots *x509.CertPool
	Getenv    func(string) string // os.Getenv
	Now       func() time.Time    // time.Now
	Logger    *slog.Logger
	// Listening, if set, is called once every listener is up.
	Listening func()
	// Listener, if set, takes the place of listen.https: all-in-one hands it the connections its
	// gateway routes to the controller, and its own control session.
	Listener net.Listener
	// Registry, if set, receives the controller's metrics and Run serves no admin listener;
	// Readiness then gets the controller's readiness check.
	Registry  telemetry.Registry
	Readiness func(check func(context.Context) error)
	// NoACME keeps Run from obtaining the public URL's certificate: all-in-one's init runs the
	// controller in memory only.
	NoACME bool
	// Port80, if set, receives the controller's port-80 handler (ACME HTTP-01 for the public URL,
	// then the redirect), which all-in-one's gateway serves for its own names when no route
	// serves them.
	Port80 func(http.Handler)
	// ACMEAfter, if set, holds back obtaining the public URL's certificate until it is closed:
	// all-in-one's gateway, through which the CA validates, must listen first.
	ACMEAfter <-chan struct{}
	// ReleaseSource and ReleaseRoots, if set, replace GitHub and the compiled-in root keys of the
	// release check (tests).
	ReleaseSource release.Source
	ReleaseRoots  []release.PublicKey
	// KEK, if set, is used instead of loading the boot file's: all-in-one's init passes the KEK it
	// has just obtained, as a new systemd credential is readable only inside a service.
	KEK *secret.KEK
}

// ErrNotInitialised is returned by Run for a database without an installation.
var ErrNotInitialised = errors.New("controller: the database holds no installation; run `rpmgr controller init` first")

// Run runs a controller from its boot file until ctx ends (docs/02-architecture.md,
// docs/10-operations.md): the database with its lifetime lock and migrations, the CA, the agent
// endpoint and the web server on port 443 split by name, the redirect on port 80, the public URL's
// certificate, the singleton jobs, and the admin listener. On the way out it drains its control
// sessions.
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
	// The ACME CA, GitHub and a domain's HTTP token are reached through the proxy variables, as
	// the connector reads them (D93); a value that is no proxy URL stops the start.
	proxy, err := proxyenv.Requests(o.Getenv)
	if err != nil {
		return fmt.Errorf("controller: %w", err)
	}
	var kek secret.KEK
	if o.KEK != nil {
		kek = *o.KEK
	} else if kek, err = loadKEK(cfg, o.Getenv); err != nil {
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
	ca, err := castore.LoadCA(sys, db, sealer, o.Now)
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
	shipper := &RevocationShipper{Path: filepath.Join(stateDir, "revocations.log"), Sink: cfg.RevocationLog.Sink, Replica: nodeID, Logger: o.Logger}

	sessions := NewSessions(SessionsOptions{DB: db, CA: ca, Node: nodeID, Version: o.Version, Sys: sys, Now: o.Now, RevLog: rl, Sealer: sealer,
		Logger:   o.Logger,
		Compiler: &snapshot.Compiler{Sources: o.Sources, Endpoints: AgentEndpoints(cfg.PublicURL), Offer: snapshot.ReleaseOfferAt(cfg.PublicURL)}})
	reg := o.Registry
	if reg == nil {
		reg = telemetry.NewRegistry()
	}
	for _, c := range shipper.Collectors() {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	if err := sessions.Register(reg); err != nil {
		return err
	}
	metrics, err := NewMetrics(reg, db, sys, o.Now)
	if err != nil {
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
	enrollment := enroll.NewService(db, ca, cfg.PublicURL, o.Now)
	enrollment.RevLog, enrollment.Logger, enrollment.Denied = rl, o.Logger, sessions.ApplyDenyList
	enrollment.Refused = metrics.Refused(LimitEnrollment)
	agentv1.RegisterEnrollmentServer(agents, enrollment)

	leases := lease.New(db, nodeID, o.Now)
	acmeStore := acme.NewStorage(db, sys, sealer, leases, o.Now)
	defer acmeStore.Close()
	certManager := acme.NewManager(acme.ManagerOptions{DB: db, Sys: sys, Sealer: sealer, Proxy: proxy, TrustedRoots: o.ACMERoots, Logger: o.Logger,
		Storage: acme.NewChallengeStorage(acmeStore, sessions, acme.GatewaysServing(db, sys))})
	var own *acme.Own
	if cfg.TLS.CertFile == "" && !o.NoACME && acme.Eligible(public.Hostname()) {
		if own, err = acme.NewOwn(acme.OwnOptions{DB: db, Sys: sys, Storage: acmeStore, Host: public.Hostname(),
			NoHTTP01: *cfg.Listen.HTTP == "" && o.Port80 == nil, Proxy: proxy, TrustedRoots: o.ACMERoots, Logger: o.Logger}); err != nil {
			return err
		}
		defer own.Stop()
		if err := own.Load(sys); err != nil {
			o.Logger.Warn("cannot load the public URL's stored certificate", "error", err)
		}
	}
	cert, err := newWebCert(cfg.TLS.CertFile, cfg.TLS.KeyFile, public.Hostname(), own, o.Logger)
	if err != nil {
		return err
	}
	webTLS := WebTLS(cert.GetCertificate, own != nil)
	port80 := RedirectHandler(public)
	if own != nil {
		port80 = own.HTTPHandler(port80)
	}
	if o.Port80 != nil {
		o.Port80(port80)
	}
	// The public API; its services are mounted on mux as they are added.
	pageKey, err := sealer.DeriveKey("api-page-token")
	if err != nil {
		return err
	}
	previewKey, err := sealer.DeriveKey("gateway-page-preview")
	if err != nil {
		return err
	}
	previews := &apisvc.PagePreviews{DB: db, Sys: sys, Key: previewKey, Now: o.Now}
	webSessions := websession.New(websession.Options{DB: db, Sys: sys, RevLog: rl, Now: o.Now, Logger: o.Logger})
	acc := accounts.New(db, sys, o.Now)
	acc.ResetLog, acc.ResetLogger = rl, o.Logger
	tokens := &accounts.Tokens{Accounts: acc, RevLog: rl, Logger: o.Logger}
	// A new rollout or upload asks the release check to run at once (D125), and so does an Instance
	// Admin's "Check now".
	mirror := &release.Mirror{Dir: filepath.Join(stateDir, "dl"), Version: o.Version, Roots: o.ReleaseRoots, Now: o.Now}
	if mirror.Roots == nil {
		mirror.Roots = release.Roots()
	}
	checks := NewReleaseChecks(mirror)
	apiServer, err := api.New(api.Options{DB: db, Sys: sys, Sealer: sealer, Resolver: api.StoreResolver(db, sys),
		OperatorsMayEnroll: api.StoreOperatorsMayEnroll(db, sys), PageKey: pageKey, Now: o.Now, Logger: o.Logger,
		Authenticator: apisvc.Credentials{Sessions: webSessions, Tokens: tokens,
			Failures: ratelimit.NewBackoff(apisvc.FreeFailures, apisvc.FirstDelay, apisvc.MaxDelay, o.Now)}, TokenStepUp: tokens.StepUpAt, Origins: origins(db, sys, public), RequireMFA: api.StoreRequireMFA(db, sys),
		RestoreReview: api.StoreRestoreReview(db, sys),
		ApplyStatus: func(ctx context.Context, org string, rev *rpmgrv1.Revision) (*rpmgrv1.ApplyStatus, error) {
			return apisvc.ApplyStatusOf(ctx, db.ReadClient(), org, store.Revision{DBEpoch: rev.GetDbEpoch(), Seq: rev.GetSeq()}, o.Now())
		}})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/.well-known/rpmgr/trust-bundle", enroll.TrustBundleHandler(ca.Root()))
	revocations := &apisvc.Revocations{Sys: sys, RevLog: rl, Logger: o.Logger, Denied: sessions.ApplyDenyList}
	mfa := &accounts.MFA{Accounts: acc, Sealer: sealer, RevLog: rl, Logger: o.Logger}
	relay := &apisvc.Relay{DB: db, Sys: sys, Sealer: sealer}
	auth := apisvc.NewAuth(mfa, webSessions, o.Now)
	auth.Tokens = tokens
	auth.IPLimit.OnRefuse, auth.Backoff.OnRefuse = metrics.Refused(LimitLogin), metrics.Refused(LimitAccount)
	auth.ResetLimit.OnRefuse = metrics.Refused(LimitPasswordReset)
	auth.Mail, auth.PublicURL, auth.Logger = relay, cfg.PublicURL, o.Logger
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_auth_proto.Services().ByName("AuthService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewAuthServiceHandler(auth, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_user_proto.Services().ByName("UserService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewUserServiceHandler(&apisvc.User{MFA: mfa, Sessions: webSessions,
				Issuer: "rpmgr " + public.Hostname(), API: apiServer, PublicURL: cfg.PublicURL, Backoff: auth.Backoff,
				RequireMFA: api.StoreRequireMFA(db, sys), RestoreReview: api.StoreRestoreReview(db, sys)}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_gateway_proto.Services().ByName("GatewayService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewGatewayServiceHandler(&apisvc.Gateways{DB: db, API: apiServer, Revocations: revocations, Previews: previews, Now: o.Now}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_connector_proto.Services().ByName("ConnectorService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewConnectorServiceHandler(&apisvc.Connectors{DB: db, API: apiServer, Revocations: revocations, Now: o.Now}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_domain_proto.Services().ByName("DomainService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewDomainServiceHandler(&apisvc.Domains{DB: db, API: apiServer, Sys: sys, Now: o.Now,
				TXT: &domains.TXTVerifier{}, HTTP: &domains.HTTPVerifier{Proxy: proxy}}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_status_proto.Services().ByName("StatusService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewStatusServiceHandler(&apisvc.Status{DB: db, Sys: sys, Now: o.Now}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_route_proto.Services().ByName("RouteService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewRouteServiceHandler(&apisvc.Routes{DB: db, API: apiServer, Sys: sys, Prober: sessions, Now: o.Now}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_certificate_proto.Services().ByName("CertificateService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewCertificateServiceHandler(&apisvc.Certificates{DB: db, API: apiServer, Sealer: sealer,
				Renewer: certManager, Background: sys, Now: o.Now}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_manifest_proto.Services().ByName("ManifestService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewManifestServiceHandler(&apisvc.Manifests{DB: db}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_pki_proto.Services().ByName("PkiService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewPkiServiceHandler(&apisvc.Pki{DB: db, Sys: sys, Sealer: sealer, CA: ca, Now: o.Now}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_release_proto.Services().ByName("ReleaseService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewReleaseServiceHandler(&apisvc.Releases{DB: db, Sys: sys, API: apiServer, Version: o.Version, MinAgentVersion: MinAgentVersion(o.Version), MirrorNow: checks.Wake,
				Checks: checks, Roots: o.ReleaseRoots, Now: o.Now}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_metrics_proto.Services().ByName("MetricsService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewMetricsServiceHandler(&apisvc.Metrics{DB: db, Now: o.Now}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_audit_proto.Services().ByName("AuditService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewAuditServiceHandler(&apisvc.Audit{DB: db, Sys: sys, API: apiServer}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_settings_proto.Services().ByName("SettingsService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewSettingsServiceHandler(&apisvc.Settings{DB: db, Sys: sys, Sealer: sealer, Now: o.Now, RevocationLog: shipper.Status}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_policy_proto.Services().ByName("PolicyService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewPolicyServiceHandler(&apisvc.Policies{DB: db, API: apiServer, Sys: sys}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_enrollment_proto.Services().ByName("EnrollmentService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewEnrollmentServiceHandler(&apisvc.Enrollment{DB: db, API: apiServer, Now: o.Now,
				PublicURL: cfg.PublicURL, RootPin: pki.RootPin(ca.Root())}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_token_proto.Services().ByName("TokenService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewTokenServiceHandler(&apisvc.Token{Tokens: tokens, API: apiServer}, opts...)
		}); err != nil {
		return err
	}
	if err := apiServer.Mount(mux, rpmgrv1.File_rpmgr_v1_org_proto.Services().ByName("OrgService"),
		func(opts ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewOrgServiceHandler(&apisvc.Org{Members: &accounts.Members{Accounts: acc, RevLog: rl, Logger: o.Logger}, Tokens: tokens,
				API: apiServer, PublicURL: cfg.PublicURL, Now: o.Now, Mail: relay, Logger: o.Logger}, opts...)
		}); err != nil {
		return err
	}
	ui, err := webui.Handler()
	if err != nil {
		return err
	}
	mux.Handle("/dl/", mirror.Handler())     // the controller's own release, for /install.sh (D59)
	mux.Handle(apisvc.PreviewPath, previews) // previews of gateway pages, by signed link (D136)
	mux.Handle("/install.sh", installsh.Handler(o.Version, mirror.Roots))
	mux.Handle("/", ui) // every path the API, the trust bundle and /dl/ do not take
	// The port-80 handler, with ACME's HTTP-01 answers, stays outside misdirected: it has no TLS.
	web := &http.Server{Handler: misdirected(cert.HSTS(mux)), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
		Protocols: webProtocols(), HTTP2: webHTTP2(), ErrorLog: slog.NewLogLogger(o.Logger.Handler(), slog.LevelDebug)}

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
		redirect = &http.Server{Handler: port80, ReadHeaderTimeout: 10 * time.Second}
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
	// The background jobs end with jobs; Run waits for them before it closes the database.
	jobs, stopJobs := context.WithCancel(sys)
	defer stopJobs()
	var bg sync.WaitGroup
	job := func(j lease.Job, name string) {
		bg.Go(func() { leases.Run(jobs, j, func(err error) { o.Logger.Warn(name, "error", err) }) })
	}
	caOpts := CAOptions{DB: db, CA: ca, Sealer: sealer, Leases: leases, Now: o.Now, Logger: o.Logger}
	job(CARotation(caOpts), "CA rotation job")
	job(certManager.Job(acme.JobEvery), "ACME job")
	job(apiServer.PruneJob(api.PruneEvery), "request_id pruning job")
	job(DomainCheckJob(DomainCheckOptions{DB: db, TXT: &domains.TXTVerifier{}, HTTP: &domains.HTTPVerifier{Proxy: proxy}, Now: o.Now,
		Logger: o.Logger}), "domain check job")
	job(PurgeJob(PurgeOptions{DB: db, RevLog: rl, Logger: o.Logger, Denied: sessions.ApplyDenyList, Now: o.Now}), "agent purge job")
	cpOpts := CheckpointOptions{DB: db, CA: ca, Log: &audit.CheckpointLog{Path: filepath.Join(stateDir, "audit-checkpoints.log")},
		Leases: leases, Now: o.Now, Logger: o.Logger}
	job(CheckpointJob(cpOpts), "audit checkpoint job")
	job(RetentionJob(cpOpts), "audit retention job")
	job(RollupJob(RollupOptions{DB: db, Leases: leases, Now: o.Now, Logger: o.Logger}), "traffic rollup job")
	job(EventsJob(RollupOptions{DB: db, Leases: leases, Now: o.Now, Logger: o.Logger}), "events job")
	job(AlertJob(AlertOptions{DB: db, Leases: leases, Now: o.Now, Logger: o.Logger, RevocationLog: shipper.Status}), "alert job")
	job(RolloutJob(RolloutOptions{DB: db, Now: o.Now, Logger: o.Logger}), "rollout job")
	bg.Go(func() { ReloadCA(jobs, caOpts) })
	bg.Go(func() { shipper.Run(jobs) })
	bg.Go(func() {
		ReleaseCheck(jobs, ReleaseCheckOptions{DB: db, Mirror: mirror, Source: releaseSource(o.ReleaseSource), Lister: releaseLister(o.ReleaseSource), Proxy: proxy,
			Wake: checks.Wakes(), Checks: checks, Logger: o.Logger})
	})
	bg.Go(func() {
		RenewNodeCertificate(jobs, NodeCertOptions{CA: ca, DB: db, Sys: sys, NodeID: nodeID, Holder: holder, Now: o.Now, Logger: o.Logger})
	})
	serve("agent endpoint", func() error { return agents.Serve(split.Agents()) })
	serve("web server", func() error {
		return web.Serve(tls.NewListener(split.Web(), webTLS))
	})
	serve("port 443", func() error { return split.Serve(ln) })
	if redirect != nil {
		serve("port 80", func() error { return redirect.Serve(httpLn) })
	}
	if own != nil {
		go func() {
			if o.ACMEAfter != nil {
				select {
				case <-o.ACMEAfter:
				case <-run.Done():
					return
				}
			}
			if err := own.Manage(run); err != nil {
				o.Logger.Warn("cannot obtain the public URL's certificate with ACME", "error", err)
			}
		}()
	}
	var admin sync.WaitGroup
	if o.Registry == nil {
		admin.Go(func() {
			if err := telemetry.ServeAdmin(run, cfg.Listen.Admin, reg, ready.Ready); err != nil {
				errs <- fmt.Errorf("controller: admin listener: %w", err)
			}
		})
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
	// The last requests are recorded; a checkpoint covers them.
	if err := FinalCheckpoints(context.WithoutCancel(sys), cpOpts); err != nil {
		o.Logger.Error("cannot write the final audit checkpoints", "error", err)
	}
	stop()
	<-sessionsDone
	stopJobs()
	bg.Wait()
	admin.Wait() // the admin listener is closed: its address is free again once Run returns
	return result
}

// AgentEndpoints returns the snapshots' controller endpoints (snapshot.Compiler.Endpoints): those
// of the instance settings, or publicURL alone while they list none, as enrollment gives them
// (docs/03-connections.md, "Reaching a private controller").
func AgentEndpoints(publicURL string) func(ctx context.Context, tx *ent.Tx) ([]string, error) {
	return func(ctx context.Context, tx *ent.Tx) ([]string, error) {
		inst, _, err := settings.Instance(ctx, tx.Client())
		if err != nil {
			return nil, err
		}
		return settings.ControllerEndpoints(inst, publicURL), nil
	}
}

// origins returns the origins a browser may call the API from: the public URL's and those of its
// aliases in the instance settings.
func origins(db *store.DB, sys context.Context, public *url.URL) func(context.Context) ([]string, error) {
	own := public.Scheme + "://" + public.Host
	return func(context.Context) ([]string, error) {
		inst, _, err := settings.Instance(sys, db.ReadClient())
		if err != nil {
			return nil, err
		}
		out := []string{own}
		for _, a := range inst.GetPublicUrlAliases() {
			if u, err := url.Parse(a); err == nil && u.Host != "" {
				out = append(out, u.Scheme+"://"+u.Host)
			}
		}
		return out, nil
	}
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

// RedirectHandler sends every plain-HTTP request to the same path on the public URL; all-in-one's
// gateway uses it for the controller's own names when no route serves them.
func RedirectHandler(public *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := *public
		target.Path, target.RawQuery = r.URL.Path, r.URL.RawQuery
		// Only the path and query come from the request; the host is the public URL's.
		http.Redirect(w, r, target.String(), http.StatusMovedPermanently) //nolint:gosec // G710: see above
	})
}
