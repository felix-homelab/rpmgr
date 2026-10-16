// SPDX-License-Identifier: Apache-2.0

// Package allinone runs a controller, a gateway and a connector in one process
// (docs/02-architecture.md, "All-in-one"; ADR-0019): the gateway owns the public ports and hands
// the controller's names to the in-process controller, and the agents' control sessions and the
// connector's data sessions reach the controller and the gateway over in-memory mutual-TLS
// connections, so both topologies share one code path (R16).
package allinone

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/memnet"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// The gateway that all-in-one init creates.
const (
	GroupName   = "default"
	GatewayName = "local"
)

// InitResult is what init reports to the operator.
type InitResult struct {
	controller.InitResult
	GatewayID, ConnectorID string
}

// Init initialises an all-in-one installation: the controller as `rpmgr controller init` does,
// from an all-in-one boot file, then its own agents, which are built in (ADR-0019): a gateway
// group "default" with the gateway "local", whose tunnel endpoint is the public URL's host on
// the port of listen.tcp, enrolled into <state_dir>/gateway/identity, and the connector "local",
// enrolled into <state_dir>/connector/identity, both through the in-process controller. What the
// agents' part adds to the state directory goes to the directory's owner, as controller.Init's own
// files do. When the agents' part fails, the database and what this init created beside it go
// again, so init can run again (docs/10-operations.md, "Install").
func Init(ctx context.Context, o controller.InitOptions) (res InitResult, err error) {
	o.AllInOne = true
	r, err := controller.Init(ctx, o)
	if err != nil {
		return InitResult{}, err
	}
	var cfg config.AllInOne
	if err := config.Load(o.ConfigPath, &cfg); err != nil {
		return InitResult{}, err
	}
	// Deferred first, so it runs after the in-memory controller has stopped.
	defer func() {
		dirs := []string{cfg.StateDir}
		if db := filepath.Dir(cfg.Database.DSN); db != cfg.StateDir {
			dirs = append(dirs, db)
		}
		for _, dir := range dirs {
			if oerr := o.Own(dir); oerr != nil && err == nil {
				res, err = InitResult{}, fmt.Errorf("allinone: initialised, but %s stays root's; give it to the service user before the first start: %w", dir, oerr)
			}
		}
	}()
	before, err := os.ReadDir(cfg.StateDir)
	if err != nil {
		return InitResult{}, err
	}
	defer func() {
		if err != nil {
			if uerr := undoInit(cfg, before); uerr != nil {
				err = fmt.Errorf("%w; undoing the init: %w", err, uerr)
			}
		}
	}()
	gw, con := cfg.Gateway(), cfg.Connector()
	for _, dir := range []string{gw.StateDir, con.StateDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return InitResult{}, err
		}
	}
	public, err := url.Parse(cfg.PublicURL)
	if err != nil {
		return InitResult{}, err
	}
	_, port, err := net.SplitHostPort(cfg.Listen.TCP)
	if err != nil {
		return InitResult{}, err
	}
	gatewayID, tok, conTok, err := createGateway(ctx, cfg, net.JoinHostPort(public.Hostname(), port), groupHostnames(public))
	if err != nil {
		return InitResult{}, err
	}
	// Enroll through the controller itself, running only in memory for the moment.
	mem := memnet.NewListener()
	rctx, stop := context.WithCancel(ctx)
	defer stop()
	listening, done := make(chan struct{}), make(chan error, 1)
	none := ""
	ccfg := cfg.Controller()
	ccfg.Listen.HTTP = &none
	go func() {
		done <- controller.Run(rctx, controller.RunOptions{Config: ccfg, Getenv: o.Getenv, Listener: mem, NoACME: true,
			Registry: telemetry.NewRegistry(), Listening: func() { close(listening) }, KEK: &r.Key})
	}()
	select {
	case <-listening:
	case err := <-done:
		return InitResult{}, err
	}
	l := newLocal(cfg)
	l.gateway.token, l.connector.token = tok, conTok
	if err = l.gateway.enroll(ctx, cfg.PublicURL, r.Root, mem.Dial, o.Now, false); err == nil {
		err = l.connector.enroll(ctx, cfg.PublicURL, r.Root, mem.Dial, o.Now, false)
	}
	stop()
	if rerr := <-done; err == nil {
		err = rerr
	}
	if err != nil {
		return InitResult{}, err
	}
	conID, err := agent.ReadIdentity(con.IdentityDir)
	if err != nil {
		return InitResult{}, err
	}
	return InitResult{InitResult: r, GatewayID: gatewayID, ConnectorID: conID.AgentID}, nil
}

// undoInit removes the database of a failed init, and what the init created in the state directory
// after the controller's part: the entries that are not among before.
func undoInit(cfg config.AllInOne, before []os.DirEntry) error {
	had := map[string]bool{}
	for _, e := range before {
		had[e.Name()] = true
	}
	now, err := os.ReadDir(cfg.StateDir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range now {
		if !had[e.Name()] {
			errs = append(errs, os.RemoveAll(filepath.Join(cfg.StateDir, e.Name())))
		}
	}
	for _, suffix := range []string{"", "-wal", "-shm", ".lock"} {
		if err := os.Remove(cfg.Database.DSN + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// groupHostnames are the public hostnames init gives the gateway group: the public URL's host,
// where clients reach this host's TCP and UDP routes as well (D79), unless the group refuses it,
// as it does a single-label name such as localhost. A fully qualified name's final dot is dropped,
// as the group's names have none.
func groupHostnames(public *url.URL) []string {
	host := []string{strings.TrimSuffix(strings.ToLower(public.Hostname()), ".")}
	if gatewaygroup.PublicHostnamesValidator(host) != nil {
		return nil
	}
	return host
}

// createGateway creates the gateway group with its public hostnames and the built-in gateway, a
// single-use token bound to it, and a single-use token that enrolls the built-in connector.
func createGateway(ctx context.Context, cfg config.AllInOne, endpoint string, hostnames []string) (gatewayID, tok, conTok string, err error) {
	db, err := store.OpenSQLite(ctx, cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		return "", "", "", err
	}
	defer func() { _ = db.Close() }()
	sys, err := authz.System(ctx, "local-cli", "rpmgr all-in-one init", audit.SystemScopes(db))
	if err != nil {
		return "", "", "", err
	}
	if tok, err = token.New(token.Enrollment); err != nil {
		return "", "", "", err
	}
	_, err = store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
		org, err := tx.Org.Create().SetName("Default").SetSlug("default").Save(sys)
		if err != nil {
			return nil, err
		}
		group, err := tx.GatewayGroup.Create().SetOrgID(org.ID).SetName(GroupName).SetPublicHostnames(hostnames).Save(sys)
		if err != nil {
			return nil, err
		}
		gw, err := tx.Gateway.Create().SetOrgID(org.ID).SetGatewayGroupID(group.ID).SetName(GatewayName).
			SetTunnelEndpoints([]string{endpoint}).SetBuiltIn(true).Save(sys)
		if err != nil {
			return nil, err
		}
		gatewayID = gw.ID
		if err := tx.EnrollmentToken.Create().SetOrgID(org.ID).SetTokenHash(token.Hash(tok)).SetRole("gateway").
			SetGatewayID(gw.ID).SetMaxUses(1).SetExpiresAt(time.Now().Add(tokenTTL)).SetCreatedBy("local-cli").Exec(sys); err != nil {
			return nil, err
		}
		if _, err := audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "gateway.create",
			TargetType: "gateway", TargetID: gw.ID, Result: audit.Success, Reason: "rpmgr all-in-one init"}); err != nil {
			return nil, err
		}
		conTok, err = connectorToken(sys, tx, org.ID, "", "local-cli", "")
		return []string{org.ID, group.ID, gw.ID}, err
	})
	return gatewayID, tok, conTok, err
}

// RunOptions configure Run.
type RunOptions struct {
	Config  config.AllInOne
	Version string
	Getenv  func(string) string
	Logger  *slog.Logger
	// DrainPeriod is the gateway's; 0 is gateway.DrainPeriod.
	DrainPeriod time.Duration
	// Listening, if set, is called once the controller, the gateway and the connector run.
	Listening func()
	// ACMERoots, if set, trusts the ACME CA's TLS certificate instead of the system roots (tests).
	ACMERoots *x509.CertPool
	// Registry, if set, receives the metrics of all three roles instead of a new registry.
	Registry telemetry.Registry
	// Now is the clock of the built-in agents' enrollment and of the check whether their
	// certificates expired; nil is time.Now.
	Now func() time.Time
}

// started, if set, is called once Run has taken SIGHUP over and before it starts anything (tests).
var started func()

// part is one role that Run runs.
type part struct {
	stop  context.CancelFunc
	done  chan error
	ended bool
	err   error
}

func start(run func(ctx context.Context) error) *part {
	ctx, cancel := context.WithCancel(context.Background())
	p := &part{stop: cancel, done: make(chan error, 1)}
	go func() { p.done <- run(ctx) }()
	return p
}

// end stops the part and waits for it.
func (p *part) end() error {
	p.stop()
	if !p.ended {
		p.err, p.ended = <-p.done, true
	}
	return p.err
}

// Run runs the controller, the gateway and the connector until ctx ends or one of them ends, which
// ends the others; the admin listener reports all three. Once the controller has migrated the
// database, and before the gateway runs, it marks the gateway built in and enrolls again, through
// the in-process controller, each of its own agents that has no identity or a certificate the
// controller cannot renew, as after a restore on a new host or of an older backup (ADR-0019,
// docs/10-operations.md, "Backup and restore"). On the way out the gateway drains first, while the
// connector serves its streams and the controller answers. SIGHUP, which reloads the connector's
// local policy, never ends the process, also while it starts or stops.
func Run(ctx context.Context, o RunOptions) error {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup { // the connector's policy watcher takes its own
		}
	}()
	defer close(hup)       // second: no signal reaches it once Stop has returned
	defer signal.Stop(hup) // first
	if started != nil {
		started()
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	cfg := o.Config
	public, err := url.Parse(cfg.PublicURL)
	if err != nil {
		return err
	}
	own, err := newOwnPorts(cfg)
	if err != nil {
		return err
	}
	// The controller would create an empty database.
	if _, err := os.Stat(cfg.Database.DSN); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("allinone: no database at %s; run rpmgr all-in-one init, or rpmgr restore, first", cfg.Database.DSN)
	}
	l, err := readLocal(cfg)
	if err != nil {
		return err
	}
	mem, tunnels := memnet.NewListener(), memnet.NewListener()
	defer func() { _, _ = mem.Close(), tunnels.Close() }()
	reg := o.Registry
	if reg == nil {
		reg = telemetry.NewRegistry()
	}
	var (
		mu     sync.Mutex
		checks []func(context.Context) error
	)
	readiness := func(c func(context.Context) error) {
		mu.Lock()
		checks = append(checks, c)
		mu.Unlock()
	}
	// The controller's port-80 handler goes to the gateway, which serves port 80; the CA validates
	// the public URL's certificate through the gateway, so ACME waits for it.
	port80 := controller.RedirectHandler(public)
	ctlListening, gwListening, conListening := make(chan struct{}), make(chan struct{}), make(chan struct{})
	ctl := start(func(ctx context.Context) error {
		return controller.Run(ctx, controller.RunOptions{Config: cfg.Controller(), Version: o.Version, Sources: routes.Sources(),
			Getenv: o.Getenv, Logger: o.Logger.With("role", "controller"), Listener: mem, Registry: reg, Readiness: readiness,
			ACMERoots: o.ACMERoots, Port80: func(h http.Handler) { port80 = h }, ACMEAfter: gwListening,
			Listening: func() { close(ctlListening) }})
	})
	if err := wait(ctlListening, ctl); err != nil {
		return err
	}
	if err := l.prepare(ctx, cfg, o.Now()); err != nil {
		return errors.Join(err, ctl.end())
	}
	own.setNames(append(l.names, public.Hostname()))
	for _, a := range []*builtIn{&l.gateway, &l.connector} {
		if a.token == "" {
			continue
		}
		o.Logger.Info("enrolling all-in-one's own "+a.role+" again", "identity", a.dir, "reason", a.why)
		if err := a.enroll(ctx, cfg.PublicURL, l.root, mem.Dial, o.Now, true); err != nil {
			return errors.Join(fmt.Errorf("%w (%s)", err, a.why), ctl.end())
		}
		o.Logger.Info("enrolled all-in-one's own "+a.role, "identity", a.dir)
	}
	gw := start(func(ctx context.Context) error {
		return gateway.Run(ctx, gateway.RunOptions{Config: cfg.Gateway(), Version: o.Version, Logger: o.Logger.With("role", "gateway"),
			DrainPeriod: o.DrainPeriod, Controller: mem.Deliver, ControllerNames: []string{public.Hostname()}, Dial: mem.Dial,
			Port80Fallback: port80, Tunnels: tunnels, RoutePorts: func(bound func(uint16) bool) { own.routes.Store(&bound) },
			Registry: telemetry.WithLabels(reg, prometheus.Labels{"role": "gateway"}), Readiness: readiness,
			Listening: func() { close(gwListening) }})
	})
	if err := wait(gwListening, gw); err != nil {
		return errors.Join(err, ctl.end())
	}
	con := start(func(ctx context.Context) error {
		return connector.Run(ctx, connector.RunOptions{Config: cfg.Connector(), Version: o.Version, Getenv: o.Getenv,
			Logger: o.Logger.With("role", "connector"), ControlDial: mem.Dial, Own: own.own,
			InProcess: &connector.InProcess{GatewayID: l.gatewayID, Dial: func(ctx context.Context) (net.Conn, error) { return tunnels.Dial(ctx, "") }},
			Registry:  telemetry.WithLabels(reg, prometheus.Labels{"role": "connector"}), Readiness: readiness,
			Listening: func() { close(conListening) }})
	})
	if err := wait(conListening, con); err != nil {
		return errors.Join(err, gw.end(), ctl.end())
	}
	admin := start(func(ctx context.Context) error {
		return telemetry.ServeAdmin(ctx, cfg.Listen.Admin, reg, func(ctx context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			var errs []error
			for _, c := range checks {
				errs = append(errs, c(ctx))
			}
			return errors.Join(errs...)
		})
	})
	if o.Listening != nil {
		o.Listening()
	}
	select {
	case <-ctx.Done():
	case gw.err = <-gw.done:
		gw.ended = true
	case ctl.err = <-ctl.done:
		ctl.ended = true
	case con.err = <-con.done:
		con.ended = true
	case admin.err = <-admin.done:
		admin.ended = true
	}
	// The admin listener is closed last: its address is free again once Run returns.
	return errors.Join(gw.end(), con.end(), ctl.end(), admin.end())
}

// wait returns once listening is closed, or the part's error if it ends first.
func wait(listening chan struct{}, p *part) error {
	select {
	case <-listening:
		return nil
	case err := <-p.done:
		p.err, p.ended = err, true
		if err == nil {
			err = errors.New("allinone: a role ended before it ran")
		}
		return err
	}
}
