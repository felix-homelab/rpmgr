// SPDX-License-Identifier: Apache-2.0

// Package allinone runs a controller and a gateway in one process (docs/02-architecture.md,
// "All-in-one"): the gateway owns the public ports and hands the controller's names to the
// in-process controller, and the gateway's own control session reaches the controller over an
// in-memory mutual-TLS connection, so both topologies share one code path (R16).
package allinone

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/gateway"
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

// memListener is the controller's port 443 in all-in-one: it accepts the connections the gateway
// hands over for the controller's names, and those Dial makes for the gateway's control plane.
type memListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newMemListener() *memListener {
	return &memListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *memListener) Addr() net.Addr { return memAddr{} }

// Deliver hands a connection to the controller; it is gateway.RunOptions.Controller.
func (l *memListener) Deliver(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.done:
		_ = c.Close()
	}
}

// Dial connects to the in-process controller over an in-memory pipe.
func (l *memListener) Dial(ctx context.Context, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.done:
		_, _ = client.Close(), server.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_, _ = client.Close(), server.Close()
		return nil, ctx.Err()
	}
}

type memAddr struct{}

func (memAddr) Network() string { return "memory" }
func (memAddr) String() string  { return "in-process" }

// InitResult is what init reports to the operator.
type InitResult struct {
	controller.InitResult
	GatewayID string
}

// Init initialises an all-in-one installation: the controller as `rpmgr controller init` does,
// from an all-in-one boot file, then its gateway, which an Admin would otherwise create: a gateway
// group "default" with the gateway "local", whose tunnel endpoint is the public URL's host on
// the port of listen.tcp, enrolled into <state_dir>/gateway/identity through the in-process
// controller. What the gateway's part adds to the state directory goes to the directory's owner, as
// controller.Init's own files do. When the gateway's part fails, the database and what this init
// created beside it go again, so init can run again (docs/10-operations.md, "Install").
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
	gw := cfg.Gateway()
	if err := os.MkdirAll(gw.StateDir, 0o750); err != nil {
		return InitResult{}, err
	}
	public, err := url.Parse(cfg.PublicURL)
	if err != nil {
		return InitResult{}, err
	}
	_, port, err := net.SplitHostPort(cfg.Listen.TCP)
	if err != nil {
		return InitResult{}, err
	}
	gatewayID, tok, err := createGateway(ctx, cfg, net.JoinHostPort(public.Hostname(), port), groupHostnames(public))
	if err != nil {
		return InitResult{}, err
	}
	// Enroll through the controller itself, running only in memory for the moment.
	mem := newMemListener()
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
	_, err = agent.Enroll(ctx, agent.EnrollOptions{Controller: cfg.PublicURL, Pin: r.RootPin, Token: tok, IdentityDir: gw.IdentityDir,
		Bundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.Root.Raw}), Dial: mem.Dial,
		Host: &agentv1.HostFacts{Hostname: "all-in-one"}, Now: o.Now})
	stop()
	if rerr := <-done; err == nil {
		err = rerr
	}
	if err != nil {
		return InitResult{}, fmt.Errorf("allinone: enroll the gateway: %w", err)
	}
	return InitResult{InitResult: r, GatewayID: gatewayID}, nil
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
// as it does a single-label name such as localhost.
func groupHostnames(public *url.URL) []string {
	host := []string{strings.ToLower(public.Hostname())}
	if host[0] == "" || gatewaygroup.PublicHostnamesValidator(host) != nil {
		return nil
	}
	return host
}

// createGateway creates the gateway group with its public hostnames and the gateway, and a
// single-use token bound to it.
func createGateway(ctx context.Context, cfg config.AllInOne, endpoint string, hostnames []string) (string, string, error) {
	db, err := store.OpenSQLite(ctx, cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		return "", "", err
	}
	defer func() { _ = db.Close() }()
	sys, err := authz.System(ctx, "local-cli", "rpmgr all-in-one init", audit.SystemScopes(db))
	if err != nil {
		return "", "", err
	}
	tok, err := token.New(token.Enrollment)
	if err != nil {
		return "", "", err
	}
	var gatewayID string
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
			SetTunnelEndpoints([]string{endpoint}).Save(sys)
		if err != nil {
			return nil, err
		}
		gatewayID = gw.ID
		if err := tx.EnrollmentToken.Create().SetOrgID(org.ID).SetTokenHash(token.Hash(tok)).SetRole("gateway").
			SetGatewayID(gw.ID).SetMaxUses(1).SetExpiresAt(time.Now().Add(10 * time.Minute)).SetCreatedBy("local-cli").Exec(sys); err != nil {
			return nil, err
		}
		_, err = audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "gateway.create",
			TargetType: "gateway", TargetID: gw.ID, Result: audit.Success, Reason: "rpmgr all-in-one init"})
		return []string{org.ID, group.ID, gw.ID}, err
	})
	return gatewayID, tok, err
}

// RunOptions configure Run.
type RunOptions struct {
	Config  config.AllInOne
	Version string
	Getenv  func(string) string
	Logger  *slog.Logger
	// DrainPeriod is the gateway's; 0 is gateway.DrainPeriod.
	DrainPeriod time.Duration
	// Listening, if set, is called once the controller and the gateway listen.
	Listening func()
	// ACMERoots, if set, trusts the ACME CA's TLS certificate instead of the system roots (tests).
	ACMERoots *x509.CertPool
	// Registry, if set, receives the metrics of both roles instead of a new registry.
	Registry telemetry.Registry
}

// Run runs the controller and the gateway until ctx ends; the admin listener reports both.
func Run(ctx context.Context, o RunOptions) error {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	cfg := o.Config
	public, err := url.Parse(cfg.PublicURL)
	if err != nil {
		return err
	}
	mem := newMemListener()
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
	// Separate lifetimes: on the way out the gateway drains first, while its controller answers.
	ctlCtx, stopCtl := context.WithCancel(context.Background())
	defer stopCtl()
	gwCtx, stopGw := context.WithCancel(context.Background())
	defer stopGw()
	// The controller's port-80 handler goes to the gateway, which serves port 80; the CA validates
	// the public URL's certificate through the gateway, so ACME waits for it.
	port80 := controller.RedirectHandler(public)
	ctlListening, ctlDone, gwListening := make(chan struct{}), make(chan error, 1), make(chan struct{})
	go func() {
		ctlDone <- controller.Run(ctlCtx, controller.RunOptions{Config: cfg.Controller(), Version: o.Version, Sources: routes.Sources(),
			Getenv: o.Getenv, Logger: o.Logger.With("role", "controller"), Listener: mem, Registry: reg, Readiness: readiness,
			ACMERoots: o.ACMERoots, Port80: func(h http.Handler) { port80 = h }, ACMEAfter: gwListening,
			Listening: func() { close(ctlListening) }})
	}()
	select {
	case <-ctlListening:
	case err := <-ctlDone:
		return err
	}
	gwDone := make(chan error, 1)
	go func() {
		gwDone <- gateway.Run(gwCtx, gateway.RunOptions{Config: cfg.Gateway(), Version: o.Version, Logger: o.Logger.With("role", "gateway"),
			DrainPeriod: o.DrainPeriod, Controller: mem.Deliver, ControllerNames: []string{public.Hostname()}, Dial: mem.Dial,
			Port80Fallback: port80,
			Registry:       reg, Readiness: readiness, Listening: func() { close(gwListening) }})
	}()
	select {
	case <-gwListening:
	case err := <-gwDone:
		stopCtl()
		return errors.Join(err, <-ctlDone)
	}
	adminCtx, stopAdmin := context.WithCancel(context.Background())
	defer stopAdmin()
	adminDone := make(chan error, 1)
	go func() {
		adminDone <- telemetry.ServeAdmin(adminCtx, cfg.Listen.Admin, reg, func(ctx context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			var errs []error
			for _, c := range checks {
				errs = append(errs, c(ctx))
			}
			return errors.Join(errs...)
		})
	}()
	if o.Listening != nil {
		o.Listening()
	}
	var gwErr, ctlErr, adminErr error
	gwEnded, ctlEnded, adminEnded := false, false, false
	select {
	case <-ctx.Done():
	case gwErr = <-gwDone:
		gwEnded = true
	case ctlErr = <-ctlDone:
		ctlEnded = true
	case adminErr = <-adminDone:
		adminEnded = true
	}
	stopGw()
	if !gwEnded {
		gwErr = <-gwDone
	}
	stopCtl()
	if !ctlEnded {
		ctlErr = <-ctlDone
	}
	stopAdmin()
	if !adminEnded { // the admin listener is closed: its address is free again once Run returns
		adminErr = <-adminDone
	}
	_ = mem.Close()
	return errors.Join(gwErr, ctlErr, adminErr)
}
