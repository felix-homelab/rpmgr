// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// sessionEnv is a controller with the Control service on a TCP port.
type sessionEnv struct {
	db       *store.DB
	ca       *pki.CA
	sessions *controller.Sessions
	addr     string
	org      string
	dbEpoch  string
	sealer   *secret.Sealer
	sys      context.Context
}

func startSessions(t *testing.T, db *store.DB, version string, admission int) *sessionEnv {
	t.Helper()
	return startSessionsWith(t, db, func(o *controller.SessionsOptions) { o.Version, o.Admission = version, admission })
}

// startSessionsWith starts the env with options that opt adjusts, and runs Sessions.Run.
func startSessionsWith(t *testing.T, db *store.DB, opt func(*controller.SessionsOptions)) *sessionEnv {
	t.Helper()
	rev := storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	kek, _ := secret.NewKEK(raw)
	s, _ := secret.NewSealer(kek)
	td := "rpmgr-teststor"
	// The CA starts 60 days ago, so tests can issue certificates that have expired since.
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error { return pki.InitCA(sys, tx, s, td, time.Now().Add(-60*24*time.Hour)) }); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadCA(sys, db, s, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	node, err := ca.NodeCertificate(sys, db, ids.New("ctn"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root())
	e := &sessionEnv{db: db, ca: ca, org: storetest.Org(t, db, "org-a"), dbEpoch: rev.DBEpoch, sealer: s, sys: sys}
	o := controller.SessionsOptions{DB: db, CA: ca, Node: "ctn_test", Sys: sys}
	opt(&o)
	e.sessions = controller.NewSessions(o)
	cfg := pki.AgentEndpointConfig(node, roots, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector, pki.KindGateway},
		Denied: e.sessions.Denied}, nil, controller.ReauthChecks(db, sys))
	srv := controller.NewAgentServer(cfg, td)
	agentv1.RegisterReauthServer(srv, controller.NewReauthService(e.sessions))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.sessions.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	agentv1.RegisterControlServer(srv, e.sessions)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return e
}

// agentCert issues a connector certificate in the env's org.
func (e *sessionEnv) agentCert(t *testing.T) (tls.Certificate, pki.Identity) {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr, _ := x509.ParseCertificateRequest(der)
	id := pki.Identity{TrustDomain: e.ca.TrustDomain(), Org: e.org, Kind: pki.KindConnector, ID: ids.New("con")}
	sys := storetest.SystemCtx(t)
	var leaf *x509.Certificate
	if err := store.WriteTx(sys, e.db, func(tx *ent.Tx) error {
		leaf, err = e.ca.Issue(sys, tx, csr, id, pki.DefaultLeafLifetime)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw, e.ca.Intermediate().Raw}, PrivateKey: key, Leaf: leaf}, id
}

// open starts a control session as the agent with cert and sends hello.
func (e *sessionEnv) open(t *testing.T, ctx context.Context, cert tls.Certificate, hello *agentv1.Hello) grpc.BidiStreamingClient[agentv1.AgentMessage, agentv1.ControllerMessage] {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.Root())
	cfg := pki.ClientConfig(cert, roots, "controller."+e.ca.TrustDomain(),
		pki.Expect{TrustDomain: e.ca.TrustDomain(), Kinds: []pki.Kind{pki.KindController}}, nil, nil)
	cc, err := grpc.NewClient("passthrough:///"+e.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	st, err := agentv1.NewControlClient(cc).Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hello != nil {
		// io.EOF means the controller ended the stream first, as admission does without reading
		// Hello; Recv then returns what it sent.
		if err := st.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Hello{Hello: hello}}); err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	}
	return st
}

func hello(version string) *agentv1.Hello {
	return &agentv1.Hello{Version: version, BootId: "boot-1", Capabilities: []string{"tunnel.quic"}}
}

func recv(t *testing.T, st grpc.BidiStreamingClient[agentv1.AgentMessage, agentv1.ControllerMessage]) *agentv1.ControllerMessage {
	t.Helper()
	m, err := st.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	return m
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestSession_WelcomeAndSupersede: Welcome carries a session epoch that rises with each session of
// the agent, the database epoch and the signing certificates; a newer session supersedes the older
// one, which gets Goodbye{superseded} and ends.
func TestSession_WelcomeAndSupersede(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := startSessions(t, db, "0.3.1", 0)
		cert, id := e.agentCert(t)
		first := e.open(t, testCtx(t), cert, hello("0.3.0"))
		w := recv(t, first).GetWelcome()
		if w == nil || w.SessionEpoch != 1 || w.DbEpoch != e.dbEpoch || w.MinAgentVersion != "0.2.0" ||
			len(w.SigningCertificates) != 2 || time.Since(w.ServerTime.AsTime()).Abs() > time.Minute {
			t.Fatalf("Welcome: %v", w)
		}
		row := e.db.Client().AgentSession.GetX(storetest.SystemCtx(t), id.ID)
		if row.SessionEpoch != 1 || row.AgentVersion != "0.3.0" || row.ControllerNode != "ctn_test" || len(row.Capabilities) != 1 {
			t.Errorf("agent_sessions row: %+v", row)
		}
		second := e.open(t, testCtx(t), cert, hello("0.3.0"))
		if w := recv(t, second).GetWelcome(); w.GetSessionEpoch() != 2 {
			t.Fatalf("second Welcome: %v", w)
		}
		if g := recv(t, first).GetGoodbye(); g.GetReason() != agentv1.GoodbyeReason_GOODBYE_REASON_SUPERSEDED {
			t.Fatalf("the older session got %v, want Goodbye{superseded}", g)
		}
		if _, err := first.Recv(); !errors.Is(err, io.EOF) {
			t.Errorf("the older session did not end: %v", err)
		}
		if got := e.sessions.Connected(); len(got) != 1 || got[0] != id.ID {
			t.Errorf("connected agents: %v", got)
		}
	})
}

// TestSession_Refusals: an old agent gets Goodbye{upgrade_required}; a first message that is not
// Hello ends the session.
func TestSession_Refusals(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.3.1", 0)
	cert, _ := e.agentCert(t)
	for _, v := range []string{"0.1.9", "dev", ""} {
		st := e.open(t, testCtx(t), cert, hello(v))
		if g := recv(t, st).GetGoodbye(); g.GetReason() != agentv1.GoodbyeReason_GOODBYE_REASON_UPGRADE_REQUIRED {
			t.Errorf("agent version %q: %v, want Goodbye{upgrade_required}", v, g)
		}
	}
	st := e.open(t, testCtx(t), cert, nil)
	if err := st.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Errorf("a first message that is not Hello: %v", err)
	}
	ok := e.open(t, testCtx(t), cert, hello("0.2.0"))
	if recv(t, ok).GetWelcome() == nil {
		t.Error("the oldest supported version was refused")
	}
	if err := ok.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Hello{Hello: hello("0.2.0")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ok.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Errorf("a second Hello: %v", err)
	}
}

// TestSession_AdmissionStorm: beyond the admission rate, agents get Goodbye{overloaded} with a
// retry_after of 1 to 10 s.
func TestSession_AdmissionStorm(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "dev", 3)
	welcomed, turned := 0, 0
	for i := 0; i < 8; i++ {
		cert, _ := e.agentCert(t)
		m := recv(t, e.open(t, testCtx(t), cert, hello("0.1.0")))
		switch {
		case m.GetWelcome() != nil:
			welcomed++
		case m.GetGoodbye().GetReason() == agentv1.GoodbyeReason_GOODBYE_REASON_OVERLOADED:
			turned++
			if d := m.GetGoodbye().GetRetryAfter().AsDuration(); d < time.Second || d > 10*time.Second {
				t.Errorf("retry_after %v", d)
			}
		default:
			t.Fatalf("unexpected %v", m)
		}
	}
	if welcomed < 3 || turned == 0 || welcomed+turned != 8 {
		t.Fatalf("%d welcomed, %d turned away", welcomed, turned)
	}
}

// TestSession_DrainAndCancel: Drain reaches connected agents and every agent that connects later
// gets Goodbye{shutdown}; an agent that cancels its stream frees its session at once.
func TestSession_DrainAndCancel(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "dev", 0)
	cert, _ := e.agentCert(t)
	ctx, cancel := context.WithCancel(testCtx(t))
	st := e.open(t, ctx, cert, hello("0.1.0"))
	recv(t, st)
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for len(e.sessions.Connected()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("a cancelled session stayed registered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	live := e.open(t, testCtx(t), cert, hello("0.1.0"))
	recv(t, live)
	until := time.Now().Add(time.Minute).Truncate(time.Second)
	e.sessions.Drain(until)
	if d := recv(t, live).GetDrain(); d == nil || !d.Deadline.AsTime().Equal(until) {
		t.Fatalf("Drain: %v", d)
	}
	other, _ := e.agentCert(t)
	if g := recv(t, e.open(t, testCtx(t), other, hello("0.1.0"))).GetGoodbye(); g.GetReason() != agentv1.GoodbyeReason_GOODBYE_REASON_SHUTDOWN {
		t.Errorf("a session while draining: %v", g)
	}
}

// TestSession_DatabaseDown: with the database gone, established sessions keep working and new
// ones are refused as unavailable, so agents retry.
func TestSession_DatabaseDown(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "dev", 0)
	cert, id := e.agentCert(t)
	st := e.open(t, testCtx(t), cert, hello("0.1.0"))
	recv(t, st)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if !e.sessions.Send(id.ID, &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Drain{Drain: &agentv1.Drain{}}}) {
		t.Fatal("no session to send to")
	}
	if recv(t, st).GetDrain() == nil {
		t.Error("an established session stopped with the database")
	}
	_, err := e.open(t, testCtx(t), cert, hello("0.1.0")).Recv()
	if status.Code(err) != codes.Unavailable {
		t.Errorf("a new session without the database: %v, want Unavailable", err)
	}
}

func TestMinAgentVersion(t *testing.T) {
	for v, want := range map[string]string{"0.3.1": "0.2.0", "v1.0.0": "1.0.0", "2.7.3-rc.1": "2.6.0", "dev": "", "": ""} {
		if got := controller.MinAgentVersion(v); got != want {
			t.Errorf("MinAgentVersion(%q) = %q, want %q", v, got, want)
		}
	}
}
