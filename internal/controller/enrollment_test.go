// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestEnrollReplace_TokenBoundToConnector (docs/12-testing-and-quality.md, "Security testing"): a
// re-enrollment token minted for connector A replaces A and nothing else, also on a host that holds
// connector B's identity; minting it needs a step-up; after the replacement A's old certificate is
// revoked by serial and refused on the control session, and the new one works.
func TestEnrollReplace_TokenBoundToConnector(t *testing.T) {
	r, c, auth, org := signedInOwner(t)
	ctx := context.Background()
	enrollment := rpmgrv1connect.NewEnrollmentServiceClient(c, r.url)
	mint := func(connectorID string) (string, error) {
		resp, err := enrollment.CreateEnrollmentToken(ctx, connect.NewRequest(&rpmgrv1.CreateEnrollmentTokenRequest{OrgId: org,
			ConnectorId: connectorID}))
		if err != nil {
			return "", err
		}
		return resp.Msg.GetToken(), nil
	}
	if _, err := mint(""); stepUpReason(err) != api.ReasonStepUpRequired {
		t.Fatalf("a token without a step-up: %v", err)
	}
	if _, err := auth.StepUp(ctx, connect.NewRequest(&rpmgrv1.StepUpRequest{Password: adminPassword})); err != nil {
		t.Fatal(err)
	}
	enrol := func(tok, dir string, replace bool) agent.Loaded { return enrolAgent(t, r, tok, dir, replace) }
	tmp := t.TempDir()
	tokA, err := mint("")
	if err != nil {
		t.Fatal(err)
	}
	tokB, err := mint("")
	if err != nil {
		t.Fatal(err)
	}
	a1 := enrol(tokA, filepath.Join(tmp, "a1"), false)
	b := enrol(tokB, filepath.Join(tmp, "b"), false)

	connected := func(l agent.Loaded) bool { return connects(t, l, 5*time.Second) }
	if !connected(a1) {
		t.Fatal("A's first certificate opens no control session")
	}
	replaceA, err := mint(a1.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	// The host holds B's identity and asks to replace it: the token still makes it A.
	a2 := enrol(replaceA, filepath.Join(tmp, "b"), true)
	if a2.AgentID != a1.AgentID || a2.AgentID == b.AgentID || a2.SPIFFE() != a1.SPIFFE() {
		t.Fatalf("the replacement is %s (%s), want A %s, not B %s", a2.AgentID, a2.SPIFFE(), a1.AgentID, b.AgentID)
	}

	db, err := store.OpenSQLite(ctx, r.h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sys := storetest.SystemCtx(t)
	old := db.Client().IssuedCertificate.GetX(sys, pki.SerialHex(a1.Certificate.Leaf.SerialNumber))
	if old.RevokedAt == nil {
		t.Fatal("A's old certificate is not revoked")
	}
	if db.Client().IssuedCertificate.GetX(sys, pki.SerialHex(a2.Certificate.Leaf.SerialNumber)).RevokedAt != nil ||
		db.Client().IssuedCertificate.GetX(sys, pki.SerialHex(b.Certificate.Leaf.SerialNumber)).RevokedAt != nil {
		t.Fatal("the new certificate or B's is revoked")
	}
	if n := db.Client().RevokedIdentity.Query().CountX(sys); n != 0 {
		t.Fatalf("%d identities revoked; a replacement revokes by serial", n)
	}

	if !connected(a2) {
		t.Fatal("the new certificate opens no control session")
	}
	if connected(a1) {
		t.Fatal("the replaced certificate still opens a control session")
	}
}

// stepUpReason is the reason of an error's ErrorInfo detail; empty for none.
func stepUpReason(err error) string {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return ""
	}
	for _, d := range cerr.Details() {
		if v, err := d.Value(); err == nil {
			if ei, ok := v.(*errdetails.ErrorInfo); ok {
				return ei.GetReason()
			}
		}
	}
	return ""
}

const adminPassword = "correct horse battery staple"

// signedInOwner starts a controller and signs its first user in, the Owner of the first org, without a
// step-up.
func signedInOwner(t *testing.T) (*running, *http.Client, rpmgrv1connect.AuthServiceClient, string) {
	t.Helper()
	var link string
	r := startRunWith(t, runSetup{prepare: func(r *running) { link = r.firstUserLink }})
	ctx := context.Background()
	_, reset, _ := strings.Cut(link, "#")
	if _, err := rpmgrv1connect.NewAuthServiceClient(r.client, r.url).CompletePasswordReset(ctx, connect.NewRequest(
		&rpmgrv1.CompletePasswordResetRequest{Token: reset, NewPassword: adminPassword, Email: "ada@example.com", DisplayName: "Ada"})); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Transport: r.client.Transport, Timeout: 10 * time.Second}
	auth := rpmgrv1connect.NewAuthServiceClient(c, r.url)
	if _, err := auth.Login(ctx, connect.NewRequest(&rpmgrv1.LoginRequest{Email: "ada@example.com", Password: adminPassword})); err != nil {
		t.Fatal(err)
	}
	s, err := auth.GetSession(ctx, connect.NewRequest(&rpmgrv1.GetSessionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return r, c, auth, s.Msg.GetMemberships()[0].GetOrgId()
}

// enrolAgent enrolls an agent with tok into dir, as `rpmgr enroll` does, and loads it.
func enrolAgent(t *testing.T, r *running, tok, dir string, replace bool) agent.Loaded {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := agent.Enroll(ctx, agent.EnrollOptions{Controller: r.url, Pin: r.pin, Token: tok, IdentityDir: dir, Replace: replace,
		HTTPClient: r.client, Host: &agentv1.HostFacts{Hostname: "host"}, Version: "0.1.0"}); err != nil {
		t.Fatalf("enrollment: %v", err)
	}
	l, err := agent.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// connects reports whether l gets a control session within d.
func connects(t *testing.T, l agent.Loaded, d time.Duration) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cl := agent.NewClient(agent.ClientOptions{Identity: l, Endpoints: l.Endpoints, Version: "0.1.0", BootID: "test"})
	done := make(chan error, 1)
	go func() { done <- cl.Run(ctx) }()
	defer func() { cancel(); <-done }()
	for ctx.Err() == nil {
		if cl.Connected() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestDecommissionConnector_EndsSessions: decommissioning a connector through the API ends its
// live control session at once, and its certificate opens none afterwards.
func TestDecommissionConnector_EndsSessions(t *testing.T) {
	r, c, auth, org := signedInOwner(t)
	ctx := context.Background()
	if _, err := auth.StepUp(ctx, connect.NewRequest(&rpmgrv1.StepUpRequest{Password: adminPassword})); err != nil {
		t.Fatal(err)
	}
	tok, err := rpmgrv1connect.NewEnrollmentServiceClient(c, r.url).CreateEnrollmentToken(ctx, connect.NewRequest(
		&rpmgrv1.CreateEnrollmentTokenRequest{OrgId: org}))
	if err != nil {
		t.Fatal(err)
	}
	l := enrolAgent(t, r, tok.Msg.GetToken(), filepath.Join(t.TempDir(), "id"), false)

	run, stop := context.WithCancel(ctx)
	defer stop()
	cl := agent.NewClient(agent.ClientOptions{Identity: l, Endpoints: l.Endpoints, Version: "0.1.0", BootID: "test"})
	done := make(chan error, 1)
	go func() { done <- cl.Run(run) }()
	defer func() { stop(); <-done }()
	wait := func(what string, want bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for cl.Connected() != want {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	wait("the connector never connected", true)
	if _, err := rpmgrv1connect.NewConnectorServiceClient(c, r.url).DecommissionConnector(ctx, connect.NewRequest(
		&rpmgrv1.DecommissionConnectorRequest{ConnectorId: l.AgentID})); err != nil {
		t.Fatal(err)
	}
	wait("the session outlived the decommission", false)
	if connects(t, l, 3*time.Second) {
		t.Fatal("the decommissioned connector opens a control session")
	}
}
