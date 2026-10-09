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
	var link string
	r := startRunWith(t, runSetup{prepare: func(r *running) { link = r.firstUserLink }})
	ctx := context.Background()
	_, reset, _ := strings.Cut(link, "#")
	const pw = "correct horse battery staple"
	if _, err := rpmgrv1connect.NewAuthServiceClient(r.client, r.url).CompletePasswordReset(ctx, connect.NewRequest(
		&rpmgrv1.CompletePasswordResetRequest{Token: reset, NewPassword: pw, Email: "ada@example.com", DisplayName: "Ada"})); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Transport: r.client.Transport, Timeout: 10 * time.Second}
	auth := rpmgrv1connect.NewAuthServiceClient(c, r.url)
	if _, err := auth.Login(ctx, connect.NewRequest(&rpmgrv1.LoginRequest{Email: "ada@example.com", Password: pw})); err != nil {
		t.Fatal(err)
	}
	s, err := auth.GetSession(ctx, connect.NewRequest(&rpmgrv1.GetSessionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	org := s.Msg.GetMemberships()[0].GetOrgId()
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
	if _, err := auth.StepUp(ctx, connect.NewRequest(&rpmgrv1.StepUpRequest{Password: pw})); err != nil {
		t.Fatal(err)
	}
	enrol := func(tok, dir string, replace bool) agent.Loaded {
		t.Helper()
		ectx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if _, err := agent.Enroll(ectx, agent.EnrollOptions{Controller: r.url, Pin: r.pin, Token: tok, IdentityDir: dir, Replace: replace,
			HTTPClient: r.client, Host: &agentv1.HostFacts{Hostname: "host"}, Version: "0.1.0"}); err != nil {
			t.Fatalf("enrollment: %v", err)
		}
		l, err := agent.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
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

	connected := func(l agent.Loaded) bool {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cl := agent.NewClient(agent.ClientOptions{Identity: l, Endpoints: l.Endpoints, Version: "0.1.0", BootID: "test"})
		done := make(chan error, 1)
		go func() { done <- cl.Run(cctx) }()
		for cctx.Err() == nil {
			if cl.Connected() {
				cancel()
				<-done
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		<-done
		return false
	}
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
