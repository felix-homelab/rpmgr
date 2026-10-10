// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/controller"
)

// TestRun_PasswordReset: init prints a first-user link, whose token AuthService accepts once
// over the controller's public URL; the user then signs in with a session cookie, and a
// cross-site request is refused; afterwards reset-password needs an e-mail address and makes a
// reset link for that user, and none for nobody.
func TestRun_PasswordReset(t *testing.T) {
	var link string
	r := startRunWith(t, runSetup{prepare: func(r *running) { link = r.firstUserLink }})
	_, tok, ok := strings.Cut(link, "/setup#")
	if !ok || !strings.HasPrefix(link, r.url) || !strings.HasPrefix(tok, "rpmgr_prs_") {
		t.Fatalf("the first-user link %q", link)
	}
	auth := rpmgrv1connect.NewAuthServiceClient(r.client, r.url)
	ctx := context.Background()
	complete := func(tok, pw string) (*connect.Response[rpmgrv1.CompletePasswordResetResponse], error) {
		return auth.CompletePasswordReset(ctx, connect.NewRequest(&rpmgrv1.CompletePasswordResetRequest{Token: tok, NewPassword: pw,
			Email: "ada@example.com", DisplayName: "Ada"}))
	}
	if _, err := complete(tok, "too short"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a short password: %v", err)
	}
	resp, err := complete(tok, "correct horse battery staple")
	if err != nil || resp.Msg.GetEmail() != "ada@example.com" || !strings.HasPrefix(resp.Msg.GetUserId(), "usr_") {
		t.Fatalf("the first user: %v %v", resp, err)
	}
	if _, err := complete(tok, "correct horse battery staple"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("the link again: %v", err)
	}

	// A browser signs in over the public URL and keeps the session in its cookie jar.
	jar, _ := cookiejar.New(nil)
	browser := rpmgrv1connect.NewAuthServiceClient(&http.Client{Jar: jar, Transport: r.client.Transport, Timeout: 10 * time.Second}, r.url)
	if _, err := browser.Login(ctx, connect.NewRequest(&rpmgrv1.LoginRequest{Email: "ada@example.com",
		Password: "correct horse battery staple"})); err != nil {
		t.Fatalf("login: %v", err)
	}
	if s, err := browser.GetSession(ctx, connect.NewRequest(&rpmgrv1.GetSessionRequest{})); err != nil || s.Msg.GetEmail() != "ada@example.com" {
		t.Fatalf("the session: %v %v", s, err)
	}
	// A cross-site POST does not reach the API.
	req, _ := http.NewRequest(http.MethodPost, r.url+"/rpmgr.v1.AuthService/Logout", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp, err := (&http.Client{Jar: jar, Transport: r.client.Transport}).Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a cross-site request: %v %v", resp, err)
	} else {
		_ = resp.Body.Close()
	}

	if _, err := controller.ResetPasswordLink(ctx, r.h.cfg, ""); !errors.Is(err, controller.ErrEmailNeeded) {
		t.Fatalf("a first-user link once a user exists: %v", err)
	}
	reset, err := controller.ResetPasswordLink(ctx, r.h.cfg, "ADA@example.com")
	if err != nil || !strings.HasPrefix(reset.URL, r.url+"/reset#rpmgr_prs_") || reset.Valid != "24 hours" {
		t.Fatalf("a reset link: %+v %v", reset, err)
	}
	_, tok, _ = strings.Cut(reset.URL, "#")
	if _, err := complete(tok, "an entirely new passphrase"); err != nil {
		t.Fatalf("the reset: %v", err)
	}
	if _, err := controller.ResetPasswordLink(ctx, r.h.cfg, "eve@example.com"); !errors.Is(err, accounts.ErrNoUser) {
		t.Fatalf("a link for nobody: %v", err)
	}
	if _, err := controller.ResetPasswordLink(ctx, r.h.cfg+".missing", ""); err == nil {
		t.Fatal("a link without a boot file")
	}
}
