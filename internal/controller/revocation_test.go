// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// TestRevocationLog_SingleNodeWithoutSink (docs/12-testing-and-quality.md, "Security testing"):
// on a single node without a sink, a revocation is enforced and appended to the local
// revocations.log; the API reports no sink, which the UI shows as the standing hardening warning,
// and never the "not yet off-host" alert; a second controller on the database refuses to start.
func TestRevocationLog_SingleNodeWithoutSink(t *testing.T) {
	var link string
	r := startRunWith(t, runSetup{prepare: func(r *running) { link = r.firstUserLink }})
	if r.cfg.RevocationLog.Sink != "" {
		t.Fatal("the test controller has a sink")
	}
	_, tok, _ := strings.Cut(link, "/setup#")
	ctx := context.Background()
	if _, err := rpmgrv1connect.NewAuthServiceClient(r.client, r.url).CompletePasswordReset(ctx, connect.NewRequest(
		&rpmgrv1.CompletePasswordResetRequest{Token: tok, NewPassword: "correct horse battery staple", Email: "ada@example.com", DisplayName: "Ada"})); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Transport: r.client.Transport, Timeout: 10 * time.Second}
	login := func(password string) error {
		_, err := rpmgrv1connect.NewAuthServiceClient(client, r.url).Login(ctx, connect.NewRequest(&rpmgrv1.LoginRequest{Email: "ada@example.com", Password: password}))
		return err
	}
	if err := login("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if _, err := rpmgrv1connect.NewUserServiceClient(client, r.url).ChangePassword(ctx, connect.NewRequest(&rpmgrv1.ChangePasswordRequest{
		CurrentPassword: "correct horse battery staple", NewPassword: "another correct horse battery"})); err != nil {
		t.Fatal(err)
	}
	if err := login("correct horse battery staple"); err == nil {
		t.Error("the old password still signs in")
	}
	entries, err := revlog.Read(filepath.Join(filepath.Dir(r.cfg.Database.DSN), "revocations.log"))
	if err != nil || len(entries) == 0 || entries[len(entries)-1].Kind != revlog.CredentialSuperseded {
		t.Fatalf("the local log: %v %v", entries, err)
	}

	if err := login("another correct horse battery"); err != nil {
		t.Fatal(err)
	}
	set, err := rpmgrv1connect.NewSettingsServiceClient(client, r.url).GetInstanceSettings(ctx, connect.NewRequest(&rpmgrv1.GetInstanceSettingsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if st := set.Msg.GetRevocationLog(); st == nil || st.GetSink() || st.GetUnshipped() != 0 || st.GetAlert() || st.GetOldestUnshippedTime() != nil {
		t.Errorf("without a sink: %v", st)
	}

	second := r.cfg
	second.Listen.HTTPS, second.Listen.Admin = freeAddr(t), freeAddr(t)
	none := ""
	second.Listen.HTTP = &none
	runCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err = controller.Run(runCtx, controller.RunOptions{Config: second, Getenv: func(string) string { return "" },
		Listening: func() { t.Error("a second controller started") }})
	if err == nil || !strings.Contains(err.Error(), "another controller") {
		t.Errorf("a second controller without a sink: %v", err)
	}
}
