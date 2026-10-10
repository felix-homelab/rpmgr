// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"encoding/base32"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/totp"
)

// TestTokenStepUp (D63; docs/04-security.md, "Human authentication and sessions"): a personal
// API token steps up with its owner's password, or second factor once the owner has one, and then
// makes the changes that need a step-up for 10 minutes; the step-up is the token's alone, not the
// owner's sessions' or other tokens'; a wrong password is refused.
func TestTokenStepUp(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	s, _ := ada.session()
	org := s.GetMemberships()[0].GetOrgId()
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	token := func() *browser {
		r, err := ada.token.CreateAPIToken(ctx, connect.NewRequest(&rpmgrv1.CreateAPITokenRequest{OrgId: org, Name: "cli",
			Scopes: []string{"org.read", "connectors.write"}}))
		if err != nil {
			t.Fatal(err)
		}
		b := e.browser()
		b.bearer = r.Msg.GetToken()
		return b
	}
	cli, other := token(), token()
	mint := func(b *browser) error {
		_, err := b.enr.CreateEnrollmentToken(ctx, connect.NewRequest(&rpmgrv1.CreateEnrollmentTokenRequest{OrgId: org}))
		return err
	}
	if err := mint(cli); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("a token without a step-up: %v", err)
	}
	// StepUp is the one method of the authenticated permission a token may call.
	if _, err := cli.user.GetMe(ctx, connect.NewRequest(&rpmgrv1.GetMeRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a token reads its owner's account: %v", err)
	}
	if err := cli.stepUp("wrong password", ""); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("a wrong password: %v", err)
	}
	r, err := cli.auth.StepUp(ctx, connect.NewRequest(&rpmgrv1.StepUpRequest{Password: pw}))
	if err != nil || !r.Msg.GetExpireTime().AsTime().Equal(e.clock.Add(api.StepUpWindow)) || cli.cookie != "" {
		t.Fatalf("a token's step-up: %v %v, cookie %q", r, err, cli.cookie)
	}
	if err := mint(cli); err != nil {
		t.Fatalf("a token after its step-up: %v", err)
	}
	if err := mint(other); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("another token of the owner: %v", err)
	}

	// After the window: the token needs another step-up, and the owner's session never got one.
	e.clock = e.clock.Add(api.StepUpWindow + time.Second)
	if err := mint(cli); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("a token after the window: %v", err)
	}
	if err := mint(ada); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("the owner's session after the token's step-up: %v", err)
	}

	// With an authenticator, the second factor is needed.
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	enrolled, err := ada.user.EnrollTOTP(ctx, connect.NewRequest(&rpmgrv1.EnrollTOTPRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrolled.Msg.GetSecret())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.user.ConfirmTOTP(ctx, connect.NewRequest(&rpmgrv1.ConfirmTOTPRequest{Code: totp.Code(seed, totp.StepOf(e.clock))})); err != nil {
		t.Fatal(err)
	}
	e.clock = e.clock.Add(30 * time.Second)
	if err := cli.stepUp(pw, ""); reason(err) != api.ReasonMFARequired {
		t.Fatalf("the password alone, with an authenticator: %v", err)
	}
	if err := cli.stepUp("", totp.Code(seed, totp.StepOf(e.clock))); err != nil {
		t.Fatalf("a step-up with a code: %v", err)
	}
	if err := mint(cli); err != nil {
		t.Fatalf("a token after a step-up with a code: %v", err)
	}
}
