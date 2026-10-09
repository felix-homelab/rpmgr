// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"encoding/base32"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/totp"
)

func reason(err error) string {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return ""
	}
	for _, d := range cerr.Details() {
		if v, derr := d.Value(); derr == nil {
			if ei, ok := v.(*errdetails.ErrorInfo); ok {
				return ei.GetReason()
			}
		}
	}
	return ""
}

func (b *browser) stepUp(password, second string) error {
	_, err := b.auth.StepUp(context.Background(), connect.NewRequest(&rpmgrv1.StepUpRequest{Password: password, SecondFactor: second}))
	return err
}

func (b *browser) loginWith(email, password, second string) error {
	_, err := b.auth.Login(context.Background(), connect.NewRequest(&rpmgrv1.LoginRequest{Email: email, Password: password,
		SecondFactor: second}))
	return err
}

// TestAuth_MFA: setting up an authenticator needs a step-up, with the password while there is none;
// confirming it ends the user's other sessions and returns recovery codes; from then on a login
// needs a second factor (MFA_REQUIRED, which counts no failure) and a step-up needs one too; a
// recovery code works once; the step-up lasts 10 minutes to the second and rotates the cookie.
func TestAuth_MFA(t *testing.T) {
	e := newEnv(t)
	b, other := e.browser(), e.browser()
	if err := b.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	if err := other.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := b.user.EnrollTOTP(ctx, connect.NewRequest(&rpmgrv1.EnrollTOTPRequest{})); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("enroll without a step-up: %v", err)
	}
	if err := b.stepUp("wrong password", ""); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("a step-up with a wrong password: %v", err)
	}
	before := b.cookie
	if err := b.stepUp(pw, ""); err != nil || b.cookie == before {
		t.Fatalf("a step-up with the password: %v (cookie rotated: %v)", err, b.cookie != before)
	}
	enrolled, err := b.user.EnrollTOTP(ctx, connect.NewRequest(&rpmgrv1.EnrollTOTPRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrolled.Msg.GetSecret())
	if err != nil {
		t.Fatal(err)
	}
	code6 := func() string { return totp.Code(seed, totp.StepOf(e.clock)) }
	if _, err := b.user.ConfirmTOTP(ctx, connect.NewRequest(&rpmgrv1.ConfirmTOTPRequest{Code: "000000"})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a wrong first code: %v", err)
	}
	confirmed, err := b.user.ConfirmTOTP(ctx, connect.NewRequest(&rpmgrv1.ConfirmTOTPRequest{Code: code6()}))
	if err != nil || len(confirmed.Msg.GetRecoveryCodes()) != 10 {
		t.Fatalf("confirm: %v %v", confirmed, err)
	}
	if _, err := other.session(); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("the other session after MFA was set up: %v", err)
	}

	// Signing in now takes a second factor; asking for it is no failure.
	fresh := e.browser()
	for range 6 {
		if err := fresh.login("ada@example.com", pw); reason(err) != api.ReasonMFARequired {
			t.Fatalf("a login without a second factor: %v", err)
		}
	}
	e.clock = e.clock.Add(totp.Step)
	if err := fresh.loginWith("ada@example.com", pw, "000000"); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("a wrong second factor: %v", err)
	}
	if err := fresh.loginWith("ada@example.com", pw, code6()); err != nil {
		t.Fatalf("a login with a code: %v", err)
	}
	recovery := confirmed.Msg.GetRecoveryCodes()[0]
	if err := e.browser().loginWith("ada@example.com", pw, recovery); err != nil {
		t.Fatalf("a login with a recovery code: %v", err)
	}
	if err := e.browser().loginWith("ada@example.com", pw, recovery); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("a recovery code twice: %v", err)
	}

	// A step-up now needs the second factor, and lasts 10 minutes to the second.
	if err := fresh.stepUp(pw, ""); reason(err) != api.ReasonMFARequired {
		t.Fatalf("a step-up with the password only: %v", err)
	}
	e.clock = e.clock.Add(totp.Step)
	if err := fresh.stepUp("", code6()); err != nil {
		t.Fatalf("a step-up with a code: %v", err)
	}
	regenerate := func() error {
		_, err := fresh.user.RegenerateRecoveryCodes(ctx, connect.NewRequest(&rpmgrv1.RegenerateRecoveryCodesRequest{}))
		return err
	}
	e.clock = e.clock.Add(api.StepUpWindow)
	if err := regenerate(); err != nil {
		t.Fatalf("at the end of the step-up: %v", err)
	}
	e.clock = e.clock.Add(time.Second)
	if err := regenerate(); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("a second after the step-up: %v", err)
	}
}

// TestStepUpActions: every method that makes one of the changes for which docs/04-security.md
// asks a step-up is annotated with it. A new such method joins this list.
func TestStepUpActions(t *testing.T) {
	for _, name := range []string{
		"rpmgr.v1.UserService.EnrollTOTP", "rpmgr.v1.UserService.ConfirmTOTP", "rpmgr.v1.UserService.RemoveTOTP",
		"rpmgr.v1.UserService.RegenerateRecoveryCodes",
	} {
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		md, ok := d.(protoreflect.MethodDescriptor)
		if !ok {
			t.Errorf("%s is not a method", name)
			continue
		}
		a, _ := proto.GetExtension(md.Options(), rpmgrv1.E_Authz).(*rpmgrv1.Authz)
		if !a.GetStepUp() {
			t.Errorf("%s does not ask for a step-up", name)
		}
	}
}
