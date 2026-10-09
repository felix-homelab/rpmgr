// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"golang.org/x/term"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// stepUpPrompt asks for the factor of a step-up; a test replaces it.
var stepUpPrompt = func() (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("the change needs a step-up, which needs a terminal")
	}
	defer func() { _ = tty.Close() }()
	if _, err := fmt.Fprint(tty, "This change needs a step-up. Your authenticator or recovery code, or your password if you have no second factor: "); err != nil {
		return "", err
	}
	b, err := term.ReadPassword(int(tty.Fd())) //nolint:gosec // G115: a file descriptor fits in an int
	_, _ = fmt.Fprintln(tty)
	return string(b), err
}

// stepUpRequired reports whether the API refused a change for want of a step-up.
func stepUpRequired(err error) bool {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return false
	}
	for _, d := range cerr.Details() {
		if v, derr := d.Value(); derr == nil {
			if info, ok := v.(*errdetails.ErrorInfo); ok && info.GetReason() == "STEP_UP_REQUIRED" {
				return true
			}
		}
	}
	return false
}

// withStepUp runs a change; if the API wants a step-up first, it asks for the factor, steps the
// token up (D63) and runs the change once more.
func (s *apiSession) withStepUp(ctx context.Context, change func() error) error {
	err := change()
	if !stepUpRequired(err) {
		return err
	}
	factor, err := stepUpPrompt()
	if err != nil {
		return err
	}
	// The API checks the second factor of an owner who has one, else the password.
	if _, err := rpmgrv1connect.NewAuthServiceClient(s.hc, s.creds.Controller).StepUp(ctx,
		connect.NewRequest(&rpmgrv1.StepUpRequest{Password: factor, SecondFactor: factor})); err != nil {
		return apiError(err)
	}
	return change()
}

// enrollmentTokenCommand is `rpmgr create enrollment-token`: it prints the token, once.
func enrollmentTokenCommand() *cli.Command {
	var (
		ttl                time.Duration
		maxUses            int
		ephemeral          bool
		labels             = mapFlag{}
		connector, gwGroup string
		fs                 *flag.FlagSet
	)
	return &cli.Command{
		Name: "enrollment-token", Summary: "make a token that enrolls connectors; it is shown once",
		Flags: func(f *flag.FlagSet) {
			fs = f
			f.DurationVar(&ttl, "ttl", time.Hour, "how long it lasts, at most 720h")
			f.IntVar(&maxUses, "max-uses", 1, "how many connectors it enrolls; more than 1, or 0 for unlimited, only with --ephemeral")
			f.BoolVar(&ephemeral, "ephemeral", false, "the connectors it enrolls are purged 30 minutes after their last disconnect")
			f.Var(labels, "label", "a label key=value each connector it enrolls gets; repeat for more")
			f.StringVar(&connector, "connector", "", "re-enroll this connector, by name or ID, with a new key: a single-use token")
			f.StringVar(&gwGroup, "gateway-group", "", "the gateway group it is scoped to, by name or ID")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 {
				return cli.Usagef("unexpected argument %q", args[0])
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			req := &rpmgrv1.CreateEnrollmentTokenRequest{OrgId: s.creds.Org, Labels: labels, Ephemeral: ephemeral, Ttl: durationpb.New(ttl)}
			if setFlags(fs)["max-uses"] {
				req.MaxUses = proto.Int32(int32(maxUses)) //nolint:gosec // G115: protovalidate bounds it
			}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			if err := s.resolve(ctx, "connector", connector, &req.ConnectorId); err != nil {
				return err
			}
			if err := s.resolve(ctx, "gateway-group", gwGroup, &req.GatewayGroupId); err != nil {
				return err
			}
			var resp *connect.Response[rpmgrv1.CreateEnrollmentTokenResponse]
			if err := s.withStepUp(ctx, func() error {
				resp, err = rpmgrv1connect.NewEnrollmentServiceClient(s.hc, s.creds.Controller).CreateEnrollmentToken(ctx, connect.NewRequest(req))
				return err
			}); err != nil {
				return apiError(err)
			}
			t := resp.Msg.GetEnrollmentToken()
			_, err = fmt.Fprintf(env.Stdout, "Enrollment token %s, valid until %s; it is shown only now:\n%s\n", t.GetId(),
				t.GetExpireTime().AsTime().UTC().Format(time.RFC3339), resp.Msg.GetToken())
			return err
		},
	}
}
