// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// connectorCommands are update connector, decommission connector and revoke enrollment-token.
func connectorCommands() (update, decommission, revoke *cli.Command) {
	var (
		name, transport, output string
		labels                  = mapFlag{}
		force                   bool
		wait                    time.Duration
		ufs                     *flag.FlagSet
	)
	update = &cli.Command{
		Name: "connector", Summary: "change a connector's name, labels or transport", Args: "<id>",
		Flags: func(fs *flag.FlagSet) {
			ufs = fs
			fs.StringVar(&name, "name", "", "the connector's name, unique in the org")
			fs.Var(labels, "label", "a label key=value; repeat for more; the labels replace the old ones")
			fs.StringVar(&transport, "transport", "", "the data-session transport: auto, quic or h2; empty is the instance's")
			fs.BoolVar(&force, "force", false, "update without checking that the connector is unchanged since this command read it")
			fs.DurationVar(&wait, "wait", 0, "wait up to this long, at most 30s, for the agents to apply the change")
			outputFlag(fs, &output)
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the connector's ID")
			}
			set := setFlags(ufs)
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			cc := rpmgrv1connect.NewConnectorServiceClient(s.hc, s.creds.Controller)
			cur, err := cc.GetConnector(ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: args[0]}))
			if err != nil {
				return apiError(err)
			}
			c := proto.Clone(cur.Msg.GetConnector()).(*rpmgrv1.Connector)
			var paths []string
			if set["name"] {
				c.Name, paths = name, append(paths, "name")
			}
			if set["label"] {
				c.Labels, paths = labels, append(paths, "labels")
			}
			if set["transport"] {
				n, err := enumOf("transport", transport)
				if err != nil {
					return err
				}
				c.Transport, paths = rpmgrv1.DataTransport(n), append(paths, "transport")
			}
			if len(paths) == 0 {
				return cli.Usagef("name a field to change: --name, --label or --transport")
			}
			req := &rpmgrv1.UpdateConnectorRequest{Connector: c, UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}
			if !force {
				req.Etag = cur.Msg.GetConnector().GetEtag()
			}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			r := connect.NewRequest(req)
			setWait(r.Header(), wait)
			resp, err := cc.UpdateConnector(ctx, r)
			if err != nil {
				return apiError(err)
			}
			return s.writtenAs(ctx, env, "Updated connector", "connector", resp.Msg.GetConnector(), resp.Msg.ProtoReflect(), output)
		},
	}
	var dforce bool
	var dwait time.Duration
	decommission = &cli.Command{
		Name: "connector", Summary: "take a connector out of service for good, revoking its identity", Args: "<id>",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&dforce, "force", false, "decommission without checking that the connector is unchanged since this command read it")
			fs.DurationVar(&dwait, "wait", 0, "wait up to this long, at most 30s, for the agents to apply the change")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the connector's ID")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			cc := rpmgrv1connect.NewConnectorServiceClient(s.hc, s.creds.Controller)
			req := &rpmgrv1.DecommissionConnectorRequest{ConnectorId: args[0]}
			if !dforce {
				cur, err := cc.GetConnector(ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: args[0]}))
				if err != nil {
					return apiError(err)
				}
				req.Etag = cur.Msg.GetConnector().GetEtag()
			}
			r := connect.NewRequest(req)
			setWait(r.Header(), dwait)
			resp, err := cc.DecommissionConnector(ctx, r)
			if err != nil {
				return apiError(err)
			}
			_, err = fmt.Fprintf(env.Stdout, "Decommissioned connector %s%s; its identity is revoked and its sessions closed.\n", args[0],
				applied(resp.Msg.ProtoReflect()))
			return err
		},
	}
	revoke = &cli.Command{
		Name: "enrollment-token", Summary: "revoke an enrollment token, so that it enrolls nothing more", Args: "<id>",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the token's ID")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			if _, err := rpmgrv1connect.NewEnrollmentServiceClient(s.hc, s.creds.Controller).RevokeEnrollmentToken(ctx,
				connect.NewRequest(&rpmgrv1.RevokeEnrollmentTokenRequest{EnrollmentTokenId: args[0]})); err != nil {
				return apiError(err)
			}
			_, err = fmt.Fprintf(env.Stdout, "Revoked enrollment token %s.\n", args[0])
			return err
		},
	}
	return update, decommission, revoke
}

// installCommand prints the command that installs an agent of the org (docs/07-api.md,
// EnrollmentService.GetInstallCommand); the token it needs is made separately and never shown in
// it.
func installCommand(ctx context.Context, env *cli.Env, role string, allow []string) error {
	roles := map[string]rpmgrv1.AgentRole{"connector": rpmgrv1.AgentRole_AGENT_ROLE_CONNECTOR, "gateway": rpmgrv1.AgentRole_AGENT_ROLE_GATEWAY}
	r, ok := roles[role]
	if !ok {
		return cli.Usagef("--role %q: connector or gateway", role)
	}
	s, err := newAPISession(env)
	if err != nil {
		return err
	}
	req := &rpmgrv1.GetInstallCommandRequest{OrgId: s.creds.Org, Role: r, AllowTargets: allow}
	if err := protovalidate.Validate(req); err != nil {
		return cli.Usagef("%v", err)
	}
	resp, err := rpmgrv1connect.NewEnrollmentServiceClient(s.hc, s.creds.Controller).GetInstallCommand(ctx, connect.NewRequest(req))
	if err != nil {
		return apiError(err)
	}
	_, err = fmt.Fprintln(env.Stdout, resp.Msg.GetCommand())
	return err
}

// writtenAs prints a written resource of kind and how far the agents are with the change.
func (s *apiSession) writtenAs(ctx context.Context, env *cli.Env, verb, kind string, res proto.Message, resp protoreflect.Message, output string) error {
	k, _ := apicli.KindOf(kind)
	id := res.ProtoReflect().Get(res.ProtoReflect().Descriptor().Fields().ByName("id")).String()
	if _, err := fmt.Fprintf(env.Stdout, "%s %s%s.\n", verb, id, applied(resp)); err != nil {
		return err
	}
	return s.print(ctx, env.Stdout, k, output, []protoreflect.Message{res.ProtoReflect()}, []string{id}, false)
}
