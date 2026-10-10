// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// infrastructureCommands are the create and update commands of gateway groups, gateways and port
// pools, and the gateway's own: drain, enable, decommission, its enrollment token, and the quotas.
func infrastructureCommands() (create, update []*cli.Command, more map[string][]*cli.Command) {
	for _, r := range []struct {
		kind   string
		fields []field
	}{
		{"gateway-group", []field{
			{flag: "name", name: "name", usage: "the group's name, unique in the org", update: true},
			{flag: "region", name: "region", usage: "where its gateways are, for people", update: true},
			{flag: "public-hostname", name: "public_hostnames", usage: "a name under which its gateways are reached", update: true},
			{flag: "trusted-proxy", name: "trusted_proxy_cidrs", usage: "a CIDR of a proxy in front of its gateways whose X-Forwarded-For counts", update: true}}},
		{"gateway", []field{
			{flag: "group", name: "gateway_group_id", usage: "its gateway group, by name or ID", ref: "gateway-group"},
			{flag: "name", name: "name", usage: "the gateway's name, unique in the org", update: true},
			{flag: "tunnel-endpoint", name: "tunnel_endpoints", usage: "a host:port at which connectors reach it", update: true}}},
		{"port-pool", []field{
			{flag: "group", name: "gateway_group_id", usage: "its gateway group, by name or ID", ref: "gateway-group"},
			{flag: "protocol", name: "protocol", usage: "tcp or udp"},
			{flag: "from", name: "port_from", usage: "its first port", update: true},
			{flag: "to", name: "port_to", usage: "its last port", update: true}}},
	} {
		c, u := resourceCommands(r.kind, r.fields)
		create, update = append(create, c), append(update, u)
	}
	more = map[string][]*cli.Command{
		"drain":        {gatewaySwitch("drain", false)},
		"enable":       {gatewaySwitch("enable", true)},
		"decommission": {decommissionGateway()},
		"create":       {gatewayTokenCommand()},
		"set":          {quotaCommand()},
	}
	return create, update, more
}

// gatewaySwitch is `drain gateway` (R22: it accepts no new connections and drains its data
// sessions) or `enable gateway`.
func gatewaySwitch(verb string, enabled bool) *cli.Command {
	var force bool
	var wait time.Duration
	summary := "stop a gateway taking new connections, letting the open ones drain"
	if enabled {
		summary = "let a drained gateway take connections again"
	}
	return &cli.Command{
		Name: "gateway", Summary: summary, Args: "<id>",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&force, "force", false, "change it without checking that it is unchanged since this command read it")
			fs.DurationVar(&wait, "wait", 0, "wait up to this long, at most 30s, for the agents to apply the change")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the gateway's ID")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			gc := rpmgrv1connect.NewGatewayServiceClient(s.hc, s.creds.Controller)
			cur, err := gc.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: args[0]}))
			if err != nil {
				return apiError(err)
			}
			g := cur.Msg.GetGateway()
			g.Enabled = enabled
			req := &rpmgrv1.UpdateGatewayRequest{Gateway: g, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"enabled"}}}
			if !force {
				req.Etag = g.GetEtag()
			}
			r := connect.NewRequest(req)
			setWait(r.Header(), wait)
			resp, err := gc.UpdateGateway(ctx, r)
			if err != nil {
				return apiError(err)
			}
			_, err = fmt.Fprintf(env.Stdout, "%s gateway %s%s.\n", map[bool]string{true: "Enabled", false: "Drained"}[enabled], args[0],
				applied(resp.Msg.ProtoReflect()))
			return err
		},
	}
}

func decommissionGateway() *cli.Command {
	var force bool
	return &cli.Command{
		Name: "gateway", Summary: "take a gateway out of service for good, revoking its identity", Args: "<id>",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&force, "force", false, "decommission without checking that the gateway is unchanged since this command read it")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the gateway's ID")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			gc := rpmgrv1connect.NewGatewayServiceClient(s.hc, s.creds.Controller)
			req := &rpmgrv1.DecommissionGatewayRequest{GatewayId: args[0]}
			if !force {
				cur, err := gc.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: args[0]}))
				if err != nil {
					return apiError(err)
				}
				req.Etag = cur.Msg.GetGateway().GetEtag()
			}
			resp, err := gc.DecommissionGateway(ctx, connect.NewRequest(req))
			if err != nil {
				return apiError(err)
			}
			_, err = fmt.Fprintf(env.Stdout, "Decommissioned gateway %s%s; its identity is revoked and its slot free.\n", args[0],
				applied(resp.Msg.ProtoReflect()))
			return err
		},
	}
}

// gatewayTokenCommand is `create gateway-token`: the token that enrolls one gateway (R15), shown
// once, after a step-up.
func gatewayTokenCommand() *cli.Command {
	var gateway string
	var ttl time.Duration
	return &cli.Command{
		Name: "gateway-token", Summary: "make the token that enrolls a gateway; it is shown once",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&gateway, "gateway", "", "the gateway, by name or ID")
			fs.DurationVar(&ttl, "ttl", time.Hour, "how long it lasts")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 || gateway == "" {
				return cli.Usagef("give --gateway and no argument")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			req := &rpmgrv1.CreateGatewayEnrollmentTokenRequest{Ttl: durationpb.New(ttl)}
			if err := s.resolve(ctx, "gateway", gateway, &req.GatewayId); err != nil {
				return err
			}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			var resp *connect.Response[rpmgrv1.CreateGatewayEnrollmentTokenResponse]
			if err := s.withStepUp(ctx, func() error {
				resp, err = rpmgrv1connect.NewEnrollmentServiceClient(s.hc, s.creds.Controller).CreateGatewayEnrollmentToken(ctx, connect.NewRequest(req))
				return err
			}); err != nil {
				return apiError(err)
			}
			_, err = fmt.Fprintf(env.Stdout, "Enrollment token %s for gateway %s; it is shown only now:\n%s\n",
				resp.Msg.GetEnrollmentToken().GetId(), req.GetGatewayId(), resp.Msg.GetToken())
			return err
		},
	}
}

// quotaCommand is `set port-quota`: how many ports of a group's pools the org may hold.
func quotaCommand() *cli.Command {
	var group, protocol string
	var maxPorts int
	return &cli.Command{
		Name: "port-quota", Summary: "set how many ports of a gateway group's pools the org may hold",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&group, "group", "", "the gateway group, by name or ID")
			fs.StringVar(&protocol, "protocol", "", "tcp or udp")
			fs.IntVar(&maxPorts, "max", 0, "the most ports")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			p, ok := map[string]rpmgrv1.PortProtocol{"tcp": rpmgrv1.PortProtocol_PORT_PROTOCOL_TCP, "udp": rpmgrv1.PortProtocol_PORT_PROTOCOL_UDP}[protocol]
			if len(args) > 0 || group == "" || !ok {
				return cli.Usagef("give --group, --protocol tcp or udp, and --max")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			req := &rpmgrv1.SetPortQuotaRequest{OrgId: s.creds.Org, Protocol: p, MaxPorts: int32(maxPorts)} //nolint:gosec // G115: protovalidate bounds it
			if err := s.resolve(ctx, "gateway-group", group, &req.GatewayGroupId); err != nil {
				return err
			}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			resp, err := rpmgrv1connect.NewGatewayServiceClient(s.hc, s.creds.Controller).SetPortQuota(ctx, connect.NewRequest(req))
			if err != nil {
				return apiError(err)
			}
			q := resp.Msg.GetPortQuota()
			_, err = fmt.Fprintf(env.Stdout, "Port quota %s: at most %d %s ports, %d held.\n", q.GetId(), q.GetMaxPorts(), protocol, q.GetAllocatedPorts())
			return err
		},
	}
}
