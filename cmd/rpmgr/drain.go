// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// withEndDrain adds --end-drain to `update gateway` and `update connector` (D160): instead of
// changing a field, the command ends the drain of the agent's old process after a hand-off, which
// closes what the old process still holds. Any other flag with it is refused.
func withEndDrain(update *cli.Command, kind string) *cli.Command {
	var end bool
	var ufs *flag.FlagSet
	c := *update
	c.Summary += "; with --end-drain, end the drain of its old process after a hand-off"
	c.Flags = func(fs *flag.FlagSet) {
		ufs = fs
		if update.Flags != nil {
			update.Flags(fs)
		}
		fs.BoolVar(&end, "end-drain", false, "end the drain of the old process of the last hand-off now: it closes its open connections and exits")
	}
	c.Run = func(ctx context.Context, env *cli.Env, args []string) error {
		if !end {
			return update.Run(ctx, env, args)
		}
		if len(args) != 1 {
			return cli.Usagef("expected the %s's ID or name", kind)
		}
		if set := setFlags(ufs); len(set) != 1 {
			return cli.Usagef("--end-drain changes no field: give no other flag with it")
		}
		s, err := newAPISession(env)
		if err != nil {
			return err
		}
		id, err := s.ref(ctx, kindOf(kind), args[0])
		if err != nil {
			return err
		}
		var ended *rpmgrv1.DrainingProcess
		err = s.withStepUp(ctx, func() error {
			if kind == "gateway" {
				resp, err := rpmgrv1connect.NewGatewayServiceClient(s.hc, s.creds.Controller).EndGatewayDrain(ctx,
					connect.NewRequest(&rpmgrv1.EndGatewayDrainRequest{GatewayId: id}))
				if err == nil {
					ended = resp.Msg.GetEnded()
				}
				return err
			}
			resp, err := rpmgrv1connect.NewConnectorServiceClient(s.hc, s.creds.Controller).EndConnectorDrain(ctx,
				connect.NewRequest(&rpmgrv1.EndConnectorDrainRequest{ConnectorId: id}))
			if err == nil {
				ended = resp.Msg.GetEnded()
			}
			return err
		})
		if err != nil {
			return apiError(err)
		}
		_, err = fmt.Fprintf(env.Stdout, "Ended the drain of the old process of %s %s; it closes its %d connections, %d UDP flows and %d sessions.\n",
			kind, id, ended.GetConnections(), ended.GetFlows(), ended.GetSessions())
		return err
	}
	return &c
}
