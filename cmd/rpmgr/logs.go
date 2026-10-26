// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// logsCommands are `rpmgr logs connector|gateway <agent>`.
func logsCommands() map[string][]*cli.Command {
	return map[string][]*cli.Command{"logs": {streamLogs("connector"), streamLogs("gateway")}}
}

// streamLogs is `rpmgr logs <kind> <agent>`: it follows the agent's live log, which the agent
// redacted, until interrupted or until the operation's deadline (docs/03-connections.md,
// "Control session"); each line is printed with its time and level, and a line where the agent
// dropped lines says how many.
func streamLogs(kind string) *cli.Command {
	var level, filter string
	var debug bool
	return &cli.Command{
		Name: kind, Summary: "follow a " + kind + "'s live log, redacted on the " + kind + ", until interrupted (Owner or Admin)",
		Args: "<" + kind + ">",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&level, "level", "info", "the lowest level shown: debug, info, warn or error")
			fs.StringVar(&filter, "filter", "", "show only lines that contain this text")
			fs.BoolVar(&debug, "debug", false, "raise the "+kind+"'s level to debug while the log is followed; audited")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected one %s, by name or ID", kind)
			}
			// Checked before anything is sent; the agent's ID replaces the placeholder once resolved.
			req := &rpmgrv1.StreamLogsRequest{Level: level, Filter: filter, RaiseToDebug: debug, AgentId: "placeholder"}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			if req.AgentId, err = kindOf(kind).Resolve(ctx, s.hc, s.creds.Controller, s.creds.Org, args[0]); err != nil {
				return apiError(err)
			}
			hc := *s.hc
			hc.Timeout = 0 // the stream lasts until interrupted; ctx ends it
			st, err := rpmgrv1connect.NewLogServiceClient(&hc, s.creds.Controller).StreamLogs(ctx, connect.NewRequest(req))
			if err != nil {
				return apiError(err)
			}
			defer func() { _ = st.Close() }()
			for st.Receive() {
				l := st.Msg().GetLine()
				if l == nil {
					continue // a heartbeat
				}
				if n := l.GetDroppedBefore(); n > 0 {
					if _, err := fmt.Fprintf(env.Stdout, "… %d lines dropped: the %s logged faster than they could be sent\n", n, kind); err != nil {
						return err
					}
				}
				cut := ""
				if l.GetTruncated() {
					cut = " …(cut)"
				}
				if _, err := fmt.Fprintf(env.Stdout, "%s %-5s %s%s\n", l.GetTime().AsTime().UTC().Format(time.RFC3339Nano),
					strings.ToUpper(l.GetLevel()), l.GetText(), cut); err != nil {
					return err
				}
			}
			switch {
			case ctx.Err() != nil:
				return nil
			case st.Err() != nil:
				return apiError(st.Err())
			}
			_, err = fmt.Fprintf(env.Stderr, "The live log ended at its deadline; run the command again to go on.\n")
			return err
		},
	}
}
