// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// auditSinkCommands are create audit-sink, update audit-sink and test audit-sink, for the Instance
// Admin (docs/16-cli.md). Get, list and delete are the generic ones. The secret comes from a file
// so that it stays out of the shell history and the process list.
func auditSinkCommands() map[string][]*cli.Command {
	create, update := resourceCommands("audit-sink", []field{
		{flag: "name", name: "name", usage: "the sink's name, unique among the sinks", update: true},
		{flag: "kind", name: "kind", usage: "how it delivers: webhook"},
		{flag: "url", name: "url", usage: "the webhook's https:// URL, without credentials", update: true},
		{flag: "secret-file", name: "secret", usage: "a file holding the secret that signs the deliveries, at least 16 bytes; " +
			"write-only", update: true, file: true, trim: true},
		{flag: "entries", name: "entries", usage: "send the entries too; the checkpoints always go", update: true},
		{flag: "enabled", name: "enabled", usage: "ship to it (false stops shipping; it catches up when enabled again)", update: true, updateOnly: true},
	})
	return map[string][]*cli.Command{"create": {create}, "update": {update}, "test": {testAuditSink()}}
}

// testAuditSink is test audit-sink.
func testAuditSink() *cli.Command {
	k, _ := apicli.KindOf("audit-sink")
	return &cli.Command{
		Name: "audit-sink", Summary: "send a sink a test item now and show the receiver's answer", Args: "<id or name>",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the sink's ID or name")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			id, err := s.ref(ctx, k, args[0])
			if err != nil {
				return err
			}
			var resp *connect.Response[rpmgrv1.TestAuditSinkResponse]
			err = s.withStepUp(ctx, func() error {
				var err error
				resp, err = rpmgrv1connect.NewAuditSinkServiceClient(s.hc, s.creds.Controller).TestAuditSink(ctx,
					connect.NewRequest(&rpmgrv1.TestAuditSinkRequest{AuditSinkId: id}))
				return err
			})
			if err != nil {
				return apiError(err)
			}
			if !resp.Msg.GetOk() {
				return fmt.Errorf("the sink %s did not accept the test item: %s", id, resp.Msg.GetError())
			}
			_, err = fmt.Fprintf(env.Stdout, "The sink %s accepted the test item.\n", id)
			return err
		},
	}
}
