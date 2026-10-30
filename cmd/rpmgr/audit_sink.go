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
		{flag: "kind", name: "kind", usage: "how it delivers: webhook, syslog (RFC 5424 over TLS) or s3 (object storage with Object Lock)"},
		{flag: "url", name: "url", usage: "the webhook's https:// URL, without credentials (webhook sinks)", update: true},
		{flag: "address", name: "address", usage: "the syslog server as host:port; its certificate is checked against the host", update: true},
		{flag: "endpoint", name: "endpoint", usage: "the object store's https:// URL, or http:// on a loopback address (s3 sinks)", update: true},
		{flag: "region", name: "region", usage: "the region the store's requests are signed for (s3 sinks)", update: true},
		{flag: "bucket", name: "bucket", usage: "the bucket, which needs Object Lock and versioning (s3 sinks)", update: true},
		{flag: "access-key-id", name: "access_key_id", usage: "the access key's ID (s3 sinks)", update: true},
		{flag: "retention-days", name: "retention_days", usage: "how long each object stays locked, 30 to 3650 days, 365 if not set (s3 sinks)", update: true},
		{flag: "ca-file", name: "ca_bundle", usage: "a file of PEM CA certificates the syslog server's or the object store's certificate must chain to; " +
			"without it the system roots", update: true, file: true},
		{flag: "secret-file", name: "secret", usage: "a file holding the secret that signs the deliveries, or the object store's secret key, " +
			"at least 16 bytes; write-only", update: true, file: true, trim: true},
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
