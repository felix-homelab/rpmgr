// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// instanceKind is the kind a command works on: with --instance the Instance Admin's endpoints
// and their deliveries stand in for the org's (docs/16-cli.md, "Webhooks"); no other kind has an
// instance variant.
func instanceKind(k apicli.Kind, instance bool) (apicli.Kind, error) {
	if !instance {
		return k, nil
	}
	if k.Name != "webhook" && k.Name != "webhook-delivery" {
		return k, cli.Usagef("--instance applies to webhook and webhook-delivery, not %s", k.Name)
	}
	return apicli.KindOf("instance-" + k.Name)
}

// webhooks are the calls on the endpoints of the org, or with instance of the instance, which
// answer alike.
type webhooks struct {
	org      rpmgrv1connect.WebhookServiceClient
	inst     rpmgrv1connect.InstanceWebhookServiceClient
	orgID    string
	instance bool
}

func newWebhooks(s *apiSession, instance bool) *webhooks {
	return &webhooks{org: rpmgrv1connect.NewWebhookServiceClient(s.hc, s.creds.Controller),
		inst: rpmgrv1connect.NewInstanceWebhookServiceClient(s.hc, s.creds.Controller), orgID: s.creds.Org, instance: instance}
}

func (w *webhooks) get(ctx context.Context, id string) (*rpmgrv1.Webhook, error) {
	if w.instance {
		r, err := w.inst.GetInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.GetInstanceWebhookRequest{WebhookId: id}))
		if err != nil {
			return nil, apiError(err)
		}
		return r.Msg.GetWebhook(), nil
	}
	r, err := w.org.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: id}))
	if err != nil {
		return nil, apiError(err)
	}
	return r.Msg.GetWebhook(), nil
}

// create makes an endpoint and returns it with its secret.
func (w *webhooks) create(ctx context.Context, h *rpmgrv1.Webhook) (*rpmgrv1.Webhook, string, error) {
	rid := make([]byte, 16)
	if _, err := rand.Read(rid); err != nil {
		return nil, "", err
	}
	id := hex.EncodeToString(rid)
	if w.instance {
		req := &rpmgrv1.CreateInstanceWebhookRequest{Webhook: h, RequestId: id}
		if err := protovalidate.Validate(req); err != nil {
			return nil, "", cli.Usagef("%v", err)
		}
		r, err := w.inst.CreateInstanceWebhook(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, "", apiError(err)
		}
		return r.Msg.GetWebhook(), r.Msg.GetSecret(), nil
	}
	req := &rpmgrv1.CreateWebhookRequest{OrgId: w.orgID, Webhook: h, RequestId: id}
	if err := protovalidate.Validate(req); err != nil {
		return nil, "", cli.Usagef("%v", err)
	}
	r, err := w.org.CreateWebhook(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, "", apiError(err)
	}
	return r.Msg.GetWebhook(), r.Msg.GetSecret(), nil
}

// update changes the fields the mask names of an endpoint, under etag.
func (w *webhooks) update(ctx context.Context, h *rpmgrv1.Webhook, paths []string, etag string) (*rpmgrv1.Webhook, error) {
	mask := &fieldmaskpb.FieldMask{Paths: paths}
	if w.instance {
		req := &rpmgrv1.UpdateInstanceWebhookRequest{Webhook: h, UpdateMask: mask, Etag: etag}
		if err := protovalidate.Validate(req); err != nil {
			return nil, cli.Usagef("%v", err)
		}
		r, err := w.inst.UpdateInstanceWebhook(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, apiError(err)
		}
		return r.Msg.GetWebhook(), nil
	}
	req := &rpmgrv1.UpdateWebhookRequest{Webhook: h, UpdateMask: mask, Etag: etag}
	if err := protovalidate.Validate(req); err != nil {
		return nil, cli.Usagef("%v", err)
	}
	r, err := w.org.UpdateWebhook(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, apiError(err)
	}
	return r.Msg.GetWebhook(), nil
}

// rotate replaces the secret of an endpoint and returns the new one.
func (w *webhooks) rotate(ctx context.Context, id string) (string, error) {
	if w.instance {
		r, err := w.inst.RotateInstanceWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateInstanceWebhookSecretRequest{WebhookId: id}))
		if err != nil {
			return "", apiError(err)
		}
		return r.Msg.GetSecret(), nil
	}
	r, err := w.org.RotateWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateWebhookSecretRequest{WebhookId: id}))
	if err != nil {
		return "", apiError(err)
	}
	return r.Msg.GetSecret(), nil
}

// test sends a test event to an endpoint.
func (w *webhooks) test(ctx context.Context, id string) (delivered bool, status int32, reason string, err error) {
	if w.instance {
		r, err := w.inst.TestInstanceWebhook(ctx, connect.NewRequest(&rpmgrv1.TestInstanceWebhookRequest{WebhookId: id}))
		if err != nil {
			return false, 0, "", apiError(err)
		}
		return r.Msg.GetDelivered(), r.Msg.GetStatusCode(), r.Msg.GetError(), nil
	}
	r, err := w.org.TestWebhook(ctx, connect.NewRequest(&rpmgrv1.TestWebhookRequest{WebhookId: id}))
	if err != nil {
		return false, 0, "", apiError(err)
	}
	return r.Msg.GetDelivered(), r.Msg.GetStatusCode(), r.Msg.GetError(), nil
}

// showSecret prints the signing secret of an endpoint. The API returns it once, at creation and
// at a rotation, so this is the only time it can be read: it is never an argument of a command
// ([04](docs/04-security.md#secrets-at-rest-and-in-logs)) and `get` and `list` do not show it.
func showSecret(w io.Writer, id, secret string) error {
	_, err := fmt.Fprintf(w, "Signing secret of %s, shown once; store it now, it cannot be read again:\n%s\n", id, secret)
	return err
}

// webhookCommands are create, update, enable, disable and test webhook; get, list and delete
// are part of the generic commands, with the kinds webhook and webhook-delivery.
func webhookCommands() map[string][]*cli.Command {
	var (
		force, instance, disabled, rotate, allEvents bool
		target                                       string
		events                                       cli.List
	)
	flags := func(fs *flag.FlagSet, write bool) {
		fs.BoolVar(&instance, "instance", false, "the instance's endpoints, which receive instance events, for an Instance Admin, instead of the org's")
		if write {
			fs.StringVar(&target, "url", "", "the https:// URL the events are sent to, without a user name, a password or a fragment")
			fs.Var(&events, "event", "an event type or a prefix such as route.*; repeat for more; none means all events")
		}
	}
	create := &cli.Command{
		Name: "webhook", Summary: "make a webhook endpoint and print its signing secret once",
		Flags: func(fs *flag.FlagSet) {
			flags(fs, true)
			fs.BoolVar(&disabled, "disabled", false, "make it disabled; enable webhook turns it on")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 || target == "" {
				return cli.Usagef("give --url and no argument")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			h, secret, err := newWebhooks(s, instance).create(ctx, &rpmgrv1.Webhook{Url: target, EventTypes: events, Enabled: !disabled})
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(env.Stdout, "Created webhook %s.\n", h.GetId()); err != nil {
				return err
			}
			return showSecret(env.Stdout, h.GetId(), secret)
		},
	}
	update := &cli.Command{
		Name: "webhook", Summary: "change a webhook endpoint; with --rotate-secret replace its signing secret and print the new one once",
		Args: "<id>",
		Flags: func(fs *flag.FlagSet) {
			flags(fs, true)
			fs.BoolVar(&allEvents, "all-events", false, "send every event, not only the types listed")
			fs.BoolVar(&rotate, "rotate-secret", false, "replace the signing secret; the old one keeps signing for 24 h")
			fs.BoolVar(&force, "force", false, "update without checking that the endpoint is unchanged since this command read it")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the webhook's ID")
			}
			if target == "" && len(events) == 0 && !allEvents && !rotate {
				return cli.Usagef("name a change: --url, --event, --all-events or --rotate-secret")
			}
			if allEvents && len(events) > 0 {
				return cli.Usagef("give --event or --all-events, not both")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			w := newWebhooks(s, instance)
			cur, err := w.get(ctx, args[0])
			if err != nil {
				return err
			}
			h := &rpmgrv1.Webhook{Id: cur.GetId()}
			var paths []string
			if target != "" {
				h.Url, paths = target, append(paths, "url")
			}
			if len(events) > 0 || allEvents {
				h.EventTypes, paths = events, append(paths, "event_types")
			}
			etag := cur.GetEtag()
			if force {
				etag = ""
			}
			if len(paths) > 0 {
				if cur, err = w.update(ctx, h, paths, etag); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(env.Stdout, "Updated webhook %s.\n", cur.GetId()); err != nil {
					return err
				}
			}
			if !rotate {
				return nil
			}
			secret, err := w.rotate(ctx, args[0])
			if err != nil {
				return err
			}
			return showSecret(env.Stdout, args[0], secret)
		},
	}
	switchTo := func(verb string, enabled bool) *cli.Command {
		var inst bool
		return &cli.Command{
			Name: "webhook", Summary: verb + " a webhook endpoint; enabling one that failed clears its disabled state", Args: "<id>",
			Flags: func(fs *flag.FlagSet) {
				fs.BoolVar(&inst, "instance", false, "the instance's endpoint, for an Instance Admin")
			},
			Run: func(ctx context.Context, env *cli.Env, args []string) error {
				if len(args) != 1 {
					return cli.Usagef("expected the webhook's ID")
				}
				s, err := newAPISession(env)
				if err != nil {
					return err
				}
				w := newWebhooks(s, inst)
				cur, err := w.get(ctx, args[0])
				if err != nil {
					return err
				}
				if _, err := w.update(ctx, &rpmgrv1.Webhook{Id: cur.GetId(), Enabled: enabled}, []string{"enabled"}, cur.GetEtag()); err != nil {
					return err
				}
				_, err = fmt.Fprintf(env.Stdout, "%s webhook %s.\n", map[bool]string{true: "Enabled", false: "Disabled"}[enabled], cur.GetId())
				return err
			},
		}
	}
	var tinst bool
	test := &cli.Command{
		Name: "webhook", Summary: "send a test event to a webhook endpoint through the egress guard and say what the receiver answered", Args: "<id>",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&tinst, "instance", false, "the instance's endpoint, for an Instance Admin")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the webhook's ID")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			delivered, status, reason, err := newWebhooks(s, tinst).test(ctx, args[0])
			if err != nil {
				return err
			}
			if !delivered {
				if reason == "" {
					reason = fmt.Sprintf("HTTP %d", status)
				}
				return fmt.Errorf("the test event was not delivered: %s", reason)
			}
			_, err = fmt.Fprintf(env.Stdout, "The receiver answered %d.\n", status)
			return err
		},
	}
	return map[string][]*cli.Command{"create": {create}, "update": {update}, "enable": {switchTo("enable", true)},
		"disable": {switchTo("disable", false)}, "test": {test}}
}
