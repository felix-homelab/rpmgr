// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

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

// webhookFormats are the values of --format.
var webhookFormats = map[string]rpmgrv1.WebhookFormat{"rpmgr": rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_RPMGR,
	"discord": rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_DISCORD, "slack": rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_SLACK,
	"teams": rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_TEAMS}

// webhookTarget sets the format and the URL of h from the flags. The URL of a chat format holds
// the service's token, so it comes from a file (or "-" for standard input), never from an
// argument, which the shell history and the process list would keep; it goes in secret_url, which
// the API never returns. An rpmgr endpoint's URL is --url. It adds the fields it set to paths.
func webhookTarget(h *rpmgrv1.Webhook, paths []string, format, target, urlFile string, stdin io.Reader) ([]string, error) {
	if format != "" {
		f, ok := webhookFormats[format]
		if !ok {
			return nil, cli.Usagef("--format is rpmgr, discord, slack or teams, not %q", format)
		}
		h.Format, paths = f, append(paths, "format")
	}
	chat := h.Format != rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_UNSPECIFIED && h.Format != rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_RPMGR
	switch {
	case target != "" && urlFile != "":
		return nil, cli.Usagef("give --url or --url-file, not both")
	case chat && target != "":
		return nil, cli.Usagef("the URL of a chat service holds its token: give it with --url-file (a file, or - for standard input), not --url")
	case !chat && urlFile != "":
		return nil, cli.Usagef("--url-file is for a chat format; give an rpmgr endpoint's URL with --url")
	case target != "":
		h.Url, paths = target, append(paths, "url")
	case urlFile != "":
		var b []byte
		var err error
		if urlFile == "-" {
			b, err = io.ReadAll(io.LimitReader(stdin, 4096))
		} else {
			b, err = os.ReadFile(urlFile) //nolint:gosec // G304: the user's file
		}
		if err != nil {
			return nil, fmt.Errorf("read --url-file: %w", err)
		}
		h.SecretUrl, paths = strings.TrimSpace(string(b)), append(paths, "secret_url")
	}
	return paths, nil
}

// webhookCommands are create, update, enable, disable and test webhook; get, list and delete
// are part of the generic commands, with the kinds webhook and webhook-delivery.
func webhookCommands() map[string][]*cli.Command {
	var (
		force, instance, disabled, rotate, allEvents bool
		target, format, urlFile                      string
		events                                       cli.List
	)
	flags := func(fs *flag.FlagSet, write bool) {
		fs.BoolVar(&instance, "instance", false, "the instance's endpoints, which receive instance events, for an Instance Admin, instead of the org's")
		if write {
			fs.StringVar(&target, "url", "", "the https:// URL the events are sent to, without a user name, a password or a fragment (format rpmgr)")
			fs.StringVar(&format, "format", "", "how events are posted: rpmgr (a signed JSON envelope, the default), discord, slack or teams (a message; "+
				"the URL then comes from --url-file, and a change of format needs a new URL)")
			fs.StringVar(&urlFile, "url-file", "", "a file holding the chat service's webhook URL, which holds its token, or - for standard input; write-only")
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
			if len(args) > 0 || (target == "" && urlFile == "") {
				return cli.Usagef("give --url (or, for a chat format, --url-file) and no argument")
			}
			in := &rpmgrv1.Webhook{EventTypes: events, Enabled: !disabled}
			if _, err := webhookTarget(in, nil, format, target, urlFile, os.Stdin); err != nil {
				return err
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			h, secret, err := newWebhooks(s, instance).create(ctx, in)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(env.Stdout, "Created webhook %s.\n", h.GetId()); err != nil {
				return err
			}
			if secret == "" {
				_, err := fmt.Fprintf(env.Stdout, "A %s endpoint has no signing secret; its URL is stored sealed and shown as %s only.\n",
					strings.ToLower(strings.TrimPrefix(h.GetFormat().String(), "WEBHOOK_FORMAT_")), h.GetUrl())
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
			if target == "" && urlFile == "" && format == "" && len(events) == 0 && !allEvents && !rotate {
				return cli.Usagef("name a change: --url, --url-file, --format, --event, --all-events or --rotate-secret")
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
			h := &rpmgrv1.Webhook{Id: cur.GetId(), Format: cur.GetFormat()}
			paths, err := webhookTarget(h, nil, format, target, urlFile, os.Stdin)
			if err != nil {
				return err
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
