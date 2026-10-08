// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"go.yaml.in/yaml/v3"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// apiCommands are the verb-first commands of the public API (docs/16-cli.md, D51).
func apiCommands() []*cli.Command {
	createRoute, updateRoute, enableRoute, disableRoute, previewRoute := routeCommands()
	createTarget, updateTarget := targetCommands()
	updateConnector, decommissionConnector, revokeToken := connectorCommands()
	return []*cli.Command{getCommand(), listCommand(), deleteCommand(),
		group("create", "create a resource of the public API", createRoute, createTarget),
		group("update", "change a resource of the public API", updateRoute, updateTarget, updateConnector),
		group("decommission", "take an agent out of service for good", decommissionConnector),
		group("revoke", "revoke a credential", revokeToken),
		group("enable", "serve a resource again", enableRoute),
		group("disable", "stop serving a resource, keeping its configuration", disableRoute),
		group("preview", "show what a change would do, saving nothing", previewRoute)}
}

// kindsHelp lists the kinds a command takes, for its synopsis.
func kindsHelp(takes func(apicli.Kind) bool) string {
	var names []string
	for _, k := range apicli.Kinds {
		if takes(k) {
			names = append(names, k.Name)
		}
	}
	return strings.Join(names, "|")
}

// apiSession is what a command of the public API works with: the stored credentials and a client.
type apiSession struct {
	creds *apicli.Credentials
	hc    *http.Client
}

func newAPISession(env *cli.Env) (*apiSession, error) {
	path, err := apicli.Path(env.Getenv)
	if err != nil {
		return nil, err
	}
	creds, err := apicli.Load(path)
	if err != nil {
		return nil, err
	}
	hc, err := apicli.Client(creds)
	if err != nil {
		return nil, err
	}
	return &apiSession{creds: creds, hc: hc}, nil
}

func (s *apiSession) call(ctx context.Context, k apicli.Kind, method string, fields map[string]any, header http.Header) (protoreflect.Message, error) {
	md, err := k.Method(method)
	if err != nil {
		return nil, err
	}
	resp, err := apicli.Call(ctx, s.hc, s.creds.Controller, md, fields, header)
	if err != nil {
		return nil, apiError(err)
	}
	return resp, nil
}

// get reads one resource.
func (s *apiSession) get(ctx context.Context, k apicli.Kind, id string) (protoreflect.Message, error) {
	resp, err := s.call(ctx, k, "Get"+k.Resource, map[string]any{k.IDField: id}, nil)
	if err != nil {
		return nil, err
	}
	fd, err := k.Field(resp)
	if err != nil {
		return nil, err
	}
	return resp.Get(fd).Message(), nil
}

func getCommand() *cli.Command {
	var output, role string
	var allow listFlag
	return &cli.Command{
		Name: "get", Summary: "show a resource of the public API, or the install command of an agent",
		Args: "install-command | <" + kindsHelp(func(k apicli.Kind) bool { return !k.NoGet }) + "> <id>",
		Flags: func(fs *flag.FlagSet) {
			outputFlag(fs, &output)
			fs.StringVar(&role, "role", "connector", "install-command: the role to install, connector or gateway")
			fs.Var(&allow, "allow-target", "install-command: a target the connector may reach, ip:port or a socket path; repeat for more")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) == 1 && args[0] == "install-command" {
				return installCommand(ctx, env, role, allow)
			}
			k, err := kindArgs(args, 2)
			if err != nil {
				return err
			}
			if k.NoGet {
				return cli.Usagef("a %s is only listed: rpmgr list %s", k.Name, k.Name)
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			res, err := s.get(ctx, k, args[1])
			if err != nil {
				return err
			}
			return s.print(ctx, env.Stdout, k, output, []protoreflect.Message{res}, []string{args[1]}, false)
		},
	}
}

func listCommand() *cli.Command {
	var output string
	var all bool
	return &cli.Command{
		Name: "list", Summary: "list the resources of a kind in the org", Args: "<" + kindsHelp(func(k apicli.Kind) bool { return k.Plural != "" }) + ">",
		Flags: func(fs *flag.FlagSet) {
			outputFlag(fs, &output)
			fs.BoolVar(&all, "all", false, "also the decommissioned agents, and the used-up, expired and revoked enrollment tokens")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			k, err := kindArgs(args, 1)
			if err != nil {
				return err
			}
			if k.Plural == "" {
				return cli.Usagef("a %s is listed with what it belongs to; see rpmgr help get", k.Name)
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			var found []protoreflect.Message
			var ids []string
			md, err := k.Method("List" + k.Plural)
			if err != nil {
				return err
			}
			for page := ""; ; {
				fields := map[string]any{"org_id": s.creds.Org, "page_size": int32(500), "page_token": page}
				for _, name := range []string{"show_decommissioned", "show_inactive"} {
					if all && md.Input().Fields().ByName(protoreflect.Name(name)) != nil {
						fields[name] = true
					}
				}
				resp, err := s.call(ctx, k, "List"+k.Plural, fields, nil)
				if err != nil {
					return err
				}
				fd, err := k.Field(resp)
				if err != nil {
					return err
				}
				l := resp.Get(fd).List()
				for i := range l.Len() {
					found = append(found, l.Get(i).Message())
					ids = append(ids, l.Get(i).Message().Get(l.Get(i).Message().Descriptor().Fields().ByName("id")).String())
				}
				if page = resp.Get(resp.Descriptor().Fields().ByName("next_page_token")).String(); page == "" {
					break
				}
			}
			return s.print(ctx, env.Stdout, k, output, found, ids, true)
		},
	}
}

func deleteCommand() *cli.Command {
	var (
		force bool
		wait  time.Duration
	)
	return &cli.Command{
		Name: "delete", Summary: "delete a resource of the public API", Args: "<" + kindsHelp(func(k apicli.Kind) bool { return k.Delete }) + "> <id>",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&force, "force", false, "delete without checking that the resource is unchanged since this command read it")
			fs.DurationVar(&wait, "wait", 0, "wait up to this long, at most 30s, for the agents to apply the change")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			k, err := kindArgs(args, 2)
			if err != nil {
				return err
			}
			if !k.Delete {
				return cli.Usagef("a %s is not deleted; see rpmgr help", k.Name)
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			fields := map[string]any{k.IDField: args[1]}
			if !force {
				res, err := s.get(ctx, k, args[1])
				if err != nil {
					return err
				}
				fields["etag"] = res.Get(res.Descriptor().Fields().ByName("etag")).String()
			}
			resp, err := s.call(ctx, k, "Delete"+k.Resource, fields, waitHeader(wait))
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Deleted %s %s%s.\n", k.Name, args[1], applied(resp))
			return err
		},
	}
}

func outputFlag(fs *flag.FlagSet, p *string) {
	fs.StringVar(p, "o", "table", "output: table, yaml (the manifest, where the kind has one) or json")
}

// kindArgs checks the positional arguments: a kind, and an ID if n is 2.
func kindArgs(args []string, n int) (apicli.Kind, error) {
	if len(args) != n {
		return apicli.Kind{}, cli.Usagef("expected %d arguments, got %d", n, len(args))
	}
	k, err := apicli.KindOf(args[0])
	if err != nil {
		return apicli.Kind{}, cli.Usagef("%v", err)
	}
	return k, nil
}

// waitHeader asks a write's answer to wait for its apply status (docs/07-api.md, "Writes and apply
// status").
func waitHeader(wait time.Duration) http.Header {
	if wait <= 0 {
		return nil
	}
	return http.Header{"Rpmgr-Wait-Applied": []string{wait.String()}}
}

// applied describes the revision and apply status of a write's answer, if it has them.
func applied(resp protoreflect.Message) string {
	fields := resp.Descriptor().Fields()
	rev, st := fields.ByName("revision"), fields.ByName("apply_status")
	if rev == nil || !resp.Has(rev) {
		return ""
	}
	out := fmt.Sprintf(" in revision %d", resp.Get(rev).Message().Get(rev.Message().Fields().ByName("seq")).Int())
	if st != nil && resp.Has(st) {
		var as rpmgrv1.ApplyStatus
		b, err := proto.Marshal(resp.Get(st).Message().Interface())
		if err == nil && proto.Unmarshal(b, &as) == nil {
			out += fmt.Sprintf(", %s on %d of %d online agents", strings.TrimPrefix(as.GetState().String(), "APPLY_STATE_"),
				as.GetAgentsApplied(), as.GetAgentsTotal())
		}
	}
	return out
}

// print writes resources as a table, as YAML manifests (or the resources as YAML for a kind
// without them) or as JSON.
func (s *apiSession) print(ctx context.Context, w io.Writer, k apicli.Kind, output string, res []protoreflect.Message, ids []string, list bool) error {
	switch output {
	case "json":
		var out []json.RawMessage
		for _, r := range res {
			b, err := protojson.Marshal(r.Interface())
			if err != nil {
				return err
			}
			out = append(out, b)
		}
		var v any = out
		if !list {
			v = out[0]
		}
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	case "yaml":
		if k.Manifest == "" {
			return writeYAML(w, res)
		}
		req := &rpmgrv1.ExportManifestsRequest{OrgId: s.creds.Org, ResourceIds: ids}
		if list {
			req = &rpmgrv1.ExportManifestsRequest{OrgId: s.creds.Org, Kinds: []string{k.Manifest}}
		}
		if len(ids) == 0 {
			return nil
		}
		r, err := rpmgrv1connect.NewManifestServiceClient(s.hc, s.creds.Controller).ExportManifests(ctx, connect.NewRequest(req))
		if err != nil {
			return apiError(err)
		}
		_, err = io.WriteString(w, r.Msg.GetYaml())
		return err
	case "table":
		return writeTable(w, k, res)
	}
	return cli.Usagef("unknown output %q: table, yaml or json", output)
}

// writeYAML writes resources as YAML documents of their protobuf JSON mapping.
func writeYAML(w io.Writer, res []protoreflect.Message) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	for _, r := range res {
		v, err := jsonOf(r)
		if err != nil {
			return err
		}
		if err := enc.Encode(v); err != nil {
			return err
		}
	}
	return enc.Close()
}

func jsonOf(r protoreflect.Message) (map[string]any, error) {
	b, err := protojson.Marshal(r.Interface())
	if err != nil {
		return nil, err
	}
	var v map[string]any
	return v, json.Unmarshal(b, &v)
}

// writeTable writes one line per resource: its ID, its name or FQDN, and the kind's columns.
func writeTable(w io.Writer, k apicli.Kind, res []protoreflect.Message) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	head := []string{"ID", "NAME"}
	for _, c := range k.Columns {
		head = append(head, strings.ToUpper(c[strings.LastIndex(c, ".")+1:]))
	}
	_, _ = fmt.Fprintln(tw, strings.Join(head, "\t"))
	for _, r := range res {
		v, err := jsonOf(r)
		if err != nil {
			return err
		}
		name := cell(v, "name")
		if name == "" {
			name = cell(v, "fqdn")
		}
		row := []string{cell(v, "id"), name}
		for _, c := range k.Columns {
			row = append(row, cell(v, c))
		}
		_, _ = fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

// cell is the value at a dotted JSON path, a list joined by commas, or "-" if it is not set.
func cell(v map[string]any, path string) string {
	var cur any = v
	for _, key := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "-"
		}
		if cur, ok = m[key]; !ok {
			return "-"
		}
	}
	switch x := cur.(type) {
	case []any:
		var parts []string
		for _, p := range x {
			parts = append(parts, fmt.Sprint(p))
		}
		return strings.Join(parts, ",")
	case string:
		return x
	}
	return fmt.Sprint(cur)
}

// apiError says what the API refused, and for a stale etag shows the resource as it is now.
func apiError(err error) error {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return err
	}
	msg := cerr.Message()
	for _, d := range cerr.Details() {
		v, derr := d.Value()
		if derr != nil {
			continue
		}
		switch x := v.(type) {
		case *errdetails.ErrorInfo:
			if x.GetReason() != "" {
				msg += " (" + x.GetReason() + ")"
			}
		default:
			if cerr.Code() == connect.CodeFailedPrecondition {
				if b, err := (protojson.MarshalOptions{Multiline: true}).Marshal(v); err == nil {
					msg += "\nIt is now:\n" + string(b)
				}
			}
		}
	}
	if cerr.Code() == connect.CodeUnauthenticated {
		msg += "; log in again with a valid token (rpmgr login)"
	}
	return fmt.Errorf("%s: %s", strings.ToLower(strings.ReplaceAll(cerr.Code().String(), "_", " ")), msg)
}
