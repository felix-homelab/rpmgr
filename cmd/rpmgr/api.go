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

	"connectrpc.com/connect"
	"go.yaml.in/yaml/v3"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// apiCommands are the verb-first commands of the public API (docs/16-cli.md, D51).
func apiCommands() []*cli.Command {
	return []*cli.Command{getCommand()}
}

// kindsHelp lists the kinds for a command's synopsis.
func kindsHelp() string {
	var names []string
	for _, k := range apicli.Kinds {
		names = append(names, k.Name)
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
	var output string
	return &cli.Command{
		Name: "get", Summary: "show a resource of the public API", Args: "<" + kindsHelp() + "> <id>",
		Flags: func(fs *flag.FlagSet) { outputFlag(fs, &output) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			k, err := kindArgs(args, 2)
			if err != nil {
				return err
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			res, err := s.get(ctx, k, args[1])
			if err != nil {
				return err
			}
			return s.print(ctx, env.Stdout, k, output, res, args[1])
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

// print writes a resource as a table, as its YAML manifest (or as YAML for a kind without
// manifests) or as JSON.
func (s *apiSession) print(ctx context.Context, w io.Writer, k apicli.Kind, output string, res protoreflect.Message, id string) error {
	switch output {
	case "json":
		b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(res.Interface())
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	case "yaml":
		if k.Manifest == "" {
			return writeYAML(w, []protoreflect.Message{res})
		}
		req := &rpmgrv1.ExportManifestsRequest{OrgId: s.creds.Org, ResourceIds: []string{id}}
		r, err := rpmgrv1connect.NewManifestServiceClient(s.hc, s.creds.Controller).ExportManifests(ctx, connect.NewRequest(req))
		if err != nil {
			return apiError(err)
		}
		_, err = io.WriteString(w, r.Msg.GetYaml())
		return err
	case "table":
		return writeTable(w, k, []protoreflect.Message{res})
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
