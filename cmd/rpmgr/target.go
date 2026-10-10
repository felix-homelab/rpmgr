// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"strconv"
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

// targetFlags are the flags of `create route-target` and `update route-target`.
type targetFlags struct {
	route, connector, address, unix, upstream, serverName, caBundle, spki, proxy string
	weight, priority                                                             uint
	disabled, force                                                              bool
	wait                                                                         time.Duration
	output                                                                       string
}

func (f *targetFlags) flags(fs *flag.FlagSet, create bool) {
	if create {
		fs.StringVar(&f.route, "route", "", "the route, by name or ID")
		fs.StringVar(&f.connector, "connector", "", "the connector that dials the target, by name or ID")
	} else {
		fs.BoolVar(&f.force, "force", false, "update without checking that the target is unchanged since this command read it")
	}
	fs.StringVar(&f.address, "address", "", "the target's host:port, as the connector dials it")
	fs.StringVar(&f.unix, "unix", "", "the target's Unix socket on the connector host, instead of --address")
	fs.StringVar(&f.upstream, "upstream", "", "what the target speaks: tcp, http, https or h2c")
	fs.StringVar(&f.serverName, "server-name", "", "https: the name its certificate must carry")
	fs.StringVar(&f.caBundle, "ca-bundle", "", "https: the CA bundle that verifies it, by name or ID; empty is the gateway's roots")
	fs.StringVar(&f.spki, "spki", "", "https: the SHA-256 of its public key, 64 hex digits, checked as well")
	fs.StringVar(&f.proxy, "proxy-protocol", "", "the PROXY header sent first: none, v1 or v2")
	fs.UintVar(&f.weight, "weight", 0, "its share of the streams among targets of the same priority")
	fs.UintVar(&f.priority, "priority", 0, "lower first; a higher one gets streams only when no lower one is ready")
	fs.BoolVar(&f.disabled, "disabled", false, "the target gets no streams")
	fs.DurationVar(&f.wait, "wait", 0, "wait up to this long, at most 30s, for the agents to apply the change")
	outputFlag(fs, &f.output)
}

func init() {
	enums["upstream"] = map[string]int32{"tcp": 1, "http": 2, "https": 3, "h2c": 4}
	enums["proxy-protocol"] = map[string]int32{"none": 1, "v1": 2, "v2": 3}
}

// targetOf applies the flags that set names to a copy of base and returns it with the update mask
// of those flags.
func (f *targetFlags) targetOf(set map[string]bool, base *rpmgrv1.RouteTarget) (*rpmgrv1.RouteTarget, []string, error) {
	if set["address"] && set["unix"] {
		return nil, nil, cli.Usagef("give --address or --unix, not both")
	}
	for _, name := range []string{"upstream", "proxy-protocol"} {
		if _, err := enumOf(name, map[string]string{"upstream": f.upstream, "proxy-protocol": f.proxy}[name]); set[name] && err != nil {
			return nil, nil, err
		}
	}
	t := proto.Clone(base).(*rpmgrv1.RouteTarget)
	var paths []string
	do := func(flagName, path string, assign func() error) error {
		if !set[flagName] {
			return nil
		}
		paths = append(paths, path)
		return assign()
	}
	for _, err := range []error{
		do("address", "host_port", func() error {
			host, port, err := net.SplitHostPort(f.address)
			n, perr := strconv.ParseUint(port, 10, 16)
			if err != nil || perr != nil {
				return cli.Usagef("--address %q is not host:port", f.address)
			}
			t.Address = &rpmgrv1.RouteTarget_HostPort{HostPort: &rpmgrv1.HostPort{Host: host, Port: uint32(n)}}
			return nil
		}),
		do("unix", "unix_path", func() error { t.Address = &rpmgrv1.RouteTarget_UnixPath{UnixPath: f.unix}; return nil }),
		do("upstream", "upstream_protocol", func() error {
			n, _ := enumOf("upstream", f.upstream)
			t.UpstreamProtocol = rpmgrv1.UpstreamProtocol(n)
			return nil
		}),
		do("server-name", "tls.server_name", func() error { tls(t).ServerName = f.serverName; return nil }),
		do("ca-bundle", "tls.ca_bundle_id", func() error { tls(t).CaBundleId = f.caBundle; return nil }),
		do("spki", "tls.spki_sha256", func() error { tls(t).SpkiSha256 = f.spki; return nil }),
		do("proxy-protocol", "proxy_protocol", func() error {
			n, _ := enumOf("proxy-protocol", f.proxy)
			t.ProxyProtocol = rpmgrv1.ProxyProtocol(n)
			return nil
		}),
		do("weight", "weight", func() error { t.Weight = uint32(f.weight); return nil }),         //nolint:gosec // G115: protovalidate bounds it
		do("priority", "priority", func() error { t.Priority = uint32(f.priority); return nil }), //nolint:gosec // G115: protovalidate bounds it
		do("disabled", "enabled", func() error { t.Enabled = !f.disabled; return nil }),
	} {
		if err != nil {
			return nil, nil, err
		}
	}
	return t, paths, nil
}

func targetCommands() (create, update *cli.Command) {
	var cf, uf targetFlags
	var cfs, ufs *flag.FlagSet
	create = &cli.Command{
		Name: "route-target", Summary: "add a target to a route",
		Flags: func(fs *flag.FlagSet) { cfs = fs; cf.flags(fs, true) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			set := setFlags(cfs)
			switch {
			case len(args) > 0:
				return cli.Usagef("unexpected argument %q", args[0])
			case cf.route == "" || cf.connector == "" || !set["address"] && !set["unix"]:
				return cli.Usagef("give --route, --connector and --address or --unix")
			}
			t, _, err := cf.targetOf(set, &rpmgrv1.RouteTarget{Enabled: !cf.disabled})
			if err != nil {
				return err
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			req := &rpmgrv1.CreateRouteTargetRequest{Target: t}
			for _, ref := range []struct {
				kind, value string
				dst         *string
			}{{"route", cf.route, &req.RouteId}, {"connector", cf.connector, &t.ConnectorId}, {"ca-bundle", cf.caBundle, &tls(t).CaBundleId}} {
				if err := s.resolve(ctx, ref.kind, ref.value, ref.dst); err != nil {
					return err
				}
			}
			if t.GetTls().GetServerName() == "" && t.GetTls().GetCaBundleId() == "" && t.GetTls().GetSpkiSha256() == "" {
				t.Tls = nil
			}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			c := connect.NewRequest(req)
			setWait(c.Header(), cf.wait)
			resp, err := rpmgrv1connect.NewRouteServiceClient(s.hc, s.creds.Controller).CreateRouteTarget(ctx, c)
			if err != nil {
				return apiError(err)
			}
			return s.writtenTarget(ctx, env, "Added", resp.Msg.GetTarget(), resp.Msg.ProtoReflect(), cf.output)
		},
	}
	update = &cli.Command{
		Name: "route-target", Summary: "change the fields of a route target that the flags name", Args: "<id>",
		Flags: func(fs *flag.FlagSet) { ufs = fs; uf.flags(fs, false) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the target's ID")
			}
			set := setFlags(ufs)
			for _, name := range []string{"force", "wait", "o"} {
				delete(set, name)
			}
			if len(set) == 0 {
				return cli.Usagef("name a field to change")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			rc := rpmgrv1connect.NewRouteServiceClient(s.hc, s.creds.Controller)
			cur, err := rc.GetRouteTarget(ctx, connect.NewRequest(&rpmgrv1.GetRouteTargetRequest{RouteTargetId: args[0]}))
			if err != nil {
				return apiError(err)
			}
			t, paths, err := uf.targetOf(set, cur.Msg.GetTarget())
			if err != nil {
				return err
			}
			if set["ca-bundle"] {
				if err := s.resolve(ctx, "ca-bundle", uf.caBundle, &tls(t).CaBundleId); err != nil {
					return err
				}
			}
			req := &rpmgrv1.UpdateRouteTargetRequest{Target: t, UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}
			if !uf.force {
				req.Etag = cur.Msg.GetTarget().GetEtag()
			}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			c := connect.NewRequest(req)
			setWait(c.Header(), uf.wait)
			resp, err := rc.UpdateRouteTarget(ctx, c)
			if err != nil {
				return apiError(err)
			}
			return s.writtenTarget(ctx, env, "Updated", resp.Msg.GetTarget(), resp.Msg.ProtoReflect(), uf.output)
		},
	}
	return create, update
}

// tls is a target's TLS settings, made if it has none.
func tls(t *rpmgrv1.RouteTarget) *rpmgrv1.UpstreamTLSSettings {
	if t.Tls == nil {
		t.Tls = &rpmgrv1.UpstreamTLSSettings{}
	}
	return t.Tls
}

// resolve sets dst to the ID of the org's resource of kind that ref names; an empty ref sets
// nothing.
func (s *apiSession) resolve(ctx context.Context, kind, ref string, dst *string) error {
	if ref == "" {
		return nil
	}
	k, err := apicli.KindOf(kind)
	if err != nil {
		return err
	}
	if *dst, err = k.Resolve(ctx, s.hc, s.creds.Controller, s.creds.Org, ref); err != nil {
		return apiError(err)
	}
	return nil
}

// writtenTarget prints a written target and how far the agents are with the change.
func (s *apiSession) writtenTarget(ctx context.Context, env *cli.Env, verb string, t *rpmgrv1.RouteTarget, resp protoreflect.Message, output string) error {
	k, _ := apicli.KindOf("route-target")
	if _, err := fmt.Fprintf(env.Stdout, "%s route target %s%s.\n", verb, t.GetId(), applied(resp)); err != nil {
		return err
	}
	return s.print(ctx, env.Stdout, k, output, []protoreflect.Message{t.ProtoReflect()}, []string{t.GetId()}, false)
}
