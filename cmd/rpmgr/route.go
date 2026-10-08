// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"slices"
	"strings"
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

// listFlag is a flag that may be given more than once.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// mapFlag is a key=value flag that may be given more than once.
type mapFlag map[string]string

func (m mapFlag) String() string { return "" }
func (m mapFlag) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return fmt.Errorf("%q is not key=value", v)
	}
	m[k] = val
	return nil
}

// routeFlags are the flags of `create route` and `update route`; each sets the fields of a route
// its paths name (docs/07-api.md, "Resource design").
type routeFlags struct {
	name, group, description, transport            string
	http, tcp, udp, passthrough, disabled          bool
	hostnames, policies                            listFlag
	labels, requestHeaders, responseHeaders        mapFlag
	pathPrefix, tlsMode, certificate, port80, host string
	hsts                                           time.Duration
	port                                           uint
	idleTimeout                                    time.Duration
	websocket                                      bool
	maxBody                                        uint64
	force                                          bool
	wait                                           time.Duration
	output                                         string
}

// flags registers the flags; create adds the type and the group, which do not change.
func (f *routeFlags) flags(fs *flag.FlagSet, create bool) {
	f.labels, f.requestHeaders, f.responseHeaders = mapFlag{}, mapFlag{}, mapFlag{}
	if create {
		fs.BoolVar(&f.http, "http", false, "an http route: TLS ends at the gateway")
		fs.BoolVar(&f.tcp, "tcp", false, "a tcp route on a public port")
		fs.BoolVar(&f.udp, "udp", false, "a udp route on a public port")
		fs.BoolVar(&f.passthrough, "tls-passthrough", false, "a TLS route the gateway passes through by its SNI")
		fs.StringVar(&f.group, "group", "", "the gateway group, by name or ID")
	} else {
		fs.BoolVar(&f.force, "force", false, "update without checking that the route is unchanged since this command read it")
	}
	fs.StringVar(&f.name, "name", "", "the route's name, unique in the org")
	fs.StringVar(&f.description, "description", "", "a description for people")
	fs.Var(f.labels, "label", "a label key=value; repeat for more")
	fs.StringVar(&f.transport, "transport", "", "the data-session transport: auto, quic or h2; empty is the connector's")
	fs.Var(&f.policies, "policy", "an access policy, by name or ID, in the order given; repeat for more")
	fs.BoolVar(&f.disabled, "disabled", false, "the route is not served")
	fs.Var(&f.hostnames, "hostname", "a hostname of an http or tls-passthrough route; repeat for more")
	fs.StringVar(&f.pathPrefix, "path-prefix", "", "http: the path prefix it serves")
	fs.StringVar(&f.tlsMode, "tls-mode", "", "http: acme or certificate")
	fs.StringVar(&f.certificate, "certificate", "", "http: the uploaded certificate's ID, with --tls-mode certificate")
	fs.StringVar(&f.port80, "port80", "", "http: what port 80 does: redirect, serve or off")
	fs.DurationVar(&f.hsts, "hsts", 0, "http: the Strict-Transport-Security max-age; 0 sends none")
	fs.StringVar(&f.host, "host-header", "", "http: the Host header towards the upstream; empty keeps the client's")
	fs.Var(f.requestHeaders, "set-request-header", "http: a header Name=value set towards the upstream; repeat for more")
	fs.Var(f.responseHeaders, "set-response-header", "http: a header Name=value set towards the client; repeat for more")
	fs.BoolVar(&f.websocket, "websocket", true, "http: whether WebSocket upgrades pass")
	fs.Uint64Var(&f.maxBody, "max-body", 0, "http: the largest request body in bytes; 0 is no limit")
	fs.UintVar(&f.port, "port", 0, "tcp, udp: the public port; 0 on create picks a free one")
	fs.DurationVar(&f.idleTimeout, "idle-timeout", 0, "tcp: close a connection idle this long; udp: forget a flow idle this long")
	fs.DurationVar(&f.wait, "wait", 0, "wait up to this long, at most 30s, for the agents to apply the change")
	outputFlag(fs, &f.output)
}

// enums are the command line's names of the API's enum values.
var enums = map[string]map[string]int32{
	"transport": {"": 0, "auto": 1, "quic": 2, "h2": 3},
	"tls-mode":  {"acme": 1, "certificate": 2},
	"port80":    {"redirect": 1, "serve": 2, "off": 3},
}

// enumOf is the value of an enum flag.
func enumOf(flagName, v string) (int32, error) {
	n, ok := enums[flagName][v]
	if !ok {
		var names []string
		for name := range enums[flagName] {
			if name != "" {
				names = append(names, name)
			}
		}
		slices.Sort(names)
		return 0, cli.Usagef("--%s %q: one of %s", flagName, v, strings.Join(names, ", "))
	}
	return n, nil
}

// routeOf applies the flags that set names to a copy of base, the route as it is (empty for a
// new one), and returns it with the update mask of those flags. A field the flags do not name
// keeps base's value, so the route as a whole passes the API's checks. typ is the route's type:
// "http", "tcp", "udp" or "tls_passthrough".
func (f *routeFlags) routeOf(set map[string]bool, typ string, base *rpmgrv1.Route) (*rpmgrv1.Route, []string, error) {
	for flagName, types := range map[string]string{"hostname": "http tls_passthrough", "path-prefix": "http", "tls-mode": "http",
		"certificate": "http", "port80": "http", "hsts": "http", "host-header": "http", "set-request-header": "http",
		"set-response-header": "http", "websocket": "http", "max-body": "http", "port": "tcp udp", "idle-timeout": "tcp udp"} {
		if set[flagName] && !strings.Contains(types, typ) {
			return nil, nil, cli.Usagef("--%s is not for a %s route", flagName, typ)
		}
	}
	for _, flagName := range []string{"transport", "tls-mode", "port80"} {
		v := map[string]string{"transport": f.transport, "tls-mode": f.tlsMode, "port80": f.port80}[flagName]
		if _, err := enumOf(flagName, v); set[flagName] && err != nil {
			return nil, nil, err
		}
	}
	r := proto.Clone(base).(*rpmgrv1.Route)
	var paths []string
	do := func(flagName, path string, assign func()) {
		if set[flagName] {
			paths = append(paths, path)
			assign()
		}
	}
	do("name", "name", func() { r.Name = f.name })
	do("description", "description", func() { r.Description = f.description })
	do("label", "labels", func() { r.Labels = f.labels })
	do("disabled", "enabled", func() { r.Enabled = !f.disabled })
	do("policy", "policy_ids", func() { r.PolicyIds = nil })
	do("transport", "transport", func() { n, _ := enumOf("transport", f.transport); r.Transport = rpmgrv1.DataTransport(n) })
	idle := proto.Uint32(uint32(f.idleTimeout / time.Second)) //nolint:gosec // G115: protovalidate bounds it
	port := uint32(f.port)                                    //nolint:gosec // G115: protovalidate bounds it
	switch typ {
	case "http":
		h := r.GetHttp()
		if h == nil {
			h = &rpmgrv1.HTTPRouteSpec{}
			r.Spec = &rpmgrv1.Route_Http{Http: h}
		}
		do("hostname", "http.hostnames", func() { h.Hostnames = f.hostnames })
		do("path-prefix", "http.path_prefix", func() { h.PathPrefix = f.pathPrefix })
		do("tls-mode", "http.tls_mode", func() { n, _ := enumOf("tls-mode", f.tlsMode); h.TlsMode = rpmgrv1.TLSMode(n) })
		do("certificate", "http.certificate_id", func() { h.CertificateId = f.certificate })
		do("port80", "http.port80", func() { n, _ := enumOf("port80", f.port80); h.Port80 = rpmgrv1.Port80Mode(n) })
		do("hsts", "http.hsts_max_age_seconds", func() { h.HstsMaxAgeSeconds = uint32(f.hsts / time.Second) }) //nolint:gosec // G115: protovalidate bounds it
		do("host-header", "http.host_header", func() { h.HostHeader = f.host })
		do("set-request-header", "http.request_headers_set", func() { h.RequestHeadersSet = f.requestHeaders })
		do("set-response-header", "http.response_headers_set", func() { h.ResponseHeadersSet = f.responseHeaders })
		do("websocket", "http.websocket", func() { h.Websocket = proto.Bool(f.websocket) })
		do("max-body", "http.max_body_bytes", func() { h.MaxBodyBytes = f.maxBody })
	case "tls_passthrough":
		t := r.GetTlsPassthrough()
		if t == nil {
			t = &rpmgrv1.TLSPassthroughRouteSpec{}
			r.Spec = &rpmgrv1.Route_TlsPassthrough{TlsPassthrough: t}
		}
		do("hostname", "tls_passthrough.hostnames", func() { t.Hostnames = f.hostnames })
	case "tcp":
		t := r.GetTcp()
		if t == nil {
			t = &rpmgrv1.TCPRouteSpec{}
			r.Spec = &rpmgrv1.Route_Tcp{Tcp: t}
		}
		do("port", "tcp.port", func() { t.Port = port })
		do("idle-timeout", "tcp.idle_timeout_seconds", func() { t.IdleTimeoutSeconds = idle })
	case "udp":
		u := r.GetUdp()
		if u == nil {
			u = &rpmgrv1.UDPRouteSpec{}
			r.Spec = &rpmgrv1.Route_Udp{Udp: u}
		}
		do("port", "udp.port", func() { u.Port = port })
		do("idle-timeout", "udp.flow_idle_timeout_seconds", func() { u.FlowIdleTimeoutSeconds = idle })
	}
	return r, paths, nil
}

// setFlags are the names of the flags the command line gave.
func setFlags(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

// resolveRefs turns the names of the route's policies into IDs.
func (s *apiSession) resolveRefs(ctx context.Context, r *rpmgrv1.Route, policies []string) error {
	k, _ := apicli.KindOf("access-policy")
	for _, p := range policies {
		id, err := k.Resolve(ctx, s.hc, s.creds.Controller, s.creds.Org, p)
		if err != nil {
			return apiError(err)
		}
		r.PolicyIds = append(r.PolicyIds, id)
	}
	return nil
}

func routeCommands() (create, update *cli.Command) {
	var cf, uf routeFlags
	var cfs, ufs *flag.FlagSet
	create = &cli.Command{
		Name: "route", Summary: "create a route", Args: "",
		Flags: func(fs *flag.FlagSet) { cfs = fs; cf.flags(fs, true) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 {
				return cli.Usagef("unexpected argument %q", args[0])
			}
			var types []string
			for typ, on := range map[string]bool{"http": cf.http, "tcp": cf.tcp, "udp": cf.udp, "tls_passthrough": cf.passthrough} {
				if on {
					types = append(types, typ)
				}
			}
			if len(types) != 1 || cf.name == "" || cf.group == "" {
				return cli.Usagef("give --name, --group and one of --http, --tcp, --udp and --tls-passthrough")
			}
			r, _, err := cf.routeOf(setFlags(cfs), types[0], &rpmgrv1.Route{Enabled: !cf.disabled})
			if err != nil {
				return err
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			gk, _ := apicli.KindOf("gateway-group")
			if r.GatewayGroupId, err = gk.Resolve(ctx, s.hc, s.creds.Controller, s.creds.Org, cf.group); err != nil {
				return apiError(err)
			}
			if err := s.resolveRefs(ctx, r, cf.policies); err != nil {
				return err
			}
			req := &rpmgrv1.CreateRouteRequest{OrgId: s.creds.Org, Route: r}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			c := connect.NewRequest(req)
			setWait(c.Header(), cf.wait)
			resp, err := rpmgrv1connect.NewRouteServiceClient(s.hc, s.creds.Controller).CreateRoute(ctx, c)
			if err != nil {
				return apiError(err)
			}
			return s.written(ctx, env, "Created", resp.Msg.GetRoute(), resp.Msg.ProtoReflect(), cf.output)
		},
	}
	update = &cli.Command{
		Name: "route", Summary: "change the fields of a route that the flags name", Args: "<id>",
		Flags: func(fs *flag.FlagSet) { ufs = fs; uf.flags(fs, false) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the route's ID")
			}
			set := setFlags(ufs)
			return updateRoute(ctx, env, args[0], &uf, set)
		},
	}
	return create, update
}

// updateRoute reads the route, then changes the fields the flags set name under its etag.
func updateRoute(ctx context.Context, env *cli.Env, id string, f *routeFlags, set map[string]bool) error {
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
	cur, err := rc.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: id}))
	if err != nil {
		return apiError(err)
	}
	// The route's type is the name of its spec's field: http, tcp, udp or tls_passthrough.
	m := cur.Msg.GetRoute().ProtoReflect()
	spec := m.WhichOneof(m.Descriptor().Oneofs().ByName("spec"))
	if spec == nil {
		return fmt.Errorf("route %s has no spec", id)
	}
	typ := string(spec.Name())
	r, paths, err := f.routeOf(set, typ, cur.Msg.GetRoute())
	if err != nil {
		return err
	}
	if err := s.resolveRefs(ctx, r, f.policies); err != nil {
		return err
	}
	r.Id = id
	req := &rpmgrv1.UpdateRouteRequest{Route: r, UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}
	if !f.force {
		req.Etag = cur.Msg.GetRoute().GetEtag()
	}
	if err := protovalidate.Validate(req); err != nil {
		return cli.Usagef("%v", err)
	}
	c := connect.NewRequest(req)
	setWait(c.Header(), f.wait)
	resp, err := rc.UpdateRoute(ctx, c)
	if err != nil {
		return apiError(err)
	}
	return s.written(ctx, env, "Updated", resp.Msg.GetRoute(), resp.Msg.ProtoReflect(), f.output)
}

// setWait asks a write's answer to wait for the agents (docs/07-api.md, "Writes and apply
// status").
func setWait(h map[string][]string, wait time.Duration) {
	for k, v := range waitHeader(wait) {
		h[k] = v
	}
}

// written prints a written route and how far the agents are with the change.
func (s *apiSession) written(ctx context.Context, env *cli.Env, verb string, r *rpmgrv1.Route, resp protoreflect.Message, output string) error {
	k, _ := apicli.KindOf("route")
	if _, err := fmt.Fprintf(env.Stdout, "%s route %s%s.\n", verb, r.GetId(), applied(resp)); err != nil {
		return err
	}
	return s.print(ctx, env.Stdout, k, output, []protoreflect.Message{r.ProtoReflect()}, []string{r.GetId()}, false)
}
