// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"slices"
	"strconv"
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

// mapFlag is a key=value flag that may be given more than once. An empty value adds nothing, so
// the flag given once with an empty value sets an empty map.
type mapFlag map[string]string

func (m mapFlag) String() string { return "" }
func (m mapFlag) Set(v string) error {
	if v == "" {
		return nil
	}
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
	http, tcp, udp, tcpUDP, passthrough, disabled  bool
	hostnames, policies                            cli.List
	labels, requestHeaders, responseHeaders        mapFlag
	pathPrefix, tlsMode, certificate, port80, host string
	hsts                                           time.Duration
	port                                           uint
	idleTimeout, flowIdleTimeout                   time.Duration
	websocket, maintenance                         bool
	maintenanceMessage                             string
	maxBody                                        uint64
	// The health check (docs/03-connections.md, "Target health").
	healthCheck, healthPath, healthStatus string
	healthPort, healthUnhealthy, healthOK uint
	healthInterval, healthTimeout         time.Duration
	force                                 bool
	wait                                  time.Duration
	output                                string
}

// flags registers the flags; create adds the type and the group, which do not change.
func (f *routeFlags) flags(fs *flag.FlagSet, create bool) {
	f.labels, f.requestHeaders, f.responseHeaders = mapFlag{}, mapFlag{}, mapFlag{}
	if create {
		fs.BoolVar(&f.http, "http", false, "an http route: TLS ends at the gateway")
		fs.BoolVar(&f.tcp, "tcp", false, "a tcp route on a public port")
		fs.BoolVar(&f.udp, "udp", false, "a udp route on a public port")
		fs.BoolVar(&f.tcpUDP, "tcp-udp", false, "a route on one public port number with both TCP and UDP")
		fs.BoolVar(&f.passthrough, "tls-passthrough", false, "a TLS route the gateway passes through by its SNI")
		fs.StringVar(&f.group, "group", "", "the gateway group, by name or ID")
	} else {
		fs.BoolVar(&f.force, "force", false, "update without checking that the route is unchanged since this command read it")
	}
	fs.StringVar(&f.name, "name", "", "the route's name, unique in the org")
	fs.StringVar(&f.description, "description", "", "a description for people")
	fs.Var(f.labels, "label", "a label key=value; repeat for more")
	fs.StringVar(&f.transport, "transport", "", "the data-session transport: auto, quic or h2; empty is the connector's")
	fs.Var(&f.policies, "policy", "an access policy, by name or ID; repeat for more")
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
	fs.BoolVar(&f.maintenance, "maintenance", false, "http: answer every request with the maintenance page, 503")
	fs.StringVar(&f.maintenanceMessage, "maintenance-message", "", "http: plain text the maintenance page shows, at most 500 characters")
	fs.UintVar(&f.port, "port", 0, "tcp, udp, tcp-udp: the public port; 0 on create picks a free one")
	fs.DurationVar(&f.idleTimeout, "idle-timeout", 0, "tcp, tcp-udp: close a connection idle this long; udp: forget a flow idle this long")
	fs.DurationVar(&f.flowIdleTimeout, "flow-idle-timeout", 0, "tcp-udp: forget a UDP flow idle this long")
	fs.StringVar(&f.healthCheck, "health-check", "", "the health check each connector runs against its targets: tcp, http, or none to remove it")
	fs.UintVar(&f.healthPort, "health-port", 0, "the port to check instead of each target's; required on udp routes")
	fs.StringVar(&f.healthPath, "health-path", "", "http check: the path to GET, / if empty")
	fs.StringVar(&f.healthStatus, "health-status", "", "http check: the passing statuses, as 200-399")
	fs.DurationVar(&f.healthInterval, "health-interval", 0, "how often each target is checked; 0 is the default")
	fs.DurationVar(&f.healthTimeout, "health-timeout", 0, "how long one check may take, below the interval; 0 is the default")
	fs.UintVar(&f.healthUnhealthy, "health-unhealthy", 0, "failed checks in a row that make a target unhealthy; 0 is the default")
	fs.UintVar(&f.healthOK, "health-healthy", 0, "passed checks in a row that make it healthy again; 0 is the default")
	fs.DurationVar(&f.wait, "wait", 0, "wait up to this long, at most 30s, for the agents to apply the change")
	outputFlag(fs, &f.output)
}

// healthFlags are the flags of the health check.
var healthFlags = []string{"health-check", "health-port", "health-path", "health-status", "health-interval", "health-timeout",
	"health-unhealthy", "health-healthy"}

// healthCheckOf applies the health check's flags to the route's check, cur, or a new one.
func (f *routeFlags) healthCheckOf(set map[string]bool, cur *rpmgrv1.HealthCheck) (*rpmgrv1.HealthCheck, error) {
	if set["health-check"] && f.healthCheck == "none" {
		if n := slices.IndexFunc(healthFlags[1:], func(n string) bool { return set[n] }); n >= 0 {
			return nil, cli.Usagef("--health-check none removes the check: --%s goes with tcp or http", healthFlags[1+n])
		}
		return nil, nil
	}
	c := &rpmgrv1.HealthCheck{}
	if cur != nil {
		c = proto.Clone(cur).(*rpmgrv1.HealthCheck)
	} else if !set["health-check"] {
		return nil, cli.Usagef("the route has no health check: give --health-check tcp or http")
	}
	if set["health-check"] {
		t, ok := map[string]rpmgrv1.HealthCheckType{"tcp": rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP,
			"http": rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP}[f.healthCheck]
		if !ok {
			return nil, cli.Usagef("--health-check %q: tcp, http or none", f.healthCheck)
		}
		c.Type = t
	}
	if set["health-status"] {
		lo, hi, ok := strings.Cut(f.healthStatus, "-")
		a, err1 := strconv.ParseUint(lo, 10, 16)
		b, err2 := strconv.ParseUint(hi, 10, 16)
		if !ok || err1 != nil || err2 != nil {
			return nil, cli.Usagef("--health-status %q: as 200-399", f.healthStatus)
		}
		c.ExpectedStatusMin, c.ExpectedStatusMax = uint32(a), uint32(b)
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{{"health-interval", f.healthInterval}, {"health-timeout", f.healthTimeout}} {
		if set[d.name] && (d.v < 0 || d.v%time.Second != 0 || d.v/time.Second > math.MaxUint32) {
			return nil, cli.Usagef("--%s %v: whole seconds", d.name, d.v)
		}
	}
	for _, n := range []struct {
		name string
		v    uint
	}{{"health-port", f.healthPort}, {"health-unhealthy", f.healthUnhealthy}, {"health-healthy", f.healthOK}} {
		if set[n.name] && n.v > math.MaxUint32 {
			return nil, cli.Usagef("--%s %d: out of range", n.name, n.v)
		}
	}
	u := func(v uint) uint32 { return uint32(v) }                           //nolint:gosec // G115: bounded above, protovalidate checks the rest
	secs := func(d time.Duration) uint32 { return uint32(d / time.Second) } //nolint:gosec // G115: bounded above, protovalidate checks the rest
	for name, assign := range map[string]func(){
		"health-port": func() { c.Port = u(f.healthPort) }, "health-path": func() { c.HttpPath = f.healthPath },
		"health-interval": func() { c.IntervalSeconds = secs(f.healthInterval) }, "health-timeout": func() { c.TimeoutSeconds = secs(f.healthTimeout) },
		"health-unhealthy": func() { c.UnhealthyThreshold = u(f.healthUnhealthy) }, "health-healthy": func() { c.HealthyThreshold = u(f.healthOK) },
	} {
		if set[name] {
			assign()
		}
	}
	return c, nil
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
// "http", "tcp", "udp", "tcp_udp" or "tls_passthrough".
func (f *routeFlags) routeOf(set map[string]bool, typ string, base *rpmgrv1.Route) (*rpmgrv1.Route, []string, error) {
	for flagName, types := range map[string]string{"hostname": "http tls_passthrough", "path-prefix": "http", "tls-mode": "http",
		"certificate": "http", "port80": "http", "hsts": "http", "host-header": "http", "set-request-header": "http",
		"set-response-header": "http", "websocket": "http", "max-body": "http", "maintenance": "http", "maintenance-message": "http",
		"port": "tcp udp tcp_udp", "idle-timeout": "tcp udp tcp_udp", "flow-idle-timeout": "tcp_udp"} {
		if set[flagName] && !slices.Contains(strings.Fields(types), typ) {
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
	if slices.ContainsFunc(healthFlags, func(n string) bool { return set[n] }) {
		c, err := f.healthCheckOf(set, r.GetHealthCheck())
		if err != nil {
			return nil, nil, err
		}
		r.HealthCheck, paths = c, append(paths, "health_check")
	}
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
		do("maintenance", "http.maintenance", func() { h.Maintenance = f.maintenance })
		do("maintenance-message", "http.maintenance_message", func() { h.MaintenanceMessage = f.maintenanceMessage })
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
	case "tcp_udp":
		b := r.GetTcpUdp()
		if b == nil {
			b = &rpmgrv1.TCPUDPRouteSpec{}
			r.Spec = &rpmgrv1.Route_TcpUdp{TcpUdp: b}
		}
		do("port", "tcp_udp.port", func() { b.Port = port })
		do("idle-timeout", "tcp_udp.idle_timeout_seconds", func() { b.IdleTimeoutSeconds = idle })
		do("flow-idle-timeout", "tcp_udp.flow_idle_timeout_seconds", func() {
			b.FlowIdleTimeoutSeconds = proto.Uint32(uint32(f.flowIdleTimeout / time.Second)) //nolint:gosec // G115: protovalidate bounds it
		})
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

func routeCommands() (create, update, enable, disable, preview *cli.Command) {
	var cf, uf, pf routeFlags
	var cfs, ufs, pfs *flag.FlagSet
	var previewOf string
	create = &cli.Command{
		Name: "route", Summary: "create a route",
		Flags: func(fs *flag.FlagSet) { cfs = fs; cf.flags(fs, true) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 {
				return cli.Usagef("unexpected argument %q", args[0])
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			r, err := s.newRoute(ctx, &cf, setFlags(cfs))
			if err != nil {
				return err
			}
			c := connect.NewRequest(&rpmgrv1.CreateRouteRequest{OrgId: s.creds.Org, Route: r})
			setWait(c.Header(), cf.wait)
			resp, err := rpmgrv1connect.NewRouteServiceClient(s.hc, s.creds.Controller).CreateRoute(ctx, c)
			if err != nil {
				return apiError(err)
			}
			return s.written(ctx, env, "Created", resp.Msg.GetRoute(), resp.Msg.ProtoReflect(), cf.output)
		},
	}
	update = &cli.Command{
		Name: "route", Summary: "change the fields of a route that the flags name", Args: "<id or name>",
		Flags: func(fs *flag.FlagSet) { ufs = fs; uf.flags(fs, false) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the route's ID or name")
			}
			return updateRoute(ctx, env, args[0], &uf, setFlags(ufs))
		},
	}
	toggle := func(name string, enabled bool) *cli.Command {
		var f routeFlags
		return &cli.Command{
			Name: "route", Summary: name + " a route", Args: "<id or name>",
			Flags: func(fs *flag.FlagSet) {
				fs.BoolVar(&f.force, "force", false, "change it without checking that it is unchanged since this command read it")
				fs.DurationVar(&f.wait, "wait", 0, "wait up to this long, at most 30s, for the agents to apply the change")
				outputFlag(fs, &f.output)
			},
			Run: func(ctx context.Context, env *cli.Env, args []string) error {
				if len(args) != 1 {
					return cli.Usagef("expected the route's ID or name")
				}
				f.disabled = !enabled
				return updateRoute(ctx, env, args[0], &f, map[string]bool{"disabled": true})
			},
		}
	}
	preview = &cli.Command{
		Name: "route", Summary: "show what creating or changing a route would do, saving nothing",
		Flags: func(fs *flag.FlagSet) {
			pfs = fs
			pf.flags(fs, true)
			fs.StringVar(&previewOf, "route", "", "the ID of a route whose change to preview, rather than a new route")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 {
				return cli.Usagef("unexpected argument %q", args[0])
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			req := &rpmgrv1.PreviewRouteRequest{OrgId: s.creds.Org}
			set := setFlags(pfs)
			delete(set, "route")
			if previewOf == "" {
				if req.Route, err = s.newRoute(ctx, &pf, set); err != nil {
					return err
				}
			} else {
				upd, err := s.changedRoute(ctx, previewOf, &pf, set)
				if err != nil {
					return err
				}
				req.Route, req.UpdateMask, req.Etag = upd.GetRoute(), upd.GetUpdateMask(), upd.GetEtag()
			}
			resp, err := rpmgrv1connect.NewRouteServiceClient(s.hc, s.creds.Controller).PreviewRoute(ctx, connect.NewRequest(req))
			if err != nil {
				return apiError(err)
			}
			info := notes(env, pf.output).Stdout
			if _, err := fmt.Fprintf(info, "Gateways that would serve it: %s\nConnectors it would reach: %s\n",
				listOrNone(resp.Msg.GetGatewayIds()), listOrNone(resp.Msg.GetConnectorIds())); err != nil {
				return err
			}
			for _, p := range resp.Msg.GetProblems() {
				if _, err := fmt.Fprintf(info, "Problem: %s: %s\n", p.GetResourceId(), p.GetMessage()); err != nil {
					return err
				}
			}
			k, _ := apicli.KindOf("route")
			if pf.output == "yaml" { // a route not saved has no manifest to export
				return writeYAML(env.Stdout, []protoreflect.Message{resp.Msg.GetRoute().ProtoReflect()})
			}
			return s.print(ctx, env.Stdout, k, pf.output, []protoreflect.Message{resp.Msg.GetRoute().ProtoReflect()}, nil, false)
		},
	}
	return create, update, toggle("enable", true), toggle("disable", false), preview
}

func listOrNone(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}

// newRoute is the route the flags of create describe, its group and policies resolved, checked
// with the API's rules.
func (s *apiSession) newRoute(ctx context.Context, f *routeFlags, set map[string]bool) (*rpmgrv1.Route, error) {
	var types []string
	for typ, on := range map[string]bool{"http": f.http, "tcp": f.tcp, "udp": f.udp, "tcp_udp": f.tcpUDP, "tls_passthrough": f.passthrough} {
		if on {
			types = append(types, typ)
		}
	}
	if len(types) != 1 || f.name == "" || f.group == "" {
		return nil, cli.Usagef("give --name, --group and one of --http, --tcp, --udp, --tcp-udp and --tls-passthrough")
	}
	r, _, err := f.routeOf(set, types[0], &rpmgrv1.Route{Enabled: !f.disabled})
	if err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(&rpmgrv1.CreateRouteRequest{OrgId: s.creds.Org, Route: r}); err != nil {
		return nil, cli.Usagef("%v", err)
	}
	gk, _ := apicli.KindOf("gateway-group")
	if r.GatewayGroupId, err = gk.Resolve(ctx, s.hc, s.creds.Controller, s.creds.Org, f.group); err != nil {
		return nil, apiError(err)
	}
	return r, s.resolveRefs(ctx, r, f.policies)
}

// changedRoute reads the route and returns the update the flags set make, under its etag.
func (s *apiSession) changedRoute(ctx context.Context, id string, f *routeFlags, set map[string]bool) (*rpmgrv1.UpdateRouteRequest, error) {
	for _, name := range []string{"force", "wait", "o"} {
		delete(set, name)
	}
	if len(set) == 0 {
		return nil, cli.Usagef("name a field to change")
	}
	id, err := s.ref(ctx, kindOf("route"), id)
	if err != nil {
		return nil, err
	}
	cur, err := rpmgrv1connect.NewRouteServiceClient(s.hc, s.creds.Controller).GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: id}))
	if err != nil {
		return nil, apiError(err)
	}
	// The route's type is the name of its spec's field: http, tcp, udp, tcp_udp or tls_passthrough.
	m := cur.Msg.GetRoute().ProtoReflect()
	spec := m.WhichOneof(m.Descriptor().Oneofs().ByName("spec"))
	if spec == nil {
		return nil, fmt.Errorf("route %s has no spec", id)
	}
	r, paths, err := f.routeOf(set, string(spec.Name()), cur.Msg.GetRoute())
	if err != nil {
		return nil, err
	}
	if err := s.resolveRefs(ctx, r, f.policies); err != nil {
		return nil, err
	}
	r.Id = id
	req := &rpmgrv1.UpdateRouteRequest{Route: r, UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}
	if !f.force {
		req.Etag = cur.Msg.GetRoute().GetEtag()
	}
	if err := protovalidate.Validate(req); err != nil {
		return nil, cli.Usagef("%v", err)
	}
	return req, nil
}

// updateRoute changes the fields the flags set name, under the etag of the route as read.
func updateRoute(ctx context.Context, env *cli.Env, id string, f *routeFlags, set map[string]bool) error {
	s, err := newAPISession(env)
	if err != nil {
		return err
	}
	req, err := s.changedRoute(ctx, id, f, set)
	if err != nil {
		return err
	}
	c := connect.NewRequest(req)
	setWait(c.Header(), f.wait)
	resp, err := rpmgrv1connect.NewRouteServiceClient(s.hc, s.creds.Controller).UpdateRoute(ctx, c)
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
	if _, err := fmt.Fprintf(notes(env, output).Stdout, "%s route %s%s.\n", verb, r.GetId(), applied(resp)); err != nil {
		return err
	}
	return s.print(ctx, env.Stdout, k, output, []protoreflect.Message{r.ProtoReflect()}, []string{r.GetId()}, false)
}
