// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"net/textproto"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/headermatch"
)

// assignment is the connector assignment of the applied snapshot: which connectors serve which
// route. It implements Assignment.
type assignment struct {
	cur atomic.Pointer[assigned]
}

type assigned struct {
	known  map[string]bool
	routes map[string][]RouteConnector
}

// Known implements Assignment.
func (a *assignment) Known(connectorID string) bool {
	s := a.cur.Load()
	return s != nil && s.known[connectorID]
}

// Connectors implements Assignment.
func (a *assignment) Connectors(routeID string) []RouteConnector {
	s := a.cur.Load()
	if s == nil {
		return nil
	}
	return s.routes[routeID]
}

// basicAuthOf parses a route's basic_auth rules: each names its policy and credential version and
// has users with distinct names and argon2id hashes.
func basicAuthOf(rules []*agentv1.BasicAuthRule) ([]BasicAuthRule, error) {
	var out []BasicAuthRule
	for i, r := range rules {
		if r.GetPolicyId() == "" || r.GetCredentialVersion() == "" || len(r.GetUsers()) == 0 {
			return nil, fmt.Errorf("rule %d: no policy, credential version or users", i+1)
		}
		rule := BasicAuthRule{PolicyID: r.GetPolicyId(), CredentialVersion: r.GetCredentialVersion(), Users: map[string]PHC{}}
		for _, u := range r.GetUsers() {
			name := u.GetName()
			if name == "" || strings.Contains(name, ":") {
				return nil, fmt.Errorf("rule %d: user name %q", i+1, name)
			}
			if _, dup := rule.Users[name]; dup {
				return nil, fmt.Errorf("rule %d: user %q twice", i+1, name)
			}
			h, err := ParsePHC(u.GetPasswordHash())
			if err != nil {
				return nil, fmt.Errorf("rule %d, user %q: %w", i+1, name, err)
			}
			rule.Users[name] = h
		}
		out = append(out, rule)
	}
	return out, nil
}

// connectorsOf returns the connectors of a gateway route resource and the same connectors ranked,
// nil for another kind.
func connectorsOf(res *agentv1.Resource) ([]string, []*agentv1.RouteConnector) {
	switch {
	case res.GetGatewayTcpRoute() != nil:
		return res.GetGatewayTcpRoute().GetConnectors(), res.GetGatewayTcpRoute().GetRankedConnectors()
	case res.GetGatewayUdpRoute() != nil:
		return res.GetGatewayUdpRoute().GetConnectors(), res.GetGatewayUdpRoute().GetRankedConnectors()
	case res.GetGatewayTcpUdpRoute() != nil:
		return res.GetGatewayTcpUdpRoute().GetConnectors(), res.GetGatewayTcpUdpRoute().GetRankedConnectors()
	case res.GetGatewayPassthroughRoute() != nil:
		return res.GetGatewayPassthroughRoute().GetConnectors(), res.GetGatewayPassthroughRoute().GetRankedConnectors()
	case res.GetGatewayHttpRoute() != nil:
		return res.GetGatewayHttpRoute().GetConnectors(), res.GetGatewayHttpRoute().GetRankedConnectors()
	}
	return nil, nil
}

// maxRankWeight bounds a ranked entry's weight: 1000 targets of the largest weight.
const maxRankWeight = 1_000_000

// rankOf returns a route's entries: the ranked ones where the controller sent them, else each
// connector at priority 0 and weight 1, as a controller before D90 meant them.
func rankOf(connectors []string, ranked []*agentv1.RouteConnector) []RouteConnector {
	out := make([]RouteConnector, 0, max(len(connectors), len(ranked)))
	if len(ranked) > 0 {
		for _, r := range ranked {
			out = append(out, RouteConnector{ID: r.GetConnectorId(), Priority: r.GetPriority(), Weight: r.GetWeight(), Ranked: true})
		}
		return out
	}
	for _, c := range connectors {
		out = append(out, RouteConnector{ID: c, Weight: 1})
	}
	return out
}

// accessOf returns the access rules of a gateway route resource, nil for another kind.
func accessOf(res *agentv1.Resource) *agentv1.RouteAccess {
	switch {
	case res.GetGatewayTcpRoute() != nil:
		return res.GetGatewayTcpRoute().GetAccess()
	case res.GetGatewayUdpRoute() != nil:
		return res.GetGatewayUdpRoute().GetAccess()
	case res.GetGatewayTcpUdpRoute() != nil:
		return res.GetGatewayTcpUdpRoute().GetAccess()
	case res.GetGatewayPassthroughRoute() != nil:
		return res.GetGatewayPassthroughRoute().GetAccess()
	case res.GetGatewayHttpRoute() != nil:
		return res.GetGatewayHttpRoute().GetAccess()
	}
	return nil
}

// authorityHostRe is a CONNECT authority as the snapshot holds it: a lower-case host name.
var authorityHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$`)

// connectAuthOf is a CONNECT listener's mode, "" for a value this release does not know.
func connectAuthOf(a agentv1.ConnectAuth) ConnectMode {
	return map[agentv1.ConnectAuth]ConnectMode{agentv1.ConnectAuth_CONNECT_AUTH_UNSPECIFIED: ConnectNone, agentv1.ConnectAuth_CONNECT_AUTH_NONE: ConnectNone,
		agentv1.ConnectAuth_CONNECT_AUTH_TLS_BASIC: ConnectTLSBasic, agentv1.ConnectAuth_CONNECT_AUTH_PLAIN_BASIC: ConnectPlainBasic}[a]
}

// basicConnect reports whether a CONNECT route's listener checks basic auth.
func basicConnect(hc *agentv1.HTTPConnect) bool {
	m := connectAuthOf(hc.GetAuth())
	return hc != nil && (m == ConnectTLSBasic || m == ConnectPlainBasic)
}

// limitsOf returns the limits of a gateway route resource, and whether res is one.
func limitsOf(res *agentv1.Resource) (*agentv1.RouteLimits, bool) {
	switch {
	case res.GetGatewayTcpRoute() != nil:
		return res.GetGatewayTcpRoute().GetLimits(), true
	case res.GetGatewayUdpRoute() != nil:
		return res.GetGatewayUdpRoute().GetLimits(), true
	case res.GetGatewayTcpUdpRoute() != nil:
		return res.GetGatewayTcpUdpRoute().GetLimits(), true
	case res.GetGatewayPassthroughRoute() != nil:
		return res.GetGatewayPassthroughRoute().GetLimits(), true
	case res.GetGatewayHttpRoute() != nil:
		return res.GetGatewayHttpRoute().GetLimits(), true
	}
	return nil, false
}

// maxClientRate bounds a rate_limit rule's rate and burst well above what the API allows, so that
// no snapshot makes a client's bucket refill in no time.
const maxClientRate = 1_000_000

// maxClientRules bounds the rate_limit rules of a route, as each new client takes an entry in the
// table of every one (docs/03-connections.md, "Timeouts, keepalive and backoff").
const maxClientRules = 4

// ReservedHeaders are the headers a route cannot set: the gateway's forwarding headers and those
// of the connection itself.
var ReservedHeaders = []string{"Connection", "Content-Length", "Forwarded", "Host", "Keep-Alive", "Proxy-Connection", "Te",
	"Trailer", "Transfer-Encoding", "Upgrade", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"}

// Applier runs a gateway's snapshots (docs/03-connections.md, "Configuration reconciliation"):
// its tcp routes on their ports and the connector assignment its data sessions are admitted
// against. It implements agent.Applier.
type Applier struct {
	served   Served
	assign   *assignment
	limits   Limits
	revision atomic.Pointer[agentv1.Revision]
}

// NewApplier returns the gateway's applier and the Assignment for its Sessions; Bind connects
// them.
func NewApplier() (*Applier, Assignment) {
	a := &Applier{assign: &assignment{}}
	return a, a.assign
}

// Served is what the applier updates; any part may be nil.
type Served struct {
	TCP          *TCPRoutes
	UDP          *UDPRoutes
	Passthrough  *Passthrough
	HTTP         *HTTPRoutes
	Certificates *Certificates
	Pages        *Pages
	Sessions     *Sessions
	// DrainPeriod is how long a disabled gateway keeps its streams; 0 is DrainPeriod.
	DrainPeriod time.Duration
}

// Bind gives the applier what it updates.
func (a *Applier) Bind(s Served) { a.served = s }

// Readiness implements agent.Applier: the tcp and udp routes whose port is not bound, and the
// certificates and custom pages not loaded.
func (a *Applier) Readiness() []*agentv1.ResourceStatus {
	s := a.served
	var status []*agentv1.ResourceStatus
	if s.TCP != nil {
		status = append(status, s.TCP.Status()...)
	}
	if s.UDP != nil {
		status = append(status, s.UDP.Status()...)
	}
	if s.Certificates != nil {
		status = append(status, s.Certificates.Status()...)
	}
	if s.Pages != nil {
		status = append(status, s.Pages.Status()...)
	}
	return status
}

// Revision returns the revision of the applied snapshot; it is TCPOptions.Revision.
func (a *Applier) Revision() *agentv1.Revision { return a.revision.Load() }

// Validate implements agent.Applier: every resource must be one a gateway runs, every port a
// valid one used once per protocol, every hostname a normalised one used once, and every connector
// ID present.
func (a *Applier) Validate(snap *agentv1.Snapshot) []*agentv1.SnapshotError {
	var errs []*agentv1.SnapshotError
	bad := func(id, format string, args ...any) {
		errs = append(errs, &agentv1.SnapshotError{ResourceId: id, Message: fmt.Sprintf(format, args...)})
	}
	ports := map[string]map[uint32]string{"TCP": {}, "UDP": {}}
	port := func(id, proto string, p uint32) {
		switch {
		case p == 0 || p > 65535:
			bad(id, "port %d is not a %s port", p, proto)
		case ports[proto][p] != "":
			bad(id, "%s port %d is also the port of %s", proto, p, ports[proto][p])
		default:
			ports[proto][p] = id
		}
	}
	// CONNECT listeners: the first route of each port, and the routes of each authority on it.
	listeners, authorities := map[uint32]*agentv1.GatewayTCPRoute{}, map[string]string{}
	connectRoute := func(id string, r *agentv1.GatewayTCPRoute) {
		hc := r.GetHttpConnect()
		if first, ok := listeners[r.GetPort()]; ok {
			if f := first.GetHttpConnect(); connectAuthOf(f.GetAuth()) != connectAuthOf(hc.GetAuth()) || f.GetHostname() != hc.GetHostname() {
				bad(id, "CONNECT port %d with another mode or hostname than the other routes of the port", r.GetPort())
			} else if f.GetOrgId() != hc.GetOrgId() {
				bad(id, "CONNECT port %d of another org than the other routes of the port", r.GetPort())
			}
		} else {
			port(id, "TCP", r.GetPort())
			listeners[r.GetPort()] = r
		}
		switch mode := connectAuthOf(hc.GetAuth()); {
		case mode == "":
			bad(id, "CONNECT authentication mode %v", hc.GetAuth())
		case mode == ConnectTLSBasic:
			if n, err := domains.Normalize(hc.GetHostname(), false); err != nil || n != hc.GetHostname() {
				bad(id, "the CONNECT listener's hostname %q is not normalised", hc.GetHostname())
			}
		case hc.GetHostname() != "":
			bad(id, "a CONNECT hostname without TLS")
		}
		if len(hc.GetAuthorities()) == 0 {
			bad(id, "a CONNECT route without authorities")
		}
		if hc.GetOrgId() == "" {
			bad(id, "a CONNECT route without an org")
		}
		for _, a := range hc.GetAuthorities() {
			key := strconv.Itoa(int(r.GetPort())) + " " + a
			switch {
			case !authorityHostRe.MatchString(a):
				bad(id, "CONNECT authority %q is not a lower-case host name", a)
			case authorities[key] != "":
				bad(id, "CONNECT authority %s is also a route of %s", a, authorities[key])
			default:
				authorities[key] = id
			}
		}
	}
	hostnames := map[string]string{} // passthrough hostnames, and http ones with their path prefix
	hostname := func(id, h string) bool {
		if n, err := domains.Normalize(h, true); err != nil || n != h {
			bad(id, "hostname %q is not normalised", h)
			return false
		}
		return true
	}
	pages := map[string]string{} // page IDs by kind
	for _, res := range snap.GetResources() {
		id := res.GetId()
		if _, err := AccessOf(accessOf(res)); err != nil {
			bad(id, "access rules: %v", err)
		}
		if n := len(accessOf(res).GetRateLimits()); n > maxClientRules {
			bad(id, "%d rate_limit rules, more than %d", n, maxClientRules)
		}
		for _, rl := range accessOf(res).GetRateLimits() {
			if rl.GetPerSecond() == 0 || rl.GetPerSecond() > maxClientRate || rl.GetBurst() > maxClientRate {
				bad(id, "rate_limit rule of policy %s: %d a second, %d at once, beyond 1 to %d", rl.GetPolicyId(), rl.GetPerSecond(),
					rl.GetBurst(), maxClientRate)
			}
		}
		if ba := accessOf(res).GetBasicAuth(); len(ba) > 0 {
			if res.GetGatewayHttpRoute() == nil && !basicConnect(res.GetGatewayTcpRoute().GetHttpConnect()) {
				bad(id, "basic auth on a route that is not http or a CONNECT route in a basic mode")
			}
			if _, err := basicAuthOf(ba); err != nil {
				bad(id, "basic auth: %v", err)
			}
		}
		if rh := accessOf(res).GetRequireHeader(); len(rh) > 0 {
			if res.GetGatewayHttpRoute() == nil {
				bad(id, "require-header rules on a route that is not http")
			}
			if _, err := requireHeaderOf(rh); err != nil {
				bad(id, "require-header rules: %v", err)
			}
		}
		switch {
		case res.GetGatewayTcpRoute().GetHttpConnect() != nil:
			connectRoute(id, res.GetGatewayTcpRoute())
		case res.GetGatewayTcpRoute() != nil:
			port(id, "TCP", res.GetGatewayTcpRoute().GetPort())
		case res.GetGatewayUdpRoute() != nil:
			port(id, "UDP", res.GetGatewayUdpRoute().GetPort())
		case res.GetGatewayTcpUdpRoute() != nil:
			port(id, "TCP", res.GetGatewayTcpUdpRoute().GetPort())
			port(id, "UDP", res.GetGatewayTcpUdpRoute().GetPort())
		case res.GetGatewayCertificate() != nil:
			c := res.GetGatewayCertificate()
			if len(c.GetContentSha256()) != sha256.Size {
				bad(id, "a certificate without a SHA-256 content hash")
			}
			if len(c.GetHostnames()) == 0 {
				bad(id, "a certificate without hostnames")
			}
			for _, h := range c.GetHostnames() {
				if n, err := domains.Normalize(h, true); err != nil || n != h {
					bad(id, "hostname %q is not normalised", h)
				}
			}
		case res.GetGatewayPassthroughRoute() != nil:
			p := res.GetGatewayPassthroughRoute()
			if len(p.GetHostnames()) == 0 {
				bad(id, "a passthrough route without hostnames")
			}
			for _, h := range p.GetHostnames() {
				switch {
				case !hostname(id, h):
				case hostnames[h] != "" || hostnames["http "+h] != "":
					bad(id, "hostname %s is also a hostname of %s", h, hostnames[h]+hostnames["http "+h])
				default:
					hostnames[h] = id
				}
			}
		case res.GetGatewayHttpRoute() != nil:
			r := res.GetGatewayHttpRoute()
			if len(r.GetHosts()) == 0 {
				bad(id, "an http route without hostnames")
			}
			if u := r.GetUpstreamProtocol(); u != "http" && u != "h2c" && u != "https" {
				bad(id, "upstream protocol %q", u)
			}
			if m := r.GetPort80(); m != "" && m != "redirect" && m != "serve" && m != "off" {
				bad(id, "port 80 mode %q", m)
			}
			if h := r.GetHostHeader(); h != "" && !httpguts.ValidHostHeader(h) {
				bad(id, "host header %q", h)
			}
			for _, hs := range [][]*agentv1.HTTPHeader{r.GetRequestHeaders(), r.GetResponseHeaders()} {
				for _, h := range hs {
					switch {
					case !httpguts.ValidHeaderFieldName(h.GetName()) || h.GetName() != textproto.CanonicalMIMEHeaderKey(h.GetName()):
						bad(id, "header name %q", h.GetName())
					case !httpguts.ValidHeaderFieldValue(h.GetValue()):
						bad(id, "the value of header %s is not a valid field value", h.GetName())
					case slices.Contains(ReservedHeaders, h.GetName()):
						bad(id, "header %s is the gateway's own", h.GetName())
					}
				}
			}
			for _, c := range r.GetTrustedProxies() {
				if _, err := netip.ParsePrefix(c); err != nil {
					bad(id, "trusted proxy %q is not a CIDR", c)
				}
			}
			matches := headerMatchesOf(r)
			if err := headermatch.Check(matches); err != nil {
				bad(id, "%v", err)
			}
			key := headermatch.Key(matches)
			targets := map[string]bool{}
			for _, u := range r.GetUpstreamTls() {
				switch {
				case u.GetTargetId() == "" || targets[u.GetTargetId()]:
					bad(id, "upstream TLS for target %q twice or without a target", u.GetTargetId())
				case u.GetServerName() == "":
					bad(id, "upstream TLS for target %s without a server name", u.GetTargetId())
				case u.GetVerification() == agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_UNVERIFIED && (len(u.GetCaPem()) > 0 || len(u.GetSpkiSha256()) > 0):
					bad(id, "the unverified target %s has a CA bundle or a pin", u.GetTargetId())
				case (u.GetVerification() == agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_UNVERIFIED ||
					u.GetVerification() == agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_PINNED_KEY) && u.GetConnectorId() == "":
					bad(id, "the target %s, not verified by its chain, names no connector", u.GetTargetId())
				case u.GetVerification() == agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_PINNED_KEY && (len(u.GetCaPem()) > 0 || len(u.GetSpkiSha256()) != sha256.Size):
					bad(id, "the pinned-key target %s has a CA bundle or no SHA-256 pin", u.GetTargetId())
				case len(u.GetCaPem()) > 0 && !x509.NewCertPool().AppendCertsFromPEM(u.GetCaPem()):
					bad(id, "the CA bundle of target %s holds no certificate", u.GetTargetId())
				case len(u.GetSpkiSha256()) != 0 && len(u.GetSpkiSha256()) != sha256.Size:
					bad(id, "the SPKI pin of target %s is not a SHA-256", u.GetTargetId())
				}
				targets[u.GetTargetId()] = true
			}
			for _, hp := range r.GetHosts() {
				h, prefix := hp.GetHostname(), hp.GetPathPrefix()
				switch {
				case !hostname(id, h):
				case prefix != "" && !strings.HasPrefix(prefix, "/"):
					bad(id, "path prefix %q does not start with /", prefix)
				case hostnames[h] != "":
					bad(id, "hostname %s is also a hostname of %s", h, hostnames[h])
				case hostnames["http "+h+prefix+" "+key] != "":
					bad(id, "%s%s is also served by %s with the same header matches", h, prefix, hostnames["http "+h+prefix+" "+key])
				default:
					hostnames["http "+h+prefix+" "+key] = id
					hostnames["http "+h] = id
				}
			}
		case res.GetGatewayDomainChallenge() != nil:
			c := res.GetGatewayDomainChallenge()
			if n, err := domains.Normalize(c.GetFqdn(), false); err != nil || n != c.GetFqdn() {
				bad(id, "domain %q is not normalised", c.GetFqdn())
			}
			if v := c.GetValue(); v == "" || len(v) > 64 || strings.Trim(v, "abcdefghijklmnopqrstuvwxyz234567") != "" {
				bad(id, "a challenge value that is not lower-case base32")
			}
		case res.GetGatewayDrain() != nil:
		case res.GetGatewayPage() != nil:
			p := res.GetGatewayPage()
			kind, ok := pageKinds[p.GetKind()]
			switch {
			case !ok:
				bad(id, "page kind %v", p.GetKind())
			case pages[kind] != "":
				bad(id, "a second %s page; %s is one", kind, pages[kind])
			case len(p.GetContentSha256()) != sha256.Size:
				bad(id, "a page without a SHA-256 content hash")
			}
			pages[kind] = id
		default:
			bad(id, "a gateway does not run %T resources", res.GetKind())
		}
		connectors, ranked := connectorsOf(res)
		if slices.Contains(connectors, "") {
			bad(id, "an empty connector ID")
		}
		if len(ranked) > 0 {
			seen, ids := map[tier]bool{}, map[string]bool{}
			for _, r := range ranked {
				k := tier{r.GetConnectorId(), r.GetPriority()}
				switch {
				case seen[k]:
					bad(id, "connector %s ranked twice at priority %d", k.connector, k.priority)
				case r.GetWeight() > maxRankWeight:
					bad(id, "connector %s at priority %d has weight %d, above %d", k.connector, k.priority, r.GetWeight(), maxRankWeight)
				}
				seen[k], ids[k.connector] = true, true
			}
			want := map[string]bool{}
			for _, c := range connectors {
				want[c] = true
			}
			if !maps.Equal(ids, want) {
				bad(id, "the ranked connectors are not the route's connectors")
			}
		}
	}
	return errs
}

// Apply implements agent.Applier: the new assignment takes effect first, then the routes, then
// the data sessions of connectors no longer assigned are closed.
func (a *Applier) Apply(ctx context.Context, snap *agentv1.Snapshot, _ agent.Changes) []*agentv1.ResourceStatus {
	next := &assigned{known: map[string]bool{}, routes: map[string][]RouteConnector{}}
	var (
		tcp         []TCPRoute
		udp         []UDPRoute
		passthrough []PassthroughRoute
		httpRoutes  []HTTPRoute
		certs       []CertificateRoute
		pages       []PageRef
		tokens      = map[string]DomainToken{}
		disabled    bool
	)
	for _, res := range snap.GetResources() {
		access, _ := AccessOf(accessOf(res)) // Validate refused any that does not parse
		// Every route keeps its limit state, also without limits, so that a limit set later counts
		// the connections already open.
		var limit *RouteLimit
		if l, ok := limitsOf(res); ok {
			limit = a.limits.Set(res.GetId(), routeLimitsOf(l, accessOf(res).GetRateLimits()))
		}
		switch {
		case res.GetGatewayTcpRoute() != nil:
			r := res.GetGatewayTcpRoute()
			tr := TCPRoute{ID: res.GetId(), Port: uint16(r.GetPort()), //nolint:gosec // G115: Validate bounds the port
				IdleTimeout: time.Duration(r.GetIdleTimeoutSeconds()) * time.Second, Access: access, Limit: limit}
			if hc := r.GetHttpConnect(); hc != nil {
				tr.Connect = &Connect{Org: hc.GetOrgId(), Authorities: hc.GetAuthorities(), Mode: connectAuthOf(hc.GetAuth()), Hostname: hc.GetHostname()}
				tr.Connect.BasicAuth, _ = basicAuthOf(r.GetAccess().GetBasicAuth()) // Validate refused any that does not parse
			}
			tcp = append(tcp, tr)
		case res.GetGatewayUdpRoute() != nil:
			r := res.GetGatewayUdpRoute()
			udp = append(udp, UDPRoute{ID: res.GetId(), Port: uint16(r.GetPort()), //nolint:gosec // G115: Validate bounds the port
				FlowIdle: time.Duration(r.GetFlowIdleTimeoutSeconds()) * time.Second, Access: access, Limit: limit})
		case res.GetGatewayTcpUdpRoute() != nil:
			// A tcp route and a udp route with the route's ID, on one port number.
			r := res.GetGatewayTcpUdpRoute()
			tcp = append(tcp, TCPRoute{ID: res.GetId(), Port: uint16(r.GetPort()), //nolint:gosec // G115: Validate bounds the port
				IdleTimeout: time.Duration(r.GetIdleTimeoutSeconds()) * time.Second, Access: access, Limit: limit})
			udp = append(udp, UDPRoute{ID: res.GetId(), Port: uint16(r.GetPort()), //nolint:gosec // G115: Validate bounds the port
				FlowIdle: time.Duration(r.GetFlowIdleTimeoutSeconds()) * time.Second, Access: access, Limit: limit})
		case res.GetGatewayHttpRoute() != nil:
			r := res.GetGatewayHttpRoute()
			hr := HTTPRoute{ID: res.GetId(), Upstream: r.GetUpstreamProtocol(), WebSocket: r.GetWebsocket(),
				HostHeader: r.GetHostHeader(), MaxBody: int64(min(r.GetMaxBodyBytes(), math.MaxInt64)), //nolint:gosec // G115: bounded above
				Port80: r.GetPort80(), HSTS: int(r.GetHstsMaxAgeSeconds()), Access: access, Maintenance: r.GetMaintenance(),
				MaintenanceMessage: r.GetMaintenanceMessage(), HeaderMatches: headermatch.Canonical(headerMatchesOf(r)), Limit: limit}
			hr.BasicAuth, _ = basicAuthOf(r.GetAccess().GetBasicAuth())             // Validate refused any that does not parse
			hr.RequireHeader, _ = requireHeaderOf(r.GetAccess().GetRequireHeader()) // and these too
			for _, h := range r.GetRequestHeaders() {
				hr.RequestHeaders = append(hr.RequestHeaders, HTTPHeader{Name: h.GetName(), Value: h.GetValue()})
			}
			for _, h := range r.GetResponseHeaders() {
				hr.ResponseHeaders = append(hr.ResponseHeaders, HTTPHeader{Name: h.GetName(), Value: h.GetValue()})
			}
			for _, c := range r.GetTrustedProxies() {
				if p, err := netip.ParsePrefix(c); err == nil {
					hr.TrustedProxies = append(hr.TrustedProxies, p.Masked())
				}
			}
			if len(r.GetUpstreamTls()) > 0 {
				hr.TLS = map[string]UpstreamTLS{}
				for _, u := range r.GetUpstreamTls() {
					v := VerifyChain // also for a way this gateway does not know: the target fails closed
					switch u.GetVerification() {
					case agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_UNVERIFIED:
						v = VerifyNothing
					case agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_PINNED_KEY:
						v = VerifyPinnedKey
					}
					hr.TLS[u.GetTargetId()] = UpstreamTLS{ServerName: u.GetServerName(), CAPEM: u.GetCaPem(), SPKISHA256: u.GetSpkiSha256(), Verify: v,
						Connector: u.GetConnectorId()}
				}
			}
			for _, hp := range r.GetHosts() {
				hr.Hosts = append(hr.Hosts, HTTPHost{Hostname: hp.GetHostname(), PathPrefix: hp.GetPathPrefix()})
			}
			httpRoutes = append(httpRoutes, hr)
		case res.GetGatewayCertificate() != nil:
			c := res.GetGatewayCertificate()
			certs = append(certs, CertificateRoute{ID: res.GetId(), ContentSHA256: c.GetContentSha256(), Hostnames: c.GetHostnames()})
			continue // serves no route of its own
		case res.GetGatewayPage() != nil:
			p := res.GetGatewayPage()
			pages = append(pages, PageRef{ID: res.GetId(), Kind: pageKinds[p.GetKind()], ContentSHA256: p.GetContentSha256()})
			continue // neither
		case res.GetGatewayDomainChallenge() != nil:
			c := res.GetGatewayDomainChallenge()
			tokens[res.GetId()] = DomainToken{FQDN: c.GetFqdn(), Value: c.GetValue()}
			continue
		case res.GetGatewayDrain() != nil:
			disabled = true
			continue
		case res.GetGatewayPassthroughRoute() != nil:
			p := res.GetGatewayPassthroughRoute()
			passthrough = append(passthrough, PassthroughRoute{ID: res.GetId(), Hostnames: p.GetHostnames(), Access: access, Limit: limit})
		}
		connectors, ranked := connectorsOf(res)
		next.routes[res.GetId()] = rankOf(connectors, ranked)
		for _, c := range connectors {
			next.known[c] = true
		}
	}
	a.revision.Store(proto.Clone(snap.GetRevision()).(*agentv1.Revision))
	s := a.served
	// A disabled gateway drains (R22): its sessions first, so that the empty assignment does not
	// close them, and the connections of its removed routes stay for the drain period too.
	removal := time.Duration(0)
	if disabled {
		removal = cmp.Or(s.DrainPeriod, DrainPeriod)
	}
	if s.Sessions != nil {
		if disabled {
			s.Sessions.Disable(removal)
		} else {
			s.Sessions.Enable()
		}
	}
	if s.TCP != nil {
		s.TCP.SetRemovalDrain(removal)
	}
	if s.Passthrough != nil {
		s.Passthrough.SetRemovalDrain(removal)
	}
	a.assign.cur.Store(next)
	keep := map[string]bool{}
	for id := range next.routes {
		keep[id] = true
	}
	s.Sessions.metrics().retain(keep)
	a.limits.Retain(keep)
	var status []*agentv1.ResourceStatus
	if s.TCP != nil {
		status = append(status, s.TCP.Apply(tcp)...)
	}
	if s.UDP != nil {
		status = append(status, s.UDP.Apply(udp)...)
	}
	if s.Passthrough != nil {
		s.Passthrough.Apply(passthrough)
	}
	if s.Certificates != nil {
		status = append(status, s.Certificates.Apply(ctx, certs)...)
	}
	if s.Pages != nil {
		status = append(status, s.Pages.Apply(ctx, pages)...)
	}
	if s.HTTP != nil {
		s.HTTP.Apply(httpRoutes)
		s.HTTP.SetDomainTokens(tokens)
	}
	if s.Sessions != nil {
		s.Sessions.Recheck()
	}
	return status
}

// headerMatchesOf returns an http route's header matches.
func headerMatchesOf(r *agentv1.GatewayHTTPRoute) []headermatch.Match {
	var out []headermatch.Match
	for _, m := range r.GetHeaderMatches() {
		out = append(out, headermatch.Match{Name: m.GetName(), Value: m.GetValue(), Present: m.GetPresent()})
	}
	return out
}
