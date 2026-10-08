// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math"
	"net/netip"
	"net/textproto"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/domains"
)

// assignment is the connector assignment of the applied snapshot: which connectors serve which
// route. It implements Assignment.
type assignment struct {
	cur atomic.Pointer[assigned]
}

type assigned struct {
	known  map[string]bool
	routes map[string][]string
}

// Known implements Assignment.
func (a *assignment) Known(connectorID string) bool {
	s := a.cur.Load()
	return s != nil && s.known[connectorID]
}

// Connectors implements Assignment.
func (a *assignment) Connectors(routeID string) []string {
	s := a.cur.Load()
	if s == nil {
		return nil
	}
	return s.routes[routeID]
}

// reservedHeaders are the headers a route cannot set: the gateway's forwarding headers and those
// of the connection itself.
var reservedHeaders = []string{"Connection", "Content-Length", "Forwarded", "Host", "Keep-Alive", "Proxy-Connection", "Te",
	"Trailer", "Transfer-Encoding", "Upgrade", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"}

// Applier runs a gateway's snapshots (docs/03-connections.md, "Configuration reconciliation"):
// its tcp routes on their ports and the connector assignment its data sessions are admitted
// against. It implements agent.Applier.
type Applier struct {
	served   Served
	assign   *assignment
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
	Sessions     *Sessions
}

// Bind gives the applier what it updates.
func (a *Applier) Bind(s Served) { a.served = s }

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
	hostnames := map[string]string{} // passthrough hostnames, and http ones with their path prefix
	hostname := func(id, h string) bool {
		if n, err := domains.Normalize(h, true); err != nil || n != h {
			bad(id, "hostname %q is not normalised", h)
			return false
		}
		return true
	}
	for _, res := range snap.GetResources() {
		id := res.GetId()
		var connectors []string
		switch {
		case res.GetGatewayTcpRoute() != nil:
			port(id, "TCP", res.GetGatewayTcpRoute().GetPort())
			connectors = res.GetGatewayTcpRoute().GetConnectors()
		case res.GetGatewayUdpRoute() != nil:
			port(id, "UDP", res.GetGatewayUdpRoute().GetPort())
			connectors = res.GetGatewayUdpRoute().GetConnectors()
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
			connectors = p.GetConnectors()
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
					case slices.Contains(reservedHeaders, h.GetName()):
						bad(id, "header %s is the gateway's own", h.GetName())
					}
				}
			}
			for _, c := range r.GetTrustedProxies() {
				if _, err := netip.ParsePrefix(c); err != nil {
					bad(id, "trusted proxy %q is not a CIDR", c)
				}
			}
			targets := map[string]bool{}
			for _, u := range r.GetUpstreamTls() {
				switch {
				case u.GetTargetId() == "" || targets[u.GetTargetId()]:
					bad(id, "upstream TLS for target %q twice or without a target", u.GetTargetId())
				case u.GetServerName() == "":
					bad(id, "upstream TLS for target %s without a server name", u.GetTargetId())
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
				case hostnames["http "+h+prefix] != "":
					bad(id, "%s%s is also served by %s", h, prefix, hostnames["http "+h+prefix])
				default:
					hostnames["http "+h+prefix] = id
					hostnames["http "+h] = id
				}
			}
			connectors = r.GetConnectors()
		default:
			bad(id, "a gateway does not run %T resources", res.GetKind())
		}
		if slices.Contains(connectors, "") {
			bad(id, "an empty connector ID")
		}
	}
	return errs
}

// Apply implements agent.Applier: the new assignment takes effect first, then the routes, then
// the data sessions of connectors no longer assigned are closed.
func (a *Applier) Apply(ctx context.Context, snap *agentv1.Snapshot, _ agent.Changes) []*agentv1.ResourceStatus {
	next := &assigned{known: map[string]bool{}, routes: map[string][]string{}}
	var (
		tcp         []TCPRoute
		udp         []UDPRoute
		passthrough []PassthroughRoute
		httpRoutes  []HTTPRoute
		certs       []CertificateRoute
	)
	for _, res := range snap.GetResources() {
		var connectors []string
		switch {
		case res.GetGatewayTcpRoute() != nil:
			r := res.GetGatewayTcpRoute()
			connectors = r.GetConnectors()
			tcp = append(tcp, TCPRoute{ID: res.GetId(), Port: uint16(r.GetPort()), //nolint:gosec // G115: Validate bounds the port
				IdleTimeout: time.Duration(r.GetIdleTimeoutSeconds()) * time.Second})
		case res.GetGatewayUdpRoute() != nil:
			r := res.GetGatewayUdpRoute()
			connectors = r.GetConnectors()
			udp = append(udp, UDPRoute{ID: res.GetId(), Port: uint16(r.GetPort()), //nolint:gosec // G115: Validate bounds the port
				FlowIdle: time.Duration(r.GetFlowIdleTimeoutSeconds()) * time.Second})
		case res.GetGatewayHttpRoute() != nil:
			r := res.GetGatewayHttpRoute()
			connectors = r.GetConnectors()
			hr := HTTPRoute{ID: res.GetId(), Upstream: r.GetUpstreamProtocol(), WebSocket: r.GetWebsocket(),
				HostHeader: r.GetHostHeader(), MaxBody: int64(min(r.GetMaxBodyBytes(), math.MaxInt64)), //nolint:gosec // G115: bounded above
				Port80: r.GetPort80(), HSTS: int(r.GetHstsMaxAgeSeconds())}
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
					hr.TLS[u.GetTargetId()] = UpstreamTLS{ServerName: u.GetServerName(), CAPEM: u.GetCaPem(), SPKISHA256: u.GetSpkiSha256()}
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
		case res.GetGatewayPassthroughRoute() != nil:
			p := res.GetGatewayPassthroughRoute()
			connectors = p.GetConnectors()
			passthrough = append(passthrough, PassthroughRoute{ID: res.GetId(), Hostnames: p.GetHostnames()})
		}
		next.routes[res.GetId()] = slices.Clone(connectors)
		for _, c := range connectors {
			next.known[c] = true
		}
	}
	a.revision.Store(proto.Clone(snap.GetRevision()).(*agentv1.Revision))
	a.assign.cur.Store(next)
	var status []*agentv1.ResourceStatus
	s := a.served
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
	if s.HTTP != nil {
		s.HTTP.Apply(httpRoutes)
	}
	if s.Sessions != nil {
		s.Sessions.Recheck()
	}
	return status
}
