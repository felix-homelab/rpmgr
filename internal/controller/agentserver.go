// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

// access is what a method of the agent protocol needs.
type access struct {
	reauth bool // only at reauth.controller.<td>; every other method only at controller.<td>
	cert   bool // a client certificate; the TLS layer has verified it
}

// agentMethods lists every method of the agent protocol and what it needs. A method that is not
// listed is refused, so a method added to the .proto files is unreachable until it is listed here.
var agentMethods = map[string]access{
	agentv1.Enrollment_Enroll_FullMethodName:     {},
	agentv1.Control_Session_FullMethodName:       {cert: true},
	agentv1.Control_Renew_FullMethodName:         {cert: true},
	agentv1.Control_FetchResource_FullMethodName: {cert: true},
	agentv1.Control_Leave_FullMethodName:         {cert: true},
	agentv1.Reauth_Reauth_FullMethodName:         {reauth: true, cert: true},
}

// Agent is the authenticated caller of an agent-protocol method.
type Agent struct {
	Identity    pki.Identity
	Certificate *x509.Certificate
}

type agentKey struct{}

// AgentFrom returns the caller of the method that ctx belongs to; ok is false for Enroll without a
// certificate.
func AgentFrom(ctx context.Context) (Agent, bool) {
	a, ok := ctx.Value(agentKey{}).(Agent)
	return a, ok
}

// NewAgentServer returns grpc-go's server of the agent protocol (docs/03-connections.md, "Control
// session"): TLS from cfg, which pki.AgentEndpointConfig builds; keepalive pings after 20 s and a
// close after 10 s without an answer, client pings accepted every 10 s even without an RPC; 4 MiB
// messages; no compressor; and the access rules of agentMethods.
func NewAgentServer(cfg *tls.Config, td string) *grpc.Server {
	auth := authorizer{td: td}
	return grpc.NewServer(
		grpc.Creds(credentials.NewTLS(withH2(cfg))),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 20 * time.Second, Timeout: 10 * time.Second}),
		grpc.MaxRecvMsgSize(agentproto.MaxControlMessage),
		grpc.MaxSendMsgSize(agentproto.MaxControlMessage),
		grpc.ChainUnaryInterceptor(auth.unary),
		grpc.ChainStreamInterceptor(auth.stream),
	)
}

// withH2 makes every configuration cfg selects offer ALPN h2, which grpc-go clients require; the
// grpc credentials add it to cfg itself, not to what GetConfigForClient returns.
func withH2(cfg *tls.Config) *tls.Config {
	cfg = cfg.Clone()
	cfg.NextProtos = []string{"h2"}
	if inner := cfg.GetConfigForClient; inner != nil {
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			c, err := inner(hello)
			if c != nil {
				c = c.Clone()
				c.NextProtos = []string{"h2"}
			}
			return c, err
		}
	}
	return cfg
}

type authorizer struct{ td string }

// authorize applies agentMethods to the call and puts its Agent into the context.
func (a authorizer) authorize(ctx context.Context, method string) (context.Context, error) {
	rule, ok := agentMethods[method]
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "method not allowed")
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "not TLS")
	}
	if strings.EqualFold(info.State.ServerName, "reauth.controller."+a.td) != rule.reauth {
		return nil, status.Error(codes.PermissionDenied, "method not available at this name")
	}
	if len(info.State.PeerCertificates) == 0 {
		if rule.cert {
			return nil, status.Error(codes.Unauthenticated, "client certificate required")
		}
		return ctx, nil
	}
	leaf := info.State.PeerCertificates[0]
	if len(leaf.URIs) != 1 {
		return nil, status.Error(codes.Unauthenticated, "not an rpmgr identity")
	}
	id, err := pki.ParseSPIFFE(leaf.URIs[0], a.td)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "not an rpmgr identity")
	}
	return context.WithValue(ctx, agentKey{}, Agent{Identity: id, Certificate: leaf}), nil
}

func (a authorizer) unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	ctx, err := a.authorize(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	return h(ctx, req)
}

func (a authorizer) stream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	ctx, err := a.authorize(ss.Context(), info.FullMethod)
	if err != nil {
		return err
	}
	return h(srv, &ctxStream{ServerStream: ss, ctx: ctx})
}

type ctxStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *ctxStream) Context() context.Context { return s.ctx }

// HasAccessRule reports whether method is in the access table of the agent protocol.
func HasAccessRule(method string) bool {
	_, ok := agentMethods[method]
	return ok
}
