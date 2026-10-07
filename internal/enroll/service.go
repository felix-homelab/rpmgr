// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/ratelimit"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
)

// The enrollment rate per client IP (docs/04-security.md, "Human authentication and sessions").
const (
	RateEvery = 6 * time.Second // 10 per minute
	RateBurst = 10
)

// Service is the agent protocol's Enrollment service (docs/03-connections.md, "Enrollment").
type Service struct {
	agentv1.UnimplementedEnrollmentServer

	DB        *store.DB
	CA        *pki.CA
	Endpoints []string // the controller endpoints agents try, in order
	Now       func() time.Time
	limit     *ratelimit.Limiter
}

// NewService returns the Enrollment service.
func NewService(db *store.DB, ca *pki.CA, endpoints []string, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{DB: db, CA: ca, Endpoints: endpoints, Now: now, limit: ratelimit.New(RateEvery, RateBurst, now)}
}

// Enroll checks the rate limit and the CSR's binding to this connection, then redeems the token,
// assigns the identity the token grants and issues the agent's first certificate.
func (s *Service) Enroll(ctx context.Context, req *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	p, ok := peer.FromContext(ctx)
	info, tlsOK := p.AuthInfo.(credentials.TLSInfo)
	if !ok || !tlsOK {
		return nil, status.Error(codes.Unauthenticated, "not TLS")
	}
	ip := hostOf(p.Addr)
	if !s.limit.Allow(ip) {
		return nil, status.Error(codes.ResourceExhausted, "too many enrollments from this address")
	}
	csr, err := x509.ParseCertificateRequest(req.GetCsr())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "the CSR does not parse")
	}
	if err := pki.VerifyBinding(csr, info.State); err != nil {
		if errors.Is(err, pki.ErrBadCSR) {
			return nil, status.Error(codes.InvalidArgument, "the CSR's signature does not verify")
		}
		return nil, status.Error(codes.PermissionDenied, "the CSR is not bound to this connection")
	}
	sys, err := authz.System(ctx, "enrollment", "enroll an agent from "+ip, audit.SystemScopes(s.DB))
	if err != nil {
		return nil, status.Error(codes.Internal, "audit")
	}
	cert, g, _, err := Redeem(sys, s.DB, req.GetToken(), csr, ip, s.Now(), s.issue(csr, req, ip))
	switch {
	case errors.Is(err, ErrInvalidToken):
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	case errors.Is(err, pki.ErrBadCSR):
		return nil, status.Error(codes.InvalidArgument, "the CSR's key is not ECDSA P-256")
	case errors.Is(err, errIdentity):
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	case err != nil:
		return nil, status.Error(codes.Internal, "enrollment failed")
	}
	id, err := pki.ParseSPIFFE(cert.URIs[0], s.CA.TrustDomain())
	if err != nil {
		return nil, status.Error(codes.Internal, "enrollment failed")
	}
	return &agentv1.EnrollResponse{
		AgentId:             id.ID,
		Chain:               s.CA.Chain(cert),
		TrustBundle:         [][]byte{s.CA.Root().Raw},
		SigningCertificates: s.CA.SigningChain(),
		ControllerEndpoints: s.Endpoints,
		Ephemeral:           g.Ephemeral,
	}, nil
}

// errIdentity is returned when the identity a token grants cannot be assigned.
var errIdentity = errors.New("enroll")

// issue assigns the identity of a grant in the transaction that consumed the token, issues the
// certificate and appends the audit entry.
func (s *Service) issue(csr *x509.CertificateRequest, req *agentv1.EnrollRequest, ip string) Issue {
	return func(ctx context.Context, tx *ent.Tx, g Grant) (*x509.Certificate, error) {
		key := pki.PublicKeyHash(csr.RawSubjectPublicKeyInfo)
		id := pki.Identity{TrustDomain: s.CA.TrustDomain(), Org: g.OrgID}
		action := ""
		switch {
		case g.Role == "gateway":
			gw, err := tx.Gateway.Get(ctx, g.GatewayID)
			if err != nil || gw.DecommissionedAt != nil {
				return nil, fmt.Errorf("%w: the token's gateway is decommissioned or gone", errIdentity)
			}
			id.Kind, id.ID, action = pki.KindGateway, gw.ID, "gateway.enroll"
			if err := tx.Gateway.UpdateOne(gw).SetSpiffeID(id.String()).SetPubkeySha256(key).Exec(ctx); err != nil {
				return nil, err
			}
		case g.ConnectorID != "":
			con, err := tx.Connector.Get(ctx, g.ConnectorID)
			if err != nil || con.DecommissionedAt != nil {
				return nil, fmt.Errorf("%w: the token's connector is decommissioned or gone", errIdentity)
			}
			id.Kind, id.ID, action = pki.KindConnector, con.ID, "connector.reenroll"
			if err := tx.Connector.UpdateOne(con).SetPubkeySha256(key).Exec(ctx); err != nil {
				return nil, err
			}
		default:
			id.Kind, id.ID, action = pki.KindConnector, ids.New("con"), "connector.enroll"
			name, err := freeName(ctx, tx, g.OrgID, req.GetHost().GetHostname())
			if err != nil {
				return nil, err
			}
			labels, err := tokenLabels(ctx, tx, g.TokenID)
			if err != nil {
				return nil, err
			}
			if err := tx.Connector.Create().SetID(id.ID).SetOrgID(g.OrgID).SetName(name).SetLabels(labels).
				SetSpiffeID(id.String()).SetPubkeySha256(key).SetEphemeral(g.Ephemeral).Exec(ctx); err != nil {
				return nil, err
			}
		}
		inst, _, err := settings.Instance(ctx, tx.Client())
		if err != nil {
			return nil, err
		}
		cert, err := s.CA.IssueEnrolled(ctx, tx, csr, id, inst.GetLeafCertificateLifetime().AsDuration(), g.TokenID)
		if err != nil {
			return nil, err
		}
		_, err = audit.Append(ctx, tx, audit.Entry{OrgID: g.OrgID, ActorType: audit.ActorAgent, ActorID: id.ID,
			CredentialID: g.TokenID, AuthMethod: "enrollment_token", IP: ip, Action: action,
			TargetType: string(id.Kind), TargetID: id.ID, Result: audit.Success,
			Reason: "serial " + pki.SerialHex(cert.SerialNumber)})
		return cert, err
	}
}

func tokenLabels(ctx context.Context, tx *ent.Tx, tokenID string) (map[string]string, error) {
	t, err := tx.EnrollmentToken.Get(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	return t.Labels, nil
}

var notSlug = regexp.MustCompile(`[^a-z0-9-]+`)

// freeName derives a connector name from the host name and makes it unique in the org: "nas",
// then "nas-2", "nas-3" and so on.
func freeName(ctx context.Context, tx *ent.Tx, org, hostname string) (string, error) {
	base := strings.Trim(notSlug.ReplaceAllString(strings.ToLower(hostname), "-"), "-")
	if len(base) > 50 {
		base = strings.Trim(base[:50], "-")
	}
	if base == "" {
		base = "connector"
	}
	for n := 1; n <= 1000; n++ {
		name := base
		if n > 1 {
			name = fmt.Sprintf("%s-%d", base, n)
		}
		taken, err := tx.Connector.Query().Where(connector.OrgID(org), connector.Name(name)).Exist(ctx)
		if err != nil {
			return "", err
		}
		if !taken {
			return name, nil
		}
	}
	return "", fmt.Errorf("%w: no free connector name for %q", errIdentity, base)
}

func hostOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

// TrustBundleHandler serves /.well-known/rpmgr/trust-bundle: the PEM of the roots an agent may pin
// (docs/03-connections.md, "Enrollment"). It is unauthenticated; the agent keeps only the root that
// matches its pin.
func TrustBundleHandler(roots ...*x509.Certificate) http.Handler {
	var body []byte
	for _, r := range roots {
		body = append(body, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.Raw})...)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(body)
	})
}
