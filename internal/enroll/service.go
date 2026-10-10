// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
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
	"github.com/felix-homelab/rpmgr/internal/revlog"
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
	// RevLog records the certificates a re-enrollment replaces; Logger reports a failed append.
	RevLog *revlog.Log
	Logger *slog.Logger
	// Denied, if set, applies a changed deny-list to this controller's sessions at once.
	Denied func()
	// Refused, if set, is called for every enrollment the rate limit refuses.
	Refused func()
	limit   *ratelimit.Limiter
}

// NewService returns the Enrollment service.
func NewService(db *store.DB, ca *pki.CA, endpoints []string, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{DB: db, CA: ca, Endpoints: endpoints, Now: now, limit: ratelimit.New(RateEvery, RateBurst, now)}
}

// failed records a refused or failed enrollment: anonymous, with the address and the error's
// message, which never holds the token.
func (s *Service) failed(ctx context.Context, ip string, err error) {
	st, _ := status.FromError(err)
	result := audit.Failure
	if st.Code() == codes.Unauthenticated || st.Code() == codes.PermissionDenied {
		result = audit.Denied
	}
	if _, aerr := audit.Record(ctx, s.DB, audit.Entry{ActorType: audit.ActorAnonymous, IP: ip, Action: "agent.enroll", Result: result,
		Reason: st.Message()}); aerr != nil && s.Logger != nil {
		s.Logger.Error("cannot record a failed enrollment in the audit log", "error", aerr)
	}
}

// Enroll checks the rate limit and the CSR's binding to this connection, then redeems the token,
// assigns the identity the token grants and issues the agent's first certificate. A refused or
// failed enrollment is recorded in the instance chain, unless the rate limit refused it.
func (s *Service) Enroll(ctx context.Context, req *agentv1.EnrollRequest) (_ *agentv1.EnrollResponse, err error) {
	p, ok := peer.FromContext(ctx)
	info, tlsOK := p.AuthInfo.(credentials.TLSInfo)
	if !ok || !tlsOK {
		return nil, status.Error(codes.Unauthenticated, "not TLS")
	}
	ip := hostOf(p.Addr)
	if !s.limit.Allow(ip) {
		if s.Refused != nil {
			s.Refused()
		}
		return nil, status.Error(codes.ResourceExhausted, "too many enrollments from this address")
	}
	defer func() {
		if err != nil {
			s.failed(context.WithoutCancel(ctx), ip, err)
		}
	}()
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
	var replaced []*ent.IssuedCertificate
	cert, g, _, err := Redeem(sys, s.DB, req.GetToken(), csr, ip, s.Now(), s.issue(csr, req, ip, &replaced))
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
	if len(replaced) > 0 && s.Denied != nil {
		s.Denied()
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
// certificate and appends the audit entry. A token bound to an identity that already holds
// certificates, a re-enrollment or a gateway enrolling again, revokes them by serial; replaced
// receives them.
func (s *Service) issue(csr *x509.CertificateRequest, req *agentv1.EnrollRequest, ip string, replaced *[]*ent.IssuedCertificate) Issue {
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
		serial := pki.SerialHex(cert.SerialNumber)
		if _, err = audit.Append(ctx, tx, audit.Entry{OrgID: g.OrgID, ActorType: audit.ActorAgent, ActorID: id.ID,
			CredentialID: g.TokenID, AuthMethod: "enrollment_token", IP: ip, Action: action,
			TargetType: string(id.Kind), TargetID: id.ID, Result: audit.Success, Reason: "serial " + serial}); err != nil {
			return nil, err
		}
		if g.GatewayID == "" && g.ConnectorID == "" {
			return cert, nil
		}
		const reason = "replaced by a re-enrollment"
		old, err := pki.RevokeReplaced(ctx, tx, id, serial, reason, s.Now())
		if err != nil {
			return nil, err
		}
		for _, c := range old {
			if s.RevLog != nil {
				if _, err := s.RevLog.Append(revlog.Entry{Kind: revlog.CertificateRevoked, Org: g.OrgID, Subject: c.ID, Detail: reason,
					NotAfter: &c.NotAfter, Actor: id.ID}); err != nil && s.Logger != nil {
					s.Logger.Error("cannot append to the revocation log", "kind", revlog.CertificateRevoked, "subject", c.ID, "error", err)
				}
			}
			if _, err := audit.Append(ctx, tx, audit.Entry{OrgID: g.OrgID, ActorType: audit.ActorAgent, ActorID: id.ID,
				CredentialID: g.TokenID, AuthMethod: "enrollment_token", IP: ip, Action: "certificate.revoke",
				TargetType: "certificate", TargetID: c.ID, Result: audit.Success, Reason: reason}); err != nil {
				return nil, err
			}
		}
		*replaced = old
		return cert, nil
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
