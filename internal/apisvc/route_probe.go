// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// probeWait bounds ProbeTargetCertificate: the connector's probe and the round trip to it
// (docs/03-connections.md, "Timeouts, keepalive and backoff"); a variable for tests.
var probeWait = 15 * time.Second

// Prober asks a connector for the certificate a target presents, normally the controller's
// Sessions; its errors are ErrProbeNotConnected, ErrProbeUnsupported or a *ProbeFailed.
type Prober interface {
	ProbeTarget(ctx context.Context, connectorID string, p *agentv1.ProbeTarget) ([]byte, error)
}

// The errors of a Prober.
var (
	ErrProbeNotConnected = errors.New("the connector has no control session with this controller")
	ErrProbeUnsupported  = errors.New("the connector's version cannot read target certificates; upgrade it")
)

// ProbeFailed is a probe the connector answered with an error.
type ProbeFailed struct{ Message string }

func (e *ProbeFailed) Error() string { return e.Message }

// ProbeTargetCertificate implements RouteService: a connector of the org reads the certificate a
// target presents (ADR-0018), for its user to pin the key.
func (r *Routes) ProbeTargetCertificate(ctx context.Context, req *connect.Request[rpmgrv1.ProbeTargetCertificateRequest]) (
	*connect.Response[rpmgrv1.ProbeTargetCertificateResponse], error) {
	m := req.Msg
	if r.Prober == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("apisvc: no connector probes here"))
	}
	con, err := r.DB.ReadClient().Connector.Get(ctx, m.GetConnectorId())
	if err != nil {
		return nil, storeError(err)
	}
	if con.DecommissionedAt != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: the connector is decommissioned"))
	}
	p := &agentv1.ProbeTarget{ServerName: m.GetServerName()}
	if hp := m.GetHostPort(); hp != nil {
		p.Address = &agentv1.ProbeTarget_HostPort{HostPort: net.JoinHostPort(hp.GetHost(), strconv.Itoa(int(hp.GetPort())))}
		if _, err := netip.ParseAddr(hp.GetHost()); p.ServerName == "" && err != nil {
			p.ServerName = hp.GetHost() // a name, sent as it would be for the target
		}
	} else {
		p.Address = &agentv1.ProbeTarget_UnixPath{UnixPath: m.GetUnixPath()}
	}
	ctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	der, err := r.Prober.ProbeTarget(ctx, con.ID, p)
	var failed *ProbeFailed
	switch {
	case errors.Is(err, ErrProbeNotConnected), errors.Is(err, ErrProbeUnsupported):
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("apisvc: %w", err))
	case errors.As(err, &failed):
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("apisvc: the connector read no certificate: %s", failed.Message))
	case errors.Is(err, context.DeadlineExceeded):
		return nil, connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf("apisvc: the connector did not answer within %v", probeWait))
	case err != nil:
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("apisvc: the target's certificate does not parse: %w", err))
	}
	return connect.NewResponse(&rpmgrv1.ProbeTargetCertificateResponse{Certificate: targetCertificateOf(cert)}), nil
}

// targetCertificateOf describes a target's certificate, with the pin of its key.
func targetCertificateOf(c *x509.Certificate) *rpmgrv1.TargetCertificate {
	spki, whole := sha256.Sum256(c.RawSubjectPublicKeyInfo), sha256.Sum256(c.Raw)
	out := &rpmgrv1.TargetCertificate{SpkiSha256: hex.EncodeToString(spki[:]), Sha256: hex.EncodeToString(whole[:]),
		Subject: c.Subject.String(), Issuer: c.Issuer.String(), DnsNames: c.DNSNames,
		NotBefore: timestamppb.New(c.NotBefore), NotAfter: timestamppb.New(c.NotAfter),
		SelfSigned: bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil}
	for _, ip := range c.IPAddresses {
		out.IpAddresses = append(out.IpAddresses, ip.String())
	}
	return out
}
