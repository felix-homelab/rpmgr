// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/policy"
)

// probeTimeout bounds a certificate probe, the dial and the handshake together
// (docs/03-connections.md, "Timeouts, keepalive and backoff"); a variable for tests.
var probeTimeout = 10 * time.Second

// Probe reads the leaf certificate a target presents, for a key pin (ADR-0018): it dials the
// target under the local policy, as a stream does, completes a TLS handshake that checks nothing,
// sends nothing else and closes the connection.
func (t *Targets) Probe(ctx context.Context, p *agentv1.ProbeTarget) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	network, address := "tcp", p.GetHostPort()
	if p.GetUnixPath() != "" {
		network, address = "unix", p.GetUnixPath()
	}
	if address == "" {
		return nil, errors.New("the probe names no target")
	}
	d := &net.Dialer{Control: policy.Control(t.o.Policy)}
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		var b *policy.BlockedError
		if errors.As(err, &b) {
			return nil, fmt.Errorf("the connector's local policy does not allow %s", b.Target)
		}
		return nil, fmt.Errorf("cannot reach %s: %w", address, err)
	}
	defer func() { _ = conn.Close() }()
	return readCertificate(ctx, conn, p.GetServerName())
}

// readCertificate completes a TLS handshake on conn and returns the leaf the peer presented. It
// checks nothing, so that a self-signed certificate can be read, and sends nothing after the
// handshake; tools/bannedapi and .golangci.yml allow InsecureSkipVerify here and in the gateway's
// UpstreamTLS.config alone (ADR-0018).
func readCertificate(ctx context.Context, conn net.Conn, serverName string) ([]byte, error) {
	tc := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, InsecureSkipVerify: true})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("no TLS handshake with the target: %w", err)
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("the target presented no certificate")
	}
	return certs[0].Raw, nil
}
