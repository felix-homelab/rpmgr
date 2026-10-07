// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/felix-homelab/rpmgr/spikes/s4/gen/rpmgr/agent/v1/agentv1connect"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/pki"
)

// ClientOptions configures one agent's control-session client.
type ClientOptions struct {
	CA   *pki.CA
	Cert tls.Certificate
	// Addr is where to dial (the controller, or a TLS-passthrough proxy in front of it). The TLS
	// server name is always controller.<td>, whatever the address.
	Addr            string
	SendPingTimeout time.Duration
	PingTimeout     time.Duration
	ClientOptions   []connect.ClientOption
}

// ClientTLSConfig trusts only the pinned root, sets ServerName to controller.<td>, and checks that
// the peer is a controller node of the trust domain.
func ClientTLSConfig(o ClientOptions) *tls.Config {
	td := o.CA.TrustDomain
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		RootCAs:      o.CA.Roots,
		Certificates: []tls.Certificate{o.Cert},
		ServerName:   "controller." + td,
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, err := pki.SPIFFEID(cs.PeerCertificates[0], td)
			if err != nil {
				return err
			}
			if role, err := pki.Role(id); err != nil || role != "controller" {
				return fmt.Errorf("peer %s is not a controller", id)
			}
			return nil
		},
	}
}

// NewTransport returns an HTTP/2-only transport with one connection to the controller, as an
// agent uses it.
func NewTransport(o ClientOptions) *http.Transport {
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}
	return &http.Transport{
		TLSClientConfig: ClientTLSConfig(o),
		Protocols:       &protocols,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, o.Addr)
		},
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: o.SendPingTimeout,
			PingTimeout:     o.PingTimeout,
		},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxConnsPerHost:     1,
	}
}

// NewClient returns a Control client that speaks the gRPC protocol over HTTP/2, with the 4 MiB
// control-message limit in both directions.
func NewClient(o ClientOptions) (agentv1connect.ControlClient, *http.Transport) {
	tr := NewTransport(o)
	opts := append([]connect.ClientOption{
		connect.WithGRPC(),
		connect.WithReadMaxBytes(MaxControlMessage),
		connect.WithSendMaxBytes(MaxControlMessage),
	}, o.ClientOptions...)
	return agentv1connect.NewControlClient(&http.Client{Transport: tr}, "https://controller."+o.CA.TrustDomain, opts...), tr
}

type protoSizer = proto.Message

// sized builds the message returned by mk with a payload chosen so that the encoded message has
// exactly n bytes.
func sized(n int, mk func([]byte) protoSizer) protoSizer {
	for l := max(n-16, 0); l <= n; l++ {
		m := mk(make([]byte, l))
		if proto.Size(m) == n {
			return m
		}
	}
	panic(errors.New("no payload length gives the requested message size"))
}
