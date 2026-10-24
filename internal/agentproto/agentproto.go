// SPDX-License-Identifier: Apache-2.0

// Package agentproto holds what the agent protocol's .proto files (proto/rpmgr/agent/v1) cannot
// say: the control session's message limit and the capability strings (docs/03-connections.md,
// "Framing", "Versioning and capabilities").
package agentproto

import (
	"fmt"

	"google.golang.org/protobuf/proto"
)

// MaxControlMessage is the largest message on the control session, 4 MiB. grpc-go enforces it at
// both ends, without compression, so it counts message bytes.
const MaxControlMessage = 4 << 20

// The capability strings of Phase 1. An agent announces those it supports in Hello, and the
// controller compiles its snapshots with only those features.
const (
	CapTunnelQUIC         = "tunnel.quic"         // data sessions over QUIC
	CapTunnelH2           = "tunnel.h2"           // data sessions over TLS and reverse HTTP/2
	CapUDPDatagram        = "udp.dgram"           // UDP routes as QUIC datagrams
	CapUDPOversizeStream  = "udp.oversize-stream" // datagrams above the limit as stream frames
	CapProxyProtoV1       = "proxyproto.v1"       // PROXY protocol v1 towards targets
	CapProxyProtoV2       = "proxyproto.v2"       // PROXY protocol v2 towards targets
	CapControlPassthrough = "control-passthrough" // the control session inside a data session
	CapProbeTarget        = "probe.target"        // reads the certificate a target presents (ProbeTarget)
)

// The capability strings of Phase 2 that are not route features, each checked where its feature
// is used (docs/03-connections.md, "Versioning and capabilities").
const (
	// CapOTA: the agent stages the release its snapshot offers for the root updater and reports
	// the update state in Status; an agent without it is never offered a release.
	CapOTA = "ota"
	// CapPagesCustom: the gateway serves the custom pages of its group, which its snapshot names;
	// a gateway without it gets none and serves the built-in pages.
	CapPagesCustom = "pages.custom"
)

// The capability strings of Phase 2 route features: the compiler leaves a route that uses one out
// of the snapshot of an agent without it (docs/03-connections.md, "Versioning and capabilities").
const (
	// CapHTTPRequireHeader: the gateway enforces the require_header rules of access policies.
	CapHTTPRequireHeader = "http.require-header"
)

// Phase1 lists every capability of Phase 1 agents.
var Phase1 = []string{CapTunnelQUIC, CapTunnelH2, CapUDPDatagram, CapUDPOversizeStream,
	CapProxyProtoV1, CapProxyProtoV2, CapControlPassthrough, CapProbeTarget}

// CheckSize returns an error if m is larger than MaxControlMessage, so the sender can refuse a
// message that the other end would refuse anyway.
func CheckSize(m proto.Message) error {
	if n := proto.Size(m); n > MaxControlMessage {
		return fmt.Errorf("agentproto: a %T of %d bytes exceeds the control session's %d bytes", m, n, MaxControlMessage)
	}
	return nil
}
