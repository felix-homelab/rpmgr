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

// The capability strings of Phase 2's gated route features: the compiler leaves a route that uses
// one out of the snapshot of every agent of the feature's kind that does not announce it
// (docs/03-connections.md, "Versioning and capabilities", D113).
const (
	// CapHTTPHeaderMatch: a gateway matches http routes on request headers.
	CapHTTPHeaderMatch = "http.header-match"
	// CapRouteLimits: the gateway enforces a route's connection, rate and bandwidth limits and the
	// per-client rate_limit rule of access policies.
	CapRouteLimits = "route.limits"
	// CapTCPHTTPConnect: a gateway serves tcp routes in http_connect mode on CONNECT listeners.
	CapTCPHTTPConnect = "tcp.http-connect"
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
	// CapTunnelWSS: data sessions over WSS (docs/03-connections.md, "Transport selection"): a
	// gateway with it gets its WSS hostname and serves /.rpmgr/tunnel on it; a connector with it
	// dials a gateway's WSS hostname.
	CapTunnelWSS = "tunnel.wss"
	// CapHealthActive: the connector runs the routes' active health checks against its targets
	// and reports the priorities with a healthy target; one without it counts every target as
	// healthy (D133).
	CapHealthActive = "health.active"
	// CapLogsStream: the agent runs live-log operations (Open of OPERATION_KIND_LOGS, Attach).
	CapLogsStream = "logs.stream"
)

// The capability strings of Phase 2 route features: the compiler leaves a route that uses one out
// of the snapshot of an agent without it (docs/03-connections.md, "Versioning and capabilities").
const (
	// CapHTTPRequireHeader: the gateway enforces the require_header rules of access policies.
	CapHTTPRequireHeader = "http.require-header"
	// CapSessionHandoff: the gateway drains the data sessions of the process a connector's
	// SessionHello names in handoff_from, instead of closing them.
	CapSessionHandoff = "session.handoff"
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
