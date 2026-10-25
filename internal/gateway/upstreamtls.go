// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/tls"

	"github.com/felix-homelab/rpmgr/internal/upstreamtls"
)

// UpstreamVerify is how the gateway checks an HTTPS upstream's certificate (docs/04-security.md,
// "HTTPS upstreams"; ADR-0017, ADR-0018).
type UpstreamVerify = upstreamtls.Verify

// The ways of UpstreamVerify, as package upstreamtls names them.
const (
	VerifyChain     = upstreamtls.Chain
	VerifyNothing   = upstreamtls.Nothing
	VerifyPinnedKey = upstreamtls.PinnedKey
)

// UpstreamTLS is how the gateway verifies the HTTPS upstream of one route target.
type UpstreamTLS struct {
	// ServerName is the name sent to the upstream (SNI) and, when verified, the name its
	// certificate must hold.
	ServerName string
	// CAPEM verifies the upstream's chain; empty is the host's trust store.
	CAPEM []byte
	// SPKISHA256, if set, must be the SHA-256 of the leaf's SubjectPublicKeyInfo.
	SPKISHA256 []byte
	Verify     UpstreamVerify
	// Connector is the target's connector: its settings apply only to the streams that connector
	// answers. "" from a controller that names none.
	Connector string
}

// config returns the TLS configuration of a connection to the upstream (upstreamtls.Settings).
func (u UpstreamTLS) config() (*tls.Config, error) {
	return upstreamtls.Settings{ServerName: u.ServerName, CAPEM: u.CAPEM, SPKISHA256: u.SPKISHA256, Verify: u.Verify}.Config()
}
