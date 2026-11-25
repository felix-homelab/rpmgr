// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/x509"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
)

// AcceptRoots is exported for the test of the roots a response, a Welcome or a snapshot offers.
var AcceptRoots = acceptRoots

// WriteIdentity is exported so that a test can lay down an identity it holds the keys of.
var WriteIdentity = writeIdentity

// NewStager is exported for the tests of OTA staging.
var NewStager = newStager

// RestartDelay and RandomFraction are exported for the test of the redial after Goodbye{restart}.
var (
	RestartDelay   = restartDelay
	RandomFraction = randomFraction
)

// RuntimeOf returns the snapshot runtime of c.
func RuntimeOf(c *Control) *Runtime { return c.rt }

// HelloOf returns the Hello the control session would send now.
func HelloOf(c *Control) *agentv1.Hello {
	h := &agentv1.Hello{}
	c.client.o.Hello(h)
	return h
}

// CapsOf returns the capabilities the agent announces.
func CapsOf(c *Control) []string { return c.client.o.Capabilities }

// OfferRoots hands the trust roots of an authenticated Welcome to the agent.
func OfferRoots(c *Control, source string, der [][]byte) bool { return c.trust.Offer(source, der) }

// RootsOf returns the roots the control plane holds in memory.
func RootsOf(c *Control) []*x509.Certificate { return c.trust.Certs() }

// SetSessionEnd makes f what ends the control session, as a session would set it.
func SetSessionEnd(c *Control, f func()) {
	c.client.sendMu.Lock()
	defer c.client.sendMu.Unlock()
	c.client.end = f
}

// DenyOf returns the deny-list of c.
func DenyOf(c *Control) *DenyList { return c.deny }
