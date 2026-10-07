// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/tls"
	"sync/atomic"
)

// Holder holds a certificate that is replaced when it is renewed; a TLS configuration that reads
// it through GetCertificate presents the current one at every handshake, and connections that are
// open keep theirs.
type Holder struct {
	c atomic.Pointer[tls.Certificate]
}

// NewHolder returns a holder of c.
func NewHolder(c tls.Certificate) *Holder {
	h := &Holder{}
	h.Set(c)
	return h
}

// Set replaces the certificate.
func (h *Holder) Set(c tls.Certificate) { h.c.Store(&c) }

// Certificate returns the current certificate.
func (h *Holder) Certificate() tls.Certificate { return *h.c.Load() }

// GetCertificate is tls.Config.GetCertificate.
func (h *Holder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return h.c.Load(), nil
}
