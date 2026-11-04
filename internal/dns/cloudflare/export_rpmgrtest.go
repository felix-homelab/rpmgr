// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package cloudflare

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

// NewForTest returns a client for the API at baseURL that trusts roots, for the tests of other
// packages. It exists only in rpmgrtest builds, which release builds refuse (D60).
func NewForTest(cfg Config, baseURL string, roots *x509.CertPool) (*Client, error) {
	return newClient(cfg, baseURL, &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
	})
}
