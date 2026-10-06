// SPDX-License-Identifier: Apache-2.0

// Package s7 is the throw-away prototype of spike S7 (docs/13-roadmap.md, "Phase 0 — spikes"):
// an rpmgr-style internal CA and the TLS checks that rest on it. It is never merged.
package s7

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Kind is the role part of an identity.
type Kind string

const (
	KindConnector  Kind = "connector"
	KindGateway    Kind = "gateway"
	KindController Kind = "controller"
)

// Identity is a principal of one trust domain (docs/04-security.md, "Trust domain and identities").
type Identity struct {
	TrustDomain string
	Org         string // empty for controller nodes
	Kind        Kind
	ID          string
}

// SPIFFE returns the identity's SPIFFE ID, the certificate's single URI SAN.
func (id Identity) SPIFFE() *url.URL {
	path := "/controller/" + id.ID
	if id.Kind != KindController {
		path = "/org/" + id.Org + "/" + string(id.Kind) + "/" + id.ID
	}
	return &url.URL{Scheme: "spiffe", Host: id.TrustDomain, Path: path}
}

// DNSName returns the DNS SAN derived from the identity, which TLS clients use as ServerName.
func (id Identity) DNSName() string {
	return id.ID + "." + string(id.Kind) + "." + id.TrustDomain
}

// DNSNames returns every DNS SAN of the identity's certificate. Controller nodes also carry the
// shared names controller.<td> and reauth.controller.<td>.
func (id Identity) DNSNames() []string {
	if id.Kind == KindController {
		return []string{id.DNSName(), "controller." + id.TrustDomain, "reauth.controller." + id.TrustDomain}
	}
	return []string{id.DNSName()}
}

func (id Identity) String() string { return id.SPIFFE().String() }

var errNotSPIFFE = errors.New("not an rpmgr SPIFFE ID")

// ParseSPIFFE parses a URI SAN strictly: scheme spiffe, host exactly the trust domain (name
// constraints also admit sub-domains, so this check is needed), no user info, port, query or
// fragment, and one of the three path shapes.
func ParseSPIFFE(u *url.URL, td string) (Identity, error) {
	if u == nil || u.Scheme != "spiffe" || u.Host != td || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return Identity{}, fmt.Errorf("%w: %v", errNotSPIFFE, u)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return Identity{}, fmt.Errorf("%w: bad path %q", errNotSPIFFE, u.Path)
		}
	}
	switch {
	case len(parts) == 2 && parts[0] == "controller":
		return Identity{TrustDomain: td, Kind: KindController, ID: parts[1]}, nil
	case len(parts) == 4 && parts[0] == "org" && (parts[2] == string(KindConnector) || parts[2] == string(KindGateway)):
		return Identity{TrustDomain: td, Org: parts[1], Kind: Kind(parts[2]), ID: parts[3]}, nil
	}
	return Identity{}, fmt.Errorf("%w: bad path %q", errNotSPIFFE, u.Path)
}
